# IoT-Devices.md — Agricultural IoT Architecture and Device Security

Satisfies FR-A1, FR-A2, FR-A4, FR-E3. Implementation: `backend/app/services/devices.py`,
`backend/app/services/telemetry.py`, `backend/app/routers/devices.py`,
`backend/app/routers/telemetry.py`, `iot/simulator.py`.

**Marking:** the device *fleet* is **DEMO/SIMULATION** (`iot/simulator.py`). The device *security
envelope* — identity, provisioning, HMAC authentication, replay protection, validation, lifecycle,
revocation, vulnerability tracking — is **REAL IMPLEMENTATION** and is exercised by the simulator
exactly as physical hardware would exercise it.

---

## 1. Device types derived from the specification

The brief names "agricultural drones, sensors, and autonomous farming equipment" and "satellite
imagery, soil sensors, and yield monitoring". That yields six device classes:

| Class | `device_type` | Telemetry channels | Interval |
|---|---|---|---|
| Agricultural drone | `DRONE` | `altitude_m`, `battery_pct`, `flight_mode`, `images_captured`, `gps_lat/lon` | 30 s while flying |
| Soil sensor | `SOIL_SENSOR` | `soil_moisture_pct`, `soil_temp_c`, `ph`, `nitrogen_ppm`, `phosphorus_ppm`, `potassium_ppm`, `ec_ds_m` | 15 min |
| Weather station | `WEATHER_STATION` | `air_temp_c`, `humidity_pct`, `rainfall_mm`, `wind_speed_ms`, `solar_w_m2` | 10 min |
| Yield monitor (harvester) | `YIELD_MONITOR` | `yield_t_ha`, `moisture_pct`, `speed_kmh`, `swath_m` | 10 s while harvesting |
| Irrigation controller | `IRRIGATION_CONTROLLER` | `valve_state`, `flow_l_min`, `pressure_bar`, `duration_s` | on change + 30 min heartbeat |
| Cold-chain / storage sensor | `COLD_CHAIN_SENSOR` | `temp_c`, `humidity_pct`, `door_open`, `shock_g` | 5 min, bound to a shipment |

Autonomous equipment is represented by `YIELD_MONITOR` and `IRRIGATION_CONTROLLER`, which are the
control-system classes relevant to FR-E2 ("automated security testing for agricultural IoT and
control systems").

## 2. Device identity

Each device has an opaque UUID `device_id` and a 256-bit secret generated with `secrets.token_hex(32)`.

The server must be able to recompute the message HMAC, so the secret has to be recoverable: a
one-way hash would make verification impossible. It is therefore stored **encrypted**, using
AES-256-GCM with the device id as associated data and a key supplied by the environment (KMS in
production). Consequences of that choice, stated plainly:

* A database dump alone does not yield usable device secrets, because the key is not in the database.
* Compromise of the application key does expose every device secret, so the key is the highest-value
  secret in the system and is the first candidate for HSM custody in production.
* The alternative that removes this trade-off entirely is asymmetric device identity (X.509 client
  certificates, private key never leaving the device), which is the documented production path in §15.

The plaintext is returned exactly once, in the provisioning response, and never appears in logs or
in any subsequent response.

## 3. Provisioning and registration

```
POST /api/v1/devices                (FARM_OPERATOR or ADMIN, org-scoped)
  body: {device_type, model, firmware_version, farm_id, field_id?, interval_seconds}
  → creates the device in status PROVISIONED
  → 201 {device_id, device_secret, note: "shown once"}
POST /api/v1/devices/{id}/activate  → PROVISIONED → ACTIVE
POST /api/v1/devices/{id}/rotate-secret → issues a new secret, invalidates the old immediately
```

## 4. Device authentication (REAL)

Canonical string, then HMAC-SHA256 with the device secret:

```
canonical = device_id + "\n" + timestamp_iso + "\n" + nonce + "\n" + sha256(compact_json(readings))
signature = hex(hmac_sha256(device_secret, canonical))
```

The request carries `X-Device-Id`, `X-Device-Timestamp`, `X-Device-Nonce`, `X-Device-Signature`.
Server checks, in order and with a generic failure response:

1. Device exists and is `ACTIVE` (not `SUSPENDED`, `QUARANTINED` or `RETIRED`).
2. `|now − timestamp| ≤ 300 s` (clock-skew window).
3. Nonce has not been seen for this device inside the window (replay cache + DB unique constraint
   on `(device_id, nonce)`).
4. `hmac.compare_digest` over the recomputed signature (constant time).

Failures increment a per-device counter and emit a security log line; repeated failures raise an
alert and can auto-suspend the device.

## 5. Device authorisation

A device may only write telemetry for itself, and only to the farm/field it is registered to. A
device credential can never be used on a user route; the two credential types resolve to different
principal classes and no device permission grants read access to other devices' data.

## 6. Secure communication

Demo: HTTP on loopback with application-layer HMAC integrity.
Production: TLS 1.3 with the same HMAC retained as defence in depth, or MQTT over mTLS with X.509
client certificates issued by a device CA (see §14). The application-layer authentication is
transport-independent by design.

## 7. Telemetry schema and validation (FR-A2)

Each reading is typed and range-checked before persistence:

| Channel | Accepted range | Action on breach |
|---|---|---|
| `soil_moisture_pct` | 0–100 | reject reading, quarantine record, alert |
| `ph` | 0–14 | reject |
| `soil_temp_c` / `air_temp_c` | −60…80 | reject |
| `battery_pct` | 0–100 | reject |
| `yield_t_ha` | 0–50 | reject |
| `temp_c` (cold chain) | −40…60 | reject |
| any unknown channel | — | rejected as schema violation |

Payloads are stored encrypted (AES-256-GCM) with the telemetry id as associated data. A SHA-256
digest of the raw payload is stored alongside for integrity checking.

## 8. Satellite imagery pipeline (FR-A2)

Scene metadata (`scene_id`, `captured_at`, `field_id`, `ndvi_mean`, `ndvi_min`, `ndvi_max`,
`cloud_cover_pct`, `checksum`) is ingested through an authenticated route, checksum-verified and
range-validated. NDVI series are joined with soil moisture to produce per-field stress ranking.
Raster imagery itself is out of scope for the demo; the pipeline is validated with synthetic scene
metadata. **DEMO/SIMULATION.**

## 9. Gateway architecture

Devices in a field may report through a farm gateway that batches messages:
`POST /api/v1/telemetry/batch` accepts up to 500 messages, each individually signed by its own
device. The gateway cannot forge a message it does not have the secret for — it is a transport, not
a trust anchor. Partial acceptance is reported per message.

## 10. Device health and monitoring (FR-A4)

`last_seen_at`, `battery_pct`, `signal_dbm`, `firmware_version`, `error_count` are updated on every
accepted message. A sweep marks a device `silent` when it misses 3 expected intervals and raises a
`WARNING` alert; battery below 15 % raises a `WARNING`; repeated authentication failures raise a
`HIGH` alert.

## 11. Anomaly detection (FR-A5)

Features per message: each numeric channel, delta from the device's rolling mean, time since the
previous message, and hour of day. An `IsolationForest` per device class scores the vector; the
score is stored on the telemetry row and, above threshold, raises an alert citing the contributing
channels. Detects: sensor drift, stuck sensors, physically implausible jumps, off-schedule bursts,
and spoofed data whose distribution differs from the device's history.

## 12. Firmware and vulnerability management (FR-E3)

Each device records its firmware version. `device_vulnerabilities` holds
`{cve_id, severity, affected_versions, fixed_in, status, discovered_at, remediated_at}`.
`GET /api/v1/devices/vulnerabilities/summary` reports fleet posture by severity and status, which
is the "vulnerability management for connected farming equipment" deliverable. A device with an
open CRITICAL vulnerability is flagged in the UI and can be suspended by policy.

## 13. Device lifecycle and compromise handling

```
PROVISIONED ──activate──► ACTIVE ──suspend──► SUSPENDED ──activate──► ACTIVE
                            │                     │
                            └──quarantine──► QUARANTINED ──retire──► RETIRED
```

Quarantine is the containment action for a suspected compromise: the secret is revoked, telemetry
is rejected at authentication, an incident is opened, and every step is audited. Historic telemetry
from the device is retained but flagged `suspect` so downstream analytics can exclude it.

## 14. Offline operation and synchronisation

A device that cannot reach the platform buffers messages locally with their original timestamps and
per-message nonces, then replays them through the batch endpoint. Because each buffered message
carries its own nonce and signature, a replayed batch is idempotent and a duplicated batch is
rejected. Messages older than the 300 s window are accepted only through the batch endpoint, which
applies a wider `backfill` window (24 h) and marks the rows `backfilled` — a deliberate,
documented relaxation of the replay window for offline farms.

## 15. Production path

| Aspect | Demo | Production |
|---|---|---|
| Transport | HTTP + HMAC | MQTT 5 over TLS 1.3, or HTTPS |
| Identity | Shared secret | X.509 client certificate from a device CA, key in a secure element |
| Broker | none | Mosquitto / EMQX / AWS IoT Core with per-device policies |
| Provisioning | API call | Zero-touch provisioning with attestation |
| Firmware | Version string | Signed OTA updates with rollback |
| Scale | Single node | Broker + stream processor + time-series store |

## 16. Simulator (`iot/simulator.py`) — DEMO/SIMULATION

Generates realistic diurnal and seasonal patterns per device class, signs every message with the
device's real secret, and supports fault-injection modes for the demonstration:

| Mode | Behaviour | Expected platform response |
|---|---|---|
| `normal` | Physically plausible readings | Accepted, low anomaly score |
| `drift` | Slow sensor drift beyond plausible bounds | Anomaly alert |
| `spoof` | Attacker-generated distribution | Anomaly alert |
| `replay` | Re-sends a captured signed message | 409 replay rejected |
| `bad-signature` | Wrong secret | 401 authentication failure + security log |
| `malformed` | Out-of-range values | 422 with quarantined record |
| `cold-chain-break` | Temperature excursion on a shipment | Fraud/integrity signal on the batch |
