# DEMO-RUNBOOK.md — running the demonstration under exam conditions

Written to be followed while someone is watching. Every command here was executed against this
repository on 2026-09-13; the numbers quoted are what the commands actually produced.

---

## A. Pre-demo check

Run this **before** the examiner is in the room. Budget ten minutes the first time: if no model
artefacts exist yet, `run_local.sh` trains them, which takes a few minutes.

```bash
cd agri-biotech-security-platform

# 1. Clean state: wipes the database and ledger, reseeds, starts the API.
./scripts/run_local.sh --reset
```

That single command creates `.env` with fresh secrets if missing, trains the AI models if they are
absent, seeds the demonstration data, and serves on **http://127.0.0.1:8000**.

In a second terminal, confirm it is actually up and populated:

```bash
# 2. Health
curl -s http://127.0.0.1:8000/health
#    -> {"status":"ok", ... "demo_mode":true}

# 3. Deeper check — nine assertions against the running instance
python3 scripts/smoke_test.py --api-url http://127.0.0.1:8000
#    -> SMOKE TEST PASSED

# 4. Layer the GMO / supply-chain / biosecurity story on top, WITHOUT the tamper step
python3 scripts/demo_flow.py --api-url http://127.0.0.1:8000 --skip-tamper
#    -> DEMONSTRATION COMPLETE — 25 steps, every check passed.
```

**Confirm the port.** The API serves on `127.0.0.1:8000`. If you started it with
`docker compose up -d api` it is the same port, published to localhost only.

**Expected clean state after the above:**

| Screen | Expect |
|---|---|
| Dashboard → Integrity failures | **0** |
| Telemetry | 78 readings, six device classes |
| Satellite & NDVI | 6 scenes, one field flagged HIGH stress |
| AI Insights | 82 analyses (INFO/WARNING mix) |
| Sequence Screening | 2 screenings — one CLEAR, one BLOCK |
| Alerts | 2 CRITICAL (blocked screening, DURC gene edit) + 1 WARNING (low NDVI) |
| Batches | 1 batch, integrity **VERIFIED** |

The two CRITICAL alerts are **supposed** to be there — they are the biosecurity demonstration
working. They are not left-over test noise, and each one opens to a stored rationale.

---

## B. Demo accounts

Every seeded account uses the same demonstration password, which is printed on the login page and
in `scripts/seed_demo.py`. It exists only in the seeded demo database — there is no real secret
here to protect.

The login form is **pre-filled with the Administrator account**, and the account buttons below the
form fill it for any other role. The highlighted button shows which account Sign in will use.

| Role | Demo email | What this role demonstrates |
|---|---|---|
| Administrator | `admin@absp.demo` | Every area — use this for the main walkthrough (23 navigation links) |
| Farm operator | `farmer@absp.demo` | Farms, devices, telemetry, satellite — the producer's view (16 links) |
| Agronomist | `agronomist@absp.demo` | Read-only agronomy: cannot create or modify a device (15 links) |
| Security analyst | `analyst@absp.demo` | Alerts, incidents, audit trail, data-theft detection (22 links) |
| Biotech researcher | `researcher@absp.demo` | Submits screenings and CRISPR proposals — **cannot** review its own (13 links) |
| Biosafety officer | `biosafety@absp.demo` | The only role that can release a BLOCK verdict (12 links) |
| Supply chain operator | `supply@absp.demo` | Batches, custody events, shipments, cold chain (16 links) |
| Certifier | `certifier@absp.demo` | Issues and revokes organic / non-GMO certifications (13 links) |
| Regulator | `regulator@absp.demo` | Cross-organisation oversight and compliance reports (22 links) |

The differing link counts are the point: the navigation is built from the caller's real permission
set, and the server enforces the same boundary independently.

---

## C. Primary demo flow

Roughly eight minutes at a calm pace. Stay on this path; the optional material is in §D.

| # | Do this | Say this |
|---|---|---|
| 1 | Sign in as **Administrator** (form is already filled) | "Nine roles, deny-by-default. I'm using the admin account so you can see every area." |
| 2 | **Dashboard** | "Tiles are filtered to the permissions this role actually holds. Integrity failures: zero — that's a healthy starting state." |
| 3 | **Farms & Fields** | "Three farms, nine fields, scoped to one organisation. A competitor cannot see these." |
| 4 | **Devices** | "Six device classes. Each has a cryptographic identity and a CVE list — vulnerability management for field equipment, not just for code." |
| 5 | **Telemetry** | "78 readings. Every one arrived HMAC-signed, was range-validated and anomaly-scored before it was stored. Payloads are encrypted at rest — you're seeing a numeric summary only." |
| 6 | **Satellite & NDVI** | "Scene metadata, checksum-verified on ingestion. Block B is flagged high stress from its NDVI." |
| 7 | **AI Insights** | "82 analyses. Open a model card — it states the training data is synthetic, on the card itself." |
| 8 | **Sequence Screening** | "k-mer seeding with Smith–Waterman alignment against a hazard database. It finds diverged homology, not just exact matches." |
| 9 | Open the **BLOCK** row | "94% identity to a severity-5 phytopathogen effector. 'Why this verdict' is the engine's own stored rationale, with the alignment coordinates a reviewer would check. The submitter cannot release this — only a biosafety officer can." |
| 10 | **GMO Registry** | "Registration is gated on a passing screening. The gate is real, not advisory." |
| 11 | **Batches** → open the batch | "Seed lot to batch to custody events, with quantity conservation enforced by the contract." |
| 12 | **Blockchain** | "Chain verification across every block and signature. Hashes and identifiers on-chain, payloads off-chain." |
| 13 | **Consumer page** — open `/verify.html?code=…` in a new tab, no login | "No account needed. Note what is *not* here: no farmer identity, no coordinates. Privacy is a design decision, not an oversight." |
| 14 | **Audit Trail** | "Append-only and hash-chained. Each entry links to the previous one, and the head is anchored to the ledger." |

Get the verification code for step 13 from the last line of `demo_flow.py`'s output, or:

```bash
sqlite3 absp.db "select verification_code from batches limit 1;"
```

---

## D. Optional security demo

Only if there is time, or if asked "how do you know detection works?".

```bash
# Tamper: alters an anchored record, proves detection, then restores it.
python3 scripts/demo_flow.py --api-url http://127.0.0.1:8000
```

Step 22 shows, in order:

1. A batch's declared origin is rewritten directly in the database — classic origin fraud.
2. `MISMATCH` — the recomputed content hash no longer matches the ledger anchor.
3. Batch integrity degrades to **FAILED** with `ledger_mismatch` cited.
4. The original value is restored; verification returns **MATCH**.
5. Re-assessment returns integrity to **VERIFIED**.

The CRITICAL fraud alert stays open on purpose — a detection is an audit record, not something a
demo should erase.

Device-level attacks, if asked:

```bash
python3 iot/simulator.py --mode replay          # 409 — nonce already used
python3 iot/simulator.py --mode bad-signature   # 404 — not 403: existence is not confirmed
python3 iot/simulator.py --mode malformed       # 202 accepted but QUARANTINED
python3 iot/simulator.py --mode spoof --count 6 # anomaly score rises, reading marked SUSPECT
```

---

## E. Reset

```bash
# Back to the clean exam state from anywhere
./scripts/run_local.sh --reset
python3 scripts/demo_flow.py --api-url http://127.0.0.1:8000 --skip-tamper
```

Run this after §D. The tamper demo leaves a CRITICAL fraud alert open by design, and you do not
want that on screen when the examiner first looks at the dashboard.

---

## F. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Address already in use` on 8000 | Something else holds the port | `PORT=8100 ./scripts/run_local.sh`, then use `--api-url http://127.0.0.1:8100` everywhere. Check the holder with `ss -ltnp \| grep :8000` |
| Docker container never becomes healthy | Still starting; the healthcheck has a 15 s start period | `docker compose logs -f api`; wait ~30 s. `docker inspect --format '{{.State.Health.Status}}' <container>` |
| UI looks stale after a reset | Browser cached the old JS module | Hard reload: Ctrl+Shift+R. The SPA is ES modules with no service worker, so one hard reload is enough |
| Dashboard shows integrity failures | The tamper demo (§D) was run and not reset | Re-run §E |
| Half the navigation is missing | Signed in as a role with fewer permissions — most often Farm operator | Sign out, pick **Administrator** on the login page, sign in again. The selected account is highlighted |
| `Device authentication failed` from the simulator | `demo_device_secrets.json` no longer matches the database (a reseed regenerates both) | Re-run `./scripts/run_local.sh --reset`, which rewrites both together |
| Telemetry / Satellite / AI Insights empty | `seed_demo.py` was not run, or a raw `create_all()` built the schema only | `./scripts/run_local.sh --reset` |
| `demo_flow.py` tamper step says SKIPPED | The script's `DATABASE_URL` does not resolve to the same database the API is using | Run it on the same host as the API, as `run_local.sh` does |

---

## G. Real vs simulated

State this before you are asked. It is the difference between a candidate who knows their system
and one who gets caught.

**Real — genuinely implemented and exercised:**

- Authentication: bcrypt (cost 12), JWT access tokens (30 min), refresh rotation with reuse
  detection, lockout after 5 failures for 15 minutes.
- Authorisation: 9 roles, deny-by-default, enforced in the data-access layer; a mutating route
  without an authorisation declaration fails the test suite.
- Multi-tenancy: a foreign organisation's record returns **404, not 403** — the platform does not
  confirm that another organisation's record exists.
- The API: 121 operations across 101 paths, generated OpenAPI, real validation.
- Device security: per-device 256-bit secret encrypted at rest, HMAC-SHA256 message signing,
  replay protection by nonce, freshness window, monotonic sequence, physical-range validation.
- The AI inference path: real models, real scoring, real model cards.
- Traceability: seed lot → batch → custody events → shipment, with quantity conservation enforced.
- The ledger: real ECDSA P-256 signing and endorsement, real SHA-256 hash chaining, Merkle roots,
  and verification that genuinely detects an altered record.
- Audit logging: append-only, hash-chained, with the head anchored to the ledger.
- Cryptography throughout: AES-256-GCM at rest, no home-made primitives.

**Simulated or demonstration-only — say so plainly:**

- Physical farm devices. There is no hardware; `iot/simulator.py` drives the fleet. The *fleet* is
  simulated, the *security envelope* is not — the simulator gets no backdoor and signs every
  message the way real hardware would.
- Agricultural telemetry values, generated by `ai/data/generate.py`.
- Satellite data: scene **metadata** with NDVI statistics and a checksum. No raster imagery, and
  OpenDroneMap/QGIS were not used.
- AI training data: synthetic labelled demonstration datasets. Reported accuracy describes the
  synthetic task only.
- The blockchain: a local single-node permissioned cryptographic ledger, Fabric-*shaped* but not a
  deployed Hyperledger Fabric consortium. Single-node ordering.
- Cloud infrastructure: Terraform and Kubernetes manifests are written and validate, but have
  never been applied to a live account or cluster.
- Hazard sequences: synthetic motifs, not real pathogen genomes.

Full detail, and what production would change, is in `EXAM-LIMITATIONS.md`.
