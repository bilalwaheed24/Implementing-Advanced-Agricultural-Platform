#!/usr/bin/env python3
"""Automated security tests for agricultural IoT, run against a live, seeded API.

Each test plays one attacker and asserts the platform's response. Used in CI (Security
workflow, job `iot-attack-tests`) and runnable by hand before a demonstration:

    python3 scripts/iot_attack_tests.py --api-url http://127.0.0.1:8000

Needs the same database as the API (it reads the seeded device list and secrets), exactly
like iot/simulator.py. Exit code 0 = every attack was stopped or detected.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "iot"))

import simulator  # noqa: E402
from ai.data.generate import telemetry_reading  # noqa: E402

PASSWORD = "DemoPassw0rd!2026"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append((name, passed, detail))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}: {detail}", flush=True)


def call(api: str, method: str, path: str, token: str | None = None,
         body: dict | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(api.rstrip("/") + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json",
                                              **({"Authorization": f"Bearer {token}"}
                                                 if token else {})})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read() or b"null")
        except ValueError:
            return error.code, {}


def login(api: str, email: str) -> str:
    status, body = call(api, "POST", "/api/v1/auth/login", body={"email": email,
                                                                  "password": PASSWORD})
    if status != 200:
        raise SystemExit(f"login failed for {email}: {status} {body}")
    return body["access_token"]


def send(api: str, device: dict, secret: str, readings: dict, *, when: datetime | None = None,
         tamper: bool = False, header_age_s: int = 0) -> tuple[int, dict, dict, dict]:
    when = when or datetime.now(timezone.utc)
    body, headers = simulator.build_message(device["id"], secret, readings, when, tamper=tamper)
    if header_age_s:                     # an old message: re-sign with an old timestamp
        old = (datetime.now(timezone.utc) - timedelta(seconds=header_age_s)).isoformat()
        body, headers = simulator.build_message(device["id"], secret, readings,
                                                datetime.fromisoformat(old), tamper=tamper)
    status, payload = simulator.post(api, "/api/v1/telemetry/ingest", body, headers)
    return status, payload, body, headers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    api = args.api_url

    secrets_by_id = simulator.load_secrets()
    devices = [d for d in simulator.load_devices()
               if d["status"] == "ACTIVE" and d["id"] in secrets_by_id]
    by_type: dict[str, dict] = {}
    for device in devices:
        by_type.setdefault(device["device_type"], device)
    if not by_type:
        raise SystemExit("no seeded devices; run scripts/seed_demo.py first")
    rng = random.Random(7)
    print(f"IoT attack tests against {api} ({len(devices)} seeded devices)\n")

    # 1. a legitimate device is accepted (baseline, otherwise every test below is meaningless)
    soil = by_type["SOIL_SENSOR"]
    status, payload, body, headers = send(api, soil, secrets_by_id[soil["id"]],
                                          telemetry_reading("SOIL_SENSOR",
                                                            datetime.now(timezone.utc), rng))
    check("legitimate signed reading is accepted", status == 202, f"HTTP {status}")

    # 2. replay: resend the exact captured message
    status, payload = simulator.post(api, "/api/v1/telemetry/ingest", body, headers)
    check("replayed message is refused", status == 409, f"HTTP {status} {payload.get('detail', '')}")

    # 3. forged signature: attacker does not hold the device secret
    status, payload, _, _ = send(api, soil, secrets_by_id[soil["id"]],
                                 telemetry_reading("SOIL_SENSOR", datetime.now(timezone.utc), rng),
                                 tamper=True)
    check("forged signature is refused", status in (401, 404), f"HTTP {status}")

    # 4. unknown device id: a rogue sensor that was never registered
    rogue = {"id": "00000000-0000-4000-8000-0000000000aa", "device_type": "SOIL_SENSOR"}
    status, payload, _, _ = send(api, rogue, "f" * 64,
                                 telemetry_reading("SOIL_SENSOR", datetime.now(timezone.utc), rng))
    check("unregistered device is refused", status in (401, 404), f"HTTP {status}")

    # 5. stale message: correctly signed, but the timestamp is 10 minutes old
    status, payload, _, _ = send(api, soil, secrets_by_id[soil["id"]],
                                 telemetry_reading("SOIL_SENSOR", datetime.now(timezone.utc), rng),
                                 header_age_s=600)
    check("stale timestamp is refused", status == 422, f"HTTP {status}")

    # 6. physically impossible value: soil pH 27.5 is quarantined, not trusted
    readings = telemetry_reading("SOIL_SENSOR", datetime.now(timezone.utc), rng)
    readings["ph"] = 27.5
    status, payload, _, _ = send(api, soil, secrets_by_id[soil["id"]], readings)
    check("out-of-range reading is quarantined", payload.get("quality") == "QUARANTINED",
          f"HTTP {status} quality={payload.get('quality')}")

    # 7. spoofed but validly signed data scores as more anomalous than normal data
    target_type = "YIELD_MONITOR" if "YIELD_MONITOR" in by_type else "SOIL_SENSOR"
    target = by_type[target_type]
    normal, spoof = [], []
    for drift, bucket in ((0.0, normal), (1.0, spoof)):
        for _ in range(6):
            now = datetime.now(timezone.utc)
            reading = {k: round(v, 3) for k, v in
                       telemetry_reading(target_type, now, rng, drift=drift).items()}
            status, payload, _, _ = send(api, target, secrets_by_id[target["id"]], reading)
            if status == 202 and payload.get("anomaly_score") is not None:
                bucket.append(float(payload["anomaly_score"]))
    mean_normal = statistics.mean(normal) if normal else 0.0
    mean_spoof = statistics.mean(spoof) if spoof else 0.0
    check(f"spoofed {target_type.lower()} data scores higher than normal data",
          bool(spoof) and mean_spoof > mean_normal + 0.1,
          f"mean anomaly normal={mean_normal:.2f} spoof={mean_spoof:.2f}")

    # 8. competitive-intelligence probing: a tenant asks for another tenant's farm records
    admin = login(api, "admin@absp.demo")
    status, farms = call(api, "GET", "/api/v1/farms?page_size=50", admin)
    farm_ids = [f["id"] for f in (farms.get("items", []) if isinstance(farms, dict) else [])]
    prober = login(api, "supply@absp.demo")
    _, me = call(api, "GET", "/api/v1/auth/me", prober)
    statuses = [call(api, "GET", f"/api/v1/farms/{farm_id}", prober)[0] for farm_id in farm_ids]
    check("foreign farm records stay hidden (404, no existence leak)",
          bool(statuses) and all(s == 404 for s in statuses), f"{statuses}")
    analyst = login(api, "analyst@absp.demo")
    status, verdict = call(api, "GET",
                           f"/api/v1/security/data-theft/evaluate?principal_id={me['id']}", analyst)
    signals = [s["signal"] for s in verdict.get("signals", [])]
    check("the data-theft detector records the cross-tenant probing",
          "cross_tenant_attempts" in signals,
          f"score={verdict.get('score')} level={verdict.get('level')} signals={signals}")

    failed = [name for name, passed, _ in RESULTS if not passed]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} attacks stopped or detected")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
