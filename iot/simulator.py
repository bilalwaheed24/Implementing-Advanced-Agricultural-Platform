#!/usr/bin/env python3
"""Agricultural IoT device simulator — DEMO/SIMULATION.

The devices are simulated; the security envelope they exercise is real. Every message
is signed with the device's real secret using the same HMAC scheme physical hardware
would use (IoT-Devices.md §4).

Fault-injection modes let the demonstration prove each control:

    normal          plausible readings                 -> accepted
    drift           progressive sensor drift           -> anomaly alert over time
    spoof           attacker-shaped distribution       -> anomaly alert
    replay          re-sends a captured signed message -> 409 replay rejected
    bad-signature   wrong secret                       -> 401/404 auth failure
    malformed       out-of-range values                -> 422 quarantined
    cold-chain-break temperature excursion             -> integrity signal on the batch

Usage:
    python3 iot/simulator.py --mode normal --count 20
    python3 iot/simulator.py --mode replay
    python3 iot/simulator.py --list-devices
"""
from __future__ import annotations

import argparse
import json
import random
import secrets
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from ai.data.generate import telemetry_reading                     # noqa: E402
from app.core.security import device_signature                     # noqa: E402

def _secrets_file() -> Path:
    from app.core.config import get_settings

    data_dir = Path(get_settings().data_dir)
    if not data_dir.is_absolute():
        data_dir = ROOT / data_dir
    return data_dir / "demo_device_secrets.json"


SECRETS_FILE = _secrets_file()
MODES = ["normal", "drift", "spoof", "replay", "bad-signature", "malformed", "cold-chain-break"]


def load_secrets() -> dict[str, str]:
    if not SECRETS_FILE.is_file():
        raise SystemExit("demo_device_secrets.json not found. Run: python3 scripts/seed_demo.py")
    return json.loads(SECRETS_FILE.read_text())["secrets"]


def load_devices() -> list[dict]:
    from app.core.database import SessionLocal
    from app.models import Device
    from sqlalchemy import select

    with SessionLocal() as db:
        return [{"id": d.id, "device_type": d.device_type, "status": d.status,
                 "model": d.model, "farm_id": d.farm_id}
                for d in db.execute(select(Device).where(Device.deleted_at.is_(None))).scalars()]


def post(url: str, path: str, body: dict, headers: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        url.rstrip("/") + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read() or b"{}")
        except Exception:                                            # noqa: BLE001
            return error.code, {}
    except urllib.error.URLError as error:
        raise SystemExit(f"Cannot reach the API at {url}: {error.reason}") from error


def build_message(device_id: str, secret: str, readings: dict, recorded_at: datetime,
                  shipment_id: str | None = None, tamper: bool = False) -> tuple[dict, dict]:
    nonce = secrets.token_hex(16)
    timestamp = recorded_at.isoformat()
    signing_secret = secret if not tamper else secrets.token_hex(32)
    signature = device_signature(signing_secret, device_id, timestamp, nonce, readings)
    body = {"recorded_at": timestamp, "nonce": nonce, "readings": readings}
    if shipment_id:
        body["shipment_id"] = shipment_id
    headers = {"X-Device-Id": device_id, "X-Device-Timestamp": timestamp,
               "X-Device-Nonce": nonce, "X-Device-Signature": signature}
    return body, headers


def run(mode: str, count: int, api_url: str, delay: float, device_type: str | None) -> int:
    device_secrets = load_secrets()
    devices = [d for d in load_devices()
               if d["status"] == "ACTIVE" and d["id"] in device_secrets]
    if device_type:
        devices = [d for d in devices if d["device_type"] == device_type.upper()]
    if not devices:
        raise SystemExit("No active seeded devices match. Run scripts/seed_demo.py first.")

    rng = random.Random()
    now = datetime.now(timezone.utc)
    accepted = rejected = 0
    print(f"Simulator mode={mode} devices={len(devices)} target={api_url}")

    if mode == "replay":
        device = devices[0]
        secret = device_secrets[device["id"]]
        readings = telemetry_reading(device["device_type"], now, rng)
        body, headers = build_message(device["id"], secret, readings, now)
        status, payload = post(api_url, "/api/v1/telemetry/ingest", body, headers)
        print(f"  first send      -> {status} {payload.get('quality', payload.get('title', ''))}")
        status, payload = post(api_url, "/api/v1/telemetry/ingest", body, headers)
        print(f"  identical replay-> {status} {payload.get('title', '')}: "
              f"{payload.get('detail', '')}")
        return 0 if status == 409 else 1

    if mode == "bad-signature":
        device = devices[0]
        readings = telemetry_reading(device["device_type"], now, rng)
        body, headers = build_message(device["id"], device_secrets[device["id"]], readings, now,
                                      tamper=True)
        status, payload = post(api_url, "/api/v1/telemetry/ingest", body, headers)
        print(f"  wrong secret    -> {status} {payload.get('title', '')}")
        return 0 if status in (401, 404) else 1

    if mode == "malformed":
        device = next((d for d in devices if d["device_type"] == "SOIL_SENSOR"), devices[0])
        readings = telemetry_reading(device["device_type"], now, rng)
        readings["ph"] = 27.5                                # outside the physical range 0-14
        body, headers = build_message(device["id"], device_secrets[device["id"]], readings, now)
        status, payload = post(api_url, "/api/v1/telemetry/ingest", body, headers)
        print(f"  out-of-range ph -> {status} quality={payload.get('quality')} "
              f"anomaly={payload.get('anomaly_score')}")
        return 0 if payload.get("quality") == "QUARANTINED" else 1

    if mode == "cold-chain-break":
        device = next((d for d in devices if d["device_type"] == "COLD_CHAIN_SENSOR"), None)
        if device is None:
            raise SystemExit("No cold-chain sensor is seeded")
        for i in range(count):
            temperature = 3.0 if i < count // 2 else 14.0 + i * 0.4     # excursion
            readings = {"temp_c": round(temperature, 2), "humidity_pct": 85.0, "shock_g": 0.4}
            body, headers = build_message(device["id"], device_secrets[device["id"]], readings,
                                          now + timedelta(seconds=i))
            status, payload = post(api_url, "/api/v1/telemetry/ingest", body, headers)
            accepted += status == 202
            print(f"  temp {temperature:5.1f} C -> {status} anomaly={payload.get('anomaly_score')}")
            time.sleep(delay)
        print(f"  accepted {accepted}/{count}; run the batch verification to see the "
              f"cold_chain_break finding")
        return 0

    # normal / drift / spoof
    for i in range(count):
        device = devices[i % len(devices)]
        drift = 0.0
        if mode == "drift":
            drift = min(0.9, (i / max(1, count - 1)) * 0.9)   # progressive
        elif mode == "spoof":
            drift = 1.0
        recorded_at = datetime.now(timezone.utc)
        readings = telemetry_reading(device["device_type"], recorded_at, rng, drift=drift)
        readings = {k: round(v, 3) for k, v in readings.items()}
        body, headers = build_message(device["id"], device_secrets[device["id"]], readings,
                                      recorded_at)
        status, payload = post(api_url, "/api/v1/telemetry/ingest", body, headers)
        if status == 202:
            accepted += 1
            print(f"  [{i + 1:3d}/{count}] {device['device_type']:22s} accepted "
                  f"anomaly={payload.get('anomaly_score'):<7} quality={payload.get('quality')}")
        else:
            rejected += 1
            print(f"  [{i + 1:3d}/{count}] {device['device_type']:22s} REJECTED {status} "
                  f"{payload.get('title', '')}")
        time.sleep(delay)

    print(f"\nAccepted {accepted}, rejected {rejected}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=MODES, default="normal")
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--device-type", default=None)
    parser.add_argument("--list-devices", action="store_true")
    args = parser.parse_args()

    if args.list_devices:
        for device in load_devices():
            print(f"  {device['id']}  {device['device_type']:22s} {device['status']:12s} "
                  f"{device['model']}")
        return 0
    return run(args.mode, args.count, args.api_url, args.delay, args.device_type)


if __name__ == "__main__":
    raise SystemExit(main())
