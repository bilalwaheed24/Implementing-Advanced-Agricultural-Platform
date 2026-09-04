#!/usr/bin/env python3
"""Seed the platform with a complete, clearly-marked demonstration dataset.

DEMO/SIMULATION: every record created here is synthetic (ADR-013).
Usage:  python3 scripts/seed_demo.py [--reset]
"""
from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.core.database import SessionLocal, create_all, drop_all          # noqa: E402
from app.core.security import (device_signature, encrypt_at_rest,         # noqa: E402
                               generate_device_secret, hash_password, utcnow,
                               verification_code)
from app.models import (Certification, Crop, Device, DeviceVulnerability, Farm,  # noqa: E402
                        Field, HazardSequence, Organization, Product, User)

DEMO_PASSWORD = "DemoPassw0rd!2026"      # documented demo credential, not a production secret

ORGS = [
    ("AgriGenome Biotech", "BIOTECH", "BiotechMSP", "US", "0950110000001", []),
    ("Green Valley Farm Cooperative", "FARM", "FarmMSP", "US", "0950110000002", []),
    ("Continental Foods Processing", "SUPPLY", "SupplyMSP", "NL", "0950110000003", []),
    ("Global Food Safety Authority", "REGULATOR", "RegulatorMSP", "US", "0950110000004",
     ["ORGANIC", "NON_GMO", "SPECIALTY"]),
]

USERS = [
    ("admin@absp.demo", "Alex Admin", "ADMIN", 3),
    ("analyst@absp.demo", "Sam Security", "SECURITY_ANALYST", 3),
    ("farmer@absp.demo", "Dana Fields", "FARM_OPERATOR", 1),
    ("agronomist@absp.demo", "Remy Green", "AGRONOMIST", 1),
    ("researcher@absp.demo", "Dr Rao Sequence", "BIOTECH_RESEARCHER", 0),
    ("biosafety@absp.demo", "Marta Safe", "BIOSAFETY_OFFICER", 0),
    ("supply@absp.demo", "Tom Logistics", "SUPPLY_CHAIN_OPERATOR", 2),
    ("certifier@absp.demo", "Ines Certify", "CERTIFIER", 3),
    ("regulator@absp.demo", "Aisha Regulate", "REGULATOR", 3),
]

FARMS = [
    ("Green Valley North", "Iowa", "US", 42.03, -93.63, 420.0),
    ("Green Valley South", "Iowa", "US", 41.88, -93.41, 310.0),
    ("Riverbend Estate", "Nebraska", "US", 40.81, -96.68, 275.0),
]

FIELD_NAMES = ["Block A", "Block B", "Block C"]

DEVICE_PLAN = [
    ("SOIL_SENSOR", "TerraProbe TP-200", "2.3.1", 900),
    ("SOIL_SENSOR", "TerraProbe TP-200", "2.1.0", 900),
    ("WEATHER_STATION", "AeroStat WS-40", "4.0.2", 600),
    ("DRONE", "AgriWing X5", "1.9.4", 30),
    ("YIELD_MONITOR", "HarvestSense YM-9", "3.2.0", 10),
    ("IRRIGATION_CONTROLLER", "AquaFlow IC-12", "1.4.7", 1800),
    ("COLD_CHAIN_SENSOR", "ChillGuard CC-3", "2.0.5", 300),
]

VULNERABILITIES = [
    ("CVE-2025-31337", "Unauthenticated firmware update on the maintenance port",
     "CRITICAL", 9.8, "< 2.3.0", "2.3.0"),
    ("CVE-2025-22110", "Hard-coded diagnostic credential in the telemetry service",
     "HIGH", 8.1, "<= 1.9.4", "1.9.5"),
    ("CVE-2024-99012", "Weak entropy in the session nonce generator",
     "MEDIUM", 5.4, "< 4.0.0", "4.0.0"),
]

PRODUCTS = [
    ("09501101530003", "Sweet Maize Kernels 400g", "Canned vegetables", False, False, None, None),
    ("09501101530010", "Organic Soy Flour 1kg", "Milled products", True, True, None, None),
    ("09501101530027", "Chilled Sweetcorn 750g", "Chilled vegetables", False, False, 0.0, 4.0),
]


# Readings per device across the observation window, and how far back that window runs.
TELEMETRY_READINGS_PER_DEVICE = 6
TELEMETRY_WINDOW_HOURS = 18

# Field NDVI for the seeded satellite scenes. One field is deliberately stressed so the
# stress ranking and the low-vegetation alert have something real to show.
SCENE_NDVI = [0.78, 0.71, 0.28, 0.64, 0.69, 0.58]


def _seed_telemetry(db, devices, device_secrets, rng, now) -> dict[str, int]:
    """Ingest demonstration telemetry through the real ingestion path.

    Nothing is inserted directly: every reading is HMAC-signed with the device's own
    secret and passed through `verify_and_ingest`, so it exercises identity checks,
    replay protection, range validation, encryption at rest and anomaly scoring
    exactly as a physical device would.  That is also what populates AI Insights,
    because scoring writes an `AIAnalysis` row per reading.
    """
    import secrets as _secrets

    from ai.data.generate import telemetry_reading
    from app.services import telemetry as telemetry_service

    accepted = quarantined = 0
    for position, device in enumerate(devices):
        secret = device_secrets[device.id]
        for step in range(TELEMETRY_READINGS_PER_DEVICE):
            # Newest reading last, spread back over the observation window.
            age_hours = TELEMETRY_WINDOW_HOURS * (TELEMETRY_READINGS_PER_DEVICE - 1 - step) / max(
                1, TELEMETRY_READINGS_PER_DEVICE - 1)
            recorded_at = now - timedelta(hours=age_hours, minutes=rng.randint(0, 20))

            # Two sensors drift near the end of the window so the data is not a flat
            # wall of "OK": those readings score in the WARNING band and appear in AI
            # Insights with their reasons.  The drift is deliberately held below the
            # alert threshold (0.65), because at that score the reading is marked
            # SUSPECT *and* raises a HIGH alert, which opens an incident — a clean exam
            # start must not begin with an open incident.  SUSPECT, QUARANTINED,
            # replay and spoofing are demonstrated on purpose from `iot/simulator.py`
            # (see the security demonstration section of README.md).
            drift = 0.0
            if position in (0, 1) and step >= TELEMETRY_READINGS_PER_DEVICE - 2:
                drift = 0.55

            readings = telemetry_reading(device.device_type, recorded_at, rng, drift=drift)
            # The signed header timestamp is the send time; recorded_at is when the
            # reading was taken.  Both are inside the accepted freshness window.
            timestamp = now.isoformat().replace("+00:00", "Z")
            nonce = _secrets.token_hex(16)
            signature = device_signature(secret, device.id, timestamp, nonce, readings)
            try:
                record = telemetry_service.verify_and_ingest(
                    db, device.id, timestamp, nonce, signature, recorded_at, readings,
                    sequence=step + 1, score_inline=True)
            except Exception as error:                              # noqa: BLE001
                print(f"  telemetry seed skipped for {device.device_type}: {error}")
                continue
            if record.quality == "QUARANTINED":
                quarantined += 1
            else:
                accepted += 1
    db.flush()
    return {"accepted": accepted, "quarantined": quarantined}


def _seed_satellite(db, fields, users, farm_org, now) -> int:
    """Ingest satellite scene metadata through the checksum-verified service path."""
    from app.services import telemetry as telemetry_service

    actor = users["FARM_OPERATOR"]
    seeded = 0
    for index, field in enumerate(fields[:len(SCENE_NDVI)]):
        ndvi = SCENE_NDVI[index]
        captured_at = (now - timedelta(days=2, hours=index)).replace(microsecond=0)
        scene_id = f"S2A-DEMO-{index + 1:04d}"
        checksum = telemetry_service.scene_checksum(scene_id, field.id, captured_at, ndvi)
        try:
            telemetry_service.ingest_scene(
                db, farm_org.id, actor.id, actor.role, scene_id, field.id,
                "Sentinel-2 (simulated)", captured_at, ndvi,
                round(ndvi - 0.19, 2), round(min(1.0, ndvi + 0.13), 2),
                round(6.0 + index * 2.5, 1), checksum)
            seeded += 1
        except Exception as error:                                  # noqa: BLE001
            print(f"  satellite seed skipped for {field.name}: {error}")
    db.flush()
    return seeded


def _seed_crop_vision(db, fields, farm_org) -> int:
    """One crop-vision analysis per condition, stored the same way the API stores it."""
    import numpy as np

    from ai.data.generate import leaf_patch
    from ai.vision import IMAGE_SIZE, classify
    from app.core.config import get_settings
    from app.models import AIAnalysis

    settings = get_settings()
    model_dir = str(settings.repo_root / "ai" / "models")
    rng = np.random.default_rng(2026)
    seeded = 0
    for index, label in enumerate(["HEALTHY", "LEAF_BLIGHT", "RUST", "NUTRIENT_DEFICIENCY"]):
        try:
            result = classify(leaf_patch(label, IMAGE_SIZE, rng), model_dir=model_dir)
        except Exception as error:                                  # noqa: BLE001
            print(f"  crop-vision seed skipped for {label}: {error}")
            continue
        field = fields[index % len(fields)]
        db.add(AIAnalysis(
            org_id=farm_org.id, analysis_type="CROP_VISION", subject_type="Field",
            subject_id=field.id, score=float(result["confidence"]),
            level="INFO" if result["label"] == "HEALTHY" else "WARNING",
            reasons=[result.get("advice", f"Classified as {result['label']}")],
            evidence={"label": result["label"], "simulated_label": label,
                      "probabilities": result["probabilities"], "field": field.name},
            model_version=result.get("model_version", "crop-vision"),
            degraded=bool(result.get("degraded"))))
        seeded += 1
    db.flush()
    return seeded


def reset(session) -> None:
    drop_all()
    create_all()


def seed(reset_first: bool) -> dict:
    create_all()
    rng = random.Random(2026)
    now = utcnow()

    with SessionLocal() as db:
        if reset_first:
            reset(db)

        if db.query(Organization).count():
            print("Database already seeded. Use --reset to rebuild.")
            return {}

        # --- organisations ----------------------------------------------
        orgs = []
        for name, org_type, msp, country, gln, trusted in ORGS:
            organization = Organization(name=name, org_type=org_type, msp_id=msp,
                                        country=country, gln=gln,
                                        trusted_issuer_types=trusted)
            db.add(organization)
            orgs.append(organization)
        db.flush()

        # --- users --------------------------------------------------------
        password_hash = hash_password(DEMO_PASSWORD)
        users = {}
        for email, full_name, role, org_index in USERS:
            user = User(email=email, full_name=full_name, password_hash=password_hash,
                        role=role, org_id=orgs[org_index].id, status="ACTIVE")
            db.add(user)
            users[role] = user
        db.flush()

        # --- farms, fields, devices ---------------------------------------
        farm_org = orgs[1]
        farms, fields, devices = [], [], []
        for name, region, country, lat, lon, area in FARMS:
            farm = Farm(org_id=farm_org.id, name=name, region=region, country=country,
                        latitude=lat, longitude=lon, area_ha=area,
                        created_by=users["FARM_OPERATOR"].id)
            db.add(farm)
            farms.append(farm)
        db.flush()

        for farm in farms:
            for field_name in FIELD_NAMES:
                field = Field(farm_id=farm.id, org_id=farm_org.id, name=field_name,
                              area_ha=round(farm.area_ha / 4, 1), soil_type="Silty clay loam")
                db.add(field)
                fields.append(field)
        db.flush()

        device_secrets: dict[str, str] = {}
        for index, (device_type, model, firmware, interval) in enumerate(DEVICE_PLAN):
            for farm_index, farm in enumerate(farms[:2] if device_type != "COLD_CHAIN_SENSOR"
                                              else farms[:1]):
                field = fields[farm_index * 3 + (index % 3)]
                secret = generate_device_secret()
                device = Device(org_id=farm_org.id, farm_id=farm.id,
                                field_id=field.id if device_type != "COLD_CHAIN_SENSOR" else None,
                                device_type=device_type, model=model,
                                serial_number=f"SN-{device_type[:3]}-{index}{farm_index}",
                                firmware_version=firmware, secret_enc="",
                                interval_seconds=interval, status="ACTIVE",
                                last_seen_at=now - timedelta(minutes=rng.randint(1, 30)),
                                battery_pct=round(rng.uniform(38, 99), 1),
                                signal_dbm=round(rng.uniform(-95, -55), 1),
                                created_by=users["FARM_OPERATOR"].id)
                db.add(device)
                db.flush()
                device.secret_enc = encrypt_at_rest(secret, device.id)
                device_secrets[device.id] = secret
                devices.append(device)
        db.flush()

        # --- device vulnerabilities (FR-E3) -------------------------------
        for offset, (cve, title, severity, cvss, affected, fixed) in enumerate(VULNERABILITIES):
            device = devices[offset % len(devices)]
            db.add(DeviceVulnerability(device_id=device.id, org_id=device.org_id, cve_id=cve,
                                       title=title, severity=severity, cvss=cvss,
                                       affected_versions=affected, fixed_in=fixed,
                                       status="OPEN",
                                       discovered_at=now - timedelta(days=offset + 2)))
        db.add(DeviceVulnerability(
            device_id=devices[3].id, org_id=devices[3].org_id, cve_id="CVE-2024-10001",
            title="Denial of service in the MQTT keepalive handler", severity="MEDIUM",
            cvss=4.3, affected_versions="< 3.0.0", fixed_in="3.0.0", status="REMEDIATED",
            discovered_at=now - timedelta(days=40), remediated_at=now - timedelta(days=12)))
        db.flush()

        # --- hazard database (synthetic) ----------------------------------
        from ai.data.generate import hazard_database

        for record in hazard_database():
            db.add(HazardSequence(agent_name=record["agent_name"],
                                  hazard_class=record["hazard_class"],
                                  severity=record["severity"], description=record["description"],
                                  sequence=record["sequence"], is_synthetic=True))
        db.flush()

        # --- products ------------------------------------------------------
        supply_org = orgs[2]
        for gtin, name, category, organic, non_gmo, tmin, tmax in PRODUCTS:
            db.add(Product(org_id=supply_org.id, gtin=gtin, name=name, category=category,
                           organic_claim=organic, non_gmo_claim=non_gmo,
                           storage_temp_min_c=tmin, storage_temp_max_c=tmax))
        db.flush()

        # --- certifications -------------------------------------------------
        regulator = orgs[3]
        db.add(Certification(
            cert_code="ORG-2026-0001", cert_type="ORGANIC", standard="USDA-NOP",
            issuer_org_id=regulator.id, subject_org_id=supply_org.id,
            scope="Organic milled products, Continental Foods Processing",
            valid_from=now - timedelta(days=200), valid_to=now + timedelta(days=165),
            status="ACTIVE", anchor_status="PENDING"))
        db.add(Certification(
            cert_code="NGM-2026-0002", cert_type="NON_GMO", standard="NON-GMO-PROJECT",
            issuer_org_id=regulator.id, subject_org_id=supply_org.id,
            scope="Non-GMO soy products",
            valid_from=now - timedelta(days=400), valid_to=now - timedelta(days=30),
            status="ACTIVE", anchor_status="PENDING"))     # deliberately expired for the demo
        db.flush()

        # --- crops ----------------------------------------------------------
        for field in fields[:4]:
            db.add(Crop(field_id=field.id, org_id=farm_org.id, crop_type="Maize",
                        variety="GV-Hybrid-12", planted_at=now - timedelta(days=120),
                        expected_harvest=now + timedelta(days=15), status="GROWING"))
        db.flush()

        # --- precision-agriculture data (FR-A1/A2/A5) -----------------------
        # These three go through the real service paths so the Telemetry, Satellite
        # and AI Insights views have content immediately after a clean reset.
        telemetry_counts = _seed_telemetry(db, devices, device_secrets, rng, now)
        scenes = _seed_satellite(db, fields, users, farm_org, now)
        vision = _seed_crop_vision(db, fields, farm_org)
        db.commit()

        summary = {
            "organizations": len(orgs), "users": len(USERS), "farms": len(farms),
            "fields": len(fields), "devices": len(devices),
            "vulnerabilities": len(VULNERABILITIES) + 1,
            "hazard_sequences": len(hazard_database()), "products": len(PRODUCTS),
            "certifications": 2,
            "telemetry": telemetry_counts["accepted"] + telemetry_counts["quarantined"],
            "telemetry_quarantined": telemetry_counts["quarantined"],
            "satellite_scenes": scenes,
            "crop_vision_analyses": vision,
        }

    from app.core.config import get_settings

    data_dir = Path(get_settings().data_dir)
    if not data_dir.is_absolute():
        data_dir = ROOT / data_dir
    data_dir.mkdir(parents=True, exist_ok=True)
    secrets_path = data_dir / "demo_device_secrets.json"
    import json

    secrets_path.write_text(json.dumps(
        {"marking": "DEMO/SIMULATION device secrets for the local simulator only. "
                    "This file is git-ignored and must never exist in a real deployment.",
         "secrets": device_secrets}, indent=2))
    secrets_path.chmod(0o600)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="drop and rebuild the schema")
    args = parser.parse_args()

    summary = seed(args.reset)
    if summary:
        print("Seeded demonstration data (DEMO/SIMULATION):")
        for key, value in summary.items():
            print(f"  {key:20s} {value}")
        print(f"\n  Demo password for every seeded account: {DEMO_PASSWORD}")
        print("  Accounts: " + ", ".join(email for email, *_ in USERS))
        print("\n  Device secrets written to demo_device_secrets.json (git-ignored).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
