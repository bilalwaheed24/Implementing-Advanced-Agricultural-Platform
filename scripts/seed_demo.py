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

from sqlalchemy import select                                             # noqa: E402

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
    from app.models import AIAnalysis
    from app.services import ai_client

    rng = np.random.default_rng(2026)
    seeded = 0
    for index, label in enumerate(["HEALTHY", "LEAF_BLIGHT", "RUST", "NUTRIENT_DEFICIENCY"]):
        try:
            size = ai_client.meta()["image_size"]
            result = ai_client.classify_image(leaf_patch(label, size, rng).ravel().tolist(), size)
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


def _seed_biotech_and_supply_chain(db, orgs, users, farms, fields, rng, now) -> dict:
    """Seed the biotechnology and supply-chain story through the real service layer.

    Without this, a clean reset leaves ten screens empty: screenings, CRISPR, review
    queue, GMO registry, seed lots, batches, shipments, fraud, compliance and the ledger.
    Those records used to come only from `demo_flow.py`, which is a separate step an
    examiner-facing reset should not depend on. Nothing here is inserted directly — every
    record goes through the same service functions the API calls, so the biosecurity gate,
    quantity conservation, claim-conflict rejection and ledger anchoring all really run.
    """
    from ai.data.generate import benign_sequence, hazard_database, hazard_derived_sequence
    from app.services import biosecurity, compliance, gmo, supplychain
    from app.models import Product

    biotech_org, farm_org, supply_org, regulator = orgs
    researcher = users["BIOTECH_RESEARCHER"]
    biosafety = users["BIOSAFETY_OFFICER"]
    supply_user = users["SUPPLY_CHAIN_OPERATOR"]
    certifier = users["CERTIFIER"]
    reg_user = users["REGULATOR"]

    def screen(name, sequence, intent, organism):
        record = biosecurity.submit_screening(
            db, biotech_org.id, researcher.id, researcher.role, name, sequence, intent, organism)
        db.flush()
        return record

    # --- biosecurity: one CLEAR, one FLAG awaiting review, one BLOCK -------------
    hazards = hazard_database()
    clear = screen("Drought-tolerance insert DT-114", benign_sequence(1400, 17),
                   "drought tolerance improvement", "Zea mays")
    screen("Partial homology candidate PR-208",
           hazard_derived_sequence(next(h for h in hazards if h["severity"] == 3)["sequence"],
                                   0.14, 5),
           "resistance marker research", "Zea mays")
    blocked = screen("Unknown construct UC-993",
                     hazard_derived_sequence(hazards[0]["sequence"], 0.05, 2),
                     "virulence enhancement study", "Fusarium oxysporum")
    # A blocked record is reviewed and rejected by the biosafety officer — never by the
    # submitter. The rejection rationale is what the detail screen displays.
    biosecurity.review_screening(
        db, blocked, biosafety.id, biosafety.role, "REJECT",
        "High-confidence homology to a severity-5 phytopathogen effector combined with a "
        "stated virulence-enhancement intent. Dual-use research of concern.")
    db.flush()

    # --- CRISPR risk assessments -------------------------------------------------
    for gene, organism, org_class, edit, intent in [
            ("ZmDREB2A", "Zea mays", "CROP", "KNOCKOUT", "drought tolerance improvement"),
            ("OsSWEET14", "Oryza sativa", "CROP", "BASE_EDIT", "blight resistance"),
            ("avr effector virulence locus", "Fusarium oxysporum", "PLANT_PATHOGEN",
             "KNOCK_IN", "virulence enhancement study")]:
        try:
            biosecurity.assess_crispr(db, biotech_org.id, researcher.id, researcher.role,
                                      gene, organism, org_class, "ACGTACGTACGTACGTACGT",
                                      "NGG", edit, intent, None)
            db.flush()
        except Exception as error:                                  # noqa: BLE001
            print(f"  CRISPR seed skipped for {gene}: {error}")

    # --- GMO registration (gated on the passing screening above) -----------------
    event = gmo.register_event(
        db, biotech_org.id, researcher.id, researcher.role, "ABS-DT114-1", "Maize",
        "Drought tolerance", "Zea mays", "AgriGenome Biotech",
        "Drought-tolerance transformation event for temperate maize.", clear.id)
    db.flush()
    for jurisdiction, status, days in [("US-USDA", "APPROVED", 900), ("US-FDA", "APPROVED", 900),
                                       ("EU", "APPROVED", 700)]:
        try:
            gmo.record_approval(
                db, event, reg_user.id, reg_user.role, jurisdiction, status,
                f"{jurisdiction}-REF-2026-0114",
                now - timedelta(days=60), now + timedelta(days=days), regulator.id)
            db.flush()
        except Exception as error:                                  # noqa: BLE001
            print(f"  GMO approval seed skipped for {jurisdiction}: {error}")

    seed_lot = gmo.create_seed_lot(
        db, biotech_org.id, researcher.id, researcher.role, "SL-2026-0114", event.id,
        "Maize", "GV-Hybrid-12", 4200.0, now - timedelta(days=210), 94.5)
    db.flush()

    # --- supply chain: seed lot -> batch -> custody events -> shipment -----------
    product = db.execute(
        select(Product).where(Product.gtin == "09501101530027")).scalar_one()
    batch = supplychain.create_batch(
        db, supply_org.id, supply_user.id, supply_user.role, "B-2026-0114", product.id,
        1800.0, "kg", None, seed_lot.id, None, farms[0].id, event.id, "Iowa", "US",
        now - timedelta(days=9))
    db.flush()

    journey = [
        ("harvesting", "in_progress", "Green Valley North", 42.03, -93.63, 8),
        ("transforming", "in_progress", "Continental Foods Plant A", 41.88, -93.41, 7),
        ("packing", "in_progress", "Continental Foods Plant A", 41.88, -93.41, 6),
        ("shipping", "in_transit", "Rotterdam Distribution Hub", 51.92, 4.48, 5),
        ("receiving", "in_progress", "Rotterdam Distribution Hub", 51.92, 4.48, 4),
    ]
    for biz_step, disposition, place, lat, lon, days_ago in journey:
        actor_org = farm_org if biz_step == "harvesting" else supply_org
        try:
            supplychain.record_event(
                db, actor_org.id, supply_user.id, supply_user.role, batch, biz_step,
                disposition, "OBJECT", None, place, lat, lon, batch.quantity, "kg", None,
                now - timedelta(days=days_ago), {"seeded": True})
            db.flush()
        except Exception as error:                                  # noqa: BLE001
            print(f"  supply-chain event seed skipped for {biz_step}: {error}")

    cold_sensor = next((d for d in db.execute(
        select(Device).where(Device.device_type == "COLD_CHAIN_SENSOR")).scalars()), None)
    try:
        supplychain.create_shipment(
            db, supply_org.id, supply_user.id, supply_user.role,
            sscc="003123450000001148", batch_id=batch.id,
            carrier="Continental Cold Logistics", origin_name="Continental Foods Plant A",
            origin_lat=41.88, origin_lon=-93.41,
            destination_name="Rotterdam Distribution Hub",
            destination_lat=51.92, destination_lon=4.48,
            departed_at=now - timedelta(days=5), arrived_at=now - timedelta(days=4),
            cold_chain_device_id=cold_sensor.id if cold_sensor else None)
        db.flush()
    except Exception as error:                                      # noqa: BLE001
        print(f"  shipment seed skipped: {error}")

    # --- certification: issue a valid specialty claim and link it ---------------
    try:
        cert = supplychain.issue_certification(
            db, regulator.id, certifier.id, certifier.role, cert_code="SPC-2026-0114",
            cert_type="SPECIALTY", standard="CODEX-GL-32", subject_org_id=supply_org.id,
            scope="Chilled vegetables", valid_from=now - timedelta(days=40),
            valid_to=now + timedelta(days=325))
        db.flush()
        supplychain.link_certification(db, cert, batch, supply_user.id, supply_user.role)
        db.flush()
    except Exception as error:                                      # noqa: BLE001
        print(f"  certification seed skipped: {error}")

    # --- fraud assessment and compliance report ---------------------------------
    try:
        supplychain.verify_batch(db, batch, supply_user.id, supply_user.role)
        db.flush()
    except Exception as error:                                      # noqa: BLE001
        print(f"  batch verification seed skipped: {error}")

    for jurisdiction in ("US-USDA", "EU"):
        try:
            compliance.evaluate_batch(db, batch, jurisdiction, reg_user.id, reg_user.role,
                                      supply_org.id)
            db.flush()
        except Exception as error:                                  # noqa: BLE001
            print(f"  compliance seed skipped for {jurisdiction}: {error}")

    # Two further batches at earlier points in their journeys. A single row made the supply
    # chain screens look like nothing had happened; a mix of states shows the lifecycle.
    for code, gtin, qty, lot, gmo_event, steps, region in [
            ("B-2026-0211", "09501101530003", 2400.0, seed_lot, event,
             [("harvesting", "in_progress", "Green Valley South", 41.88, -93.41, 4)], "Iowa"),
            ("B-2026-0298", "09501101530010", 950.0, None, None,
             [("harvesting", "in_progress", "Riverbend Estate", 40.81, -96.68, 6),
              ("transforming", "in_progress", "Continental Foods Plant A", 41.88, -93.41, 3)],
             "Nebraska")]:
        try:
            other_product = db.execute(
                select(Product).where(Product.gtin == gtin)).scalar_one()
            extra = supplychain.create_batch(
                db, supply_org.id, supply_user.id, supply_user.role, code, other_product.id,
                qty, "kg", None, lot.id if lot else None, None, farms[1].id,
                gmo_event.id if gmo_event else None, region, "US",
                now - timedelta(days=steps[-1][5] + 2))
            db.flush()
            for biz_step, disposition, place, lat, lon, days_ago in steps:
                supplychain.record_event(
                    db, supply_org.id, supply_user.id, supply_user.role, extra, biz_step,
                    disposition, "OBJECT", None, place, lat, lon, extra.quantity, "kg", None,
                    now - timedelta(days=days_ago), {"seeded": True})
                db.flush()
            supplychain.verify_batch(db, extra, supply_user.id, supply_user.role)
            db.flush()
        except Exception as error:                                  # noqa: BLE001
            print(f"  extra batch seed skipped for {code}: {error}")

    try:
        compliance.environmental_impact(
            db, event, reg_user.id, reg_user.role, regulator.id,
            cultivation_area_ha=240.0, adjacent_wild_relatives=True,
            pesticide_change_pct=-18.0,
            notes="Temperate maize, drought-tolerance trait. Wild relatives recorded within "
                  "the buffer zone, so gene-flow monitoring is required.")
        db.flush()
    except Exception as error:                                      # noqa: BLE001
        print(f"  environmental impact seed skipped: {error}")

    # Report what is actually in the database rather than what the loops above think they
    # wrote: a hand-kept tally drifts the moment one call is skipped or retried.
    from app.models import (Batch, ComplianceReport, CrisprAssessment, GMOEvent, SeedLot,
                            SequenceScreening, Shipment, SupplyChainEvent)
    from sqlalchemy import func

    def total(model):
        return db.execute(select(func.count()).select_from(model)).scalar_one()

    return {
        "screenings": total(SequenceScreening), "crispr": total(CrisprAssessment),
        "gmo_events": total(GMOEvent), "seed_lots": total(SeedLot),
        "batches": total(Batch), "supply_chain_events": total(SupplyChainEvent),
        "shipments": total(Shipment), "compliance_reports": total(ComplianceReport),
    }


def reset(session) -> None:
    from app.services import ledger_client

    drop_all()
    create_all()
    # The ledger is a separate store. Without clearing it, `batch:B-2026-0114` and the other
    # fixed demo codes survive the database wipe and the next seed's anchoring is rejected as
    # duplicate-code fraud. `run_local.sh --reset` already removes this directory; doing it
    # here means `seed_demo.py --reset` on its own is a real reset too.
    # In the split stack (ADR-016) this asks the ledger container to reset itself.
    ledger_client.reset_store()


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

        # --- biotechnology and supply chain (FR-B/C/D/F) --------------------
        domain = _seed_biotech_and_supply_chain(db, orgs, users, farms, fields, rng, now)
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
            **domain,
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
