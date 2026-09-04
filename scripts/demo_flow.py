#!/usr/bin/env python3
"""Scripted end-to-end demonstration of the whole platform (brief §32, SC-3).

Runs the complete journey against a live API over HTTP, exactly as a user would:

  biosecurity screening -> GMO registration -> jurisdictional approval -> seed lot
  -> planting -> harvest batch -> processing -> packaging -> shipment (cold chain)
  -> certification -> integrity verification -> compliance report -> consumer QR
  -> tamper detection -> audit chain verification

Every step prints its outcome, so the demonstration is reproducible and self-evidencing.

Usage:  python3 scripts/demo_flow.py [--api-url http://127.0.0.1:8100]
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

PASSWORD = "DemoPassw0rd!2026"
STEP = 0
FAILURES: list[str] = []


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat()


class Api:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.tokens: dict[str, str] = {}

    def login(self, email: str) -> str:
        """Log in, honouring Retry-After if the authentication rate limit is hit.

        The limiter is a real security control (10 attempts per minute per IP); a
        well-behaved client waits rather than the platform relaxing the limit.
        """
        if email in self.tokens:
            return self.tokens[email]
        for attempt in range(6):
            status, body = self.call("POST", "/api/v1/auth/login",
                                     {"email": email, "password": PASSWORD})
            if status == 200:
                self.tokens[email] = body["access_token"]
                return self.tokens[email]
            if status == 429:
                wait = float(body.get("retry_after") or 5) + 0.5
                print(f"           authentication rate limit hit; waiting {wait:.1f}s "
                      f"(attempt {attempt + 1}/6)")
                time.sleep(wait)
                continue
            raise SystemExit(f"Login failed for {email}: {status} {body}")
        raise SystemExit(f"Login for {email} kept hitting the rate limit")

    def call(self, method: str, path: str, body: dict | None = None,
             token: str | None = None) -> tuple[int, dict]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
                content_type = response.headers.get("content-type", "")
                if not raw:
                    return response.status, {}
                if "json" not in content_type:
                    # Non-JSON responses (SVG QR codes, exports) are reported by size.
                    return response.status, {"_content_type": content_type,
                                             "_bytes": len(raw)}
                return response.status, json.loads(raw)
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                return error.code, json.loads(raw) if raw else {}
            except Exception:                                    # noqa: BLE001
                return error.code, {"raw": raw[:200].decode(errors="replace")}
        except urllib.error.URLError as error:
            raise SystemExit(f"Cannot reach {self.base}: {error.reason}") from error

    def as_user(self, email: str, method: str, path: str, body: dict | None = None):
        return self.call(method, path, body, self.login(email))


def step(title: str) -> None:
    global STEP
    STEP += 1
    print(f"\n\033[1m[{STEP:02d}] {title}\033[0m")


def ok(message: str) -> None:
    print(f"     PASS  {message}")


def fail(message: str) -> None:
    FAILURES.append(message)
    print(f"     FAIL  {message}")


def info(message: str) -> None:
    print(f"           {message}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-url", default="http://127.0.0.1:8100")
    parser.add_argument(
        "--skip-tamper", action="store_true",
        help="omit the tamper-detection step, which deliberately raises a CRITICAL fraud "
             "alert. Use this to build the clean state an examiner should see first; run "
             "without it to demonstrate detection.")
    args = parser.parse_args()
    api = Api(args.api_url)
    rng = random.Random()
    suffix = rng.randint(1000, 9999)

    print("=" * 78)
    print(" Agricultural Biotechnology Security Platform — end-to-end demonstration")
    print(" DEMO/SIMULATION: synthetic data, single-node permissioned ledger,")
    print(" real cryptography (ECDSA P-256, SHA-256, HMAC, AES-GCM).")
    print("=" * 78)

    status, health = api.call("GET", "/health/ready")
    if status != 200:
        raise SystemExit(f"API is not ready: {status} {health}")
    info(f"API ready: {health['checks']}")

    # --- organisations we need -------------------------------------------
    status, orgs = api.as_user("admin@absp.demo", "GET", "/api/v1/admin/organizations")
    org_by_type = {o["org_type"]: o for o in orgs["items"]}
    supply_org, regulator_org = org_by_type["SUPPLY"], org_by_type["REGULATOR"]

    # ================================================================== 1
    step("Biosecurity screening of a benign crop insert (FR-C1)")
    from ai.data.generate import benign_sequence, hazard_database, hazard_derived_sequence

    status, benign = api.as_user(
        "researcher@absp.demo", "POST", "/api/v1/biosecurity/screenings",
        {"name": f"Drought-tolerance insert {suffix}", "sequence": benign_sequence(1200, suffix),
         "intent": "drought tolerance improvement", "organism": "Zea mays"})
    if status == 201 and benign["verdict"] == "CLEAR":
        ok(f"verdict CLEAR, status {benign['status']}, "
           f"{benign['sequence_length']} bases, engine {benign['engine_version']}")
    else:
        fail(f"expected a CLEAR verdict, got {status} {benign.get('verdict')}")
    screening_id = benign.get("id")

    # ================================================================== 2
    step("Biosecurity screening of a mutated hazard-derived sequence (FR-C1)")
    hazard = hazard_database()[0]
    mutated = hazard_derived_sequence(hazard["sequence"], divergence=0.08, seed=suffix)
    status, blocked = api.as_user(
        "researcher@absp.demo", "POST", "/api/v1/biosecurity/screenings",
        {"name": f"Unknown construct {suffix}", "sequence": mutated,
         "intent": "virulence enhancement study", "organism": "Fusarium oxysporum"})
    if status == 201 and blocked["verdict"] == "BLOCK":
        ok(f"verdict BLOCK, status {blocked['status']}, DURC flag {blocked['durc_flag']}, "
           f"identity {blocked['max_identity']:.1%}")
        for hit in blocked.get("hits", [])[:2]:
            info(f"hit: {hit['agent_name']} — {hit['identity']:.1%} identity over "
                 f"{hit['align_length']} bases ({hit['hazard_class']})")
        info("8% divergence from the hazard motif: exact matching would have missed this")
    else:
        fail(f"expected BLOCK, got {status} {blocked.get('verdict')}")

    # ================================================================== 3
    step("A blocked screening cannot be self-released by the submitter (FR-C4)")
    status, denied = api.as_user(
        "researcher@absp.demo", "POST",
        f"/api/v1/biosecurity/screenings/{blocked['id']}/review",
        {"decision": "APPROVE", "rationale": "I would like to proceed with this construct."})
    if status == 403:
        ok("403 permission denied: only a biosafety officer may review a blocked screening")
    else:
        fail(f"expected 403, got {status} {denied}")

    # ================================================================== 4
    step("Biosafety officer rejects the blocked construct (FR-C3/C4)")
    status, reviewed = api.as_user(
        "biosafety@absp.demo", "POST",
        f"/api/v1/biosecurity/screenings/{blocked['id']}/review",
        {"decision": "REJECT",
         "rationale": "High-confidence homology to a severity-5 phytopathogen effector combined "
                      "with a stated virulence-enhancement intent. Dual-use research of concern."})
    if status == 200 and reviewed["status"] == "REJECTED":
        ok("recorded as REJECTED with a rationale, and written to the audit trail")
    else:
        fail(f"review failed: {status} {reviewed}")

    # ================================================================== 5
    step("CRISPR risk assessment: benign edit versus dual-use proposal (FR-C2/C3)")
    reference = benign_sequence(3000, suffix + 1)
    guide = reference[500:520]
    status, low = api.as_user(
        "researcher@absp.demo", "POST", "/api/v1/biosecurity/crispr",
        {"target_gene": "DREB2A", "organism": "Zea mays", "organism_class": "CROP",
         "guide_rna": guide, "pam": "NGG", "edit_type": "KNOCKOUT",
         "intent": "drought tolerance improvement", "reference_sequence": reference})
    status2, high = api.as_user(
        "researcher@absp.demo", "POST", "/api/v1/biosecurity/crispr",
        {"target_gene": "avr effector virulence locus", "organism": "Fusarium oxysporum",
         "organism_class": "PLANT_PATHOGEN", "guide_rna": guide, "pam": "NGG",
         "edit_type": "KNOCK_IN", "intent": "expand host range and enhance virulence",
         "reference_sequence": reference})
    if low.get("risk_level") == "LOW" and high.get("risk_level") == "PROHIBITED":
        ok(f"benign edit {low['risk_level']} ({low['risk_score']}), "
           f"dual-use proposal {high['risk_level']} ({high['risk_score']}), "
           f"DURC flag {high['durc_flag']}")
        info(f"reason: {high['reasons'][-1]}")
        info(f"off-target sites scanned on the supplied reference: {low['off_target_count']}")
    else:
        fail(f"unexpected risk levels: {low.get('risk_level')} / {high.get('risk_level')}")

    # ================================================================== 6
    step("GMO registration is gated on a passing screening (FR-B1 + FR-C1 gate)")
    event_code = f"ABS-{suffix:05d}-1"
    status, refused = api.as_user(
        "researcher@absp.demo", "POST", "/api/v1/gmo/events",
        {"event_code": event_code, "crop_type": "Maize", "trait": "Drought tolerance",
         "donor_organism": "Bacillus subtilis", "developer": "AgriGenome Biotech",
         "description": "Attempt to register against the rejected screening.",
         "screening_id": blocked["id"]})
    if status == 422:
        ok("422 rejected: a rejected screening cannot support a GMO registration")
        info(refused.get("detail", "")[:110])
    else:
        fail(f"expected 422, got {status}")

    # ================================================================== 7
    step("GMO transformation event registered and anchored to the ledger (FR-B1/B4)")
    status, event = api.as_user(
        "researcher@absp.demo", "POST", "/api/v1/gmo/events",
        {"event_code": event_code, "crop_type": "Maize", "trait": "Drought tolerance",
         "donor_organism": "Bacillus subtilis", "developer": "AgriGenome Biotech",
         "description": "Demonstration transformation event (synthetic).",
         "screening_id": screening_id})
    if status == 201 and event["anchor_status"] == "ANCHORED":
        ok(f"event {event['event_code']} anchored in block {event['block_number']}")
        info(f"content hash {event['content_hash'][:32]}…  tx {event['tx_id'][:24]}…")
        info("endorsement policy for gmo_registry.RegisterEvent: BiotechMSP AND RegulatorMSP")
    else:
        fail(f"registration failed: {status} {event}")

    # ================================================================== 8
    step("Regulator records jurisdictional approvals (FR-B3/F1)")
    approved = 0
    for jurisdiction in ("US-USDA", "US-FDA", "EU"):
        status, approval = api.as_user(
            "regulator@absp.demo", "POST", f"/api/v1/gmo/events/{event['id']}/approvals",
            {"jurisdiction": jurisdiction, "status": "APPROVED",
             "reference": f"{jurisdiction}-FILE-{suffix}", "approved_at": iso(now())})
        # An approval that is not anchored is not an approval.
        approved += status == 201 and bool(approval.get("tx_id"))
    if approved == 3:
        ok("approvals recorded AND anchored for US-USDA, US-FDA and EU "
           "(endorsed by RegulatorMSP)")
    else:
        fail(f"only {approved}/3 approvals recorded")

    # ================================================================== 9
    step("Seed lot produced from the registered event (FR-B5)")
    status, lot = api.as_user(
        "researcher@absp.demo", "POST", "/api/v1/gmo/seed-lots",
        {"lot_code": f"SL-2026-{suffix}", "gmo_event_id": event["id"], "crop_type": "Maize",
         "variety": "GV-Hybrid-12", "quantity_kg": 4200.0, "produced_at": iso(now()),
         "germination_pct": 94.5})
    if status == 201 and lot["anchor_status"] == "ANCHORED":
        ok(f"seed lot {lot['lot_code']} anchored, {lot['quantity_kg']} kg")
    else:
        fail(f"seed lot creation failed: {status} {lot}")

    # ================================================================= 10
    step("Product and harvest batch created with GMO lineage (FR-B2)")
    status, product = api.as_user(
        "supply@absp.demo", "POST", "/api/v1/supply-chain/products",
        {"gtin": f"095011015{suffix:05d}", "name": f"Chilled Sweetcorn Demo {suffix}",
         "category": "Chilled vegetables", "organic_claim": False, "non_gmo_claim": False,
         "storage_temp_min_c": 0.0, "storage_temp_max_c": 4.0})
    if status != 201:
        fail(f"product creation failed: {status} {product}")
        product = {"id": None}

    batch_code = f"B-2026-{suffix}"
    status, batch = api.as_user(
        "supply@absp.demo", "POST", "/api/v1/supply-chain/batches",
        {"batch_code": batch_code, "product_id": product["id"], "quantity": 12000.0,
         "unit": "kg", "seed_lot_id": lot["id"], "gmo_event_id": event["id"],
         "origin_region": "Iowa", "origin_country": "US",
         "harvested_at": iso(now() - timedelta(days=6))})
    if status == 201 and batch["anchor_status"] == "ANCHORED":
        ok(f"batch {batch['batch_code']} anchored, verification code "
           f"{batch['verification_code']}")
    else:
        fail(f"batch creation failed: {status} {batch}")

    # ================================================================= 11
    step("Supply-chain events recorded as an EPCIS-shaped chain of custody (FR-B2)")
    timeline = [
        ("harvesting", "in_progress", "Green Valley North", 12000.0, 5),
        ("transforming", "in_progress", "Continental Foods Plant A", 11400.0, 4),
        ("packing", "in_progress", "Continental Foods Plant A", 11200.0, 3),
        ("shipping", "in_transit", "Rotterdam Distribution Hub", 11200.0, 2),
        ("receiving", "in_storage", "Rotterdam Distribution Hub", 11200.0, 1),
    ]
    recorded = 0
    for biz_step, disposition, location, quantity, days_ago in timeline:
        status, sc_event = api.as_user(
            "supply@absp.demo", "POST", "/api/v1/supply-chain/events",
            {"batch_id": batch["id"], "biz_step": biz_step, "disposition": disposition,
             "location_name": location, "location_gln": "9501101530003",
             "quantity": quantity, "unit": "kg",
             "occurred_at": iso(now() - timedelta(days=days_ago))})
        if status == 201:
            recorded += 1
            info(f"{biz_step:14s} {quantity:>9.0f} kg  anchored={sc_event['anchor_status']} "
                 f"block={sc_event.get('tx_id', '')[:12]}…")
        else:
            fail(f"event {biz_step} rejected: {status} {sc_event.get('detail', sc_event)}")
    if recorded == len(timeline):
        ok(f"{recorded} events recorded, each anchored; quantity conservation enforced on-chain")

    # ================================================================= 12
    step("An illegal lifecycle transition is rejected by the smart contract (FR-B2)")
    status, illegal = api.as_user(
        "supply@absp.demo", "POST", "/api/v1/supply-chain/events",
        {"batch_id": batch["id"], "biz_step": "harvesting", "disposition": "in_progress",
         "location_name": "Green Valley North", "quantity": 11200.0, "unit": "kg",
         "occurred_at": iso(now())})
    if status == 422:
        ok("422 rejected: a received batch cannot go back to harvesting")
        info(illegal.get("detail", "")[:120])
    else:
        fail(f"expected the contract to reject this transition, got {status}")

    # ================================================================= 13
    step("Quantity conservation is enforced (FR-D3)")
    status, inflated = api.as_user(
        "supply@absp.demo", "POST", "/api/v1/supply-chain/events",
        {"batch_id": batch["id"], "biz_step": "storing", "disposition": "in_storage",
         "location_name": "Rotterdam Distribution Hub", "quantity": 99999.0, "unit": "kg",
         "occurred_at": iso(now())})
    if status == 422:
        ok("422 rejected: output quantity cannot exceed the batch quantity")
    else:
        fail(f"expected 422 for an inflated quantity, got {status}")

    # ================================================================= 14
    step("Shipment created and cold-chain telemetry bound to it (FR-D1)")
    status, devices = api.as_user("farmer@absp.demo", "GET",
                                  "/api/v1/devices?device_type=COLD_CHAIN_SENSOR")
    cold_device = devices["items"][0]["id"] if devices.get("items") else None
    status, shipment = api.as_user(
        "supply@absp.demo", "POST", "/api/v1/supply-chain/shipments",
        {"sscc": f"00312345{suffix:010d}", "batch_id": batch["id"],
         "carrier": "Continental Cold Logistics", "origin_name": "Continental Foods Plant A",
         "origin_lat": 41.88, "origin_lon": -93.41,
         "destination_name": "Rotterdam Distribution Hub",
         "destination_lat": 51.92, "destination_lon": 4.48,
         "departed_at": iso(now() - timedelta(days=2)),
         "arrived_at": iso(now() - timedelta(days=1)),
         "cold_chain_device_id": cold_device})
    if status == 201:
        ok(f"shipment {shipment['sscc']} recorded, cold-chain sensor attached")
    else:
        fail(f"shipment creation failed: {status} {shipment}")

    # ================================================================= 15
    step("An organic claim on GMO lineage is refused at claim time (FR-D2/FR-B3)")
    status, cert = api.as_user(
        "certifier@absp.demo", "POST", "/api/v1/supply-chain/certifications",
        {"cert_code": f"ORG-DEMO-{suffix}", "cert_type": "ORGANIC", "standard": "USDA-NOP",
         "subject_org_id": supply_org["id"], "scope": "Chilled vegetables",
         "valid_from": iso(now() - timedelta(days=30)),
         "valid_to": iso(now() + timedelta(days=335))})
    if status != 201:
        fail(f"certification issuance failed: {status} {cert}")
    else:
        status, link = api.as_user(
            "supply@absp.demo", "POST",
            f"/api/v1/supply-chain/certifications/{cert['id']}/link",
            {"batch_id": batch["id"]})
        if status == 422:
            ok("422 refused: ORGANIC cannot be claimed on a batch whose lineage contains a "
               "GMO event")
            info(link.get("detail", "")[:120])
        else:
            fail(f"expected the claim conflict to be refused, got {status}")

    # ================================================================= 16
    step("A valid specialty certification is issued and claimed (FR-D2)")
    status, specialty = api.as_user(
        "certifier@absp.demo", "POST", "/api/v1/supply-chain/certifications",
        {"cert_code": f"SPC-DEMO-{suffix}", "cert_type": "SPECIALTY",
         "standard": "CODEX-GL-32", "subject_org_id": supply_org["id"],
         "scope": "Cold-chain chilled vegetables",
         "valid_from": iso(now() - timedelta(days=10)),
         "valid_to": iso(now() + timedelta(days=355))})
    if status == 201 and specialty["anchor_status"] == "ANCHORED":
        status, link = api.as_user(
            "supply@absp.demo", "POST",
            f"/api/v1/supply-chain/certifications/{specialty['id']}/link",
            {"batch_id": batch["id"]})
        if status == 201:
            ok(f"{specialty['cert_code']} issued, anchored and claimed on the batch")
        else:
            fail(f"linking the specialty certification failed: {status} {link}")
    else:
        fail(f"specialty certification issuance failed: {status} {specialty}")

    # ================================================================= 17
    step("Supply-chain integrity verification and fraud scoring (FR-D3)")
    status, verification = api.as_user(
        "supply@absp.demo", "POST", f"/api/v1/supply-chain/batches/{batch['id']}/verify")
    if status == 200:
        ok(f"integrity {verification['integrity_status']}, fraud score "
           f"{verification['fraud_score']} ({verification['fraud_level']}), "
           f"ledger {verification['ledger_status']}")
        info(f"{verification['events_checked']} events and "
             f"{verification['certifications_checked']} certification(s) checked")
        for reason in verification["reasons"][:3]:
            info(f"reason [{reason['rule']}]: {reason['detail'][:90]}")
    else:
        fail(f"verification failed: {status} {verification}")

    # ================================================================= 18
    step("Automated regulatory compliance evaluation (FR-F1)")
    for jurisdiction in ("US-USDA", "EU"):
        status, report = api.as_user(
            "regulator@absp.demo", "POST", "/api/v1/compliance/evaluate",
            {"subject_type": "BATCH", "subject_id": batch["id"], "jurisdiction": jurisdiction})
        if status == 201:
            summary = report["summary"]
            ok(f"{jurisdiction}: {report['status']} — {summary['passed']}/"
               f"{summary['rules_evaluated']} rules passed, anchored={report['anchor_status']}")
            for result in report["results"]:
                if not result["passed"]:
                    info(f"failed [{result['rule_id']}] {result['title']}: "
                         f"{result['detail'][:80]}")
        else:
            fail(f"compliance evaluation for {jurisdiction} failed: {status} {report}")

    # ================================================================= 19
    step("Environmental impact assessment for the biotech crop (FR-F2)")
    status, eia = api.as_user(
        "regulator@absp.demo", "POST", "/api/v1/compliance/eia",
        {"gmo_event_id": event["id"], "cultivation_area_ha": 240.0,
         "adjacent_wild_relatives": True, "pesticide_change_pct": -18.0,
         "notes": "Demonstration assessment over synthetic cultivation data."})
    if status == 201:
        ok(f"EIA {eia['status']}, gene-flow risk {eia['summary']['gene_flow_risk']}, "
           f"anchored={eia['anchor_status']}")
    else:
        fail(f"EIA failed: {status} {eia}")

    # ================================================================= 20
    step("Consumer verification by QR code, unauthenticated (FR-D4)")
    code = batch["verification_code"]
    status, public = api.call("GET", f"/api/v1/verify/{code}")
    if status == 200:
        ok(f"public lookup succeeded with no authentication: {public['product_name']}")
        info(f"origin {public['origin_region']}, {public['origin_country']} — "
             f"GMO status {public['gmo_status']} ({public['gmo_event_code']})")
        info(f"ledger verified: {public['ledger_verified']}, integrity "
             f"{public['integrity_status']}, journey stages {len(public['journey'])}")
        leaked = [f for f in ("latitude", "longitude", "farmer", "created_by", "org_id")
                  if f in json.dumps(public)]
        if leaked:
            fail(f"public payload leaks sensitive fields: {leaked}")
        else:
            ok("payload contains no coordinates, farmer identity or organisation ids")
    else:
        fail(f"public verification failed: {status} {public}")

    status, qr = api.call("GET", f"/api/v1/verify/{code}/qr")
    if status == 200 and "svg" in qr.get("_content_type", ""):
        ok(f"QR code generated server-side as SVG ({qr['_bytes']} bytes), no external dependency")
    else:
        fail(f"QR generation failed: {status} {qr}")

    # ================================================================= 21
    step("Blockchain chain verification (FR-B4)")
    status, chain = api.as_user("regulator@absp.demo", "GET", "/api/v1/blockchain/verify")
    if status == 200 and chain["valid"]:
        ok(f"chain valid: height {chain['height']}, {chain['transactions']} transactions, "
           f"{chain['signatures_verified']} signatures verified")
        info(f"network: {chain['network']}")
    else:
        fail(f"chain verification failed: {status} {chain}")

    # ================================================================= 22
    step("Tamper detection: origin substitution on an anchored record (SC-4)")
    from sqlalchemy import select
    from sqlalchemy.exc import NoResultFound

    from app.core.database import SessionLocal
    from app.models import Batch

    original_region = None
    tamper_available = False

    if args.skip_tamper:
        info("SKIPPED by --skip-tamper: this step alters a record on purpose and raises a")
        info("CRITICAL fraud alert, which is the opposite of the clean state an examiner")
        info("should be shown first. Re-run without the flag to demonstrate detection.")
    else:
        info("Scenario: an insider rewrites the declared origin in the database to pass the")
        info("produce off as coming from a higher-value region — classic origin fraud.")
        info("This step opens the database directly, so it only works when this script runs")
        info("on the same host as the API process (the documented ./scripts/run_local.sh path).")
        tamper_available = True
        try:
            with SessionLocal() as db:
                row = db.execute(select(Batch).where(Batch.id == batch["id"])).scalar_one()
                original_region = row.origin_region
                row.origin_region = "Kansas"
                db.commit()
            info(f"database row altered directly: origin_region {original_region!r} -> 'Kansas'")
        except NoResultFound:
            tamper_available = False
            info("SKIPPED: this script's local SessionLocal does not see the target API's "
                 "database — you are pointing --api-url at a different host/container than "
                 "the one this process's DATABASE_URL resolves to. Run this script on the "
                 "same host as the API (as ./scripts/run_local.sh does) to see this step live.")

    if tamper_available:
        status, tamper = api.as_user("regulator@absp.demo", "POST",
                                     "/api/v1/blockchain/verify-record",
                                     {"entity_type": "BATCH", "entity_id": batch["id"]})
        if status == 200 and tamper["result"] == "MISMATCH":
            ok("MISMATCH detected: the recomputed content hash no longer matches the anchor")
            info(f"anchored {tamper['anchored_hash'][:28]}…")
            info(f"computed {tamper['computed_hash'][:28]}…")
        else:
            fail(f"tampering was not detected: {status} {tamper}")
    elif not args.skip_tamper:
        info("tamper-detection live demonstration skipped (see above) — not counted as a "
             "failure, since it is a property of the script's DB access, not the platform")

    if tamper_available:
        status, reverify = api.as_user(
            "supply@absp.demo", "POST", f"/api/v1/supply-chain/batches/{batch['id']}/verify")
        if reverify.get("integrity_status") in {"FAILED", "SUSPECT"}:
            ok(f"batch integrity now {reverify['integrity_status']} "
               f"(fraud score {reverify['fraud_score']}) with ledger_mismatch cited")
        else:
            fail(f"integrity status did not degrade: {reverify.get('integrity_status')}")

        with SessionLocal() as db:
            row = db.execute(select(Batch).where(Batch.id == batch["id"])).scalar_one()
            row.origin_region = original_region
            db.commit()
        info("original value restored")

        status, restored = api.as_user("regulator@absp.demo", "POST",
                                       "/api/v1/blockchain/verify-record",
                                       {"entity_type": "BATCH", "entity_id": batch["id"]})
        if restored.get("result") == "MATCH":
            ok("verification returns MATCH again once the record is restored")
        else:
            fail(f"expected MATCH after restoration, got {restored.get('result')}")

        # Re-run the batch assessment so the stored integrity_status reflects the
        # restored record.  Without this the batch stays FAILED for the rest of the
        # session and the dashboard keeps reporting an integrity failure that no
        # longer exists.
        status, healed = api.as_user(
            "supply@absp.demo", "POST", f"/api/v1/supply-chain/batches/{batch['id']}/verify")
        if healed.get("integrity_status") == "VERIFIED":
            ok("batch integrity returns to VERIFIED on re-assessment")
        else:
            fail(f"integrity did not recover: {healed.get('integrity_status')}")
        info("The CRITICAL fraud alert raised while the record was altered is left open on")
        info("purpose: a detection is an audit record, not something a demo should erase.")
        info("`./scripts/run_local.sh --reset` returns the platform to the clean state.")

    info("Note: mutable state (current quantity, batch state) is deliberately NOT part of")
    info("the batch anchor — each change is anchored by its own event transaction instead.")

    # ================================================================= 23
    step("Audit trail hash-chain verification and ledger anchoring (FR-F3)")
    status, audit = api.as_user("regulator@absp.demo", "GET", "/api/v1/audit/verify")
    if status == 200 and audit["valid"]:
        ok(f"audit chain valid across {audit['entries']} entries")
        info(f"head sequence {audit['head_seq']}, head hash {audit['head_hash'][:28]}…")
    else:
        fail(f"audit chain verification failed: {status} {audit}")

    status, anchored = api.as_user("regulator@absp.demo", "POST", "/api/v1/audit/anchor")
    if anchored.get("ok"):
        ok(f"audit head anchored to the ledger in block {anchored['block_number']}")
    else:
        fail(f"audit anchoring failed: {anchored}")

    # ================================================================= 24
    step("Agricultural data-theft detection over recorded access patterns (FR-A3)")
    status, theft = api.as_user("analyst@absp.demo", "GET",
                                "/api/v1/security/data-theft/evaluate")
    if status == 200:
        ok(f"principal scored {theft['score']} ({theft['level']}) over "
           f"{theft['requests_examined']} requests, threshold {theft['threshold']}")
        for signal in theft["signals"][:3]:
            info(f"signal {signal['signal']}: {signal['detail']}")
        if not theft["signals"]:
            info("no exfiltration signals on this session, as expected for normal use")
    else:
        fail(f"data-theft evaluation failed: {status} {theft}")

    # ================================================================= 25
    step("Security posture and dashboards (FR-A4/E3/X5)")
    status, posture = api.as_user("analyst@absp.demo", "GET", "/api/v1/devices/posture")
    if status == 200:
        ok(f"{posture['devices_total']} devices, {posture['vulnerabilities_open']} open "
           f"vulnerabilities ({posture['open_by_severity']}), remediation rate "
           f"{posture['remediation_rate']:.0%}")
    else:
        fail(f"posture failed: {status}")

    status, dash = api.as_user("regulator@absp.demo", "GET", "/api/v1/dashboard")
    if status == 200:
        ok(f"regulator dashboard: ledger height {dash['ledger']['height']}, "
           f"batches {dash['supply_chain']['batches']}, "
           f"screenings {dash['biosecurity']['screenings']}")
    else:
        fail(f"dashboard failed: {status}")

    # --- summary ----------------------------------------------------------
    print("\n" + "=" * 78)
    if FAILURES:
        print(f" DEMONSTRATION COMPLETED WITH {len(FAILURES)} FAILURE(S):")
        for failure in FAILURES:
            print(f"   - {failure}")
        print("=" * 78)
        return 1
    print(f" DEMONSTRATION COMPLETE — {STEP} steps, every check passed.")
    print(f" Consumer verification page: {args.api_url}/verify.html?code={code}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
