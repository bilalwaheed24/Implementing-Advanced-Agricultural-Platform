"""End-to-end traceability, compliance, verification and audit (SC-3, SC-4, FR-B/D/F)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ai.data.generate import benign_sequence
from .conftest import unique


def iso(value: datetime) -> str:
    return value.isoformat()


def now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def gmo_event(client, auth, hazards):
    screening = client.post("/api/v1/biosecurity/screenings",
                            headers=auth("BIOTECH_RESEARCHER"),
                            json={"name": unique("insert"),
                                  "sequence": benign_sequence(900, 21),
                                  "intent": "drought tolerance"}).json()
    assert screening["status"] == "APPROVED_AUTO"
    suffix = unique("")[-4:]
    response = client.post("/api/v1/gmo/events", headers=auth("BIOTECH_RESEARCHER"), json={
        "event_code": f"ABS-{abs(hash(suffix)) % 90000 + 10000}-1", "crop_type": "Maize",
        "trait": "Drought tolerance", "donor_organism": "Bacillus subtilis",
        "developer": "Test Biotech", "description": "Test event",
        "screening_id": screening["id"]})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
def traced_batch(client, auth, gmo_event, product, orgs, farm):
    """A batch carrying GMO lineage with a complete, anchored chain of custody."""
    batch = client.post("/api/v1/supply-chain/batches",
                        headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
        "batch_code": unique("B"), "product_id": product.id, "quantity": 10000.0,
        "unit": "kg", "gmo_event_id": gmo_event["id"], "farm_id": farm.id,
        "origin_region": "Iowa", "origin_country": "US",
        "harvested_at": iso(now() - timedelta(days=6))}).json()
    timeline = [("harvesting", "in_progress", 10000.0, 5), ("transforming", "in_progress", 9600.0, 4),
                ("packing", "in_progress", 9500.0, 3), ("shipping", "in_transit", 9500.0, 2),
                ("receiving", "in_storage", 9500.0, 1)]
    for biz_step, disposition, quantity, days in timeline:
        response = client.post("/api/v1/supply-chain/events",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_id": batch["id"], "biz_step": biz_step, "disposition": disposition,
            "location_name": "Test Plant", "location_gln": "9501101530003",
            "quantity": quantity, "unit": "kg", "occurred_at": iso(now() - timedelta(days=days))})
        assert response.status_code == 201, response.text
    return batch


class TestGmoRegistration:
    def test_event_is_anchored_with_a_content_hash(self, gmo_event):
        assert gmo_event["anchor_status"] == "ANCHORED"
        assert len(gmo_event["content_hash"]) == 64
        assert gmo_event["tx_id"]
        assert gmo_event["block_number"] is not None

    def test_registration_requires_a_passing_screening(self, client, auth):
        response = client.post("/api/v1/gmo/events", headers=auth("BIOTECH_RESEARCHER"), json={
            "event_code": "ABS-77777-1", "crop_type": "Maize", "trait": "Test trait",
            "donor_organism": "Test donor", "developer": "Test Dev",
            "screening_id": "does-not-exist"})
        assert response.status_code == 422
        assert "screening" in response.json()["detail"].lower()

    def test_event_code_format_is_enforced(self, client, auth, hazards):
        screening = client.post("/api/v1/biosecurity/screenings",
                                headers=auth("BIOTECH_RESEARCHER"),
                                json={"name": unique("s"), "sequence": benign_sequence(400, 5),
                                      "intent": "research"}).json()
        response = client.post("/api/v1/gmo/events", headers=auth("BIOTECH_RESEARCHER"), json={
            "event_code": "NOT-A-VALID-CODE-AT-ALL", "crop_type": "Maize",
            "trait": "Test trait", "donor_organism": "Test donor", "developer": "Test Dev",
            "screening_id": screening["id"]})
        assert response.status_code == 422

    def test_duplicate_event_code_rejected(self, client, auth, gmo_event, hazards):
        screening = client.post("/api/v1/biosecurity/screenings",
                                headers=auth("BIOTECH_RESEARCHER"),
                                json={"name": unique("s"), "sequence": benign_sequence(400, 6),
                                      "intent": "research"}).json()
        response = client.post("/api/v1/gmo/events", headers=auth("BIOTECH_RESEARCHER"), json={
            "event_code": gmo_event["event_code"], "crop_type": "Maize",
            "trait": "Test trait", "donor_organism": "Test donor", "developer": "Test Dev",
            "screening_id": screening["id"]})
        assert response.status_code == 409

    def test_anchor_verification_matches(self, client, auth, gmo_event):
        response = client.get(f"/api/v1/gmo/events/{gmo_event['id']}/verify",
                              headers=auth("BIOTECH_RESEARCHER"))
        assert response.status_code == 200
        assert response.json()["result"] == "MATCH"

    def test_jurisdictional_approval_recorded_and_anchored(self, client, auth, gmo_event):
        response = client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals",
                               headers=auth("REGULATOR"),
                               json={"jurisdiction": "US-USDA", "status": "APPROVED",
                                     "reference": "USDA-TEST-1", "approved_at": iso(now())})
        assert response.status_code == 201
        assert response.json()["tx_id"]

    def test_researcher_cannot_approve_a_jurisdiction(self, client, auth, gmo_event):
        response = client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"jurisdiction": "EU", "status": "APPROVED"})
        assert response.status_code == 403

    def test_biosafety_officer_cannot_grant_market_access(self, client, auth, gmo_event):
        """Biosafety review and jurisdictional approval are separate authorities."""
        response = client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals",
                               headers=auth("BIOSAFETY_OFFICER"),
                               json={"jurisdiction": "EU", "status": "APPROVED"})
        assert response.status_code == 403

    def test_seed_lot_links_to_the_event(self, client, auth, gmo_event):
        response = client.post("/api/v1/gmo/seed-lots", headers=auth("BIOTECH_RESEARCHER"),
                               json={"lot_code": unique("SL"), "gmo_event_id": gmo_event["id"],
                                     "crop_type": "Maize", "variety": "V1",
                                     "quantity_kg": 500.0, "produced_at": iso(now())})
        assert response.status_code == 201
        assert response.json()["anchor_status"] == "ANCHORED"


class TestTraceability:
    def test_batch_is_anchored_with_a_verification_code(self, traced_batch):
        assert traced_batch["anchor_status"] == "ANCHORED"
        assert len(traced_batch["verification_code"].replace("-", "")) == 20

    def test_chain_of_custody_is_ordered_and_complete(self, client, auth, traced_batch):
        response = client.get(f"/api/v1/supply-chain/batches/{traced_batch['id']}/custody",
                              headers=auth("SUPPLY_CHAIN_OPERATOR"))
        assert response.status_code == 200
        events = response.json()["events"]
        assert [e["biz_step"] for e in events] == ["harvesting", "transforming", "packing",
                                                    "shipping", "receiving"]
        assert all(e["anchor_status"] == "ANCHORED" for e in events)
        assert all(len(e["content_hash"]) == 64 for e in events)

    def test_batch_state_advanced_with_the_chain(self, client, auth, traced_batch):
        batch = client.get(f"/api/v1/supply-chain/batches/{traced_batch['id']}",
                           headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert batch["state"] == "RECEIVED"

    def test_illegal_transition_rejected(self, client, auth, traced_batch):
        response = client.post("/api/v1/supply-chain/events",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_id": traced_batch["id"], "biz_step": "harvesting",
            "disposition": "in_progress", "occurred_at": iso(now())})
        assert response.status_code == 422
        assert "transition" in response.json()["detail"].lower()

    def test_quantity_cannot_exceed_the_batch(self, client, auth, traced_batch):
        response = client.post("/api/v1/supply-chain/events",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_id": traced_batch["id"], "biz_step": "storing", "disposition": "in_storage",
            "quantity": 99999.0, "unit": "kg", "occurred_at": iso(now())})
        assert response.status_code == 422

    def test_duplicate_batch_code_rejected(self, client, auth, traced_batch, product):
        response = client.post("/api/v1/supply-chain/batches",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_code": traced_batch["batch_code"], "product_id": product.id,
            "quantity": 10.0, "unit": "kg"})
        assert response.status_code == 409

    def test_child_batch_cannot_exceed_its_parent(self, client, auth, traced_batch, product):
        response = client.post("/api/v1/supply-chain/batches",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_code": unique("B"), "product_id": product.id, "quantity": 999999.0,
            "unit": "kg", "parent_batch_id": traced_batch["id"]})
        assert response.status_code == 422


class TestCertificationAuthentication:
    def test_issuer_must_be_trusted_for_the_type(self, client, auth, orgs, db):
        """FR-D2: an untrusted issuer cannot mint a certification."""
        from app.models import Organization

        untrusted = Organization(name="Untrusted Body", org_type="REGULATOR",
                                 msp_id=unique("MSP"), country="US", trusted_issuer_types=[])
        db.add(untrusted)
        db.commit()
        from app.services import supplychain
        from app.core.errors import ValidationFailed

        with pytest.raises(ValidationFailed, match="trusted issuer"):
            supplychain.issue_certification(
                db, untrusted.id, "actor", "CERTIFIER", unique("C"), "ORGANIC", "USDA-NOP",
                orgs["SUPPLY"].id, "scope", now(), now() + timedelta(days=30))

    def test_organic_claim_on_gmo_lineage_is_refused(self, client, auth, orgs, traced_batch):
        cert = client.post("/api/v1/supply-chain/certifications", headers=auth("CERTIFIER"),
                           json={"cert_code": unique("ORG"), "cert_type": "ORGANIC",
                                 "standard": "USDA-NOP", "subject_org_id": orgs["SUPPLY"].id,
                                 "scope": "Test scope",
                                 "valid_from": iso(now() - timedelta(days=1)),
                                 "valid_to": iso(now() + timedelta(days=300))}).json()
        response = client.post(f"/api/v1/supply-chain/certifications/{cert['id']}/link",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"),
                               json={"batch_id": traced_batch["id"]})
        assert response.status_code == 422
        assert "lineage" in response.json()["detail"].lower()

    def test_specialty_claim_is_accepted_and_authenticates(self, client, auth, orgs,
                                                           traced_batch):
        cert = client.post("/api/v1/supply-chain/certifications", headers=auth("CERTIFIER"),
                           json={"cert_code": unique("SPC"), "cert_type": "SPECIALTY",
                                 "standard": "CODEX-GL-32", "subject_org_id": orgs["SUPPLY"].id,
                                 "scope": "Test scope",
                                 "valid_from": iso(now() - timedelta(days=1)),
                                 "valid_to": iso(now() + timedelta(days=300))}).json()
        assert cert["anchor_status"] == "ANCHORED"
        link = client.post(f"/api/v1/supply-chain/certifications/{cert['id']}/link",
                           headers=auth("SUPPLY_CHAIN_OPERATOR"),
                           json={"batch_id": traced_batch["id"]})
        assert link.status_code == 201
        custody = client.get(f"/api/v1/supply-chain/batches/{traced_batch['id']}/custody",
                             headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        claim = next(c for c in custody["certifications"] if c["cert_code"] == cert["cert_code"])
        assert claim["authentic"] is True
        assert claim["issuer_trusted"] is True

    def test_revocation_invalidates_the_claim(self, client, auth, orgs, traced_batch):
        cert = client.post("/api/v1/supply-chain/certifications", headers=auth("CERTIFIER"),
                           json={"cert_code": unique("SPC"), "cert_type": "SPECIALTY",
                                 "standard": "CODEX-GL-32", "subject_org_id": orgs["SUPPLY"].id,
                                 "scope": "Test scope",
                                 "valid_from": iso(now() - timedelta(days=1)),
                                 "valid_to": iso(now() + timedelta(days=300))}).json()
        client.post(f"/api/v1/supply-chain/certifications/{cert['id']}/link",
                    headers=auth("SUPPLY_CHAIN_OPERATOR"), json={"batch_id": traced_batch["id"]})
        revoked = client.post(f"/api/v1/supply-chain/certifications/{cert['id']}/revoke",
                              headers=auth("CERTIFIER"), json={"reason": "Audit finding"})
        assert revoked.status_code == 200
        custody = client.get(f"/api/v1/supply-chain/batches/{traced_batch['id']}/custody",
                             headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        claim = next(c for c in custody["certifications"] if c["cert_code"] == cert["cert_code"])
        assert claim["authentic"] is False
        assert claim["status"] == "REVOKED"

    def test_expired_certification_does_not_authenticate(self, client, auth, orgs,
                                                         traced_batch, db):
        from app.models import Certification, CertificationLink

        expired = Certification(cert_code=unique("EXP"), cert_type="SPECIALTY",
                                standard="CODEX-GL-32", issuer_org_id=orgs["REGULATOR"].id,
                                subject_org_id=orgs["SUPPLY"].id, scope="s",
                                valid_from=now() - timedelta(days=400),
                                valid_to=now() - timedelta(days=30), status="ACTIVE")
        db.add(expired)
        db.flush()
        db.add(CertificationLink(certification_id=expired.id, batch_id=traced_batch["id"]))
        db.commit()
        custody = client.get(f"/api/v1/supply-chain/batches/{traced_batch['id']}/custody",
                             headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        claim = next(c for c in custody["certifications"]
                     if c["cert_code"] == expired.cert_code)
        assert claim["within_validity"] is False
        assert claim["authentic"] is False


class TestIntegrityVerificationAndFraud:
    def test_clean_chain_verifies(self, client, auth, traced_batch):
        response = client.post(f"/api/v1/supply-chain/batches/{traced_batch['id']}/verify",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"))
        assert response.status_code == 200
        body = response.json()
        assert body["integrity_status"] == "VERIFIED"
        assert body["ledger_status"] == "MATCH"
        assert body["events_checked"] == 5
        assert body["reasons"]

    def test_tampering_an_anchored_field_is_detected(self, client, auth, db, traced_batch):
        """SC-4: altering an immutable anchored field must break verification."""
        from sqlalchemy import select

        from app.models import Batch

        row = db.execute(select(Batch).where(Batch.id == traced_batch["id"])).scalar_one()
        original = row.origin_region
        row.origin_region = "Substituted Region"
        db.commit()
        try:
            verify = client.post("/api/v1/blockchain/verify-record",
                                 headers=auth("REGULATOR"),
                                 json={"entity_type": "BATCH",
                                       "entity_id": traced_batch["id"]}).json()
            assert verify["result"] == "MISMATCH"
            assert verify["computed_hash"] != verify["anchored_hash"]

            batch_check = client.post(
                f"/api/v1/supply-chain/batches/{traced_batch['id']}/verify",
                headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
            assert batch_check["integrity_status"] in {"FAILED", "SUSPECT"}
            assert any(r["rule"] == "ledger_mismatch" for r in batch_check["reasons"])
        finally:
            row.origin_region = original
            db.commit()

    def test_verification_restores_after_the_record_is_corrected(self, client, auth,
                                                                 traced_batch):
        verify = client.post("/api/v1/blockchain/verify-record", headers=auth("REGULATOR"),
                             json={"entity_type": "BATCH",
                                   "entity_id": traced_batch["id"]}).json()
        assert verify["result"] == "MATCH"

    def test_cold_chain_break_is_reported(self, client, auth, db, traced_batch,
                                          provisioned_device):
        """FR-D1: IoT evidence feeds the integrity verdict."""
        from app.models import Shipment, Telemetry
        from app.core.security import encrypt_at_rest, sha256_hex

        shipment = Shipment(org_id=traced_batch["custodian_org_id"], sscc=unique("00")[:18],
                            batch_id=traced_batch["id"], carrier="Test Carrier",
                            origin_name="A", origin_lat=41.0, origin_lon=-93.0,
                            destination_name="B", destination_lat=51.9, destination_lon=4.4,
                            departed_at=now() - timedelta(days=2),
                            arrived_at=now() - timedelta(days=1), status="DELIVERED")
        db.add(shipment)
        db.flush()
        for index, temperature in enumerate([3.0, 3.4, 19.5]):
            payload = f'{{"temp_c": {temperature}}}'
            record = Telemetry(device_id=provisioned_device["id"],
                               org_id=traced_batch["custodian_org_id"],
                               shipment_id=shipment.id, recorded_at=now(),
                               nonce=f"cc-{index}-{unique('n')}", payload_enc="",
                               payload_hash=sha256_hex(payload),
                               summary={"temp_c": temperature}, quality="OK")
            db.add(record)
            db.flush()
            record.payload_enc = encrypt_at_rest(payload, record.id)
        db.commit()

        cold = client.get(f"/api/v1/supply-chain/shipments/{shipment.id}/cold-chain",
                          headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert cold["temp_max_c"] == 19.5

        verify = client.post(f"/api/v1/supply-chain/batches/{traced_batch['id']}/verify",
                             headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert any(r["rule"] == "cold_chain_break" for r in verify["reasons"])


class TestCompliance:
    def test_compliant_batch_passes_every_rule(self, client, auth, traced_batch, gmo_event):
        approval = client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals",
                               headers=auth("REGULATOR"),
                               json={"jurisdiction": "US-USDA", "status": "APPROVED",
                                     "reference": "R1", "approved_at": iso(now())})
        assert approval.status_code == 201 and approval.json()["tx_id"]
        response = client.post("/api/v1/compliance/evaluate", headers=auth("REGULATOR"),
                               json={"subject_type": "BATCH", "subject_id": traced_batch["id"],
                                     "jurisdiction": "US-USDA"})
        assert response.status_code == 201
        body = response.json()
        failed_rules = [(r["rule_id"], r["detail"]) for r in body["results"] if not r["passed"]]
        assert body["status"] == "COMPLIANT", f"failing rules: {failed_rules}"
        assert body["summary"]["failed"] == 0
        assert body["anchor_status"] == "ANCHORED"
        assert all(result["citation"] for result in body["results"])

    def test_missing_approval_fails_the_critical_rule(self, client, auth, traced_batch):
        response = client.post("/api/v1/compliance/evaluate", headers=auth("REGULATOR"),
                               json={"subject_type": "BATCH", "subject_id": traced_batch["id"],
                                     "jurisdiction": "EU"})
        assert response.status_code == 201
        body = response.json()
        failed = [r["rule_id"] for r in body["results"] if not r["passed"]]
        assert "GMO-001" in failed
        assert body["status"] == "NON_COMPLIANT"

    def test_unknown_jurisdiction_rejected(self, client, auth, traced_batch):
        response = client.post("/api/v1/compliance/evaluate", headers=auth("REGULATOR"),
                               json={"subject_type": "BATCH", "subject_id": traced_batch["id"],
                                     "jurisdiction": "ATLANTIS"})
        assert response.status_code == 422

    def test_environmental_impact_assessment(self, client, auth, gmo_event):
        response = client.post("/api/v1/compliance/eia", headers=auth("REGULATOR"), json={
            "gmo_event_id": gmo_event["id"], "cultivation_area_ha": 300.0,
            "adjacent_wild_relatives": True, "pesticide_change_pct": 40.0,
            "notes": "Test assessment"})
        assert response.status_code == 201
        body = response.json()
        assert body["report_type"] == "ENVIRONMENTAL_IMPACT"
        assert body["summary"]["gene_flow_risk"] == "HIGH"
        assert any(not r["passed"] for r in body["results"])

    def test_farm_operator_cannot_run_compliance(self, client, auth, traced_batch):
        response = client.post("/api/v1/compliance/evaluate", headers=auth("FARM_OPERATOR"),
                               json={"subject_type": "BATCH", "subject_id": traced_batch["id"],
                                     "jurisdiction": "US-USDA"})
        assert response.status_code == 403

    def test_rule_catalogue_is_published(self, client, auth):
        response = client.get("/api/v1/compliance/rules", headers=auth("REGULATOR"))
        assert response.status_code == 200
        assert len(response.json()["rules"]) >= 10
        assert "not legal advice" in response.json()["disclaimer"]

    def test_labelling_validation_reports_a_citation(self, client, auth, traced_batch):
        response = client.get(f"/api/v1/gmo/labelling/{traced_batch['id']}",
                              headers=auth("SUPPLY_CHAIN_OPERATOR"),
                              params={"jurisdiction": "EU"})
        assert response.status_code == 200
        body = response.json()
        assert body["requires_label"] is True
        assert body["required_label_text"]
        assert "1829/2003" in body["citation"]


class TestPublicVerification:
    def test_consumer_lookup_requires_no_authentication(self, client, traced_batch):
        response = client.get(f"/api/v1/verify/{traced_batch['verification_code']}")
        assert response.status_code == 200
        body = response.json()
        assert body["product_name"]
        assert body["gmo_status"] == "CONTAINS_GMO"
        assert body["journey"]
        assert body["disclaimer"]

    def test_public_payload_withholds_sensitive_fields(self, client, traced_batch):
        text = client.get(f"/api/v1/verify/{traced_batch['verification_code']}").text
        for field in ("latitude", "longitude", "org_id", "created_by", "farm_id",
                      "custodian_org_id"):
            assert field not in text, f"public payload leaked {field}"

    def test_journey_marks_each_stage_verified(self, client, traced_batch):
        body = client.get(f"/api/v1/verify/{traced_batch['verification_code']}").json()
        assert len(body["journey"]) == 5
        assert all(stage["verified"] for stage in body["journey"])
        assert body["ledger_verified"] is True

    def test_qr_code_is_generated(self, client, traced_batch):
        response = client.get(f"/api/v1/verify/{traced_batch['verification_code']}/qr")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("image/svg+xml")
        assert b"<svg" in response.content

    def test_unknown_code_is_404(self, client):
        assert client.get("/api/v1/verify/ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ").status_code == 404


class TestBlockchainAndAudit:
    def test_chain_verifies_after_all_activity(self, client, auth, traced_batch):
        response = client.get("/api/v1/blockchain/verify", headers=auth("REGULATOR"))
        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is True
        assert body["signatures_verified"] > 0
        assert body["network"] == "single-node-demo"

    def test_inclusion_proof_for_a_batch_transaction(self, client, auth, traced_batch):
        response = client.get(f"/api/v1/blockchain/transactions/{traced_batch['tx_id']}/proof",
                              headers=auth("REGULATOR"))
        assert response.status_code == 200
        assert response.json()["merkle_root"]

    def test_contract_catalogue_lists_policies(self, client, auth):
        response = client.get("/api/v1/blockchain/contracts", headers=auth("REGULATOR"))
        assert response.status_code == 200
        body = response.json()
        assert "provenance" in body["contracts"]
        assert body["endorsement_policies"]["gmo_registry.RegisterEvent"]["rule"] == "AND"

    def test_world_state_is_queryable(self, client, auth, traced_batch):
        response = client.get(f"/api/v1/blockchain/state/batch:{traced_batch['batch_code']}",
                              headers=auth("REGULATOR"))
        assert response.status_code == 200
        assert response.json()["value"]["batch_code"] == traced_batch["batch_code"]

    def test_audit_chain_verifies(self, client, auth, traced_batch):
        response = client.get("/api/v1/audit/verify", headers=auth("REGULATOR"))
        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is True
        assert body["entries"] > 0
        assert len(body["head_hash"]) == 64

    def test_audit_records_are_hash_chained(self, client, auth):
        response = client.get("/api/v1/audit/logs", headers=auth("REGULATOR"),
                              params={"page_size": 5})
        assert response.status_code == 200
        for entry in response.json()["items"]:
            assert len(entry["entry_hash"]) == 64
            assert len(entry["prev_hash"]) == 64

    def test_tampering_the_audit_log_is_detected(self, client, auth, db):
        """FR-F3: retroactive edits must break the chain."""
        from sqlalchemy import select

        from app.models import AuditLog

        entry = db.execute(select(AuditLog).order_by(AuditLog.seq.asc()).limit(1)).scalar_one()
        original = entry.action
        entry.action = "tampered.action"
        db.commit()
        try:
            body = client.get("/api/v1/audit/verify", headers=auth("REGULATOR")).json()
            assert body["valid"] is False
            assert body["first_divergence"]["issue"] == "entry_hash_mismatch"
        finally:
            entry.action = original
            db.commit()
        assert client.get("/api/v1/audit/verify",
                          headers=auth("REGULATOR")).json()["valid"] is True

    def test_audit_head_can_be_anchored(self, client, auth):
        response = client.post("/api/v1/audit/anchor", headers=auth("REGULATOR"))
        assert response.status_code == 200
        assert response.json()["ok"] is True

    def test_audit_export_includes_its_verification(self, client, auth):
        response = client.get("/api/v1/audit/export", headers=auth("REGULATOR"),
                              params={"limit": 10})
        assert response.status_code == 200
        body = response.json()
        assert body["chain_verification"]["valid"] is True
        assert body["entries"]

    def test_operator_cannot_export_the_audit_trail(self, client, auth):
        assert client.get("/api/v1/audit/export",
                          headers=auth("FARM_OPERATOR")).status_code == 403


class TestDashboards:
    def test_dashboard_is_role_aware(self, client, auth):
        operator = client.get("/api/v1/dashboard", headers=auth("FARM_OPERATOR")).json()
        assert "devices" in operator
        assert "biosecurity" not in operator, "an operator has no biosecurity permission"

        officer = client.get("/api/v1/dashboard", headers=auth("BIOSAFETY_OFFICER")).json()
        assert "biosecurity" in officer

    def test_regulator_sees_the_ledger_tile(self, client, auth):
        body = client.get("/api/v1/dashboard", headers=auth("REGULATOR")).json()
        assert body["ledger"]["height"] > 0
        assert body["ledger"]["network"] == "single-node-demo"

    def test_ai_summary_is_available(self, client, auth):
        response = client.get("/api/v1/ai/summary", headers=auth("AGRONOMIST"))
        assert response.status_code == 200
        assert "by_type_and_level" in response.json()

    def test_model_cards_declare_synthetic_training_data(self, client, auth):
        response = client.get("/api/v1/ai/model-cards", headers=auth("AGRONOMIST"))
        assert response.status_code == 200
        assert "synthetic" in response.json()["marking"].lower()


class TestCertificationLinkAuthorization:
    """BOLA regression: a certification may only be linked by the org it was issued to."""

    def test_cannot_link_another_organisations_certification(self, client, auth, orgs,
                                                             traced_batch, db):
        """A supply chain operator must not be able to attach a certification that was
        issued to a different organisation onto their own batch."""
        from app.models import Certification

        foreign_cert = Certification(
            cert_code=unique("FOREIGN"), cert_type="SPECIALTY", standard="CODEX-GL-32",
            issuer_org_id=orgs["REGULATOR"].id, subject_org_id=orgs["BIOTECH"].id,
            scope="Issued to a different organisation entirely",
            valid_from=now() - __import__("datetime").timedelta(days=1),
            valid_to=now() + __import__("datetime").timedelta(days=300), status="ACTIVE")
        db.add(foreign_cert)
        db.commit()

        response = client.post(
            f"/api/v1/supply-chain/certifications/{foreign_cert.id}/link",
            headers=auth("SUPPLY_CHAIN_OPERATOR"), json={"batch_id": traced_batch["id"]})
        assert response.status_code == 403
        assert "different organisation" in response.json()["detail"].lower()

    def test_inactive_certification_cannot_be_linked(self, client, auth, orgs,
                                                     traced_batch, db):
        from app.models import Certification

        revoked_cert = Certification(
            cert_code=unique("REVOKED"), cert_type="SPECIALTY", standard="CODEX-GL-32",
            issuer_org_id=orgs["REGULATOR"].id, subject_org_id=orgs["SUPPLY"].id,
            scope="Already revoked",
            valid_from=now() - __import__("datetime").timedelta(days=100),
            valid_to=now() + __import__("datetime").timedelta(days=100), status="REVOKED")
        db.add(revoked_cert)
        db.commit()

        response = client.post(
            f"/api/v1/supply-chain/certifications/{revoked_cert.id}/link",
            headers=auth("SUPPLY_CHAIN_OPERATOR"), json={"batch_id": traced_batch["id"]})
        assert response.status_code == 422
        assert "REVOKED" in response.json()["detail"]


class TestBlockchainVerifyRecordAuthorization:
    """IDOR regression: verify-record must not disclose another org's data or its
    existence to an ordinary (non-oversight) role."""

    def test_rival_cannot_verify_a_foreign_batch(self, client, rival_auth, traced_batch):
        response = client.post("/api/v1/blockchain/verify-record", headers=rival_auth,
                               json={"entity_type": "BATCH", "entity_id": traced_batch["id"]})
        assert response.status_code == 404

    def test_owning_org_can_verify_its_own_batch(self, client, auth, traced_batch):
        response = client.post("/api/v1/blockchain/verify-record",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"),
                               json={"entity_type": "BATCH", "entity_id": traced_batch["id"]})
        assert response.status_code == 200
        assert response.json()["result"] == "MATCH"

    def test_oversight_role_can_verify_any_batch(self, client, auth, traced_batch):
        response = client.post("/api/v1/blockchain/verify-record", headers=auth("REGULATOR"),
                               json={"entity_type": "BATCH", "entity_id": traced_batch["id"]})
        assert response.status_code == 200

    def test_rival_cannot_verify_a_foreign_certification(self, client, rival_auth, orgs, db):
        from app.models import Certification
        import datetime as dt

        cert = Certification(
            cert_code=unique("PRIV"), cert_type="SPECIALTY", standard="CODEX-GL-32",
            issuer_org_id=orgs["REGULATOR"].id, subject_org_id=orgs["SUPPLY"].id,
            scope="s", valid_from=now() - dt.timedelta(days=1),
            valid_to=now() + dt.timedelta(days=300), status="ACTIVE")
        db.add(cert)
        db.commit()
        response = client.post("/api/v1/blockchain/verify-record", headers=rival_auth,
                               json={"entity_type": "CERTIFICATION", "entity_id": cert.id})
        assert response.status_code == 404
