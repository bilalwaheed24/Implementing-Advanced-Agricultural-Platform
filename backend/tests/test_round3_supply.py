"""Round 3: supply-chain rules, read visibility and notification recipients.

Certifiers read the batches their certificates are claimed on; holders see certificates
claimed on their batches; a recall reaches every organisation that handled the batch; a bad
batch cannot be shipped or sold; verify-record follows read visibility and a compliance
report verifies MATCH; the dashboard counts shipments for both ends; approval loss and
re-approval reach growers with crops in the ground; a directly recorded receipt has the
arrival's side effects; certificate expiry downgrades VERIFIED like revocation does.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.security import utcnow
from app.models import (AuditLog, Batch, Certification, CertificationLink, Crop, Notification,
                        Organization)
from app.services import supplychain as supply_service
from .conftest import unique
from .test_shipments_recall import _ship, chilled_product, farm_batch  # noqa: F401
from .test_supplychain_e2e import gmo_event, iso, now  # noqa: F401

API = "/api/v1"


def _issue(client, auth, subject_org_id) -> dict:
    response = client.post(f"{API}/supply-chain/certifications", headers=auth("CERTIFIER"), json={
        "cert_code": unique("R3C"), "cert_type": "SPECIALTY", "standard": "Test Std",
        "subject_org_id": subject_org_id, "scope": "Whole-farm crop production",
        "valid_from": iso(now() - timedelta(days=1)),
        "valid_to": iso(now() + timedelta(days=200))})
    assert response.status_code == 201, response.text
    return response.json()


def _claim(client, auth, cert, batch_id, role="FARM_OPERATOR"):
    response = client.post(f"{API}/supply-chain/certifications/{cert['id']}/link",
                           headers=auth(role), json={"batch_id": batch_id})
    assert response.status_code == 201, response.text


def _notes(db, users, role, title_part) -> list[Notification]:
    db.expire_all()
    return [n for n in db.execute(select(Notification).where(
        Notification.user_id == users[role].id)).scalars() if title_part in n.title]


def _event(client, auth, role, batch_id, step, disposition, **extra):
    return client.post(f"{API}/supply-chain/events", headers=auth(role), json={
        "batch_id": batch_id, "biz_step": step, "disposition": disposition,
        "occurred_at": iso(now()), **extra})


def _arrive(client, auth, shipment_id, role="SUPPLY_CHAIN_OPERATOR"):
    response = client.post(f"{API}/supply-chain/shipments/{shipment_id}/arrive",
                           headers=auth(role), json={"arrived_at": iso(now())})
    assert response.status_code == 200, response.text


# --------------------------------------------------------------------------- #
# 1. Certifier read access and certificate visibility for holders
# --------------------------------------------------------------------------- #
class TestCertifierReadsCertifiedBatches:
    def test_certifier_opens_a_batch_its_certificate_is_claimed_on(self, client, auth, orgs,
                                                                   farm_batch):
        batch_id = farm_batch["id"]
        assert client.get(f"{API}/supply-chain/batches/{batch_id}",
                          headers=auth("CERTIFIER")).status_code == 404
        cert = _issue(client, auth, orgs["FARM"].id)
        _claim(client, auth, cert, batch_id)

        assert client.get(f"{API}/supply-chain/batches/{batch_id}",
                          headers=auth("CERTIFIER")).status_code == 200
        custody = client.get(f"{API}/supply-chain/batches/{batch_id}/custody",
                             headers=auth("CERTIFIER"))
        assert custody.status_code == 200, custody.text
        assert [c["cert_code"] for c in custody.json()["certifications"]] == [cert["cert_code"]]
        listed = client.get(f"{API}/supply-chain/batches?page_size=200",
                            headers=auth("CERTIFIER")).json()["items"]
        assert batch_id in {b["id"] for b in listed}
        # The certificate list now links the claimed batch for its issuer.
        certs = client.get(f"{API}/supply-chain/certifications?page_size=200",
                           headers=auth("CERTIFIER")).json()["items"]
        row = next(c for c in certs if c["id"] == cert["id"])
        assert row["claimed_batches"] == [{"id": batch_id,
                                           "batch_code": farm_batch["batch_code"]}]

    def test_read_access_is_read_only(self, client, auth, orgs, farm_batch):
        cert = _issue(client, auth, orgs["FARM"].id)
        _claim(client, auth, cert, farm_batch["id"])
        # The certifier role has no supply:write; the verify path keeps the plain scope.
        assert _event(client, auth, "CERTIFIER", farm_batch["id"], "storing",
                      "in_storage").status_code == 403
        assert client.post(f"{API}/supply-chain/batches/{farm_batch['id']}/verify",
                           headers=auth("CERTIFIER")).status_code == 404

    def test_an_uncertified_batch_stays_hidden(self, client, auth, farm_batch):
        assert client.get(f"{API}/supply-chain/batches/{farm_batch['id']}/custody",
                          headers=auth("CERTIFIER")).status_code == 404

    def test_the_holder_of_a_claimed_batch_lists_the_certificate(self, client, auth, orgs,
                                                                 farm_batch):
        cert = _issue(client, auth, orgs["FARM"].id)
        _claim(client, auth, cert, farm_batch["id"])
        listed = client.get(f"{API}/supply-chain/certifications?page_size=200",
                            headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        assert cert["id"] not in {c["id"] for c in listed}
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201
        listed = client.get(f"{API}/supply-chain/certifications?page_size=200",
                            headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        assert cert["id"] in {c["id"] for c in listed}


# --------------------------------------------------------------------------- #
# 2. Recall reaches intermediate holders
# --------------------------------------------------------------------------- #
def test_recall_notifies_an_intermediate_holder(client, auth, db, orgs, users, farm_batch,
                                                second_farm_org):
    batch_id = farm_batch["id"]
    first = _ship(client, auth, batch_id, to_org_id=orgs["SUPPLY"].id).json()
    _arrive(client, auth, first["id"])
    onward = _ship(client, auth, batch_id, role="SUPPLY_CHAIN_OPERATOR",
                   to_org_id=second_farm_org.id, departed_at=iso(now()))
    assert onward.status_code == 201, onward.text
    # The processor no longer owns or holds the batch.
    assert client.get(f"{API}/supply-chain/batches/{batch_id}",
                      headers=auth("SUPPLY_CHAIN_OPERATOR")).status_code == 404

    recalled = _event(client, auth, "FARM_OPERATOR", batch_id, "recalling", "recalled")
    assert recalled.status_code == 201, recalled.text
    title = f"Batch {farm_batch['batch_code']} has been recalled"
    notes = _notes(db, users, "SUPPLY_CHAIN_OPERATOR", title)
    assert notes, "the intermediate processor was not told about the recall"
    # Linked to a shipment it can open, never to the batch it can no longer read.
    assert notes[-1].entity_type == "Shipment"
    assert _notes(db, users, "FARM_OPERATOR", title)


# --------------------------------------------------------------------------- #
# 3. Release gate
# --------------------------------------------------------------------------- #
class TestReleaseGate:
    def test_a_batch_made_from_a_recalled_batch_cannot_be_shipped(self, client, auth,
                                                                  farm_batch):
        child = client.post(f"{API}/supply-chain/batches", headers=auth("FARM_OPERATOR"), json={
            "batch_code": unique("R3K"), "product_id": farm_batch["product_id"],
            "quantity": 100.0, "unit": "kg", "parent_batch_id": farm_batch["id"]})
        assert child.status_code == 201, child.text
        assert _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "recalling",
                      "recalled").status_code == 201
        refused = _ship(client, auth, child.json()["id"])
        assert refused.status_code == 422
        assert "recalled batch" in refused.text
        # A recall is never gated.
        assert _event(client, auth, "FARM_OPERATOR", child.json()["id"], "recalling",
                      "recalled").status_code == 201

    def test_an_integrity_failed_batch_cannot_be_shipped_or_sold(self, client, auth, db,
                                                                 farm_batch):
        batch = db.get(Batch, farm_batch["id"])
        batch.integrity_status = "FAILED"
        db.commit()
        refused = _ship(client, auth, farm_batch["id"])
        assert refused.status_code == 422 and "integrity" in refused.text
        assert _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "harvesting",
                      "in_progress").status_code == 201
        assert _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "storing",
                      "in_storage").status_code == 201
        sold = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "retail_selling",
                      "sellable_accessible")
        assert sold.status_code == 422 and "put on sale" in sold.text
        assert _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "recalling",
                      "recalled").status_code == 201

    def test_a_batch_whose_gmo_approval_lapsed_cannot_be_shipped(self, client, auth, product,
                                                                 gmo_event):
        approve = client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                              headers=auth("REGULATOR"),
                              json={"jurisdiction": "CODEX", "status": "APPROVED"})
        assert approve.status_code in (200, 201), approve.text
        batch = client.post(f"{API}/supply-chain/batches", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                            json={"batch_code": unique("R3G"), "product_id": product.id,
                                  "quantity": 50.0, "unit": "kg",
                                  "gmo_event_id": gmo_event["id"]}).json()
        withdrawn = client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                                headers=auth("REGULATOR"),
                                json={"jurisdiction": "CODEX", "status": "REJECTED"})
        assert withdrawn.status_code in (200, 201), withdrawn.text
        refused = _ship(client, auth, batch["id"], role="SUPPLY_CHAIN_OPERATOR")
        assert refused.status_code == 422
        assert gmo_event["event_code"] in refused.text and "shipped" in refused.text


# --------------------------------------------------------------------------- #
# 4. verify-record visibility and report digests
# --------------------------------------------------------------------------- #
class TestVerifyRecord:
    def test_the_custodian_can_verify_the_batch(self, client, auth, orgs, farm_batch):
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201
        response = client.post(f"{API}/blockchain/verify-record",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"),
                               json={"entity_type": "BATCH", "entity_id": farm_batch["id"]})
        assert response.status_code == 200, response.text
        assert response.json()["result"] == "MATCH"

    def test_a_stranger_still_gets_404(self, client, farm_batch, rival_auth):
        response = client.post(f"{API}/blockchain/verify-record", headers=rival_auth,
                               json={"entity_type": "BATCH", "entity_id": farm_batch["id"]})
        assert response.status_code == 404

    def test_a_compliance_report_verifies_match(self, client, auth, orgs, farm_batch):
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201
        report = client.post(f"{API}/compliance/evaluate", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                             json={"subject_id": farm_batch["id"], "jurisdiction": "US-USDA"})
        assert report.status_code == 201, report.text
        for role in ("SUPPLY_CHAIN_OPERATOR", "FARM_OPERATOR", "REGULATOR"):
            response = client.post(f"{API}/blockchain/verify-record", headers=auth(role), json={
                "entity_type": "COMPLIANCE_REPORT", "entity_id": report.json()["id"]})
            assert response.status_code == 200, (role, response.text)
            body = response.json()
            assert body["result"] == "MATCH", (role, body)
            assert body["computed_hash"] == body["stored_hash"]

    def test_an_environmental_assessment_verifies_match(self, client, auth, gmo_event):
        report = client.post(f"{API}/compliance/eia", headers=auth("REGULATOR"), json={
            "gmo_event_id": gmo_event["id"], "cultivation_area_ha": 40.0})
        assert report.status_code == 201, report.text
        response = client.post(f"{API}/blockchain/verify-record", headers=auth("REGULATOR"),
                               json={"entity_type": "COMPLIANCE_REPORT",
                                     "entity_id": report.json()["id"]})
        assert response.status_code == 200 and response.json()["result"] == "MATCH"


# --------------------------------------------------------------------------- #
# 5. Dashboard counts both ends of a shipment
# --------------------------------------------------------------------------- #
def test_the_receiver_counts_shipments_coming_to_it(client, auth, orgs, farm_batch):
    before = client.get(f"{API}/dashboard",
                        headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["supply_chain"]
    assert _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).status_code == 201
    after = client.get(f"{API}/dashboard",
                       headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["supply_chain"]
    assert after["shipments_in_transit"] == before["shipments_in_transit"] + 1
    assert after["awaiting_arrival"] == before["awaiting_arrival"] + 1


# --------------------------------------------------------------------------- #
# 6. Approval loss and restoration reach crops planted without a seed lot
# --------------------------------------------------------------------------- #
def test_approval_loss_and_restoration_reach_a_crop_without_a_seed_lot(
        client, auth, db, users, field, farm, gmo_event):
    approve = client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                          headers=auth("REGULATOR"),
                          json={"jurisdiction": "US-USDA", "status": "APPROVED"})
    assert approve.status_code in (200, 201), approve.text
    crop = client.post(f"{API}/crops", headers=auth("FARM_OPERATOR"), json={
        "field_id": field.id, "crop_type": "Maize", "gmo_event_id": gmo_event["id"],
        "planted_at": iso(now())})
    assert crop.status_code == 201, crop.text
    assert db.get(Crop, crop.json()["id"]).seed_lot_id is None

    for status in ("REJECTED",):
        assert client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                           headers=auth("REGULATOR"),
                           json={"jurisdiction": "US-USDA", "status": status}
                           ).status_code in (200, 201)
    lost = _notes(db, users, "FARM_OPERATOR",
                  f"GMO approval withdrawn: {gmo_event['event_code']}")
    assert lost, "the grower with the event in the ground was not told"
    assert lost[-1].entity_type == "Farm" and lost[-1].entity_id == farm.id
    assert "Maize crop at Test Farm" in lost[-1].body

    for status in ("PENDING", "APPROVED"):
        assert client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                           headers=auth("REGULATOR"),
                           json={"jurisdiction": "US-USDA", "status": status}
                           ).status_code in (200, 201)
    restored = _notes(db, users, "FARM_OPERATOR",
                      f"GMO approval restored: {gmo_event['event_code']}")
    assert restored and restored[-1].entity_type == "Farm"


def test_reapproval_without_a_prior_loss_tells_only_the_developer(client, auth, db, users,
                                                                  gmo_event):
    assert client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                       headers=auth("REGULATOR"),
                       json={"jurisdiction": "EU", "status": "APPROVED"}
                       ).status_code in (200, 201)
    assert not _notes(db, users, "FARM_OPERATOR",
                      f"GMO approval restored: {gmo_event['event_code']}")


# --------------------------------------------------------------------------- #
# 7. Receiving recorded directly; certificate expiry
# --------------------------------------------------------------------------- #
def test_a_direct_receiving_event_has_the_arrival_side_effects(client, auth, db, users, orgs,
                                                               farm_batch):
    shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
    received = _event(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"], "receiving",
                      "in_storage", location_name="Plant A dock")
    assert received.status_code == 201, received.text
    listed = client.get(f"{API}/supply-chain/shipments?batch_id={farm_batch['id']}",
                        headers=auth("FARM_OPERATOR")).json()["items"]
    assert listed[0]["status"] == "DELIVERED"
    notes = _notes(db, users, "FARM_OPERATOR", f"Shipment {shipment['sscc']} arrived")
    assert notes and "Plant A dock" in notes[-1].body
    assert db.execute(select(AuditLog).where(
        AuditLog.action == "supply.shipment_arrived",
        AuditLog.entity_id == shipment["id"])).first() is not None


def test_certificate_expiry_downgrades_a_verified_batch(client, auth, db, orgs, farm_batch):
    regulator = db.execute(select(Organization).where(
        Organization.id == orgs["REGULATOR"].id)).scalar_one()
    certificate = Certification(
        cert_code=unique("R3X"), cert_type="SPECIALTY", standard="Test",
        issuer_org_id=regulator.id, subject_org_id=orgs["FARM"].id, scope="Test",
        valid_from=utcnow() - timedelta(days=30), valid_to=utcnow() - timedelta(days=1),
        status="ACTIVE")
    db.add(certificate)
    db.flush()
    db.add(CertificationLink(certification_id=certificate.id, batch_id=farm_batch["id"]))
    batch = db.get(Batch, farm_batch["id"])
    batch.integrity_status = "VERIFIED"
    db.commit()
    supply_service.sweep_certification_expiry(db)
    db.commit()
    db.refresh(batch)
    assert db.get(Certification, certificate.id).status == "EXPIRED"
    assert batch.integrity_status == "UNVERIFIED"


@pytest.mark.parametrize("module", ["batch-detail", "shipments", "certifications"])
def test_frontend_copy(module):
    from pathlib import Path

    source = (Path(__file__).resolve().parents[2] / "frontend" / "views"
              / f"{module}.js").read_text()
    if module == "batch-detail":
        assert "fmtDay(row.valid_to)" in source and "fmtDay(a.expires_at)" in source
        assert "recall ? ', and you can still recall it' : ''" in source
    elif module == "shipments":
        assert "Internal move (no hand-over)" in source
    else:
        assert "can('cert:revoke')" in source
