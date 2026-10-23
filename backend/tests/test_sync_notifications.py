"""Regulated decisions reach the people they concern, and dependent records stay in sync.

GMO approvals (withdrawal, expiry, liveness), biosecurity review outcomes, certificate
revocation and expiry, fraud assessments, compliance reports and the release check.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from ai.data.generate import hazard_database, hazard_derived_sequence
from app.models import (Alert, Batch, Certification, CertificationLink, GMOApproval, Incident,
                        IncidentEvent, Notification, User)
from .conftest import unique
from .test_supplychain_e2e import gmo_event, iso, now, traced_batch  # noqa: F401 (fixtures)

API = "/api/v1"


def _notes(db, user: User, entity_id: str | None = None) -> list[Notification]:
    db.expire_all()
    query = select(Notification).where(Notification.user_id == user.id)
    if entity_id:
        query = query.where(Notification.entity_id == entity_id)
    return list(db.execute(query).scalars())


def _org_notes(db, org_id: str, needle: str) -> list[Notification]:
    db.expire_all()
    return list(db.execute(select(Notification).join(User, User.id == Notification.user_id)
                           .where(User.org_id == org_id,
                                  Notification.title.contains(needle))).scalars())


def _approve(client, auth, event_id, jurisdiction="US-USDA", status="APPROVED", **extra):
    response = client.post(f"{API}/gmo/events/{event_id}/approvals", headers=auth("REGULATOR"),
                           json={"jurisdiction": jurisdiction, "status": status, **extra})
    assert response.status_code in (200, 201), response.text
    return response.json()


@pytest.fixture
def gmo_holdings(client, auth, gmo_event, orgs, product):
    """An approved event whose seed lot the developer supplied to the farm, and a batch the
    processor produced from that lot."""
    _approve(client, auth, gmo_event["id"])
    lot = client.post(f"{API}/gmo/seed-lots", headers=auth("BIOTECH_RESEARCHER"), json={
        "lot_code": unique("SL"), "gmo_event_id": gmo_event["id"], "crop_type": "Maize",
        "variety": "V1", "quantity_kg": 100.0, "produced_at": iso(now())}).json()
    moved = client.post(f"{API}/gmo/seed-lots/{lot['id']}/transfer",
                        headers=auth("BIOTECH_RESEARCHER"), json={"to_org_id": orgs["FARM"].id})
    assert moved.status_code == 200, moved.text
    batch = client.post(f"{API}/supply-chain/batches", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                        json={"batch_code": unique("B"), "product_id": product.id,
                              "quantity": 50.0, "unit": "kg", "seed_lot_id": lot["id"],
                              "origin_region": "Iowa", "origin_country": "US",
                              "harvested_at": iso(now())})
    assert batch.status_code == 201, batch.text
    return {"event": gmo_event, "lot": lot, "batch": batch.json()}


# --------------------------------------------------------------------------- #
# 1. Withdrawal and expiry of a GMO approval
# --------------------------------------------------------------------------- #
class TestApprovalLoss:
    def test_withdrawal_reaches_developer_and_every_holder(self, client, auth, db, orgs, users,
                                                           gmo_holdings):
        event, batch = gmo_holdings["event"], gmo_holdings["batch"]
        _approve(client, auth, event["id"], status="REJECTED", reference="WITHDRAWN-1")

        needle = f"withdrawn: {event['event_code']}"
        for org in ("BIOTECH", "FARM", "SUPPLY"):
            assert _org_notes(db, orgs[org].id, needle), f"{org} was not told"
        # The processor's notification names its batch; the farm's names the lot it holds.
        supply = _org_notes(db, orgs["SUPPLY"].id, needle)[0]
        assert batch["batch_code"] in supply.body
        farm = _org_notes(db, orgs["FARM"].id, needle)[0]
        assert gmo_holdings["lot"]["lot_code"] in farm.body

        alerts = list(db.execute(select(Alert).where(
            Alert.entity_id == batch["id"], Alert.category == "COMPLIANCE")).scalars())
        assert alerts and alerts[0].org_id == orgs["SUPPLY"].id

    def test_developer_is_told_every_decision(self, client, auth, db, users, gmo_event):
        _approve(client, auth, gmo_event["id"], jurisdiction="EU", status="PENDING")
        titles = [n.title for n in _notes(db, users["BIOTECH_RESEARCHER"], gmo_event["id"])]
        assert any("EU decision PENDING" in t for t in titles)

    def test_expiry_sweep_propagates_once(self, client, auth, db, orgs, gmo_holdings):
        from app.services import gmo as gmo_service

        event, batch = gmo_holdings["event"], gmo_holdings["batch"]
        approval = db.execute(select(GMOApproval).where(
            GMOApproval.gmo_event_id == event["id"])).scalar_one()
        approval.expires_at = now() - timedelta(minutes=5)
        db.commit()

        handled = gmo_service.sweep_expired_approvals(db)
        db.commit()
        mine = [r for r in handled if r["event_code"] == event["event_code"]]
        assert mine and batch["id"] in mine[0]["batches"]
        assert gmo_holdings["lot"]["id"] in mine[0]["seed_lots"]
        assert _org_notes(db, orgs["SUPPLY"].id, f"expired: {event['event_code']}")
        assert _org_notes(db, orgs["FARM"].id, f"expired: {event['event_code']}")

        again = gmo_service.sweep_expired_approvals(db)
        db.commit()
        assert not [r for r in again if r["event_code"] == event["event_code"]]


# --------------------------------------------------------------------------- #
# 2. One liveness rule: labelling and the approved_only selector
# --------------------------------------------------------------------------- #
class TestLiveApproval:
    def test_expired_approval_does_not_permit_labelling(self, client, auth, db, gmo_holdings):
        event, batch = gmo_holdings["event"], gmo_holdings["batch"]
        ok = client.get(f"{API}/gmo/labelling/{batch['id']}?jurisdiction=US-USDA",
                        headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert ok["approved_in_jurisdiction"] is True

        approval = db.execute(select(GMOApproval).where(
            GMOApproval.gmo_event_id == event["id"])).scalar_one()
        approval.expires_at = now() - timedelta(days=1)
        db.commit()
        lapsed = client.get(f"{API}/gmo/labelling/{batch['id']}?jurisdiction=US-USDA",
                            headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert lapsed["approved_in_jurisdiction"] is False
        assert lapsed["compliant"] is False
        assert "expired" in lapsed["findings"][0]["detail"]

    def test_future_approval_is_not_offered_or_live(self, client, auth, gmo_event):
        approval = _approve(client, auth, gmo_event["id"], jurisdiction="EU",
                            approved_at=iso(now() + timedelta(days=10)))
        assert approval["live"] is False
        listed = client.get(f"{API}/gmo/events?approved_only=true&page_size=200",
                            headers=auth("BIOTECH_RESEARCHER")).json()["items"]
        assert gmo_event["id"] not in {row["id"] for row in listed}

    def test_expired_event_is_not_offered(self, client, auth, gmo_event):
        _approve(client, auth, gmo_event["id"], jurisdiction="EU",
                 approved_at=iso(now() - timedelta(days=30)),
                 expires_at=iso(now() - timedelta(days=1)))
        listed = client.get(f"{API}/gmo/events?approved_only=true&page_size=200",
                            headers=auth("BIOTECH_RESEARCHER")).json()["items"]
        assert gmo_event["id"] not in {row["id"] for row in listed}


# --------------------------------------------------------------------------- #
# 3. Regulators learn of new events; the registry shows decisions and a queue
# --------------------------------------------------------------------------- #
class TestRegulatorQueue:
    def test_regulator_is_told_and_queue_tracks_decisions(self, client, auth, db, users,
                                                          gmo_event):
        assert _notes(db, users["REGULATOR"], gmo_event["id"])

        def queue():
            rows = client.get(f"{API}/gmo/events?awaiting_decision=true&page_size=200",
                              headers=auth("REGULATOR")).json()["items"]
            return {row["id"]: row for row in rows}

        assert gmo_event["id"] in queue()
        _approve(client, auth, gmo_event["id"], jurisdiction="EU",
                 expires_at=iso(now() + timedelta(days=365)))
        assert gmo_event["id"] not in queue()
        _approve(client, auth, gmo_event["id"], jurisdiction="CODEX", status="PENDING")
        assert gmo_event["id"] in queue()

        listed = client.get(f"{API}/gmo/events?page_size=200",
                            headers=auth("REGULATOR")).json()["items"]
        row = next(r for r in listed if r["id"] == gmo_event["id"])
        by_code = {a["jurisdiction"]: a for a in row["approvals"]}
        assert by_code["EU"]["status"] == "APPROVED" and by_code["EU"]["live"] is True
        assert by_code["EU"]["expires_at"]
        assert by_code["CODEX"]["status"] == "PENDING"


# --------------------------------------------------------------------------- #
# 4. Biosecurity outcomes reach the researcher; review closes the alert and incident
# --------------------------------------------------------------------------- #
class TestBiosecurityOutcomes:
    def test_screening_review_notifies_and_resolves(self, client, auth, db, users, hazards):
        hazard = hazard_database()[0]
        submitted = client.post(f"{API}/biosecurity/screenings",
                                headers=auth("BIOTECH_RESEARCHER"),
                                json={"name": unique("hazard"),
                                      "sequence": hazard_derived_sequence(
                                          hazard["sequence"], 0.05, 2),
                                      "intent": "virulence enhancement",
                                      "organism": "Fusarium oxysporum"}).json()
        assert submitted["status"] == "BLOCKED"
        researcher = users["BIOTECH_RESEARCHER"]
        assert any("blocked" in n.title for n in _notes(db, researcher, submitted["id"]))
        alert = db.execute(select(Alert).where(Alert.entity_id == submitted["id"])).scalar_one()
        assert alert.status == "OPEN" and alert.incident_id

        reviewed = client.post(f"{API}/biosecurity/screenings/{submitted['id']}/review",
                               headers=auth("BIOSAFETY_OFFICER"),
                               json={"decision": "REJECT",
                                     "rationale": "Hazard homology with virulence intent."})
        assert reviewed.status_code == 200, reviewed.text
        assert any("rejected by biosafety review" in n.title
                   for n in _notes(db, researcher, submitted["id"]))
        db.expire_all()
        alert = db.get(Alert, alert.id)
        assert alert.status == "RESOLVED"
        events = db.execute(select(IncidentEvent.action).where(
            IncidentEvent.incident_id == alert.incident_id)).scalars().all()
        assert "RESOLVED" in events
        assert db.get(Incident, alert.incident_id).status == "RESOLVED"

    def test_crispr_review_notifies_and_queue_lists_pending(self, client, auth, db, users):
        created = client.post(f"{API}/biosecurity/crispr", headers=auth("BIOTECH_RESEARCHER"),
                              json={"target_gene": "avr virulence effector",
                                    "organism": "Fusarium oxysporum",
                                    "organism_class": "PLANT_PATHOGEN",
                                    "guide_rna": "ACGTACGTACGTACGTACGT", "pam": "NGG",
                                    "edit_type": "KNOCK_IN",
                                    "intent": "enhance virulence and host range"}).json()
        assert created["status"] == "PENDING_REVIEW"
        pending = client.get(f"{API}/biosecurity/crispr?status=PENDING_REVIEW&page_size=200",
                             headers=auth("BIOSAFETY_OFFICER")).json()["items"]
        assert created["id"] in {row["id"] for row in pending}
        assert all(row["status"] == "PENDING_REVIEW" for row in pending)

        response = client.post(f"{API}/biosecurity/crispr/{created['id']}/review",
                               headers=auth("BIOSAFETY_OFFICER"),
                               json={"decision": "REJECT",
                                     "rationale": "Gain-of-function intent is prohibited."})
        assert response.status_code == 200, response.text
        titles = [n.title for n in _notes(db, users["BIOTECH_RESEARCHER"], created["id"])]
        assert any("held for biosafety review" in t for t in titles)
        assert any("rejected by biosafety review" in t for t in titles)
        db.expire_all()
        assert all(a.status == "RESOLVED" for a in db.execute(select(Alert).where(
            Alert.entity_id == created["id"])).scalars())


# --------------------------------------------------------------------------- #
# 5. Certificates: issue, revoke, expiry
# --------------------------------------------------------------------------- #
def _issue(client, auth, orgs, **extra):
    body = {"cert_code": unique("SPC"), "cert_type": "SPECIALTY", "standard": "CODEX-GL-32",
            "subject_org_id": orgs["SUPPLY"].id, "scope": "Processing",
            "valid_from": iso(now() - timedelta(days=1)),
            "valid_to": iso(now() + timedelta(days=300)), **extra}
    response = client.post(f"{API}/supply-chain/certifications", headers=auth("CERTIFIER"),
                           json=body)
    assert response.status_code == 201, response.text
    return response.json()


class TestCertificates:
    def test_issue_and_revoke_reach_every_party(self, client, auth, db, orgs, users,
                                                traced_batch):
        cert = _issue(client, auth, orgs)
        assert _notes(db, users["SUPPLY_CHAIN_OPERATOR"], cert["id"]), "subject not told"

        assert client.post(f"{API}/supply-chain/certifications/{cert['id']}/link",
                           headers=auth("SUPPLY_CHAIN_OPERATOR"),
                           json={"batch_id": traced_batch["id"]}).status_code == 201
        verified = client.post(f"{API}/supply-chain/batches/{traced_batch['id']}/verify",
                               headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert verified["integrity_status"] == "VERIFIED"
        # Hand the batch to the farm, so owner and custodian differ.
        shipped = client.post(f"{API}/supply-chain/events", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                              json={"batch_id": traced_batch["id"], "biz_step": "shipping",
                                    "disposition": "in_transit", "occurred_at": iso(now()),
                                    "to_org_id": orgs["FARM"].id})
        assert shipped.status_code == 201, shipped.text

        listed = client.get(f"{API}/supply-chain/certifications?page_size=200",
                            headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        row = next(r for r in listed if r["id"] == cert["id"])
        assert row["subject_org_name"] == orgs["SUPPLY"].name
        assert {"id": traced_batch["id"], "batch_code": traced_batch["batch_code"]} \
            in row["claimed_batches"]

        revoked = client.post(f"{API}/supply-chain/certifications/{cert['id']}/revoke",
                              headers=auth("CERTIFIER"), json={"reason": "Audit finding"})
        assert revoked.status_code == 200, revoked.text
        for role in ("SUPPLY_CHAIN_OPERATOR", "FARM_OPERATOR", "CERTIFIER"):
            titles = [n.title for n in _notes(db, users[role], cert["id"])]
            assert any("revoked" in t for t in titles), f"{role} was not told"
        db.expire_all()
        assert db.get(Batch, traced_batch["id"]).integrity_status == "UNVERIFIED"

    def test_expired_certificate_reads_expired_and_sweep_persists_it(self, client, auth, db,
                                                                    orgs, users,
                                                                    traced_batch):
        from app.services import supplychain as supply_service

        expired = Certification(cert_code=unique("EXP"), cert_type="SPECIALTY",
                                standard="CODEX-GL-32", issuer_org_id=orgs["REGULATOR"].id,
                                subject_org_id=orgs["SUPPLY"].id, scope="s",
                                valid_from=now() - timedelta(days=400),
                                valid_to=now() - timedelta(days=30), status="ACTIVE")
        db.add(expired)
        db.flush()
        db.add(CertificationLink(certification_id=expired.id, batch_id=traced_batch["id"]))
        db.commit()

        listed = client.get(f"{API}/supply-chain/certifications?page_size=200",
                            headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        assert next(r for r in listed if r["id"] == expired.id)["status"] == "EXPIRED"
        custody = client.get(f"{API}/supply-chain/batches/{traced_batch['id']}/custody",
                             headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert next(c for c in custody["certifications"]
                    if c["cert_code"] == expired.cert_code)["status"] == "EXPIRED"
        refused = client.post(f"{API}/supply-chain/certifications/{expired.id}/link",
                              headers=auth("SUPPLY_CHAIN_OPERATOR"),
                              json={"batch_id": traced_batch["id"]})
        assert refused.status_code in (409, 422)

        result = supply_service.sweep_certification_expiry(db)
        db.commit()
        assert result["expired"] >= 1
        db.expire_all()
        assert db.get(Certification, expired.id).status == "EXPIRED"
        assert any("expired" in n.title
                   for n in _notes(db, users["SUPPLY_CHAIN_OPERATOR"], expired.id))


# --------------------------------------------------------------------------- #
# 6. Fraud assessments and compliance reports belong to both parties
# --------------------------------------------------------------------------- #
class TestSharedReports:
    def test_custodian_sees_its_fraud_assessment(self, client, auth, orgs, traced_batch):
        client.post(f"{API}/supply-chain/events", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                    json={"batch_id": traced_batch["id"], "biz_step": "shipping",
                          "disposition": "in_transit", "occurred_at": iso(now()),
                          "to_org_id": orgs["FARM"].id})
        run = client.post(f"{API}/supply-chain/batches/{traced_batch['id']}/verify",
                          headers=auth("FARM_OPERATOR"))
        assert run.status_code == 200, run.text
        for role in ("FARM_OPERATOR", "SUPPLY_CHAIN_OPERATOR"):
            rows = client.get(f"{API}/supply-chain/fraud-assessments?page_size=200",
                              headers=auth(role)).json()["items"]
            assert traced_batch["id"] in {r["batch_id"] for r in rows}, role

    def test_regulator_report_is_visible_to_the_batch_parties(self, client, auth, db, orgs,
                                                              users, traced_batch):
        report = client.post(f"{API}/compliance/evaluate", headers=auth("REGULATOR"),
                             json={"subject_type": "BATCH", "subject_id": traced_batch["id"],
                                   "jurisdiction": "EU"})
        assert report.status_code == 201, report.text
        report = report.json()
        rows = client.get(f"{API}/compliance/reports?page_size=200",
                          headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        assert report["id"] in {r["id"] for r in rows}
        assert client.get(f"{API}/compliance/reports/{report['id']}",
                          headers=auth("SUPPLY_CHAIN_OPERATOR")).status_code == 200
        # A stranger to the batch still cannot read it.
        assert client.get(f"{API}/compliance/reports/{report['id']}",
                          headers=auth("BIOTECH_RESEARCHER")).status_code in (403, 404)
        assert any(traced_batch["batch_code"] in n.title
                   for n in _notes(db, users["SUPPLY_CHAIN_OPERATOR"], traced_batch["id"]))
        alert = db.execute(select(Alert).where(
            Alert.entity_id == traced_batch["id"], Alert.category == "COMPLIANCE")
            .order_by(Alert.created_at.desc())).scalars().first()
        if report["status"] != "COMPLIANT":
            assert alert is not None and alert.org_id == orgs["SUPPLY"].id


# --------------------------------------------------------------------------- #
# 7. The holder runs the release check
# --------------------------------------------------------------------------- #
class TestReleaseCheck:
    def test_holder_may_check_release_others_may_not(self, client, auth, orgs, traced_batch):
        url = f"{API}/gmo/labelling/{traced_batch['id']}/check-release?jurisdiction=CODEX"
        ok = client.post(url, headers=auth("SUPPLY_CHAIN_OPERATOR"))
        assert ok.status_code == 200, ok.text
        assert ok.json()["compliant"] is True
        assert client.post(url, headers=auth("BIOTECH_RESEARCHER")).status_code == 403

        client.post(f"{API}/supply-chain/events", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                    json={"batch_id": traced_batch["id"], "biz_step": "shipping",
                          "disposition": "in_transit", "occurred_at": iso(now()),
                          "to_org_id": orgs["FARM"].id})
        # The owner no longer holds it; the farm now does.
        assert client.post(url, headers=auth("SUPPLY_CHAIN_OPERATOR")).status_code == 403
        assert client.post(url, headers=auth("FARM_OPERATOR")).status_code == 200
