"""Round 6: visibility, alerts and notification routing.

A biosafety officer reads other tenants' biosecurity alerts only, certificate-only custody
views, oversight incident assignees, ledger-rejection notices to the submitting organisation,
holder names on batches and seed lots, the data-theft detector's recency rule, one notification
per blocked screening, settled regulator notices, migration 0013 and readable jurisdictions.
"""
from __future__ import annotations

import importlib.util
import uuid
from datetime import timedelta

from sqlalchemy import create_engine, select, text

from ai.data.generate import hazard_database, hazard_derived_sequence
from app.core.security import hash_password, utcnow
from app.models import (AccessRecord, Alert, Base, GMOApproval, Incident,
                        IncidentEvent, LedgerWrite, Notification, User)
from app.services import anchoring, audit, notifications, security_ops
from .conftest import ROOT, unique
from .test_round3_supply import _arrive, _claim, _issue
from .test_shipments_recall import _ship, chilled_product, farm_batch  # noqa: F401
from .test_supplychain_e2e import gmo_event  # noqa: F401

API = "/api/v1"


def _alert(db, category, org_id, **extra) -> Alert:
    alert = notifications.raise_alert(
        db, category, "HIGH", f"R6 {category} {unique('A')}", org_id=org_id,
        entity_type="Device", entity_id=str(uuid.uuid4()), notify=False, **extra)
    db.commit()
    return alert


def _listed(client, headers, **params) -> set[str]:
    response = client.get(f"{API}/security/alerts", headers=headers,
                          params={"page_size": 200, **params})
    assert response.status_code == 200, response.text
    return {a["id"] for a in response.json()["items"]}


# --------------------------------------------------------------------------- #
# 1. A biosafety officer reads other tenants' biosecurity alerts only
# --------------------------------------------------------------------------- #
class TestBiosafetyOfficerReach:
    def test_foreign_device_and_certificate_alerts_are_hidden(self, client, auth, db, orgs):
        device = _alert(db, "DEVICE_HEALTH", orgs["FARM"].id)
        cert = _alert(db, "CERTIFICATION", orgs["SUPPLY"].id)
        bio = _alert(db, "BIOSECURITY", orgs["FARM"].id)
        own = _alert(db, "AGRONOMY", orgs["BIOTECH"].id)
        officer = auth("BIOSAFETY_OFFICER")
        listed = _listed(client, officer, status="OPEN")
        assert device.id not in listed and cert.id not in listed
        assert bio.id in listed, "biosecurity oversight is cross-tenant"
        assert own.id in listed, "her own organisation's alerts stay visible"
        # Not acknowledgeable or resolvable either: it is not hers to see.
        for action in ("acknowledge", "resolve"):
            response = client.post(f"{API}/security/alerts/{device.id}/{action}",
                                   headers=officer)
            assert response.status_code == 404, response.text
        assert client.post(f"{API}/security/alerts/{bio.id}/acknowledge",
                           headers=officer).status_code == 200

    def test_incidents_follow_the_same_rule(self, client, auth, db, orgs):
        device = _alert(db, "DEVICE_ANOMALY", orgs["FARM"].id)
        durc = _alert(db, "DURC", orgs["SUPPLY"].id)
        officer = auth("BIOSAFETY_OFFICER")
        listed = {i["id"] for i in client.get(f"{API}/security/incidents", headers=officer,
                                              params={"page_size": 200}).json()["items"]}
        assert durc.incident_id in listed
        assert device.incident_id not in listed
        assert client.get(f"{API}/security/incidents/{device.incident_id}",
                          headers=officer).status_code == 404

    def test_other_oversight_roles_are_unchanged(self, client, auth, db, orgs):
        device = _alert(db, "DEVICE_HEALTH", orgs["FARM"].id)
        for role in ("REGULATOR", "SECURITY_ANALYST", "ADMIN"):
            assert device.id in _listed(client, auth(role), status="OPEN"), role

    def test_security_board_counts_only_what_she_can_read(self, client, auth, db, orgs):
        before = client.get(f"{API}/security/dashboard",
                            headers=auth("BIOSAFETY_OFFICER")).json()["alerts_total"]
        _alert(db, "DEVICE_HEALTH", orgs["FARM"].id)
        after = client.get(f"{API}/security/dashboard",
                           headers=auth("BIOSAFETY_OFFICER")).json()["alerts_total"]
        assert after == before

    def test_audit_trail_is_her_org_plus_biosecurity(self, client, auth, db, orgs, users):
        foreign_ship = audit.record(db, "supply.create_shipment", actor_id=users["FARM_OPERATOR"].id,
                                    actor_role="FARM_OPERATOR", org_id=orgs["FARM"].id,
                                    entity_type="Shipment", entity_id=str(uuid.uuid4()))
        foreign_bio = audit.record(db, "biosecurity.screening_submit",
                                   actor_id=users["FARM_OPERATOR"].id, actor_role="FARM_OPERATOR",
                                   org_id=orgs["FARM"].id, entity_type="SequenceScreening",
                                   entity_id=str(uuid.uuid4()))
        db.commit()
        rows = client.get(f"{API}/audit/logs", headers=auth("BIOSAFETY_OFFICER"),
                          params={"page_size": 200}).json()["items"]
        ids = {r["entity_id"] for r in rows}
        assert foreign_bio.entity_id in ids
        assert foreign_ship.entity_id not in ids
        assert all(r["org_id"] == orgs["BIOTECH"].id or r["action"].startswith("biosecurity.")
                   for r in rows)
        # A regulator still reads the whole trail.
        regulator = {r["entity_id"] for r in client.get(
            f"{API}/audit/logs", headers=auth("REGULATOR"),
            params={"page_size": 200}).json()["items"]}
        assert foreign_ship.entity_id in regulator


# --------------------------------------------------------------------------- #
# 2. A certifier reading through its certificate sees its certified organisation only
# --------------------------------------------------------------------------- #
def test_certificate_custody_view_names_only_the_certified_organisation(
        client, auth, orgs, farm_batch, second_farm_org):
    cert = _issue(client, auth, orgs["FARM"].id)
    _claim(client, auth, cert, farm_batch["id"])
    first = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
    _arrive(client, auth, first["id"])
    _ship(client, auth, farm_batch["id"], role="SUPPLY_CHAIN_OPERATOR",
          to_org_id=second_farm_org.id)

    body = client.get(f"{API}/supply-chain/batches/{farm_batch['id']}/custody",
                      headers=auth("CERTIFIER")).json()
    farm_id = orgs["FARM"].id
    assert body["events"], "the certified farm's own events are shown"
    assert all(farm_id in {e["org_id"], e["from_org_id"], e["to_org_id"]}
               for e in body["events"])
    context = body["context"]
    assert set(context["organisations"]) <= {farm_id}
    assert context["custodian"]["name"] == "another organisation"
    assert context["owner"]["id"] == farm_id
    assert body["batch"]["custodian_name"] == "another organisation"
    names = str(body)
    assert orgs["SUPPLY"].name not in names and second_farm_org.name not in names

    # The owner still sees everything.
    owner = client.get(f"{API}/supply-chain/batches/{farm_batch['id']}/custody",
                       headers=auth("FARM_OPERATOR")).json()
    assert len(owner["events"]) > len(body["events"])

    # verify-record follows the same rule for events.
    hidden = [e for e in owner["events"]
              if farm_id not in {e["org_id"], e["from_org_id"], e["to_org_id"]}]
    assert hidden
    response = client.post(f"{API}/blockchain/verify-record", headers=auth("CERTIFIER"),
                           json={"entity_type": "SUPPLY_CHAIN_EVENT",
                                 "entity_id": hidden[0]["id"]})
    assert response.status_code == 404, response.text
    shown = body["events"][0]
    assert client.post(f"{API}/blockchain/verify-record", headers=auth("CERTIFIER"),
                       json={"entity_type": "SUPPLY_CHAIN_EVENT",
                             "entity_id": shown["id"]}).status_code == 200


# --------------------------------------------------------------------------- #
# 3. A data-theft incident is assigned to security operations only
# --------------------------------------------------------------------------- #
def test_oversight_incident_assignee_must_be_security_operations(client, auth, db, orgs, users):
    suspect = users["FARM_OPERATOR"]
    alert = notifications.raise_alert(
        db, "DATA_THEFT", "HIGH", f"Possible data exfiltration by {unique('S')}",
        org_id=suspect.org_id, entity_type="User", entity_id=suspect.id, notify=False,
        kind=unique("exfil"))
    db.commit()
    url = f"{API}/security/incidents/{alert.incident_id}"
    analyst = auth("SECURITY_ANALYST")
    refused = client.patch(url, headers=analyst, json={"assignee_id": suspect.id})
    assert refused.status_code == 422, refused.text
    assert client.patch(url, headers=analyst,
                        json={"assignee_id": users["SECURITY_ANALYST"].id}).status_code == 200
    # An ordinary incident can still go to a member of its organisation.
    device = _alert(db, "DEVICE_ANOMALY", orgs["FARM"].id)
    assert client.patch(f"{API}/security/incidents/{device.incident_id}", headers=analyst,
                        json={"assignee_id": suspect.id}).status_code == 200


# --------------------------------------------------------------------------- #
# 4. A ledger rejection is explained to the submitting organisation
# --------------------------------------------------------------------------- #
def test_a_ledger_rejection_notifies_the_submitting_organisation(db, orgs, users):
    code = unique("GHOST")
    row = LedgerWrite(contract="provenance", function="RecordEvent",
                      args={"batch_code": code, "event_id": unique("E"), "biz_step": "shipping"},
                      submitter_msp="SupplyMSP", chain_key=f"batch:{code}", requires=[],
                      anchor_status="FAILED", attempts=1)
    db.add(row)
    db.commit()
    anchoring.retry_pending(db)
    db.commit()
    db.expire_all()
    notes = list(db.execute(select(Notification).where(
        Notification.user_id == users["SUPPLY_CHAIN_OPERATOR"].id,
        Notification.title.contains(code))).scalars())
    assert len(notes) == 1, [n.title for n in notes]
    assert f"batch {code}" in notes[0].title
    assert "analysts" in notes[0].body
    # The alert itself stays security operations' only.
    alert = db.execute(select(Alert).where(Alert.entity_id == row.id)).scalar_one()
    assert alert.category == "LEDGER"


def test_record_description_reads_like_a_record():
    assert anchoring.record_description("batch:B-1") == "batch B-1"
    assert anchoring.record_description("gmoapproval:EV-1:US-USDA") == \
        "the USDA (US) approval of GMO event EV-1"
    assert anchoring.record_description(None) == "a record"


# --------------------------------------------------------------------------- #
# 5. Holder names come with the records
# --------------------------------------------------------------------------- #
def test_batches_and_seed_lots_carry_their_holder_name(client, auth, orgs, farm_batch,
                                                       gmo_event):  # noqa: F811
    batches = client.get(f"{API}/supply-chain/batches", headers=auth("AGRONOMIST"),
                         params={"page_size": 200}).json()["items"]
    mine = next(b for b in batches if b["id"] == farm_batch["id"])
    assert mine["custodian_name"] == orgs["FARM"].name
    approved = client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                           headers=auth("REGULATOR"),
                           json={"jurisdiction": "US-USDA", "status": "APPROVED",
                                 "reference": "R6"})
    assert approved.status_code == 201, approved.text
    lot = client.post(f"{API}/gmo/seed-lots", headers=auth("BIOTECH_RESEARCHER"), json={
        "lot_code": unique("SL"), "gmo_event_id": gmo_event["id"], "crop_type": "Maize",
        "variety": "V1", "quantity_kg": 10.0, "produced_at": utcnow().isoformat()}).json()
    assert lot["holder_name"] == orgs["BIOTECH"].name
    moved = client.post(f"{API}/gmo/seed-lots/{lot['id']}/transfer",
                        headers=auth("BIOTECH_RESEARCHER"), json={"to_org_id": orgs["FARM"].id})
    assert moved.json()["holder_name"] == orgs["FARM"].name
    lots = client.get(f"{API}/gmo/seed-lots", headers=auth("AGRONOMIST"),
                      params={"page_size": 200}).json()["items"]
    assert next(x for x in lots if x["id"] == lot["id"])["holder_name"] == orgs["FARM"].name


# --------------------------------------------------------------------------- #
# 6. Data-theft detector: stale probes do not corroborate a later burst of page loads
# --------------------------------------------------------------------------- #
def _principal(db, org_id) -> User:
    user = User(email=f"{unique('r6dt')}@test.absp", full_name="Round Six Browser",
                password_hash=hash_password("x" * 16), role="SUPPLY_CHAIN_OPERATOR",
                org_id=org_id, status="ACTIVE")
    db.add(user)
    db.commit()
    return user


def _access(db, user, count, *, minutes_ago, spread_minutes=8, cross=False, status=200,
            routes=None):
    now = utcnow()
    for index in range(count):
        route = routes[index % len(routes)] if routes else "/api/v1/supply-chain/batches"
        db.add(AccessRecord(principal_id=user.id, org_id=user.org_id, route=route,
                            method="GET", page_size=25, result_count=0, status_code=status,
                            hour=12, cross_tenant_attempt=cross,
                            created_at=now - timedelta(minutes=minutes_ago)
                            - timedelta(seconds=(spread_minutes * 60 * index) // max(count, 1))))
    db.commit()


class TestDataTheftRecency:
    def test_a_supply_crawl_after_stale_probes_is_not_flagged(self, db, orgs):
        user = _principal(db, orgs["SUPPLY"].id)
        # Five 404 probes from an earlier end-to-end run, three hours ago.
        _access(db, user, 5, minutes_ago=180, cross=True, status=404)
        # 153 page loads in ten minutes over 31 kinds of page, many of them detail pages.
        routes = [f"/api/v1/supply-chain/view-{i}" for i in range(31)]
        routes += [f"/api/v1/supply-chain/batches/{uuid.uuid4()}" for _ in range(60)]
        _access(db, user, 153, minutes_ago=0, spread_minutes=9, routes=routes)
        _access(db, user, 60, minutes_ago=60, routes=routes)
        verdict = security_ops.evaluate_principal(db, user.id, user.org_id)
        names = {s["signal"] for s in verdict["signals"]}
        assert "cross_tenant_attempts" not in names, verdict
        assert not verdict["flagged"], verdict

    def test_recent_repeated_probing_is_still_a_signal(self, db, orgs):
        user = _principal(db, orgs["SUPPLY"].id)
        _access(db, user, 3, minutes_ago=1, spread_minutes=2, cross=True, status=404)
        verdict = security_ops.evaluate_principal(db, user.id, user.org_id)
        assert "cross_tenant_attempts" in {s["signal"] for s in verdict["signals"]}

    def test_sustained_probing_over_the_day_is_still_a_signal(self, db, orgs):
        user = _principal(db, orgs["SUPPLY"].id)
        _access(db, user, 12, minutes_ago=120, spread_minutes=300, cross=True, status=404)
        verdict = security_ops.evaluate_principal(db, user.id, user.org_id)
        assert "cross_tenant_attempts" in {s["signal"] for s in verdict["signals"]}

    def test_route_shape_folds_record_ids(self):
        assert security_ops.route_shape(f"/api/v1/batches/{uuid.uuid4()}/custody") == \
            "/api/v1/batches/{id}/custody"


# --------------------------------------------------------------------------- #
# 7. One notification per blocked screening, at the alert's severity
# --------------------------------------------------------------------------- #
def test_a_blocked_screening_gives_its_submitter_one_notification(client, auth, db, users,
                                                                  hazards):
    hazard = hazard_database()[0]
    name = unique("r6blk")
    response = client.post(f"{API}/biosecurity/screenings", headers=auth("BIOSAFETY_OFFICER"),
                           json={"name": name,
                                 "sequence": hazard_derived_sequence(hazard["sequence"], 0.05, 3),
                                 "intent": "diagnostic assay", "organism": "Fusarium oxysporum"})
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "BLOCKED"
    db.expire_all()
    mine = [n for n in db.execute(select(Notification).where(
        Notification.user_id == users["BIOSAFETY_OFFICER"].id)).scalars() if name in n.title]
    assert len(mine) == 1, [(n.title, n.severity) for n in mine]
    assert mine[0].severity == "CRITICAL"
    # The other officers still get the alert's notification.
    alert = db.execute(select(Alert).where(
        Alert.entity_id == response.json()["id"])).scalar_one()
    assert alert.severity == "CRITICAL"
    others = list(db.execute(select(Notification).where(
        Notification.title == alert.title,
        Notification.user_id != users["BIOSAFETY_OFFICER"].id)).scalars())
    assert others


# --------------------------------------------------------------------------- #
# 9. A decision settles the regulators' "awaits a decision" notice
# --------------------------------------------------------------------------- #
def test_a_decision_marks_the_awaiting_notice_read(client, auth, db, users,
                                                   gmo_event):  # noqa: F811
    def unread():
        db.expire_all()
        return [n for n in db.execute(select(Notification).where(
            Notification.user_id == users["REGULATOR"].id,
            Notification.entity_id == gmo_event["id"],
            Notification.read_at.is_(None))).scalars() if "awaits" in n.title]

    assert unread(), "registration tells the regulators"
    response = client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                           headers=auth("REGULATOR"),
                           json={"jurisdiction": "EU", "status": "APPROVED", "reference": "R6"})
    assert response.status_code == 201, response.text
    assert unread() == []


# --------------------------------------------------------------------------- #
# 10. Migration 0013
# --------------------------------------------------------------------------- #
def _runner():
    spec = importlib.util.spec_from_file_location(
        "r6_migrations_run", ROOT / "backend" / "migrations" / "run.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


def test_0013_resolves_incidents_left_empty(tmp_path):
    # A private database: the statements touch every incident, and the shared test database
    # holds other tests' incidents.
    engine = create_engine(f"sqlite:///{tmp_path / 'm13.db'}")
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import Session

    with Session(engine) as session:
        def incident(status="OPEN", category="DEVICE_HEALTH"):
            row = Incident(title="Incident: x", severity="HIGH", status=status, category=category)
            session.add(row)
            session.flush()
            return row

        def alert(incident_row, status, category="DEVICE_HEALTH"):
            row = Alert(category=category, severity="HIGH", title="x", status=status,
                        incident_id=incident_row.id, reasons=[], occurrences=1)
            session.add(row)
            session.flush()
            return row

        emptied = incident()
        alert(emptied, "RESOLVED")
        live = incident()
        alert(live, "RESOLVED")
        alert(live, "OPEN")
        bare = incident()
        theft = incident(category="DATA_THEFT")
        alert(theft, "RESOLVED", category="DATA_THEFT")
        kept = incident()
        alert(kept, "RESOLVED")
        session.add(IncidentEvent(incident_id=kept.id, action="NOTE",
                                  detail="Every linked alert is resolved. The incident stays "
                                         "open until someone who works incidents closes it."))
        session.commit()
        ids = {k: v.id for k, v in {"emptied": emptied, "live": live, "bare": bare,
                                     "theft": theft, "kept": kept}.items()}

    sql = (ROOT / "backend" / "migrations" / "0013_resolve_emptied_incidents.sql").read_text()
    statements = _runner()._statements(sql)
    assert [s.split()[0] for s in statements] == ["INSERT", "UPDATE"]
    for _ in range(2):                                   # re-running changes nothing more
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))

    with Session(engine) as session:
        status = {k: session.get(Incident, v).status for k, v in ids.items()}
        assert status == {"emptied": "RESOLVED", "live": "OPEN", "bare": "OPEN",
                          "theft": "OPEN", "kept": "OPEN"}
        assert session.get(Incident, ids["emptied"]).closed_at is not None
        notes = list(session.execute(select(IncidentEvent).where(
            IncidentEvent.incident_id == ids["emptied"])).scalars())
        assert len(notes) == 1 and notes[0].actor_id is None and notes[0].action == "RESOLVED"
    engine.dispose()


# --------------------------------------------------------------------------- #
# 11. Readable jurisdiction names in alert sources
# --------------------------------------------------------------------------- #
def test_approval_alert_source_names_the_jurisdiction(client, auth, db, orgs,
                                                      gmo_event):  # noqa: F811
    approval = GMOApproval(gmo_event_id=gmo_event["id"], jurisdiction="US-USDA",
                           status="APPROVED")
    db.add(approval)
    db.flush()
    alert = notifications.raise_alert(
        db, "COMPLIANCE", "WARNING", f"R6 approval {unique('J')}", org_id=orgs["BIOTECH"].id,
        entity_type="GMOApproval", entity_id=approval.id, notify=False, open_incident=False)
    db.commit()
    rows = client.get(f"{API}/security/alerts", headers=auth("REGULATOR"),
                      params={"page_size": 200, "entity_id": approval.id}).json()["items"]
    label = next(r for r in rows if r["id"] == alert.id)["source_label"]
    assert label.endswith("in USDA (US)"), label


