"""Round 4: security and custody rules.

1. A custody hand-over only on a `shipping` event, which passes the release gate.
2. Open alerts and active incidents follow a batch to its current custodian.
3. DATA_THEFT and LEDGER alerts are worked by security operations only, resolving an alert
   closes its incident only for someone who may update incidents, and the data-theft sweep and
   per-user scores are for security roles.
4. One notification per person for a recall and for a GMO approval decision.
5. A resolved exfiltration finding is not raised again from the same access records.
6. Migration 0010 gives legacy alerts their kind and resolves the duplicates that leaves.
7. The security dashboard's request count is the caller's organisation's for a tenant.
"""
from __future__ import annotations

import importlib.util
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select, text

from app.core.database import engine
from app.core.security import utcnow
from app.models import AccessRecord, Alert, Batch, Incident, Notification, User
from app.services import notifications, security_ops, supplychain
from .conftest import ROOT, unique
from .test_supplychain_e2e import gmo_event, iso, now  # noqa: F401 (shared fixture)

API = "/api/v1"


def _batch(client, auth, product, role="SUPPLY_CHAIN_OPERATOR") -> dict:
    response = client.post(f"{API}/supply-chain/batches", headers=auth(role), json={
        "batch_code": unique("R4"), "product_id": product.id, "quantity": 100.0, "unit": "kg",
        "origin_region": "Iowa", "origin_country": "US",
        "harvested_at": iso(now() - timedelta(days=2))})
    assert response.status_code == 201, response.text
    return response.json()


def _event(client, headers, batch_id, biz_step, disposition, to_org_id=None, minutes_ago=0):
    payload = {"batch_id": batch_id, "biz_step": biz_step, "disposition": disposition,
               "occurred_at": iso(now() - timedelta(minutes=minutes_ago))}
    if to_org_id:
        payload["to_org_id"] = to_org_id
    return client.post(f"{API}/supply-chain/events", headers=headers, json=payload)


def _custodian(db, batch_id):
    db.expire_all()
    return db.get(Batch, batch_id).custodian_org_id


# --------------------------------------------------------------------------- #
# 1. Release-gate bypass through POST /events
# --------------------------------------------------------------------------- #
class TestHandOverOnlyOnShipping:
    def test_a_failed_batch_cannot_be_handed_over_on_a_storing_event(self, client, auth, db,
                                                                     product, orgs):
        batch = _batch(client, auth, product)
        row = db.get(Batch, batch["id"])
        row.integrity_status = "FAILED"
        db.commit()
        supply = auth("SUPPLY_CHAIN_OPERATOR")

        stored = _event(client, supply, batch["id"], "storing", "in_storage",
                        to_org_id=orgs["FARM"].id)
        assert stored.status_code == 422, stored.text
        assert "shipping" in stored.json()["detail"]
        shipped = _event(client, supply, batch["id"], "shipping", "in_transit",
                         to_org_id=orgs["FARM"].id)
        assert shipped.status_code == 422 and "integrity" in shipped.text
        assert _custodian(db, batch["id"]) == orgs["SUPPLY"].id

    @pytest.mark.parametrize("step,disposition", [("storing", "in_storage"),
                                                  ("harvesting", "in_progress"),
                                                  ("recalling", "recalled")])
    def test_no_other_step_may_carry_a_receiver(self, client, auth, db, product, orgs, step,
                                                disposition):
        batch = _batch(client, auth, product)
        response = _event(client, auth("SUPPLY_CHAIN_OPERATOR"), batch["id"], step,
                          disposition, to_org_id=orgs["FARM"].id)
        assert response.status_code == 422, response.text
        assert _custodian(db, batch["id"]) == orgs["SUPPLY"].id

    def test_naming_the_current_holder_is_not_a_hand_over(self, client, auth, product, orgs):
        batch = _batch(client, auth, product)
        response = _event(client, auth("SUPPLY_CHAIN_OPERATOR"), batch["id"], "harvesting",
                          "in_progress", to_org_id=orgs["SUPPLY"].id)
        assert response.status_code == 201, response.text

    def test_a_releasable_batch_is_handed_over_on_shipping(self, client, auth, db, product,
                                                           orgs):
        batch = _batch(client, auth, product)
        shipped = _event(client, auth("SUPPLY_CHAIN_OPERATOR"), batch["id"], "shipping",
                         "in_transit", to_org_id=orgs["FARM"].id)
        assert shipped.status_code == 201, shipped.text
        assert _custodian(db, batch["id"]) == orgs["FARM"].id


# --------------------------------------------------------------------------- #
# 2. Alerts and incidents follow custody
# --------------------------------------------------------------------------- #
class TestAlertsFollowCustody:
    def _alert_ids(self, client, headers, batch_id):
        response = client.get(f"{API}/security/alerts", params={"entity_id": batch_id},
                              headers=headers)
        assert response.status_code == 200, response.text
        return {a["id"] for a in response.json()["items"]}

    def test_alerts_and_incidents_move_with_each_hand_over(self, client, auth, rival_auth, db,
                                                           product, orgs, second_farm_org):
        batch = _batch(client, auth, product)
        alert = notifications.raise_alert(
            db, "COMPLIANCE", "HIGH", f"Custody probe {unique('CP')}", org_id=orgs["SUPPLY"].id,
            entity_type="Batch", entity_id=batch["id"], notify=False, kind="r4_probe")
        db.commit()
        alert_id, incident_id = alert.id, alert.incident_id
        assert incident_id is not None and alert.custodian_org_id is None

        # Owner -> farm: the farm now sees and can follow both.
        assert _event(client, auth("SUPPLY_CHAIN_OPERATOR"), batch["id"], "shipping",
                      "in_transit", to_org_id=orgs["FARM"].id, minutes_ago=30).status_code == 201
        db.expire_all()
        assert db.get(Alert, alert_id).custodian_org_id == orgs["FARM"].id
        assert db.get(Incident, incident_id).custodian_org_id == orgs["FARM"].id
        assert alert_id in self._alert_ids(client, auth("FARM_OPERATOR"), batch["id"])
        assert client.get(f"{API}/security/incidents/{incident_id}",
                          headers=auth("FARM_OPERATOR")).status_code == 200

        # Farm -> rival farm: the farm, which can no longer open the batch, loses the alert.
        farm = auth("FARM_OPERATOR")
        assert _event(client, farm, batch["id"], "receiving", "in_storage",
                      minutes_ago=20).status_code == 201
        assert _event(client, farm, batch["id"], "shipping", "in_transit",
                      to_org_id=second_farm_org.id, minutes_ago=10).status_code == 201
        assert client.get(f"{API}/supply-chain/batches/{batch['id']}",
                          headers=farm).status_code == 404
        assert alert_id not in self._alert_ids(client, farm, batch["id"])
        assert client.post(f"{API}/security/alerts/{alert_id}/acknowledge",
                           headers=farm).status_code == 404
        assert client.get(f"{API}/security/incidents/{incident_id}",
                          headers=farm).status_code == 404
        assert alert_id in self._alert_ids(client, rival_auth, batch["id"])

        # Rival -> back to the owner: no second party any more.
        assert _event(client, rival_auth, batch["id"], "receiving", "in_storage",
                      minutes_ago=5).status_code == 201
        assert _event(client, rival_auth, batch["id"], "shipping", "in_transit",
                      to_org_id=orgs["SUPPLY"].id).status_code == 201
        db.expire_all()
        assert db.get(Alert, alert_id).custodian_org_id is None
        assert db.get(Incident, incident_id).custodian_org_id is None
        assert alert_id not in self._alert_ids(client, rival_auth, batch["id"])

    def test_a_resolved_alert_keeps_the_custodian_it_was_resolved_under(self, client, auth, db,
                                                                         product, orgs):
        batch = _batch(client, auth, product)
        alert = notifications.raise_alert(
            db, "COMPLIANCE", "WARNING", "Resolved probe", org_id=orgs["SUPPLY"].id,
            entity_type="Batch", entity_id=batch["id"], notify=False, kind="r4_done")
        notifications.resolve(db, alert)
        db.commit()
        assert _event(client, auth("SUPPLY_CHAIN_OPERATOR"), batch["id"], "shipping",
                      "in_transit", to_org_id=orgs["FARM"].id).status_code == 201
        db.expire_all()
        assert db.get(Alert, alert.id).custodian_org_id is None

    def test_a_new_holders_alert_does_not_join_another_holders_incident(self, db, orgs,
                                                                        second_farm_org):
        entity = str(uuid.uuid4())
        first = notifications.raise_alert(
            db, "COMPLIANCE", "HIGH", "Held by the processor", org_id=orgs["FARM"].id,
            entity_type="Batch", entity_id=entity, notify=False, kind="r4_a",
            party_org_id=orgs["SUPPLY"].id)
        second = notifications.raise_alert(
            db, "COMPLIANCE", "HIGH", "Held by the rival", org_id=orgs["FARM"].id,
            entity_type="Batch", entity_id=entity, notify=False, kind="r4_b",
            party_org_id=second_farm_org.id)
        assert first.incident_id and second.incident_id
        assert first.incident_id != second.incident_id
        assert db.get(Incident, second.incident_id).custodian_org_id == second_farm_org.id
        third = notifications.raise_alert(
            db, "COMPLIANCE", "HIGH", "Still with the processor", org_id=orgs["FARM"].id,
            entity_type="Batch", entity_id=entity, notify=False, kind="r4_c",
            party_org_id=orgs["SUPPLY"].id)
        assert third.incident_id == first.incident_id, "same custodian joins the same incident"
        db.rollback()


# --------------------------------------------------------------------------- #
# 3. No self-clearing
# --------------------------------------------------------------------------- #
class TestOversightAlerts:
    @pytest.fixture
    def theft_alert(self, db, users):
        """An exfiltration finding filed under the supply-chain operator's own organisation.

        A fresh entity id per test, so each alert opens its own incident (the incident one
        test leaves open would otherwise absorb the next test's alert)."""
        target = users["SUPPLY_CHAIN_OPERATOR"]
        alert = notifications.raise_alert(
            db, "DATA_THEFT", "HIGH", f"Possible data exfiltration by {target.full_name}",
            org_id=target.org_id, entity_type="User", entity_id=str(uuid.uuid4()),
            notify=False, kind="exfiltration")
        db.commit()
        return alert

    def test_the_suspect_can_neither_see_nor_clear_it(self, client, auth, db, theft_alert):
        # Round 5: the suspect no longer even sees the alert (it was readable in round 4), so
        # acknowledging or resolving it is a 404 rather than a 403.
        supply = auth("SUPPLY_CHAIN_OPERATOR")
        listed = client.get(f"{API}/security/alerts", params={"entity_id": theft_alert.entity_id,
                                                              "category": "DATA_THEFT"},
                            headers=supply)
        assert theft_alert.id not in {a["id"] for a in listed.json()["items"]}
        for action in ("acknowledge", "resolve"):
            response = client.post(f"{API}/security/alerts/{theft_alert.id}/{action}",
                                   headers=supply)
            assert response.status_code == 404, response.text
        db.expire_all()
        assert db.get(Alert, theft_alert.id).status == "OPEN"
        assert db.get(Incident, theft_alert.incident_id).status == "OPEN"

    def test_a_farm_operator_cannot_clear_a_ledger_alert(self, client, auth, db, orgs):
        alert = notifications.raise_alert(
            db, "LEDGER", "WARNING", "Ledger probe", org_id=orgs["FARM"].id, notify=False,
            open_incident=False)
        db.commit()
        response = client.post(f"{API}/security/alerts/{alert.id}/resolve",
                               headers=auth("FARM_OPERATOR"))
        # Hidden from the tenant since round 5 (404); refused outright in round 4 (403).
        assert response.status_code == 404, response.text

    @pytest.mark.parametrize("role", ["SECURITY_ANALYST", "ADMIN"])
    def test_security_operations_resolve_it_and_the_incident_follows(self, client, auth, db,
                                                                     theft_alert, role):
        response = client.post(f"{API}/security/alerts/{theft_alert.id}/resolve",
                               headers=auth(role))
        assert response.status_code == 200, response.text
        db.expire_all()
        assert db.get(Incident, theft_alert.incident_id).status == "RESOLVED"

    def test_resolving_an_alert_does_not_close_the_incident_without_incident_write(
            self, client, auth, db, product, orgs):
        batch = _batch(client, auth, product)
        alert = notifications.raise_alert(
            db, "COMPLIANCE", "HIGH", "Tenant resolvable probe", org_id=orgs["SUPPLY"].id,
            entity_type="Batch", entity_id=batch["id"], notify=False, kind="r4_tenant")
        db.commit()
        response = client.post(f"{API}/security/alerts/{alert.id}/resolve",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"))
        assert response.status_code == 200, response.text
        db.expire_all()
        incident = db.get(Incident, alert.incident_id)
        assert incident.status == "OPEN", "a tenant's alert resolve closed the incident"
        detail = client.get(f"{API}/security/incidents/{incident.id}",
                            headers=auth("SECURITY_ANALYST")).json()
        assert any(e["action"] == "ALERT_RESOLVED" for e in detail["timeline"])

    @pytest.mark.parametrize("role", ["SUPPLY_CHAIN_OPERATOR", "FARM_OPERATOR",
                                      "BIOSAFETY_OFFICER", "REGULATOR"])
    def test_tenants_and_other_oversight_roles_cannot_sweep_or_score(self, client, auth,
                                                                     users, role):
        assert client.post(f"{API}/security/data-theft/sweep",
                           headers=auth(role)).status_code == 403
        colleague = users["FARM_OPERATOR"].id
        assert client.get(f"{API}/security/data-theft/evaluate",
                          params={"principal_id": colleague},
                          headers=auth(role)).status_code == 403

    def test_the_analyst_may_score_anyone(self, client, auth, users):
        response = client.get(f"{API}/security/data-theft/evaluate",
                              params={"principal_id": users["FARM_OPERATOR"].id},
                              headers=auth("SECURITY_ANALYST"))
        assert response.status_code == 200, response.text
        assert response.json()["principal_id"] == users["FARM_OPERATOR"].id


# --------------------------------------------------------------------------- #
# 4. One notification per person
# --------------------------------------------------------------------------- #
def _user_notes(db, user, entity_id=None, title=None):
    db.expire_all()
    query = select(Notification).where(Notification.user_id == user.id)
    if entity_id:
        query = query.where(Notification.entity_id == entity_id)
    if title:
        query = query.where(Notification.title.contains(title))
    return list(db.execute(query).scalars())


class TestNoDuplicateNotifications:
    def test_a_recall_reaches_a_party_operator_once(self, client, auth, db, users, product):
        batch = _batch(client, auth, product)
        recalled = _event(client, auth("SUPPLY_CHAIN_OPERATOR"), batch["id"], "recalling",
                          "recalled")
        assert recalled.status_code == 201, recalled.text
        title = f"Batch {batch['batch_code']} has been recalled"
        mine = _user_notes(db, users["SUPPLY_CHAIN_OPERATOR"], batch["id"], title)
        assert [n.category for n in mine] == ["RECALL"], [n.category for n in mine]
        # A regulator outside the batch's organisations still hears of it, once.
        regulator = _user_notes(db, users["REGULATOR"], batch["id"], title)
        assert len(regulator) == 1 and regulator[0].category == "COMPLIANCE"
        # The alert itself is still raised.
        assert notifications.has_open_alert(db, "COMPLIANCE", batch["id"], kind="recall")

    def test_the_developer_hears_of_one_decision_once(self, client, auth, db, users,
                                                      gmo_event):
        approve = client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                              headers=auth("REGULATOR"),
                              json={"jurisdiction": "US-USDA", "status": "APPROVED"})
        assert approve.status_code in (200, 201), approve.text
        lot = client.post(f"{API}/gmo/seed-lots", headers=auth("BIOTECH_RESEARCHER"), json={
            "lot_code": unique("SL4"), "gmo_event_id": gmo_event["id"], "crop_type": "Maize",
            "variety": "V1", "quantity_kg": 10.0, "produced_at": iso(now())})
        assert lot.status_code == 201, lot.text
        developer = users["BIOTECH_RESEARCHER"]
        before = len(_user_notes(db, developer, gmo_event["id"]))

        withdrawn = client.post(f"{API}/gmo/events/{gmo_event['id']}/approvals",
                                headers=auth("REGULATOR"),
                                json={"jurisdiction": "US-USDA", "status": "REJECTED"})
        assert withdrawn.status_code in (200, 201), withdrawn.text
        new = _user_notes(db, developer, gmo_event["id"])[before:]
        assert len(new) == 1, [n.title for n in new]
        assert "withdrawn" in new[0].title and "decision: rejected" in new[0].title
        assert lot.json()["lot_code"] in new[0].body, "the developer's own holdings are named"
        assert not _user_notes(db, developer, lot.json()["id"], "withdrawn")


# --------------------------------------------------------------------------- #
# 5. A resolved exfiltration finding stays resolved
# --------------------------------------------------------------------------- #
def _flagging_records(db, principal_id, org_id, start):
    for index in range(25):
        db.add(AccessRecord(principal_id=principal_id, org_id=org_id,
                            route="/api/v1/supply-chain/batches", method="GET", page_size=200,
                            result_count=200, status_code=200, hour=12,
                            cross_tenant_attempt=True,
                            created_at=start - timedelta(seconds=10 * index)))
    db.commit()


def test_a_resolved_finding_is_not_raised_again_from_the_same_records(db, orgs):
    principal = str(uuid.uuid4())
    _flagging_records(db, principal, orgs["FARM"].id, utcnow() - timedelta(minutes=30))

    def exfiltration_alerts():
        db.expire_all()
        return list(db.execute(select(Alert).where(
            Alert.entity_id == principal, Alert.kind == security_ops.EXFILTRATION_KIND)
            .order_by(Alert.created_at)).scalars())

    security_ops.sweep_data_theft(db, 24, org_id=orgs["FARM"].id)
    db.commit()
    assert len(exfiltration_alerts()) == 1
    notifications.resolve(db, exfiltration_alerts()[0])
    db.commit()

    security_ops.sweep_data_theft(db, 24, org_id=orgs["FARM"].id)
    db.commit()
    assert len(exfiltration_alerts()) == 1, "re-raised from records already reviewed"

    # New probing after the resolution is a new finding.
    _flagging_records(db, principal, orgs["FARM"].id, utcnow() + timedelta(minutes=5))
    security_ops.sweep_data_theft(db, 24, org_id=orgs["FARM"].id)
    db.commit()
    alerts = exfiltration_alerts()
    assert len(alerts) == 2 and alerts[-1].status == "OPEN"


# --------------------------------------------------------------------------- #
# 6. Migration 0010
# --------------------------------------------------------------------------- #
def test_0010_backfills_kinds_and_resolves_legacy_duplicates(client, auth, db, orgs, product):
    batch = _batch(client, auth, product)
    code = batch["batch_code"]
    report = client.post(f"{API}/compliance/evaluate", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                         json={"subject_id": batch["id"], "jurisdiction": "EU"})
    assert report.status_code in (200, 201), report.text
    principal = str(uuid.uuid4())
    legacy = {
        "lockout": ("DATA_THEFT", "User", principal, "Account locked after 5 failed logins"),
        "exfil": ("DATA_THEFT", "User", principal, "Possible data exfiltration by Tom"),
        "fraud": ("FRAUD", "Batch", batch["id"],
                  f"Supply-chain integrity check flagged batch {code}"),
        "compliance": ("COMPLIANCE", "Batch", batch["id"], f"Batch {code} is non-compliant in EU"),
        "labelling": ("COMPLIANCE", "Batch", batch["id"],
                      f"Labelling non-compliance on batch {code} in JP"),
        "unknown": ("COMPLIANCE", "Batch", batch["id"], "Something nobody can classify"),
    }
    ids = {}
    with engine.begin() as connection:
        for key, (category, entity_type, entity_id, title) in legacy.items():
            ids[key] = str(uuid.uuid4())
            connection.execute(text(
                "INSERT INTO alerts (id, category, severity, title, detail, entity_type, "
                "entity_id, reasons, status, org_id, occurrences, created_at) VALUES "
                "(:id, :category, 'HIGH', :title, '', :entity_type, :entity_id, '[]', 'OPEN', "
                ":org, 1, :created)"),
                {"id": ids[key], "category": category, "title": title,
                 "entity_type": entity_type, "entity_id": entity_id, "org": orgs["SUPPLY"].id,
                 "created": (utcnow() - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S.%f")})
    # A newer, kind-ed alert duplicating the legacy fraud alert, as the code raises today.
    newer = notifications.raise_alert(
        db, "FRAUD", "HIGH", f"Supply-chain integrity check flagged batch {code}",
        org_id=orgs["SUPPLY"].id, entity_type="Batch", entity_id=batch["id"], notify=False,
        open_incident=False, kind="fraud")
    db.commit()

    spec = importlib.util.spec_from_file_location(
        "r4_migrations_run", ROOT / "backend" / "migrations" / "run.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    sql = (ROOT / "backend" / "migrations" / "0010_alert_kind_backfill.sql").read_text()
    statements = runner._statements(sql)
    assert all(s.split()[0] == "UPDATE" for s in statements), statements
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))

    db.expire_all()
    kinds = {key: db.get(Alert, alert_id).kind for key, alert_id in ids.items()}
    assert kinds == {"lockout": "account_lockout", "exfil": "exfiltration", "fraud": "fraud",
                     "compliance": "compliance:EU", "labelling": "labelling:JP",
                     "unknown": None}
    assert db.get(Alert, ids["fraud"]).status == "RESOLVED", "legacy duplicate left open"
    assert db.get(Alert, newer.id).status == "OPEN", "the current alert must stay open"
    assert db.get(Alert, ids["lockout"]).status == "OPEN"


# --------------------------------------------------------------------------- #
# 7. Dashboard request count
# --------------------------------------------------------------------------- #
def test_a_tenant_dashboard_counts_its_own_requests(client, auth, db, orgs, second_farm_org):
    _flagging_records(db, str(uuid.uuid4()), second_farm_org.id, utcnow())
    farm = client.get(f"{API}/security/dashboard", headers=auth("FARM_OPERATOR"))
    analyst = client.get(f"{API}/security/dashboard", headers=auth("SECURITY_ANALYST"))
    assert farm.status_code == 200 and analyst.status_code == 200
    since = utcnow() - timedelta(hours=24)
    own = db.execute(select(func.count()).select_from(AccessRecord).where(
        AccessRecord.org_id == orgs["FARM"].id, AccessRecord.created_at >= since)).scalar_one()
    # The request itself may be recorded after the count is taken.
    assert own - 2 <= farm.json()["access_records_24h"] <= own
    assert analyst.json()["access_records_24h"] > farm.json()["access_records_24h"]
