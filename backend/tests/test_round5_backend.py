"""Round 5 (backend): security-oversight alerts hidden from tenants, custody sync and automatic
resolution leave them alone, migration 0011's legacy kinds, certificate read access that
expires and stops at the certified organisation, backdated events, hand-over notifications
settled by a booking, the migration runner, dashboard and shipment-filter counts, and readable
jurisdiction names.
"""
from __future__ import annotations

import importlib.util
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, text

from app.core.database import engine
from app.core.security import utcnow
from app.models import (Alert, Batch, Certification, Device, DeviceVulnerability, Incident,
                        Notification, User)
from app.services import notifications, security_ops
from .conftest import ROOT, unique
from .test_round3_supply import _arrive, _claim, _issue
from .test_shipments_recall import _ship, chilled_product, farm_batch  # noqa: F401
from .test_supplychain_e2e import iso, now

API = "/api/v1"


def _theft(db, user, **extra) -> Alert:
    """An exfiltration finding about `user`, filed under the user's own organisation."""
    alert = notifications.raise_alert(
        db, "DATA_THEFT", "HIGH", f"Possible data exfiltration by {user.full_name}",
        org_id=user.org_id, entity_type="User", entity_id=str(uuid.uuid4()), notify=False,
        kind="exfiltration", **extra)
    db.commit()
    return alert


def _ids(response) -> set[str]:
    assert response.status_code == 200, response.text
    return {row["id"] for row in response.json()["items"]}


def _runner(name: str):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "backend" / "migrations" / "run.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


# --------------------------------------------------------------------------- #
# 1. Oversight alerts and their incidents are hidden from tenant roles
# --------------------------------------------------------------------------- #
class TestOversightHiddenFromTenants:
    def test_the_suspect_cannot_read_the_alert_its_incident_or_the_notes(self, client, auth,
                                                                         db, users):
        alert = _theft(db, users["SUPPLY_CHAIN_OPERATOR"])
        analyst = auth("SECURITY_ANALYST")
        noted = client.patch(f"{API}/security/incidents/{alert.incident_id}", headers=analyst,
                             json={"note": "monitoring this user, do not tip off"})
        assert noted.status_code == 200, noted.text

        supply = auth("SUPPLY_CHAIN_OPERATOR")
        assert alert.id not in _ids(client.get(f"{API}/security/alerts?page_size=200",
                                               headers=supply))
        assert alert.incident_id not in _ids(client.get(
            f"{API}/security/incidents?page_size=200", headers=supply))
        detail = client.get(f"{API}/security/incidents/{alert.incident_id}", headers=supply)
        assert detail.status_code == 404
        assert "tip off" not in detail.text
        # A colleague with a different role in the same organisation, and an operator
        # elsewhere, see nothing either.
        assert client.get(f"{API}/security/incidents/{alert.incident_id}",
                          headers=auth("FARM_OPERATOR")).status_code == 404

        # Security operations are unchanged.
        for role in ("SECURITY_ANALYST", "ADMIN"):
            headers = auth(role)
            assert alert.id in _ids(client.get(
                f"{API}/security/alerts?category=DATA_THEFT&page_size=200", headers=headers))
            shown = client.get(f"{API}/security/incidents/{alert.incident_id}", headers=headers)
            assert shown.status_code == 200 and "tip off" in shown.text

    def test_an_incident_opened_from_an_oversight_alert_is_hidden_whatever_its_category(
            self, client, auth, db, users, orgs):
        alert = _theft(db, users["FARM_OPERATOR"])
        incident = db.get(Incident, alert.incident_id)
        incident.category = None                 # e.g. an incident from before 0007
        db.commit()
        assert client.get(f"{API}/security/incidents/{incident.id}",
                          headers=auth("FARM_OPERATOR")).status_code == 404
        # And one an oversight alert merely joined.
        other = Incident(title="Shared incident", severity="HIGH", org_id=orgs["FARM"].id,
                         category="DEVICE_ANOMALY")
        db.add(other)
        db.flush()
        alert.incident_id = other.id
        db.commit()
        assert client.get(f"{API}/security/incidents/{other.id}",
                          headers=auth("FARM_OPERATOR")).status_code == 404
        assert client.get(f"{API}/security/incidents/{other.id}",
                          headers=auth("SECURITY_ANALYST")).status_code == 200

    def test_dashboards_do_not_count_them_for_tenants(self, client, auth, db, users, orgs):
        def counts(role):
            tiles = client.get(f"{API}/dashboard", headers=auth(role)).json()["alerts"]
            board = client.get(f"{API}/security/dashboard", headers=auth(role)).json()
            return tiles["open"], board["alerts_open"], board["incidents_total"]

        supply_before, analyst_before = counts("SUPPLY_CHAIN_OPERATOR"), counts("SECURITY_ANALYST")
        _theft(db, users["SUPPLY_CHAIN_OPERATOR"])
        notifications.raise_alert(db, "LEDGER", "HIGH", "Ledger rejected a replay",
                                  org_id=orgs["SUPPLY"].id, notify=False, open_incident=False)
        db.commit()
        assert counts("SUPPLY_CHAIN_OPERATOR") == supply_before
        after = counts("SECURITY_ANALYST")
        assert after[0] == analyst_before[0] + 2 and after[1] == analyst_before[1] + 2
        assert after[2] == analyst_before[2] + 1
        board = security_ops.security_dashboard(db, orgs["SUPPLY"].id,
                                                role="SUPPLY_CHAIN_OPERATOR")
        assert "DATA_THEFT" not in board["open_by_category"]
        assert "LEDGER" not in board["open_by_category"]

    def test_notifications_reach_security_operations_only(self, db, users, orgs):
        start = utcnow() - timedelta(seconds=1)
        title = unique("Possible data exfiltration by probe")
        notifications.fan_out(db, "DATA_THEFT", "HIGH", title, "", orgs["SUPPLY"].id,
                              "User", users["SUPPLY_CHAIN_OPERATOR"].id)
        notifications.notify_parties(db, [orgs["SUPPLY"].id], "LEDGER", title, "", "Batch",
                                     None, include_oversight=False)
        db.commit()
        roles = {db.get(User, n.user_id).role for n in db.execute(select(Notification).where(
            Notification.title == title, Notification.created_at >= start)).scalars()}
        assert roles and roles <= {"SECURITY_ANALYST", "ADMIN"}, roles


# --------------------------------------------------------------------------- #
# 2. A hand-over does not move oversight alerts
# --------------------------------------------------------------------------- #
def test_sync_custodian_leaves_ledger_alerts_where_they_are(client, auth, db, orgs, farm_batch):
    ledger = notifications.raise_alert(
        db, "LEDGER", "HIGH", "Ledger rejected the replayed provenance.RecordEvent",
        org_id=orgs["FARM"].id, entity_type="Batch", entity_id=farm_batch["id"], notify=False,
        kind="ledger_replay_rejected", open_incident=True)
    business = notifications.raise_alert(
        db, "COMPLIANCE", "HIGH", "Probe compliance", org_id=orgs["FARM"].id,
        entity_type="Batch", entity_id=farm_batch["id"], notify=False, kind="r5_probe",
        open_incident=False)
    db.commit()
    assert _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).status_code == 201
    db.expire_all()
    assert db.get(Alert, business.id).custodian_org_id == orgs["SUPPLY"].id
    assert db.get(Alert, ledger.id).custodian_org_id is None
    assert db.get(Incident, ledger.incident_id).custodian_org_id is None


# --------------------------------------------------------------------------- #
# 3. Migration 0011
# --------------------------------------------------------------------------- #
def test_0011_backfills_legacy_titles_and_resolves_duplicates(client, auth, db, orgs, farm,
                                                              farm_batch):
    device = Device(org_id=orgs["FARM"].id, farm_id=farm.id, device_type="SOIL_SENSOR",
                    model="Legacy", firmware_version="1.0", status="ACTIVE",
                    interval_seconds=300, secret_enc="x", deleted_at=utcnow())
    db.add(device)
    db.flush()
    db.add(DeviceVulnerability(device_id=device.id, org_id=orgs["FARM"].id,
                               cve_id="CVE-2026-1234", title="Probe", severity="HIGH"))
    db.commit()
    code, short = farm_batch["batch_code"], device.id[:8]
    field_id = str(uuid.uuid4())
    principal = str(uuid.uuid4())
    legacy = {
        "exfil": ("DATA_THEFT", "User", principal,
                  f"Possible agricultural data exfiltration by principal {principal[:8]}", ""),
        "label_usda": ("COMPLIANCE", "Batch", farm_batch["id"],
                       f"Labelling non-compliance on batch {code}",
                       "Release into us-usda blocked: GMO event X is not approved"),
        "label_unknown": ("COMPLIANCE", "Batch", farm_batch["id"],
                          f"Labelling non-compliance on batch {code}", "Release into JP blocked"),
        "quarantined": ("DEVICE_AUTH", "Device", device.id, f"Device {short} quarantined", ""),
        "auth": ("DEVICE_AUTH", "Device", device.id,
                 f"Repeated authentication failures from device {short}", ""),
        "battery": ("DEVICE_HEALTH", "Device", device.id, f"Low battery on device {short}", ""),
        "silent": ("DEVICE_HEALTH", "Device", device.id, f"Device {short} has stopped reporting",
                   ""),
        "vuln_old": ("DEVICE_HEALTH", "Device", device.id,
                     f"HIGH vulnerability CVE-2026-1234 on device {short}", ""),
        "anomaly": ("DEVICE_ANOMALY", "Device", device.id,
                    f"Anomalous telemetry from SOIL_SENSOR {short}", ""),
        "ndvi": ("AGRONOMY", "Field", field_id, "Low vegetation index on field North", ""),
    }
    ids = {}
    created = (utcnow() - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S.%f")
    with engine.begin() as connection:
        for key, (category, entity_type, entity_id, title, detail) in legacy.items():
            ids[key] = str(uuid.uuid4())
            connection.execute(text(
                "INSERT INTO alerts (id, category, severity, title, detail, entity_type, "
                "entity_id, reasons, status, org_id, occurrences, created_at) VALUES "
                "(:id, :category, 'WARNING', :title, :detail, :entity_type, :entity_id, '[]', "
                "'OPEN', :org, 1, :created)"),
                {"id": ids[key], "category": category, "title": title, "detail": detail,
                 "entity_type": entity_type, "entity_id": entity_id, "org": orgs["FARM"].id,
                 "created": created})
    # Current, kind-ed alerts duplicating two of the legacy ones.
    newer_battery = notifications.raise_alert(
        db, "DEVICE_HEALTH", "WARNING", "Low battery on Legacy", org_id=orgs["FARM"].id,
        entity_type="Device", entity_id=device.id, notify=False, open_incident=False,
        kind="low_battery")
    newer_ndvi = notifications.raise_alert(
        db, "AGRONOMY", "WARNING", "Low vegetation index on field North",
        org_id=orgs["FARM"].id, entity_type="Field", entity_id=field_id, notify=False,
        open_incident=False, kind="low_ndvi")
    db.commit()

    runner = _runner("r5_migrations_run")
    sql = (ROOT / "backend" / "migrations" / "0011_alert_kind_backfill_legacy.sql").read_text()
    statements = runner._statements(sql)
    assert all(s.split()[0] == "UPDATE" for s in statements), statements
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))

    db.expire_all()
    kinds = {key: db.get(Alert, alert_id).kind for key, alert_id in ids.items()}
    assert kinds == {"exfil": "exfiltration", "label_usda": "labelling:US-USDA",
                     "label_unknown": None, "quarantined": "quarantined",
                     "auth": "auth_failures", "battery": "low_battery", "silent": "silent",
                     "vuln_old": "vulnerability:CVE-2026-1234", "anomaly": "anomaly",
                     "ndvi": "low_ndvi"}
    # The kinds are the ones the raise sites fold into, so dedupe now finds them.
    assert notifications.find_open_alert(db, "DEVICE_HEALTH", device.id, "silent").id == \
        ids["silent"]
    assert db.get(Alert, ids["battery"]).status == "RESOLVED", "legacy duplicate left open"
    assert db.get(Alert, ids["ndvi"]).status == "RESOLVED"
    assert db.get(Alert, newer_battery.id).status == "OPEN"
    assert db.get(Alert, newer_ndvi.id).status == "OPEN"
    assert db.get(Alert, ids["anomaly"]).status == "OPEN"
    # Idempotent: a second run changes nothing.
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
    db.expire_all()
    assert {key: db.get(Alert, alert_id).kind for key, alert_id in ids.items()} == kinds


# --------------------------------------------------------------------------- #
# 4. Certificate-based read access
# --------------------------------------------------------------------------- #
class TestCertificateReadAccess:
    def _batch_status(self, client, auth, batch_id):
        return client.get(f"{API}/supply-chain/batches/{batch_id}",
                          headers=auth("CERTIFIER")).status_code

    def test_a_revoked_certificate_no_longer_opens_the_batch(self, client, auth, orgs,
                                                             farm_batch):
        cert = _issue(client, auth, orgs["FARM"].id)
        _claim(client, auth, cert, farm_batch["id"])
        assert self._batch_status(client, auth, farm_batch["id"]) == 200
        revoked = client.post(f"{API}/supply-chain/certifications/{cert['id']}/revoke",
                              headers=auth("CERTIFIER"), json={"reason": "Audit failed badly"})
        assert revoked.status_code == 200, revoked.text
        assert self._batch_status(client, auth, farm_batch["id"]) == 404
        assert client.get(f"{API}/supply-chain/shipments?batch_id={farm_batch['id']}",
                          headers=auth("CERTIFIER")).json()["items"] == []

    def test_an_expired_certificate_no_longer_opens_the_batch(self, client, auth, db, orgs,
                                                             farm_batch):
        cert = _issue(client, auth, orgs["FARM"].id)
        _claim(client, auth, cert, farm_batch["id"])
        assert self._batch_status(client, auth, farm_batch["id"]) == 200
        row = db.get(Certification, cert["id"])
        row.valid_to = utcnow() - timedelta(minutes=1)          # status still ACTIVE
        db.commit()
        assert self._batch_status(client, auth, farm_batch["id"]) == 404

    def test_the_certifier_sees_only_shipments_of_the_certified_organisation(
            self, client, auth, orgs, farm_batch, second_farm_org):
        cert = _issue(client, auth, orgs["FARM"].id)
        _claim(client, auth, cert, farm_batch["id"])
        first = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        _arrive(client, auth, first["id"])
        onward = _ship(client, auth, farm_batch["id"], role="SUPPLY_CHAIN_OPERATOR",
                       to_org_id=second_farm_org.id, departed_at=iso(now())).json()
        listed = _ids(client.get(f"{API}/supply-chain/shipments?batch_id={farm_batch['id']}",
                                 headers=auth("CERTIFIER")))
        assert first["id"] in listed
        assert onward["id"] not in listed, "a holder-to-holder shipment leaked to the certifier"
        # The owner, a party to the batch, still sees both.
        owner = _ids(client.get(f"{API}/supply-chain/shipments?batch_id={farm_batch['id']}",
                                headers=auth("FARM_OPERATOR")))
        assert {first["id"], onward["id"]} <= owner


# --------------------------------------------------------------------------- #
# 5. An incident left open is flagged for review, and automatic resolution respects oversight
# --------------------------------------------------------------------------- #
class TestIncidentLeftOpen:
    def test_a_tenant_resolve_tells_the_analysts(self, client, auth, db, users, orgs,
                                                 farm_batch):
        alert = notifications.raise_alert(
            db, "COMPLIANCE", "HIGH", "Tenant resolvable r5", org_id=orgs["FARM"].id,
            entity_type="Batch", entity_id=farm_batch["id"], notify=False, kind="r5_tenant")
        db.commit()
        response = client.post(f"{API}/security/alerts/{alert.id}/resolve",
                               headers=auth("FARM_OPERATOR"))
        assert response.status_code == 200, response.text
        db.expire_all()
        assert db.get(Incident, alert.incident_id).status == "OPEN"
        notes = list(db.execute(select(Notification).where(
            Notification.user_id == users["SECURITY_ANALYST"].id,
            Notification.entity_type == "Incident",
            Notification.entity_id == alert.incident_id)).scalars())
        assert len(notes) == 1 and notes[0].title.startswith("Incident needs review: ")
        assert not db.execute(select(Notification).where(
            Notification.user_id == users["FARM_OPERATOR"].id,
            Notification.entity_id == alert.incident_id)).first()

    def test_automatic_resolution_does_not_close_an_oversight_incident(self, db, users, orgs):
        entity = str(uuid.uuid4())
        alert = notifications.raise_alert(
            db, "LEDGER", "HIGH", "Ledger rejected r5", org_id=orgs["FARM"].id,
            entity_type="Batch", entity_id=entity, notify=False, kind="r5_ledger",
            open_incident=True)
        db.commit()
        notifications.resolve_alerts(db, "LEDGER", entity, kind="r5_ledger",
                                     note="A later check passed")
        db.commit()
        db.expire_all()
        assert db.get(Alert, alert.id).status == "RESOLVED"
        assert db.get(Incident, alert.incident_id).status == "OPEN"
        assert db.execute(select(Notification).where(
            Notification.user_id == users["SECURITY_ANALYST"].id,
            Notification.entity_id == alert.incident_id)).first() is not None

    def test_resolving_a_records_alerts_leaves_oversight_alerts_open(self, db, orgs):
        entity = str(uuid.uuid4())
        ledger = notifications.raise_alert(
            db, "LEDGER", "HIGH", "Ledger rejected r5 cert", org_id=orgs["FARM"].id,
            entity_type="Certification", entity_id=entity, notify=False, open_incident=False)
        business = notifications.raise_alert(
            db, "CERTIFICATION", "WARNING", "Certificate expiring r5", org_id=orgs["FARM"].id,
            entity_type="Certification", entity_id=entity, notify=False, open_incident=False)
        notifications.resolve_entity_alerts(db, "Certification", entity, None, "Renewed")
        db.commit()
        db.expire_all()
        assert db.get(Alert, business.id).status == "RESOLVED"
        assert db.get(Alert, ledger.id).status == "OPEN"


# --------------------------------------------------------------------------- #
# 6-7. Backdated events, and the hand-over notification settled by a booking
# --------------------------------------------------------------------------- #
def _event(client, auth, role, batch_id, step, disposition, occurred_at, **extra):
    return client.post(f"{API}/supply-chain/events", headers=auth(role), json={
        "batch_id": batch_id, "biz_step": step, "disposition": disposition,
        "occurred_at": iso(occurred_at), **extra})


def test_an_event_dated_before_the_latest_handover_is_refused(client, auth, db, orgs,
                                                              farm_batch):
    handed = now() - timedelta(hours=1)
    shipped = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "shipping", "in_transit",
                     handed, to_org_id=orgs["SUPPLY"].id)
    assert shipped.status_code == 201, shipped.text
    backdated = _event(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"], "storing",
                       "in_storage", handed - timedelta(days=1))
    assert backdated.status_code == 422, backdated.text
    assert "last recorded step" in backdated.text   # round 6: in words, any prior step
    booked = _event(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"], "storing",
                    "in_storage", handed + timedelta(minutes=5))
    assert booked.status_code == 201, booked.text
    pending = _ids(client.get(f"{API}/supply-chain/batches?awaiting_receipt=true&page_size=200",
                              headers=auth("SUPPLY_CHAIN_OPERATOR")))
    assert farm_batch["id"] not in pending


def test_a_booking_settles_a_bare_shipping_handover_notification(client, auth, db, users,
                                                                 orgs, farm_batch):
    shipped = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "shipping", "in_transit",
                     now() - timedelta(minutes=30), to_org_id=orgs["SUPPLY"].id)
    assert shipped.status_code == 201, shipped.text

    def unread():
        db.expire_all()
        return list(db.execute(select(Notification).where(
            Notification.user_id == users["SUPPLY_CHAIN_OPERATOR"].id,
            Notification.category == "HANDOVER", Notification.entity_id == farm_batch["id"],
            Notification.read_at.is_(None))).scalars())

    assert len(unread()) == 1
    booked = _event(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"], "receiving",
                    "in_storage", now())
    assert booked.status_code == 201, booked.text
    assert unread() == []


# --------------------------------------------------------------------------- #
# 8. The migration runner skips one duplicate-column statement, not the rest of the file
# --------------------------------------------------------------------------- #
def test_the_runner_continues_after_a_duplicate_column(tmp_path, monkeypatch):
    version = f"9999_r5_probe_{uuid.uuid4().hex[:8]}"
    table = f"r5_probe_{uuid.uuid4().hex[:8]}"
    path = tmp_path / f"{version}.sql"
    path.write_text(
        "-- probe\n"
        "ALTER TABLE alerts ADD COLUMN kind VARCHAR(80);\n"
        f"CREATE TABLE {table} (id INTEGER);\n"
        f"INSERT INTO {table} (id) VALUES (1);\n")
    runner = _runner("r5_runner_probe")
    monkeypatch.setattr(runner, "_discover", lambda: [(version, path)])
    try:
        assert runner.run() == 0
        with engine.connect() as connection:
            assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 1
            assert connection.execute(text(
                "SELECT count(*) FROM schema_version WHERE version = :v"),
                {"v": version}).scalar_one() == 1
    finally:
        with engine.begin() as connection:
            connection.execute(text(f"DROP TABLE IF EXISTS {table}"))
            connection.execute(text("DELETE FROM schema_version WHERE version = :v"),
                               {"v": version})


# --------------------------------------------------------------------------- #
# 9. Dashboard "held" and the incoming=false filter
# --------------------------------------------------------------------------- #
def test_a_batch_on_the_road_is_not_counted_as_held(client, auth, orgs, farm_batch):
    def tiles():
        return client.get(f"{API}/dashboard",
                          headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["supply_chain"]

    before = tiles()
    shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
    on_road = tiles()
    assert on_road["held"] == before["held"]
    assert on_road["awaiting_arrival"] == before["awaiting_arrival"] + 1
    _arrive(client, auth, shipment["id"])
    assert tiles()["held"] == before["held"] + 1


def test_outgoing_filter_keeps_another_senders_internal_move(client, auth, orgs, farm_batch):
    internal = _ship(client, auth, farm_batch["id"],
                     departed_at=iso(now() - timedelta(hours=5)),
                     arrived_at=iso(now() - timedelta(hours=4)))
    assert internal.status_code == 201, internal.text
    assert internal.json()["to_org_id"] is None
    handover = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
    _arrive(client, auth, handover["id"])
    query = f"{API}/supply-chain/shipments?batch_id={farm_batch['id']}&page_size=200"
    supply = auth("SUPPLY_CHAIN_OPERATOR")
    outgoing = _ids(client.get(f"{query}&incoming=false", headers=supply))
    incoming = _ids(client.get(f"{query}&incoming=true", headers=supply))
    assert internal.json()["id"] in outgoing, "the NULL to_org_id row was dropped"
    assert handover["id"] in incoming and handover["id"] not in outgoing
    assert internal.json()["id"] not in incoming
    # The sender's own internal move is incoming for it (it marks it arrived), not outgoing.
    farm = auth("FARM_OPERATOR")
    assert internal.json()["id"] in _ids(client.get(f"{query}&incoming=true", headers=farm))
    assert internal.json()["id"] not in _ids(client.get(f"{query}&incoming=false",
                                                        headers=farm))


# --------------------------------------------------------------------------- #
# 10. Readable jurisdiction names
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("code, label", [("US-USDA", "USDA (US)"), ("US-FDA", "FDA (US)"),
                                         ("EU", "EU"), ("CODEX", "Codex Alimentarius"),
                                         ("GS1", "GS1 data standard"), ("JP", "JP")])
def test_jurisdiction_label(code, label):
    assert notifications.jurisdiction_label(code) == label


def test_compliance_texts_name_the_jurisdiction_for_people(client, auth, db, orgs, farm_batch):
    report = client.post(f"{API}/compliance/evaluate", headers=auth("REGULATOR"),
                         json={"subject_id": farm_batch["id"], "jurisdiction": "US-USDA"})
    assert report.status_code in (200, 201), report.text
    db.expire_all()
    titles = [n.title for n in db.execute(select(Notification).where(
        Notification.entity_id == farm_batch["id"], Notification.category == "COMPLIANCE"))
        .scalars()]
    titles += [a.title for a in db.execute(select(Alert).where(
        Alert.entity_id == farm_batch["id"], Alert.category == "COMPLIANCE")).scalars()]
    assert titles, "the evaluation told nobody"
    assert all("USDA (US)" in t and "US-USDA" not in t for t in titles), titles
    # The kind keeps the code, so dedupe and resolution are unchanged.
    kinds = {a.kind for a in db.execute(select(Alert).where(
        Alert.entity_id == farm_batch["id"], Alert.category == "COMPLIANCE")).scalars()}
    assert kinds <= {"compliance:US-USDA"}
    assert db.get(Batch, farm_batch["id"]) is not None
