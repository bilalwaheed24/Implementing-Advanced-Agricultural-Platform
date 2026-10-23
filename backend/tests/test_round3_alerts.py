"""Round 3: alert kinds, dedupe and resolution, custodian visibility, the data-theft
detector's noise, and the wording people read."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.core.security import hash_password, utcnow, verification_code
from app.models import (AccessRecord, Alert, AuditLog, Batch, Device, IncidentEvent,
                        Notification, Product, Shipment, User)
from app.services import cold_chain, devices, notifications, security_ops, supplychain
from .conftest import unique

API = "/api/v1"


@pytest.fixture
def held_batch(db, orgs, product) -> Batch:
    """A farm's batch now held by the processor (custodian)."""
    batch = Batch(batch_code=unique("R3B"), product_id=product.id,
                  verification_code=verification_code(), org_id=orgs["FARM"].id,
                  custodian_org_id=orgs["SUPPLY"].id, quantity=100.0, initial_quantity=100.0,
                  unit="kg", state="IN_TRANSIT", origin_region="Iowa", origin_country="US",
                  harvested_at=utcnow())
    db.add(batch)
    db.commit()
    return batch


def _alerts(db, entity_id, **filters):
    query = select(Alert).where(Alert.entity_id == entity_id)
    for key, value in filters.items():
        query = query.where(getattr(Alert, key) == value)
    db.expire_all()
    return list(db.execute(query.order_by(Alert.created_at)).scalars())


# --------------------------------------------------------------------------- #
# 1. Recall is not suppressed by an unrelated COMPLIANCE alert
# --------------------------------------------------------------------------- #
class TestRecallAlertKinds:
    def test_an_open_compliance_alert_does_not_hide_the_recall(self, db, held_batch, users):
        notifications.raise_alert(
            db, "COMPLIANCE", "HIGH", "Unrelated failed evaluation", org_id=held_batch.org_id,
            entity_type="Batch", entity_id=held_batch.id, kind="compliance:US",
            notify=False, open_incident=False)
        supplychain.propagate_recall(db, held_batch, users["FARM_OPERATOR"].id, "FARM_OPERATOR",
                                     held_batch.org_id)
        db.commit()
        recall = _alerts(db, held_batch.id, kind="recall")
        assert len(recall) == 1, "the recall alert must be raised despite the open alert"
        assert recall[0].custodian_org_id == held_batch.custodian_org_id
        assert recall[0].reasons == ["Batch recalled"]

    def test_the_custodian_sees_and_acknowledges_the_recall_alert(self, client, auth, db,
                                                                  held_batch, users):
        supplychain.propagate_recall(db, held_batch, users["FARM_OPERATOR"].id, "FARM_OPERATOR",
                                     held_batch.org_id)
        db.commit()
        listed = client.get(f"{API}/security/alerts", params={"entity_id": held_batch.id},
                            headers=auth("SUPPLY_CHAIN_OPERATOR"))
        assert listed.status_code == 200, listed.text
        items = listed.json()["items"]
        assert items, "the processor holding the batch must see its alert"
        assert items[0]["source_label"] == held_batch.batch_code
        acknowledged = client.post(f"{API}/security/alerts/{items[0]['id']}/acknowledge",
                                   headers=auth("SUPPLY_CHAIN_OPERATOR"))
        assert acknowledged.status_code == 200, acknowledged.text
        db.expire_all()
        entry = db.execute(select(AuditLog).where(
            AuditLog.action == "alert.acknowledge",
            AuditLog.entity_id == items[0]["id"])).scalars().first()
        assert entry is not None, "acknowledging an alert is audit-logged"

    def test_an_unrelated_organisation_still_cannot_see_it(self, client, rival_auth, db,
                                                           held_batch, users):
        supplychain.propagate_recall(db, held_batch, users["FARM_OPERATOR"].id, "FARM_OPERATOR",
                                     held_batch.org_id)
        db.commit()
        listed = client.get(f"{API}/security/alerts", params={"entity_id": held_batch.id},
                            headers=rival_auth)
        assert listed.status_code == 200 and listed.json()["items"] == []


# --------------------------------------------------------------------------- #
# 2. Batch alerts dedupe on kind and resolve when the condition clears
# --------------------------------------------------------------------------- #
class TestBatchAlertDedupeAndResolution:
    def _raise(self, db, batch, severity="HIGH"):
        return notifications.alert_parties(
            db, "FRAUD", severity, f"Supply-chain integrity check flagged batch "
            f"{batch.batch_code}", party_org_ids=[batch.custodian_org_id],
            org_id=batch.org_id, entity_type="Batch", entity_id=batch.id, kind="fraud",
            party_org_id=batch.custodian_org_id)

    def test_repeated_failures_fold_into_one_alert_and_one_round_of_notices(
            self, db, held_batch, users):
        self._raise(db, held_batch)
        sent = db.execute(select(Notification).where(
            Notification.entity_id == held_batch.id)).scalars().all()
        self._raise(db, held_batch)
        db.commit()
        alerts = _alerts(db, held_batch.id, category="FRAUD")
        assert len(alerts) == 1 and alerts[0].occurrences == 2
        again = db.execute(select(Notification).where(
            Notification.entity_id == held_batch.id)).scalars().all()
        assert len(again) == len(sent), "a plain repeat must not notify everyone again"

    def test_escalation_renotifies(self, db, held_batch):
        self._raise(db, held_batch)
        before = len(db.execute(select(Notification).where(
            Notification.entity_id == held_batch.id)).scalars().all())
        self._raise(db, held_batch, "CRITICAL")
        db.commit()
        after = len(db.execute(select(Notification).where(
            Notification.entity_id == held_batch.id)).scalars().all())
        assert after > before
        assert _alerts(db, held_batch.id, category="FRAUD")[0].severity == "CRITICAL"

    def test_a_passing_result_resolves_it_with_one_resolved_entry(self, db, held_batch):
        alert = self._raise(db, held_batch)
        assert alert.incident_id, "a HIGH fraud alert opens an incident"
        resolved = notifications.resolve_alerts(db, "FRAUD", held_batch.id, kind="fraud",
                                                note="A later integrity check verified it")
        db.commit()
        assert [a.id for a in resolved] == [alert.id]
        events = db.execute(select(IncidentEvent).where(
            IncidentEvent.incident_id == alert.incident_id)).scalars().all()
        assert [e.action for e in events].count("RESOLVED") == 1
        assert any("verified it" in e.detail for e in events)

    def test_resolve_entity_alerts_writes_a_single_resolved_entry(self, db, held_batch):
        alert = notifications.raise_alert(
            db, "COMPLIANCE", "HIGH", "Probe", org_id=held_batch.org_id, entity_type="Batch",
            entity_id=held_batch.id, kind="probe", notify=False)
        notifications.resolve_entity_alerts(db, "Batch", held_batch.id, None, "Dealt with")
        db.commit()
        actions = db.execute(select(IncidentEvent.action).where(
            IncidentEvent.incident_id == alert.incident_id)).scalars().all()
        assert actions.count("RESOLVED") == 1, actions

    def test_other_kinds_are_left_alone(self, db, held_batch):
        notifications.raise_alert(db, "COMPLIANCE", "HIGH", "Labelling", org_id=held_batch.org_id,
                                  entity_type="Batch", entity_id=held_batch.id,
                                  kind="labelling:EU", notify=False, open_incident=False)
        notifications.resolve_alerts(db, "COMPLIANCE", held_batch.id, kind="compliance:EU")
        db.commit()
        assert _alerts(db, held_batch.id, kind="labelling:EU")[0].status == "OPEN"


# --------------------------------------------------------------------------- #
# 3. Lockout and exfiltration are separate kinds; the detector is less noisy
# --------------------------------------------------------------------------- #
@pytest.fixture
def principal(db, second_farm_org) -> User:
    user = User(email=f"{unique('dt')}@test.absp", full_name="Dana Theft-Probe",
                password_hash=hash_password("x" * 16), role="FARM_OPERATOR",
                org_id=second_farm_org.id, status="ACTIVE")
    db.add(user)
    db.commit()
    return user


def _records(db, principal, count, *, status=200, cross=False, page_size=20, routes=10,
             minutes=8):
    now = utcnow()
    for index in range(count):
        db.add(AccessRecord(principal_id=principal.id, org_id=principal.org_id,
                            route=f"/api/v1/view-{index % routes}", method="GET",
                            page_size=page_size, result_count=0, status_code=status, hour=12,
                            cross_tenant_attempt=cross,
                            created_at=now - timedelta(seconds=(minutes * 60 * index) // count)))
    db.commit()


class TestDataTheftDetector:
    def test_ordinary_heavy_browsing_is_not_flagged(self, db, principal):
        # ~150 requests in a few minutes with the app's maximum-size lookups, and a handful of
        # pages the role may not open: the pattern that used to open a HIGH incident.
        _records(db, principal, 150, page_size=200)
        _records(db, principal, 25, status=403, cross=True)
        verdict = security_ops.evaluate_principal(db, principal.id, principal.org_id)
        assert not verdict["flagged"], verdict
        assert verdict["level"] in {"INFO", "WARNING"}
        assert "cross_tenant_attempts" not in {s["signal"] for s in verdict["signals"]}

    def test_a_single_foreign_probe_is_not_a_signal(self, db, principal):
        _records(db, principal, 1, status=404, cross=True)
        verdict = security_ops.evaluate_principal(db, principal.id, principal.org_id)
        assert "cross_tenant_attempts" not in {s["signal"] for s in verdict["signals"]}

    def test_repeated_probing_with_bulk_reads_is_flagged(self, db, principal):
        _records(db, principal, 25, status=404, cross=True, page_size=200, routes=1)
        verdict = security_ops.evaluate_principal(db, principal.id, principal.org_id)
        assert verdict["flagged"] and verdict["level"] in {"HIGH", "CRITICAL"}, verdict

    def test_sweep_alert_is_readable_and_not_hidden_by_a_lockout(self, db, principal):
        notifications.raise_alert(
            db, "DATA_THEFT", "HIGH", "Account locked after 5 failed logins",
            org_id=principal.org_id, entity_type="User", entity_id=principal.id,
            kind="account_lockout", notify=False)
        _records(db, principal, 25, status=404, cross=True, page_size=200, routes=1)
        security_ops.sweep_data_theft(db, 24, org_id=principal.org_id)
        db.commit()
        alerts = _alerts(db, principal.id, kind="exfiltration")
        assert len(alerts) == 1, "an open lockout alert must not hide the exfiltration alert"
        assert "Dana Theft-Probe" in alerts[0].title and principal.email in alerts[0].title
        assert "Attempts to open other organisations' records" in alerts[0].reasons
        assert not any("_" in str(r) for r in alerts[0].reasons)


# --------------------------------------------------------------------------- #
# 4. Devices leaving service, counts, cold chain, wording
# --------------------------------------------------------------------------- #
class TestDeviceLeavingService:
    def test_retiring_clears_silence_and_battery(self, db, orgs, farm, users):
        device = Device(org_id=orgs["FARM"].id, farm_id=farm.id, device_type="SOIL_SENSOR",
                        model="R3", firmware_version="1.0", secret_enc="x",
                        interval_seconds=60, status="ACTIVE",
                        last_seen_at=utcnow() - timedelta(hours=2))
        db.add(device)
        db.flush()
        devices.sweep_silent_devices(db, org_id=orgs["FARM"].id)
        notifications.raise_alert(db, "DEVICE_HEALTH", "WARNING", "Low battery",
                                  org_id=device.org_id, entity_type="Device",
                                  entity_id=device.id, kind="low_battery",
                                  open_incident=False, notify=False)
        assert device.offline_since is not None
        devices.transition(db, device, "RETIRED", users["FARM_OPERATOR"].id, "FARM_OPERATOR",
                           "end of life")
        db.commit()
        assert device.offline_since is None
        open_health = [a for a in _alerts(db, device.id, category="DEVICE_HEALTH")
                       if a.status != "RESOLVED"]
        assert open_health == []


class TestCountsAndTimeline:
    def test_acknowledged_alerts_count_as_open(self, db, orgs):
        alert = notifications.raise_alert(
            db, "AGRONOMY", "WARNING", "Count probe", org_id=orgs["FARM"].id,
            entity_type="Field", entity_id=str(uuid.uuid4()), notify=False)
        before = security_ops.security_dashboard(db, orgs["FARM"].id)["alerts_open"]
        notifications.acknowledge(db, alert, None)
        after = security_ops.security_dashboard(db, orgs["FARM"].id)["alerts_open"]
        db.commit()
        assert after == before

    def test_automatic_timeline_entries_are_labelled_system(self, client, auth, db, orgs):
        alert = notifications.raise_alert(
            db, "DATA_THEFT", "HIGH", "Timeline probe", org_id=orgs["FARM"].id,
            entity_type="User", entity_id=str(uuid.uuid4()), notify=False)
        db.commit()
        detail = client.get(f"{API}/security/incidents/{alert.incident_id}",
                            headers=auth("SECURITY_ANALYST")).json()
        opened = detail["timeline"][0]
        assert opened["actor_label"] == "system"
        assert opened["detail"].startswith("Opened automatically from a high data theft alert")


class TestColdChainSender:
    def test_the_sender_of_the_leg_is_notified(self, db, orgs, users, held_batch):
        product = Product(gtin=f"0{uuid.uuid4().int % 10**12:012d}", name="Chilled R3",
                          category="Chilled", org_id=orgs["FARM"].id,
                          storage_temp_min_c=0.0, storage_temp_max_c=4.0)
        db.add(product)
        db.flush()
        held_batch.product_id = product.id
        shipment = Shipment(org_id=orgs["FARM"].id, to_org_id=orgs["SUPPLY"].id,
                            sscc=f"{uuid.uuid4().int % 10**18:018d}", batch_id=held_batch.id,
                            carrier="R3", origin_name="Farm", origin_lat=0, origin_lon=0,
                            destination_name="Plant", destination_lat=1, destination_lon=1,
                            departed_at=utcnow() - timedelta(hours=1))
        db.add(shipment)
        db.flush()
        reading = SimpleNamespace(summary={"temp_c": 11.0}, device_id=str(uuid.uuid4()),
                                  recorded_at=datetime(2026, 9, 23, 14, 5, tzinfo=timezone.utc))
        cold_chain.record_reading(db, shipment, reading)
        db.commit()
        farmer = users["FARM_OPERATOR"]
        notes = db.execute(select(Notification).where(
            Notification.user_id == farmer.id,
            Notification.entity_id == shipment.id)).scalars().all()
        assert notes, "the farm that sent the shipment must hear about its excursion"
        assert "23 Sep 2026" in notes[0].body and "between 0 and 4 °C" in notes[0].body
        alert = _alerts(db, shipment.id, kind="cold_chain_excursion")[0]
        assert alert.custodian_org_id == orgs["SUPPLY"].id


class TestWording:
    def test_human_dates_and_statuses(self):
        assert notifications.human_date(date(2026, 9, 23)) == "23 Sep 2026"
        assert notifications.human_date(datetime(2027, 9, 13, tzinfo=timezone.utc)) == \
            "13 Sep 2027"
        assert notifications.human_status("NON_COMPLIANT") == "non-compliant"
        assert notifications.human_status("NON_GMO") == "non-GMO"
        assert notifications.with_article(notifications.human_status("SPECIALTY")) == \
            "a specialty"
        assert notifications.with_article("organic") == "an organic"

    def test_vulnerability_alert_title_says_vulnerability(self, db, orgs, farm, users):
        device = Device(org_id=orgs["FARM"].id, farm_id=farm.id, device_type="SOIL_SENSOR",
                        model="R3", firmware_version="1.0", secret_enc="x",
                        interval_seconds=60, status="ACTIVE")
        db.add(device)
        db.flush()
        devices.add_vulnerability(db, device, users["SECURITY_ANALYST"].id, "SECURITY_ANALYST",
                                  "CVE-2026-0001", "Buffer overflow", "HIGH", 8.1, None, None)
        db.commit()
        alert = _alerts(db, device.id, category="DEVICE_HEALTH")[0]
        assert alert.title.startswith("Vulnerability CVE-2026-0001 (high severity)")
