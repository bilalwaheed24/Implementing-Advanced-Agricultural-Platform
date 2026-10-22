"""Alert de-duplication and alert <-> incident <-> entity synchronisation.

Covers: repeated anomalies and low-battery readings folding into one alert; has_open_alert
treating ACKNOWLEDGED as open and matching on kind; resolve syncing in both directions;
quarantine attaching to (and containing) the device's existing incident; the incident
write rules for biosafety officers and farm operators; the health sweep's offline flag; and
the sweep's rescore of readings that were stored unscored.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from .conftest import unique
from .test_devices_telemetry import headers_for, soil_reading


def _ingest(client, device, reading):
    body, headers = headers_for(device["id"], device["secret"], reading)
    response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
    assert response.status_code == 202, response.text
    return response.json()


def _device_alerts(db, device_id, category=None):
    from app.models import Alert

    db.expire_all()
    query = db.query(Alert).filter(Alert.entity_id == device_id)
    if category:
        query = query.filter(Alert.category == category)
    return query.all()


def _device_incidents(db, device_id):
    from app.models import Incident

    db.expire_all()
    return db.query(Incident).filter(Incident.entity_id == device_id).all()


def _bad_reading():
    reading = soil_reading()
    reading["ph"] = 27.5            # out of physical range -> CRITICAL anomaly
    return reading


class TestAnomalyDeduplication:
    def test_repeated_anomalies_make_one_alert_and_one_incident(self, client, db,
                                                                provisioned_device):
        for _ in range(3):
            _ingest(client, provisioned_device, _bad_reading())

        alerts = _device_alerts(db, provisioned_device["id"], "DEVICE_ANOMALY")
        assert len(alerts) == 1, "every anomalous reading raised its own alert"
        assert alerts[0].occurrences == 3
        assert alerts[0].kind == "anomaly"
        assert alerts[0].last_seen_at is not None

        incidents = _device_incidents(db, provisioned_device["id"])
        assert len(incidents) == 1, "every anomalous reading opened its own incident"
        incident = incidents[0]
        assert alerts[0].incident_id == incident.id
        assert (incident.entity_type, incident.category) == ("Device", "DEVICE_ANOMALY")
        assert incident.source_alert_id == alerts[0].id

    def test_repeats_do_not_renotify(self, client, db, users, provisioned_device):
        from app.models import Notification

        _ingest(client, provisioned_device, _bad_reading())
        db.expire_all()
        before = db.query(Notification).filter(
            Notification.entity_id == provisioned_device["id"]).count()
        _ingest(client, provisioned_device, _bad_reading())
        db.expire_all()
        after = db.query(Notification).filter(
            Notification.entity_id == provisioned_device["id"]).count()
        assert after == before

    def test_a_resolved_alert_lets_the_next_anomaly_raise_afresh(self, client, auth, db,
                                                                 provisioned_device):
        _ingest(client, provisioned_device, _bad_reading())
        first = _device_alerts(db, provisioned_device["id"], "DEVICE_ANOMALY")[0]
        assert client.post(f"/api/v1/security/alerts/{first.id}/resolve",
                           headers=auth("SECURITY_ANALYST")).status_code == 200
        _ingest(client, provisioned_device, _bad_reading())
        alerts = _device_alerts(db, provisioned_device["id"], "DEVICE_ANOMALY")
        assert len(alerts) == 2

    def test_an_acknowledged_alert_still_absorbs_repeats(self, client, auth, db,
                                                         provisioned_device):
        _ingest(client, provisioned_device, _bad_reading())
        alert = _device_alerts(db, provisioned_device["id"], "DEVICE_ANOMALY")[0]
        assert client.post(f"/api/v1/security/alerts/{alert.id}/acknowledge",
                           headers=auth("SECURITY_ANALYST")).status_code == 200
        _ingest(client, provisioned_device, _bad_reading())
        alerts = _device_alerts(db, provisioned_device["id"], "DEVICE_ANOMALY")
        assert len(alerts) == 1 and alerts[0].occurrences == 2


class TestLowBatteryAndKinds:
    def test_low_battery_alerts_once(self, client, db, provisioned_device):
        for _ in range(3):
            reading = soil_reading()
            reading["battery_pct"] = 9.0
            _ingest(client, provisioned_device, reading)
        alerts = [a for a in _device_alerts(db, provisioned_device["id"], "DEVICE_HEALTH")
                  if a.kind == "low_battery"]
        assert len(alerts) == 1
        assert alerts[0].occurrences == 3

    def test_has_open_alert_counts_acknowledged_and_matches_kind(self, db, orgs):
        from app.services import notifications

        entity = unique("ENT")
        alert = notifications.raise_alert(
            db, "DEVICE_HEALTH", "WARNING", "Low battery probe", org_id=orgs["FARM"].id,
            entity_type="Device", entity_id=entity, notify=False, kind="low_battery")
        notifications.acknowledge(db, alert, actor_id=None)
        assert notifications.has_open_alert(db, "DEVICE_HEALTH", entity)
        assert notifications.has_open_alert(db, "DEVICE_HEALTH", entity, kind="low_battery")
        assert not notifications.has_open_alert(db, "DEVICE_HEALTH", entity, kind="silent"), \
            "a low-battery alert must not suppress a stopped-reporting one"
        notifications.resolve(db, alert)
        assert not notifications.has_open_alert(db, "DEVICE_HEALTH", entity)
        db.rollback()

    def test_escalation_opens_an_incident_on_the_existing_alert(self, db, orgs):
        from app.services import notifications

        entity = unique("ENT")
        first = notifications.raise_alert(
            db, "DEVICE_AUTH", "WARNING", "Auth failures probe", org_id=orgs["FARM"].id,
            entity_type="Device", entity_id=entity, notify=False, kind="auth_failures")
        assert first.incident_id is None
        again = notifications.raise_alert(
            db, "DEVICE_AUTH", "HIGH", "Auth failures probe", org_id=orgs["FARM"].id,
            entity_type="Device", entity_id=entity, notify=False, kind="auth_failures")
        assert again.id == first.id
        assert again.severity == "HIGH" and again.incident_id is not None
        db.rollback()


class TestResolveSync:
    @pytest.fixture
    def linked(self, db, orgs):
        from app.models import Incident
        from app.services import notifications

        alert = notifications.raise_alert(
            db, "DEVICE_ANOMALY", "HIGH", f"Sync probe {unique('S')}", org_id=orgs["FARM"].id,
            entity_type="Device", entity_id=unique("DEV"), notify=False, kind="anomaly")
        db.commit()
        return alert, db.get(Incident, alert.incident_id)

    def test_resolving_the_last_alert_resolves_the_incident(self, client, auth, db, linked):
        alert, incident = linked
        response = client.post(f"/api/v1/security/alerts/{alert.id}/resolve",
                               headers=auth("SECURITY_ANALYST"))
        assert response.status_code == 200, response.text
        detail = client.get(f"/api/v1/security/incidents/{incident.id}",
                            headers=auth("SECURITY_ANALYST")).json()
        assert detail["incident"]["status"] == "RESOLVED"
        assert any(e["action"] == "ALERT_RESOLVED" for e in detail["timeline"])

    def test_resolving_the_incident_resolves_its_alerts(self, client, auth, db, linked):
        alert, incident = linked
        response = client.patch(f"/api/v1/security/incidents/{incident.id}",
                                headers=auth("SECURITY_ANALYST"),
                                json={"status": "RESOLVED", "note": "sensor replaced"})
        assert response.status_code == 200, response.text
        detail = client.get(f"/api/v1/security/incidents/{incident.id}",
                            headers=auth("SECURITY_ANALYST")).json()
        assert [a["status"] for a in detail["alerts"]] == ["RESOLVED"]
        assert detail["timeline"][-1]["detail"] == "sensor replaced"

    def test_triage_acknowledges_open_alerts(self, client, auth, linked):
        alert, incident = linked
        client.patch(f"/api/v1/security/incidents/{incident.id}",
                     headers=auth("SECURITY_ANALYST"), json={"status": "TRIAGED"})
        detail = client.get(f"/api/v1/security/incidents/{incident.id}",
                            headers=auth("SECURITY_ANALYST")).json()
        assert detail["alerts"][0]["status"] == "ACKNOWLEDGED"

    def test_a_note_alone_is_recorded_as_a_note(self, client, auth, linked):
        _, incident = linked
        response = client.patch(f"/api/v1/security/incidents/{incident.id}",
                                headers=auth("SECURITY_ANALYST"),
                                json={"note": "Called the farm; probe was flooded."})
        assert response.status_code == 200, response.text
        timeline = client.get(f"/api/v1/security/incidents/{incident.id}",
                              headers=auth("SECURITY_ANALYST")).json()["timeline"]
        assert timeline[-1]["action"] == "NOTE"
        assert timeline[-1]["actor_name"]

    def test_assignment(self, client, auth, users, linked):
        _, incident = linked
        analyst = users["SECURITY_ANALYST"]
        response = client.patch(f"/api/v1/security/incidents/{incident.id}",
                                headers=auth("SECURITY_ANALYST"),
                                json={"assignee_id": analyst.id})
        assert response.status_code == 200, response.text
        assert response.json()["assignee_id"] == analyst.id
        bogus = client.patch(f"/api/v1/security/incidents/{incident.id}",
                             headers=auth("SECURITY_ANALYST"),
                             json={"assignee_id": users["SUPPLY_CHAIN_OPERATOR"].id})
        assert bogus.status_code == 422, "a role that cannot read incidents is not assignable"


class TestQuarantineAttachesToIncident:
    def test_quarantine_joins_and_contains_the_open_incident(self, client, auth, db,
                                                             provisioned_device):
        _ingest(client, provisioned_device, _bad_reading())
        incidents = _device_incidents(db, provisioned_device["id"])
        assert len(incidents) == 1

        response = client.post(f"/api/v1/devices/{provisioned_device['id']}/quarantine",
                               headers=auth("FARM_OPERATOR"),
                               json={"reason": "Contained from the anomaly incident"})
        assert response.status_code == 200, response.text

        incidents = _device_incidents(db, provisioned_device["id"])
        assert len(incidents) == 1, "quarantine opened a second incident"
        assert incidents[0].status == "CONTAINED"
        quarantine = [a for a in _device_alerts(db, provisioned_device["id"], "DEVICE_AUTH")
                      if a.kind == "quarantined"]
        assert len(quarantine) == 1 and quarantine[0].incident_id == incidents[0].id


class TestIncidentPermissions:
    @pytest.fixture
    def bio_incident(self, db, orgs):
        from app.models import Incident
        from app.services import notifications

        alert = notifications.raise_alert(
            db, "BIOSECURITY", "CRITICAL", f"Bio probe {unique('B')}",
            org_id=orgs["BIOTECH"].id, entity_type="SequenceScreening",
            entity_id=unique("SCR"), notify=False)
        db.commit()
        return db.get(Incident, alert.incident_id)

    @pytest.fixture
    def device_incident(self, db, orgs):
        from app.models import Incident
        from app.services import notifications

        alert = notifications.raise_alert(
            db, "DEVICE_ANOMALY", "HIGH", f"Device probe {unique('D')}",
            org_id=orgs["FARM"].id, entity_type="Device", entity_id=unique("DEV"),
            notify=False)
        db.commit()
        return db.get(Incident, alert.incident_id)

    def test_biosafety_officer_may_work_a_biosecurity_incident(self, client, auth,
                                                               bio_incident):
        detail = client.get(f"/api/v1/security/incidents/{bio_incident.id}",
                            headers=auth("BIOSAFETY_OFFICER")).json()
        assert detail["can_update"] is True
        response = client.patch(f"/api/v1/security/incidents/{bio_incident.id}",
                                headers=auth("BIOSAFETY_OFFICER"), json={"status": "TRIAGED"})
        assert response.status_code == 200, response.text

    def test_biosafety_officer_may_not_work_a_device_incident(self, client, auth,
                                                              device_incident):
        response = client.patch(f"/api/v1/security/incidents/{device_incident.id}",
                                headers=auth("BIOSAFETY_OFFICER"), json={"status": "TRIAGED"})
        assert response.status_code == 403, response.text

    def test_farm_operator_reads_own_org_incidents_only(self, client, auth, rival_auth,
                                                        device_incident):
        own = client.get(f"/api/v1/security/incidents/{device_incident.id}",
                         headers=auth("FARM_OPERATOR"))
        assert own.status_code == 200, own.text
        assert own.json()["can_update"] is False
        assert client.patch(f"/api/v1/security/incidents/{device_incident.id}",
                            headers=auth("FARM_OPERATOR"),
                            json={"status": "TRIAGED"}).status_code == 403
        rival = client.get(f"/api/v1/security/incidents/{device_incident.id}",
                           headers=rival_auth)
        assert rival.status_code == 404


class TestHealthSweep:
    @pytest.fixture
    def silent_device(self, db, orgs, farm):
        from app.core.security import encrypt_at_rest, generate_device_secret, utcnow
        from app.models import Device

        device = Device(device_type="SOIL_SENSOR", model="Silent-1", firmware_version="1.0.0",
                        org_id=orgs["FARM"].id, farm_id=farm.id,
                        secret_enc=encrypt_at_rest(generate_device_secret()), status="ACTIVE",
                        interval_seconds=60, last_seen_at=utcnow() - timedelta(hours=6))
        db.add(device)
        db.commit()
        return device

    def test_silent_device_is_flagged_offline_and_alerted_once(self, client, auth, db,
                                                               silent_device):
        from app.services import notifications

        # An unrelated open low-battery alert must not hide the stopped-reporting one.
        notifications.raise_alert(
            db, "DEVICE_HEALTH", "WARNING", "Low battery", org_id=silent_device.org_id,
            entity_type="Device", entity_id=silent_device.id, notify=False,
            open_incident=False, kind="low_battery")
        db.commit()
        for _ in range(2):
            response = client.post("/api/v1/devices/sweep/health",
                                   headers=auth("FARM_OPERATOR"))
            assert response.status_code == 200, response.text
        silent = [a for a in _device_alerts(db, silent_device.id, "DEVICE_HEALTH")
                  if a.kind == "silent"]
        assert len(silent) == 1
        db.refresh(silent_device)
        assert silent_device.offline_since is not None
        assert silent_device.status == "ACTIVE"

        tiles = client.get("/api/v1/dashboard", headers=auth("FARM_OPERATOR")).json()
        assert tiles["devices"]["offline"] >= 1

    def test_reporting_again_clears_the_flag_and_resolves_the_alert(self, client, auth, db,
                                                                   provisioned_device):
        from app.core.security import utcnow
        from app.models import Device

        device = db.get(Device, provisioned_device["id"])
        device.last_seen_at = utcnow() - timedelta(hours=10)
        db.commit()
        client.post("/api/v1/devices/sweep/health", headers=auth("FARM_OPERATOR"))
        db.expire_all()
        assert db.get(Device, provisioned_device["id"]).offline_since is not None

        _ingest(client, provisioned_device, soil_reading())
        db.expire_all()
        assert db.get(Device, provisioned_device["id"]).offline_since is None
        silent = [a for a in _device_alerts(db, provisioned_device["id"], "DEVICE_HEALTH")
                  if a.kind == "silent"]
        assert silent and all(a.status == "RESOLVED" for a in silent)

    def test_sweep_rescores_unscored_readings(self, client, auth, db, provisioned_device):
        from app.core.security import utcnow
        from app.models import Telemetry

        result = _ingest(client, provisioned_device, soil_reading())
        record = db.get(Telemetry, result["telemetry_id"])
        record.anomaly_score = None
        record.received_at = utcnow() - timedelta(minutes=10)
        db.commit()

        response = client.post("/api/v1/devices/sweep/health", headers=auth("FARM_OPERATOR"))
        assert response.status_code == 200, response.text
        assert response.json()["rescored_readings"] >= 1
        db.expire_all()
        assert db.get(Telemetry, record.id).anomaly_score is not None
