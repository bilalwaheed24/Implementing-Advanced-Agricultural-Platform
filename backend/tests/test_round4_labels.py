"""Round 4: one readable name per device in alert titles and the alerts list, and readable
names for the records incidents and alerts are about."""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import select

from app.core.security import utcnow
from app.models import Alert, Device
from app.services import devices, notifications

API = "/api/v1"


def _device(db, device_id: str) -> Device:
    db.expire_all()
    return db.get(Device, device_id)


class TestDeviceLabel:
    def test_model_and_serial(self):
        device = SimpleNamespace(id="649773a6-0000", model="ChillGuard CC-3",
                                 serial_number="SN-COL-60", device_type="COLD_CHAIN_SENSOR")
        assert devices.device_label(device) == "ChillGuard CC-3 (SN-COL-60)"

    def test_falls_back_to_id_prefix_and_type(self):
        device = SimpleNamespace(id="649773a6-0000", model="", serial_number=None,
                                 device_type="COLD_CHAIN_SENSOR")
        assert devices.device_label(device) == "Cold Chain Sensor (649773a6)"

    def test_silent_alert_title_and_source_label_name_the_device_alike(
            self, client, auth, db, provisioned_device):
        device = _device(db, provisioned_device["id"])
        device.last_seen_at = utcnow() - timedelta(days=1)
        db.commit()
        devices.sweep_silent_devices(db, org_id=device.org_id)
        db.commit()
        label = devices.device_label(device)
        assert label.startswith("TestProbe (")
        alert = db.execute(select(Alert).where(Alert.entity_id == device.id,
                                               Alert.kind == "silent")).scalar_one()
        assert alert.title == f"{label} has stopped reporting"

        listed = client.get(f"{API}/security/alerts", params={"entity_id": device.id},
                            headers=auth("FARM_OPERATOR"))
        assert listed.status_code == 200, listed.text
        items = listed.json()["items"]
        assert items and all(item["source_label"] == label for item in items)


class TestIncidentLabels:
    def test_incident_list_detail_and_alert_list_carry_names(self, client, auth, db,
                                                             provisioned_device):
        device = _device(db, provisioned_device["id"])
        alert = notifications.raise_alert(
            db, "DEVICE_AUTH", "HIGH", "Round 4 label probe", org_id=device.org_id,
            entity_type="Device", entity_id=device.id, kind="r4-label-probe", notify=False)
        db.commit()
        assert alert.incident_id, "a HIGH alert opens an incident"
        label = devices.device_label(device)

        incidents = client.get(f"{API}/security/incidents", params={"entity_id": device.id},
                               headers=auth("SECURITY_ANALYST"))
        assert incidents.status_code == 200, incidents.text
        row = next(i for i in incidents.json()["items"] if i["id"] == alert.incident_id)
        assert row["entity_label"] == label

        detail = client.get(f"{API}/security/incidents/{alert.incident_id}",
                            headers=auth("SECURITY_ANALYST"))
        assert detail.status_code == 200, detail.text
        body = detail.json()
        assert body["incident"]["entity_label"] == label
        assert any(a["source_label"] == label for a in body["alerts"])

        alerts = client.get(f"{API}/security/alerts", params={"incident_id": alert.incident_id},
                            headers=auth("SECURITY_ANALYST"))
        assert alerts.status_code == 200, alerts.text
        item = next(a for a in alerts.json()["items"] if a["id"] == alert.id)
        assert item["incident_label"]
        assert not item["incident_label"].lower().startswith("incident:")
        assert "Round 4 label probe" in item["incident_label"]
