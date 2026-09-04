"""Device provisioning, HMAC ingestion and replay protection (FR-A1, FR-A2, FR-A4, FR-E3)."""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import device_signature, utcnow
from ai.data.generate import telemetry_reading


def headers_for(device_id: str, secret: str, readings: dict, when: datetime | None = None,
                nonce: str | None = None) -> tuple[dict, dict]:
    when = when or utcnow()
    nonce = nonce or secrets.token_hex(16)
    timestamp = when.isoformat()
    signature = device_signature(secret, device_id, timestamp, nonce, readings)
    body = {"recorded_at": timestamp, "nonce": nonce, "readings": readings}
    headers = {"X-Device-Id": device_id, "X-Device-Timestamp": timestamp,
               "X-Device-Nonce": nonce, "X-Device-Signature": signature}
    return body, headers


def soil_reading() -> dict:
    import random

    return {k: round(v, 3) for k, v in
            telemetry_reading("SOIL_SENSOR", utcnow(), random.Random(11)).items()}


class TestProvisioning:
    def test_secret_is_returned_once_with_a_warning(self, client, auth, farm, field):
        response = client.post("/api/v1/devices", headers=auth("FARM_OPERATOR"), json={
            "device_type": "SOIL_SENSOR", "model": "TestProbe", "firmware_version": "1.0.0",
            "farm_id": farm.id, "field_id": field.id})
        assert response.status_code == 201
        body = response.json()
        assert len(bytes.fromhex(body["device_secret"])) == 32
        assert "once" in body["warning"].lower()
        assert body["device"]["status"] == "PROVISIONED"

    def test_secret_is_never_returned_again(self, client, auth, provisioned_device):
        response = client.get(f"/api/v1/devices/{provisioned_device['id']}",
                              headers=auth("FARM_OPERATOR"))
        assert response.status_code == 200
        assert "secret" not in response.text.lower()

    def test_device_must_belong_to_a_farm_in_the_callers_organisation(self, client, rival_auth,
                                                                     farm):
        response = client.post("/api/v1/devices", headers=rival_auth, json={
            "device_type": "SOIL_SENSOR", "model": "X", "firmware_version": "1",
            "farm_id": farm.id})
        assert response.status_code == 404

    def test_field_must_belong_to_the_named_farm(self, client, auth, farm, db, orgs):
        from app.models import Farm, Field

        other_farm = Farm(org_id=orgs["FARM"].id, name="Other Farm", region="Iowa",
                          country="US", latitude=41.0, longitude=-93.0, area_ha=10.0)
        db.add(other_farm)
        db.flush()
        stray = Field(farm_id=other_farm.id, org_id=orgs["FARM"].id, name="Stray", area_ha=1.0)
        db.add(stray)
        db.commit()
        response = client.post("/api/v1/devices", headers=auth("FARM_OPERATOR"), json={
            "device_type": "SOIL_SENSOR", "model": "X", "firmware_version": "1",
            "farm_id": farm.id, "field_id": stray.id})
        assert response.status_code == 422

    @pytest.mark.parametrize("device_type", ["LASER", "", "soil sensor"])
    def test_unknown_device_type_rejected(self, client, auth, farm, device_type):
        response = client.post("/api/v1/devices", headers=auth("FARM_OPERATOR"), json={
            "device_type": device_type, "model": "X", "firmware_version": "1",
            "farm_id": farm.id})
        assert response.status_code == 422


class TestDeviceAuthentication:
    def test_valid_signed_message_accepted(self, client, provisioned_device):
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    soil_reading())
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.status_code == 202, response.text
        assert response.json()["quality"] == "OK"

    def test_wrong_secret_rejected(self, client, provisioned_device):
        body, headers = headers_for(provisioned_device["id"], secrets.token_hex(32),
                                    soil_reading())
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.status_code == 404
        assert "authentication failed" in response.json()["detail"].lower()

    def test_unknown_device_gives_the_same_response_as_a_wrong_secret(self, client):
        """T-07: an attacker must not learn which device ids exist."""
        body, headers = headers_for("00000000-0000-0000-0000-000000000000",
                                    secrets.token_hex(32), soil_reading())
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.status_code == 404
        assert "authentication failed" in response.json()["detail"].lower()

    def test_tampered_readings_break_the_signature(self, client, provisioned_device):
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    soil_reading())
        body["readings"]["soil_moisture_pct"] = 99.0        # altered in flight
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.status_code == 404

    def test_missing_signature_header_rejected(self, client, provisioned_device):
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    soil_reading())
        del headers["X-Device-Signature"]
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.status_code == 422

    def test_nonce_header_must_match_the_body(self, client, provisioned_device):
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    soil_reading())
        headers["X-Device-Nonce"] = secrets.token_hex(16)
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.status_code == 422

    def test_auth_failures_are_counted_and_persisted(self, client, auth, provisioned_device):
        """The counter must survive the rejected request that produced it."""
        before = client.get(f"/api/v1/devices/{provisioned_device['id']}",
                            headers=auth("FARM_OPERATOR")).json()["auth_failures"]
        for _ in range(3):
            body, headers = headers_for(provisioned_device["id"], secrets.token_hex(32),
                                        soil_reading())
            client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        after = client.get(f"/api/v1/devices/{provisioned_device['id']}",
                           headers=auth("FARM_OPERATOR")).json()["auth_failures"]
        assert after >= before + 3


class TestReplayProtection:
    def test_identical_message_replay_rejected(self, client, provisioned_device):
        """T-08: a captured message must not be replayable."""
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    soil_reading())
        assert client.post("/api/v1/telemetry/ingest", json=body,
                           headers=headers).status_code == 202
        replay = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert replay.status_code == 409
        assert "replay" in replay.json()["detail"].lower()

    def test_stale_timestamp_rejected(self, client, provisioned_device):
        old = utcnow() - timedelta(hours=2)
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    soil_reading(), when=old)
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.status_code == 422
        assert "window" in response.json()["detail"].lower()

    def test_future_timestamp_rejected(self, client, provisioned_device):
        future = utcnow() + timedelta(hours=2)
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    soil_reading(), when=future)
        assert client.post("/api/v1/telemetry/ingest", json=body,
                           headers=headers).status_code == 422

    def test_non_monotonic_sequence_rejected(self, client, provisioned_device):
        reading = soil_reading()
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    reading)
        body["sequence"] = 10
        headers["X-Device-Signature"] = device_signature(
            provisioned_device["secret"], provisioned_device["id"],
            headers["X-Device-Timestamp"], body["nonce"], reading)
        assert client.post("/api/v1/telemetry/ingest", json=body,
                           headers=headers).status_code == 202
        body2, headers2 = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                      reading)
        body2["sequence"] = 5
        response = client.post("/api/v1/telemetry/ingest", json=body2, headers=headers2)
        assert response.status_code == 409


class TestValidationAndQuarantine:
    def test_out_of_range_reading_is_quarantined_not_silently_stored(self, client,
                                                                    provisioned_device):
        reading = soil_reading()
        reading["ph"] = 27.5
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    reading)
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.status_code == 202
        assert response.json()["quality"] == "QUARANTINED"
        assert response.json()["anomaly_score"] >= 0.9

    def test_unknown_channel_is_quarantined(self, client, provisioned_device):
        reading = soil_reading()
        reading["backdoor_channel"] = 1.0
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    reading)
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.json()["quality"] == "QUARANTINED"

    def test_empty_readings_rejected(self, client, provisioned_device):
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"], {})
        assert client.post("/api/v1/telemetry/ingest", json=body,
                           headers=headers).status_code == 422

    def test_payload_is_encrypted_at_rest(self, client, db, provisioned_device):
        """NFR-8: the stored payload must not be readable from the database."""
        from sqlalchemy import select

        from app.models import Telemetry

        reading = soil_reading()
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    reading)
        telemetry_id = client.post("/api/v1/telemetry/ingest", json=body,
                                   headers=headers).json()["telemetry_id"]
        db.expire_all()
        record = db.execute(select(Telemetry).where(Telemetry.id == telemetry_id)).scalar_one()
        assert "soil_moisture_pct" not in record.payload_enc
        assert str(reading["ph"]) not in record.payload_enc

        from app.services.telemetry import decrypt_payload

        assert decrypt_payload(record)["ph"] == reading["ph"]


class TestLifecycleAndContainment:
    def test_quarantine_stops_ingestion(self, client, auth, provisioned_device):
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    soil_reading())
        assert client.post("/api/v1/telemetry/ingest", json=body,
                           headers=headers).status_code == 202
        quarantine = client.post(f"/api/v1/devices/{provisioned_device['id']}/quarantine",
                                 headers=auth("FARM_OPERATOR"),
                                 json={"reason": "Anomalous readings under investigation"})
        assert quarantine.status_code == 200
        assert quarantine.json()["status"] == "QUARANTINED"
        body2, headers2 = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                      soil_reading())
        assert client.post("/api/v1/telemetry/ingest", json=body2,
                           headers=headers2).status_code == 404

    def test_illegal_lifecycle_transition_rejected(self, client, auth, provisioned_device):
        client.post(f"/api/v1/devices/{provisioned_device['id']}/retire",
                    headers=auth("FARM_OPERATOR"), json={"reason": "end of life"})
        response = client.post(f"/api/v1/devices/{provisioned_device['id']}/activate",
                               headers=auth("FARM_OPERATOR"))
        assert response.status_code == 409

    def test_secret_rotation_invalidates_the_old_secret(self, client, auth, provisioned_device):
        old_secret = provisioned_device["secret"]
        rotated = client.post(f"/api/v1/devices/{provisioned_device['id']}/rotate-secret",
                              headers=auth("FARM_OPERATOR"))
        assert rotated.status_code == 200
        new_secret = rotated.json()["device_secret"]
        assert new_secret != old_secret
        body, headers = headers_for(provisioned_device["id"], old_secret, soil_reading())
        assert client.post("/api/v1/telemetry/ingest", json=body,
                           headers=headers).status_code == 404
        body, headers = headers_for(provisioned_device["id"], new_secret, soil_reading())
        assert client.post("/api/v1/telemetry/ingest", json=body,
                           headers=headers).status_code == 202


class TestVulnerabilityManagement:
    def test_record_and_remediate(self, client, auth, provisioned_device):
        created = client.post("/api/v1/devices/vulnerabilities", headers=auth("FARM_OPERATOR"),
                              json={"device_id": provisioned_device["id"],
                                    "cve_id": f"CVE-2026-{secrets.randbelow(90000) + 10000}",
                                    "title": "Test finding", "severity": "HIGH", "cvss": 8.1,
                                    "affected_versions": "< 2.0", "fixed_in": "2.0"})
        assert created.status_code == 201
        assert created.json()["status"] == "OPEN"
        remediated = client.post(
            f"/api/v1/devices/vulnerabilities/{created.json()['id']}/remediate",
            headers=auth("FARM_OPERATOR"), json={"new_firmware": "2.0"})
        assert remediated.status_code == 200
        assert remediated.json()["status"] == "REMEDIATED"

    def test_duplicate_open_finding_rejected(self, client, auth, provisioned_device):
        cve = f"CVE-2026-{secrets.randbelow(90000) + 10000}"
        payload = {"device_id": provisioned_device["id"], "cve_id": cve, "title": "Dup",
                   "severity": "MEDIUM"}
        assert client.post("/api/v1/devices/vulnerabilities", headers=auth("FARM_OPERATOR"),
                           json=payload).status_code == 201
        assert client.post("/api/v1/devices/vulnerabilities", headers=auth("FARM_OPERATOR"),
                           json=payload).status_code == 409

    def test_invalid_severity_rejected(self, client, auth, provisioned_device):
        response = client.post("/api/v1/devices/vulnerabilities", headers=auth("FARM_OPERATOR"),
                               json={"device_id": provisioned_device["id"],
                                     "cve_id": "CVE-2026-1", "title": "x",
                                     "severity": "APOCALYPTIC"})
        assert response.status_code == 422

    def test_fleet_posture_reports_severity_breakdown(self, client, auth):
        response = client.get("/api/v1/devices/posture", headers=auth("SECURITY_ANALYST"))
        assert response.status_code == 200
        body = response.json()
        assert "open_by_severity" in body
        assert set(body["open_by_severity"]) >= {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert 0.0 <= body["remediation_rate"] <= 1.0
