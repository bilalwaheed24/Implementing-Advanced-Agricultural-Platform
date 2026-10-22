"""Regression tests for the frontend/backend audit of 22 Oct 2026.

Custody transfer visibility, live-approval gating of GMO use, the per-device vulnerability
filter, and a QR payload that carries a complete absolute URL.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app import qrcode
from .conftest import unique
from .test_supplychain_e2e import gmo_event, iso, now  # noqa: F401  (shared fixture)


def _batch(client, auth, product, **extra) -> dict:
    response = client.post("/api/v1/supply-chain/batches", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                           json={"batch_code": unique("B"), "product_id": product.id,
                                 "quantity": 1000.0, "unit": "kg", "origin_region": "Iowa",
                                 "origin_country": "US",
                                 "harvested_at": iso(now() - timedelta(days=2)), **extra})
    return response


class TestCustodyTransferVisibility:
    def test_receiving_organisation_can_read_and_continue_the_batch(self, client, auth,
                                                                   product, orgs):
        batch = _batch(client, auth, product).json()
        assert client.get(f"/api/v1/supply-chain/batches/{batch['id']}",
                          headers=auth("FARM_OPERATOR")).status_code == 404

        handed_over = client.post("/api/v1/supply-chain/events",
                                  headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_id": batch["id"], "biz_step": "harvesting", "disposition": "in_progress",
            "quantity": 1000.0, "unit": "kg", "to_org_id": orgs["FARM"].id,
            "occurred_at": iso(now() - timedelta(days=1))})
        assert handed_over.status_code == 201, handed_over.text

        seen = client.get(f"/api/v1/supply-chain/batches/{batch['id']}",
                          headers=auth("FARM_OPERATOR"))
        assert seen.status_code == 200, seen.text
        assert seen.json()["custodian_org_id"] == orgs["FARM"].id
        listed = client.get("/api/v1/supply-chain/batches?page_size=200",
                            headers=auth("FARM_OPERATOR")).json()["items"]
        assert batch["id"] in {row["id"] for row in listed}

        continued = client.post("/api/v1/supply-chain/events", headers=auth("FARM_OPERATOR"),
                                json={"batch_id": batch["id"], "biz_step": "transforming",
                                      "disposition": "in_progress", "quantity": 950.0,
                                      "unit": "kg", "occurred_at": iso(now())})
        assert continued.status_code == 201, continued.text

    def test_an_uninvolved_organisation_still_gets_404(self, client, auth, product, orgs):
        batch = _batch(client, auth, product).json()
        client.post("/api/v1/supply-chain/events", headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_id": batch["id"], "biz_step": "harvesting", "disposition": "in_progress",
            "to_org_id": orgs["FARM"].id, "occurred_at": iso(now())})
        assert client.get(f"/api/v1/supply-chain/batches/{batch['id']}",
                          headers=auth("BIOTECH_RESEARCHER")).status_code == 404


class TestGmoUseRequiresLiveApproval:
    def test_batch_refused_for_an_unapproved_event(self, client, auth, product, gmo_event):
        response = _batch(client, auth, product, gmo_event_id=gmo_event["id"])
        assert response.status_code == 422, response.text
        assert "approval" in response.json()["detail"].lower()

    def test_batch_refused_when_the_only_approval_has_expired(self, client, auth, product,
                                                              gmo_event):
        approval = client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals",
                               headers=auth("REGULATOR"),
                               json={"jurisdiction": "US-USDA", "status": "APPROVED",
                                     "approved_at": iso(now() - timedelta(days=800)),
                                     "expires_at": iso(now() - timedelta(days=1))})
        assert approval.status_code in (200, 201), approval.text
        response = _batch(client, auth, product, gmo_event_id=gmo_event["id"])
        assert response.status_code == 422, response.text
        assert "expired" in response.json()["detail"].lower()

    def test_batch_accepted_with_a_live_approval(self, client, auth, product, gmo_event):
        client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals", headers=auth("REGULATOR"),
                    json={"jurisdiction": "US-USDA", "status": "APPROVED",
                          "expires_at": iso(now() + timedelta(days=365))})
        response = _batch(client, auth, product, gmo_event_id=gmo_event["id"])
        assert response.status_code == 201, response.text

    def test_planting_refused_for_an_unapproved_event(self, client, auth, field, gmo_event):
        response = client.post("/api/v1/crops", headers=auth("FARM_OPERATOR"), json={
            "field_id": field.id, "crop_type": "Maize", "variety": "V1",
            "gmo_event_id": gmo_event["id"], "planted_at": iso(now())})
        assert response.status_code == 422, response.text


class TestVulnerabilityFilter:
    def test_device_filter_returns_only_that_devices_vulnerabilities(self, client, auth,
                                                                    farm, field):
        ids = []
        for _ in range(2):
            device = client.post("/api/v1/devices", headers=auth("FARM_OPERATOR"), json={
                "device_type": "SOIL_SENSOR", "model": "Probe", "firmware_version": "1.0.0",
                "farm_id": farm.id, "field_id": field.id, "interval_seconds": 900}).json()
            device_id = device["device"]["id"]
            ids.append(device_id)
            created = client.post("/api/v1/devices/vulnerabilities",
                                  headers=auth("FARM_OPERATOR"), json={
                "device_id": device_id, "cve_id": f"CVE-2026-{unique('')[-4:]}",
                "title": "Test weakness", "severity": "LOW"})
            assert created.status_code == 201, created.text
        page = client.get(f"/api/v1/devices/vulnerabilities?device_id={ids[0]}&page_size=200",
                          headers=auth("FARM_OPERATOR")).json()
        assert page["items"]
        assert {row["device_id"] for row in page["items"]} == {ids[0]}


class TestQrPayload:
    @staticmethod
    def _decode_payload(text: str) -> bytes:
        """Read the byte-mode payload back out of the data codewords."""
        codewords = qrcode._encode_bytes(text)[:qrcode.DATA_CODEWORDS]
        bits = "".join(f"{c:08b}" for c in codewords)
        assert bits[:4] == "0100"
        length = int(bits[4:12], 2)
        return bytes(int(bits[12 + 8 * i:20 + 8 * i], 2) for i in range(length))

    def test_full_absolute_url_is_encoded_without_truncation(self):
        url = "http://127.0.0.1:8080/verify.html?code=OONG-PJLN-6EFS-DZHY-MXBB"
        assert self._decode_payload(url) == url.encode()
        assert len(qrcode.build_matrix(url)) == qrcode.SIZE

    def test_overlong_payload_is_refused_not_truncated(self):
        with pytest.raises(ValueError):
            qrcode.build_matrix("x" * (qrcode.MAX_PAYLOAD + 1))

    def test_reed_solomon_matches_the_standard_example(self):
        # ISO/IEC 18004 Annex I: "01234567" at version 1-M (16 data, 10 EC codewords).
        data = [0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11,
                0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11]
        assert qrcode._rs_encode(data, 10) == [0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7,
                                               0x87, 0x2C, 0x55]

    def test_qr_endpoint_answers_svg(self, client, auth, product):
        batch = _batch(client, auth, product).json()
        response = client.get(f"/api/v1/verify/{batch['verification_code']}/qr")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("image/svg+xml")
