"""Backend support for the console's polish pass: role-fitted dashboard tiles, the caller's
organisation name, crop status updates, batch fields the lists need, and user search."""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from app.gs1 import with_check_digit
from .conftest import unique


def _dash(client, auth, role):
    response = client.get("/api/v1/dashboard", headers=auth(role))
    assert response.status_code == 200, response.text
    return response.json()


class TestRoleFittedDashboard:
    def test_supply_operator_gets_custody_tiles_not_fleet_tiles(self, client, auth):
        body = _dash(client, auth, "SUPPLY_CHAIN_OPERATOR")
        for absent in ("devices", "telemetry", "gmo", "ledger", "certifications"):
            assert absent not in body, absent
        for key in ("held", "shipments_in_transit", "pending_handovers"):
            assert isinstance(body["supply_chain"][key], int)

    def test_certifier_gets_certificate_tiles(self, client, auth):
        body = _dash(client, auth, "CERTIFIER")
        for absent in ("devices", "telemetry", "gmo", "supply_chain", "ledger"):
            assert absent not in body, absent
        for key in ("issued", "active", "expiring", "claimed"):
            assert isinstance(body["certifications"][key], int)

    def test_researcher_has_no_fleet_or_ledger_tile(self, client, auth):
        body = _dash(client, auth, "BIOTECH_RESEARCHER")
        assert "devices" not in body and "telemetry" not in body and "ledger" not in body
        assert "gmo" in body

    def test_farm_sees_gmo_material_it_holds(self, client, auth):
        body = _dash(client, auth, "FARM_OPERATOR")
        assert "gmo" not in body and "ledger" not in body
        assert set(body["gmo_holdings"]) == {"seed_lots", "batches"}
        assert "devices" in body

    def test_device_count_is_live(self, client, auth, farm, field):
        before = _dash(client, auth, "FARM_OPERATOR")["devices"]["total"]
        created = client.post("/api/v1/devices", headers=auth("FARM_OPERATOR"), json={
            "device_type": "SOIL_SENSOR", "model": "DashProbe", "firmware_version": "1.0.0",
            "farm_id": farm.id, "field_id": field.id, "interval_seconds": 900})
        assert created.status_code == 201, created.text
        assert _dash(client, auth, "FARM_OPERATOR")["devices"]["total"] == before + 1


def test_me_names_the_callers_organisation(client, auth, orgs):
    body = client.get("/api/v1/auth/me", headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
    assert body["org_name"] == orgs["SUPPLY"].name


class TestCropStatus:
    def _crop(self, client, auth, field):
        response = client.post("/api/v1/crops", headers=auth("FARM_OPERATOR"),
                               json={"field_id": field.id, "crop_type": "Maize"})
        assert response.status_code == 201, response.text
        return response.json()

    def test_grower_marks_a_crop_harvested(self, client, auth, field):
        crop = self._crop(client, auth, field)
        response = client.patch(f"/api/v1/crops/{crop['id']}", headers=auth("FARM_OPERATOR"),
                                json={"status": "HARVESTED"})
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "HARVESTED"

    def test_unknown_status_is_refused(self, client, auth, field):
        crop = self._crop(client, auth, field)
        response = client.patch(f"/api/v1/crops/{crop['id']}", headers=auth("FARM_OPERATOR"),
                                json={"status": "EATEN"})
        assert response.status_code in (400, 422)

    def test_needs_farm_write(self, client, auth, field):
        crop = self._crop(client, auth, field)
        response = client.patch(f"/api/v1/crops/{crop['id']}", headers=auth("AGRONOMIST"),
                                json={"status": "HARVESTED"})
        assert response.status_code == 403

    def test_another_farm_cannot_touch_it(self, client, auth, rival_auth, field):
        crop = self._crop(client, auth, field)
        response = client.patch(f"/api/v1/crops/{crop['id']}", headers=rival_auth,
                                json={"status": "FAILED"})
        assert response.status_code == 404


def test_batch_list_carries_crop_and_product_name(client, auth, field):
    crop = client.post("/api/v1/crops", headers=auth("FARM_OPERATOR"),
                       json={"field_id": field.id, "crop_type": "Maize"}).json()
    gtin = with_check_digit("0" + "".join(secrets.choice("0123456789") for _ in range(12)))
    product = client.post("/api/v1/supply-chain/products", headers=auth("FARM_OPERATOR"),
                          json={"gtin": gtin, "name": "Polish maize", "category": "Grain"}).json()
    harvested = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    batch = client.post("/api/v1/supply-chain/batches", headers=auth("FARM_OPERATOR"), json={
        "batch_code": unique("FS"), "product_id": product["id"], "crop_id": crop["id"],
        "quantity": 100.0, "unit": "kg", "origin_region": "Iowa", "origin_country": "US",
        "harvested_at": harvested})
    assert batch.status_code == 201, batch.text
    assert batch.json()["crop_id"] == crop["id"]
    assert batch.json()["product_name"] == "Polish maize"
    listed = client.get("/api/v1/supply-chain/batches?page_size=200",
                        headers=auth("FARM_OPERATOR")).json()["items"]
    row = next(item for item in listed if item["id"] == batch.json()["id"])
    assert row["crop_id"] == crop["id"] and row["product_name"] == "Polish maize"


def test_user_search_matches_email_or_name(client, auth, users):
    response = client.get("/api/v1/admin/users?q=supply_chain", headers=auth("ADMIN"))
    assert response.status_code == 200, response.text
    emails = {row["email"] for row in response.json()["items"]}
    assert users["SUPPLY_CHAIN_OPERATOR"].email in emails
    assert users["FARM_OPERATOR"].email not in emails
    # A LIKE wildcard in the term is matched literally.
    assert client.get("/api/v1/admin/users?q=%25", headers=auth("ADMIN")).json()["total"] == 0
