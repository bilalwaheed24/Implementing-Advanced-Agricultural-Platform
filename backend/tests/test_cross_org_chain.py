"""The seed-to-consumer chain across organisations, driven through the API.

Developer supplies seed to a farm -> farm plants it -> farm harvests a batch from the crop
and hands it to the processor -> processor receives it and claims its certification ->
the consumer verifies it. Each hand-over makes the record visible to the receiver only.
"""
from __future__ import annotations

import secrets
from datetime import timedelta

import pytest

from app.gs1 import with_check_digit
from .conftest import unique
from .test_supplychain_e2e import gmo_event, iso, now  # noqa: F401  (shared fixture)


@pytest.fixture
def supplied_lot(client, auth, gmo_event, orgs):
    """An approved GMO seed lot that the developer has supplied to the farm."""
    approval = client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals",
                           headers=auth("REGULATOR"),
                           json={"jurisdiction": "US-USDA", "status": "APPROVED"})
    assert approval.status_code in (200, 201), approval.text
    lot = client.post("/api/v1/gmo/seed-lots", headers=auth("BIOTECH_RESEARCHER"), json={
        "lot_code": unique("SL"), "gmo_event_id": gmo_event["id"], "crop_type": "Maize",
        "variety": "V1", "quantity_kg": 800.0, "produced_at": iso(now())}).json()
    moved = client.post(f"/api/v1/gmo/seed-lots/{lot['id']}/transfer",
                        headers=auth("BIOTECH_RESEARCHER"), json={"to_org_id": orgs["FARM"].id})
    assert moved.status_code == 200, moved.text
    return {**moved.json(), "event": gmo_event}


def _farm_product(client, auth) -> dict:
    gtin = with_check_digit("0" + "".join(secrets.choice("0123456789") for _ in range(12)))
    response = client.post("/api/v1/supply-chain/products", headers=auth("FARM_OPERATOR"),
                           json={"gtin": gtin, "name": "Field maize, bulk", "category": "Grain"})
    assert response.status_code == 201, response.text
    return response.json()


def _event(client, auth, role, batch_id, step, disposition, **extra):
    return client.post("/api/v1/supply-chain/events", headers=auth(role), json={
        "batch_id": batch_id, "biz_step": step, "disposition": disposition,
        "occurred_at": iso(now()), **extra})


class TestSeedSupply:
    def test_farm_sees_the_supplied_lot_with_its_event_code(self, client, auth, supplied_lot):
        lots = client.get("/api/v1/gmo/seed-lots?page_size=200",
                          headers=auth("FARM_OPERATOR")).json()["items"]
        mine = [lot for lot in lots if lot["id"] == supplied_lot["id"]]
        assert mine and mine[0]["gmo_event_code"] == supplied_lot["event"]["event_code"]

    def test_an_unrelated_organisation_does_not_see_it(self, client, auth, supplied_lot):
        lots = client.get("/api/v1/gmo/seed-lots?page_size=200",
                          headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        assert supplied_lot["id"] not in {lot["id"] for lot in lots}

    def test_seed_goes_only_to_farms(self, client, auth, gmo_event, orgs):
        client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals", headers=auth("REGULATOR"),
                    json={"jurisdiction": "EU", "status": "APPROVED"})
        lot = client.post("/api/v1/gmo/seed-lots", headers=auth("BIOTECH_RESEARCHER"), json={
            "lot_code": unique("SL"), "gmo_event_id": gmo_event["id"], "crop_type": "Maize",
            "variety": "V1", "quantity_kg": 10.0, "produced_at": iso(now())}).json()
        response = client.post(f"/api/v1/gmo/seed-lots/{lot['id']}/transfer",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"to_org_id": orgs["SUPPLY"].id})
        assert response.status_code == 422

    def test_planting_from_the_lot_inherits_its_gmo_event(self, client, auth, field,
                                                         supplied_lot):
        crop = client.post("/api/v1/crops", headers=auth("FARM_OPERATOR"), json={
            "field_id": field.id, "crop_type": "Maize", "seed_lot_id": supplied_lot["id"],
            "planted_at": iso(now() - timedelta(days=120))})
        assert crop.status_code == 201, crop.text
        assert crop.json()["gmo_event_id"] == supplied_lot["event"]["id"]


class TestHarvestToProcessor:
    def test_the_full_hand_over(self, client, auth, field, farm, orgs, supplied_lot):
        crop = client.post("/api/v1/crops", headers=auth("FARM_OPERATOR"), json={
            "field_id": field.id, "crop_type": "Maize",
            "seed_lot_id": supplied_lot["id"]}).json()
        product = _farm_product(client, auth)
        batch = client.post("/api/v1/supply-chain/batches", headers=auth("FARM_OPERATOR"), json={
            "batch_code": unique("H"), "product_id": product["id"], "crop_id": crop["id"],
            "quantity": 5000.0, "unit": "kg", "origin_region": "Iowa", "origin_country": "US",
            "harvested_at": iso(now() - timedelta(days=1))})
        assert batch.status_code == 201, batch.text
        batch = batch.json()
        # Lineage came from the crop, not from retyped ids.
        assert batch["farm_id"] == farm.id
        assert batch["seed_lot_id"] == supplied_lot["id"]
        assert batch["gmo_event_id"] == supplied_lot["event"]["id"]

        assert _event(client, auth, "FARM_OPERATOR", batch["id"], "harvesting",
                      "in_progress", quantity=5000.0, unit="kg").status_code == 201
        shipped = _event(client, auth, "FARM_OPERATOR", batch["id"], "shipping", "in_transit",
                         to_org_id=orgs["SUPPLY"].id)
        assert shipped.status_code == 201, shipped.text

        # The processor now holds it and was told so.
        assert client.get(f"/api/v1/supply-chain/batches/{batch['id']}",
                          headers=auth("SUPPLY_CHAIN_OPERATOR")).status_code == 200
        notes = client.get("/api/v1/notifications?page_size=50",
                           headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        assert any(batch["batch_code"] in n["title"] for n in notes)

        # The farm keeps read access but can no longer act on what it no longer holds.
        late = _event(client, auth, "FARM_OPERATOR", batch["id"], "receiving", "in_storage")
        assert late.status_code == 403
        received = _event(client, auth, "SUPPLY_CHAIN_OPERATOR", batch["id"], "receiving",
                          "in_storage")
        assert received.status_code == 201, received.text

        context = client.get(f"/api/v1/supply-chain/batches/{batch['id']}/custody",
                             headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["context"]
        assert context["owner"]["id"] == orgs["FARM"].id
        assert context["custodian"]["id"] == orgs["SUPPLY"].id
        assert context["farm"]["name"] == farm.name
        assert context["gmo"]["event_code"] == supplied_lot["event"]["event_code"]
        assert {"jurisdiction": "US-USDA", "status": "APPROVED", "expires_at": None} \
            in context["gmo"]["approvals"]

        # The processor claims its own certification on the received batch.
        cert = client.post("/api/v1/supply-chain/certifications", headers=auth("CERTIFIER"),
                           json={"cert_code": unique("SPC"), "cert_type": "SPECIALTY",
                                 "standard": "Specialty Crop Standard",
                                 "subject_org_id": orgs["SUPPLY"].id, "scope": "Processing",
                                 "valid_from": iso(now() - timedelta(days=1)),
                                 "valid_to": iso(now() + timedelta(days=365))})
        assert cert.status_code == 201, cert.text
        stolen = client.post(f"/api/v1/supply-chain/certifications/{cert.json()['id']}/link",
                             headers=auth("FARM_OPERATOR"), json={"batch_id": batch["id"]})
        assert stolen.status_code == 403
        linked = client.post(f"/api/v1/supply-chain/certifications/{cert.json()['id']}/link",
                             headers=auth("SUPPLY_CHAIN_OPERATOR"), json={"batch_id": batch["id"]})
        assert linked.status_code == 201, linked.text

        public = client.get(f"/api/v1/verify/{batch['verification_code']}").json()
        assert public["gmo_event_code"] == supplied_lot["event"]["event_code"]
        assert [c for c in public["certifications"]]


class TestOnboarding:
    def test_every_role_can_list_trading_partners_but_nothing_more(self, client, auth, orgs):
        rows = client.get("/api/v1/admin/organizations/directory",
                          headers=auth("FARM_OPERATOR")).json()
        assert {orgs["SUPPLY"].id, orgs["BIOTECH"].id} <= {r["id"] for r in rows}
        assert set(rows[0]) == {"id", "name", "org_type"}

    def test_admin_onboards_a_farm_operator_who_can_sign_in(self, client, auth, orgs):
        email = f"{unique('grower').lower()}@test.absp"
        created = client.post("/api/v1/admin/users", headers=auth("ADMIN"), json={
            "email": email, "full_name": "New Grower", "password": "Temp-Passw0rd!2026",
            "org_id": orgs["FARM"].id, "role": "FARM_OPERATOR"})
        assert created.status_code == 201, created.text
        assert created.json()["status"] == "ACTIVE"
        login = client.post("/api/v1/auth/login",
                            json={"email": email, "password": "Temp-Passw0rd!2026"})
        assert login.status_code == 200, login.text

    def test_a_privileged_role_still_needs_approval(self, client, auth, orgs):
        created = client.post("/api/v1/admin/users", headers=auth("ADMIN"), json={
            "email": f"{unique('cert').lower()}@test.absp", "full_name": "New Certifier",
            "password": "Temp-Passw0rd!2026", "org_id": orgs["REGULATOR"].id,
            "role": "CERTIFIER"})
        assert created.status_code == 201, created.text
        assert created.json()["status"] == "PENDING"

    def test_only_user_admins_onboard(self, client, auth, orgs):
        response = client.post("/api/v1/admin/users", headers=auth("FARM_OPERATOR"), json={
            "email": f"{unique('x').lower()}@test.absp", "full_name": "X",
            "password": "Temp-Passw0rd!2026", "org_id": orgs["FARM"].id,
            "role": "FARM_OPERATOR"})
        assert response.status_code == 403


class TestReviewFindings:
    """Regressions for the independent review of the cross-organisation chain."""

    def test_gmo_through_a_seed_lot_still_needs_a_live_approval(self, client, auth, product,
                                                               gmo_event, db):
        """Naming only the seed lot must not carry a lapsed event past the approval gate."""
        from app.models import GMOApproval, SeedLot
        client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals", headers=auth("REGULATOR"),
                    json={"jurisdiction": "US-USDA", "status": "APPROVED"})
        lot = client.post("/api/v1/gmo/seed-lots", headers=auth("BIOTECH_RESEARCHER"), json={
            "lot_code": unique("SL"), "gmo_event_id": gmo_event["id"], "crop_type": "Maize",
            "variety": "V1", "quantity_kg": 10.0, "produced_at": iso(now())}).json()
        approval = db.query(GMOApproval).filter(
            GMOApproval.gmo_event_id == gmo_event["id"]).one()
        approval.expires_at = now() - timedelta(days=1)             # the approval lapses
        db.commit()
        response = client.post("/api/v1/supply-chain/batches",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_code": unique("B"), "product_id": product.id, "quantity": 10.0,
            "unit": "kg", "seed_lot_id": lot["id"], "origin_region": "Iowa",
            "origin_country": "US", "harvested_at": iso(now())})
        assert response.status_code == 422, response.text
        assert db.get(SeedLot, lot["id"]) is not None

    def test_crop_lineage_cannot_be_overridden(self, client, auth, field, supplied_lot, orgs):
        crop = client.post("/api/v1/crops", headers=auth("FARM_OPERATOR"), json={
            "field_id": field.id, "crop_type": "Maize",
            "seed_lot_id": supplied_lot["id"]}).json()
        other_lot = client.post("/api/v1/gmo/seed-lots", headers=auth("BIOTECH_RESEARCHER"),
                                json={"lot_code": unique("SL"), "crop_type": "Maize",
                                      "variety": "V2", "quantity_kg": 5.0,
                                      "produced_at": iso(now())}).json()
        product = _farm_product(client, auth)
        response = client.post("/api/v1/supply-chain/batches", headers=auth("FARM_OPERATOR"),
                               json={"batch_code": unique("H"), "product_id": product["id"],
                                     "crop_id": crop["id"], "seed_lot_id": other_lot["id"],
                                     "quantity": 10.0, "unit": "kg",
                                     "origin_region": "Iowa", "origin_country": "US",
                                     "harvested_at": iso(now())})
        assert response.status_code == 422, response.text
        assert "does not match" in response.json()["detail"]

    def test_former_holder_cannot_ship_a_handed_over_batch(self, client, auth, product, orgs):
        batch = client.post("/api/v1/supply-chain/batches",
                            headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_code": unique("B"), "product_id": product.id, "quantity": 10.0,
            "unit": "kg", "origin_region": "Iowa", "origin_country": "US",
            "harvested_at": iso(now())}).json()
        _event(client, auth, "SUPPLY_CHAIN_OPERATOR", batch["id"], "shipping", "in_transit",
               to_org_id=orgs["FARM"].id)
        response = client.post("/api/v1/supply-chain/shipments",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "sscc": with_check_digit("0" + "".join(secrets.choice("0123456789")
                                                   for _ in range(16))),
            "batch_id": batch["id"], "carrier": "Test Carrier", "origin_name": "Plant A",
            "origin_lat": 41.9, "origin_lon": -93.4, "destination_name": "Hub B",
            "destination_lat": 41.9, "destination_lon": -87.6, "departed_at": iso(now())})
        assert response.status_code == 403, response.text

    def test_partner_directory_is_limited_to_roles_that_hand_over(self, client, auth):
        assert client.get("/api/v1/admin/organizations/directory",
                          headers=auth("AGRONOMIST")).status_code == 403
        assert client.get("/api/v1/admin/organizations/directory",
                          headers=auth("BIOTECH_RESEARCHER")).status_code == 200
