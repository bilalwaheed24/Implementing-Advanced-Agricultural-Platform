"""Shipments, cold chain and recall across organisations.

A shipment is the hand-over: creating it records the batch's shipping event and moves custody
to the receiver, which then sees the shipment and marks it arrived. The cold-chain sensor named
on the shipment, not the device's own claim, binds telemetry to it. A recall reaches every
party to the batch's lineage.
"""
from __future__ import annotations

import secrets
from datetime import timedelta

import pytest

from app.gs1 import with_check_digit
from .conftest import unique
from .test_devices_telemetry import headers_for
from .test_supplychain_e2e import iso, now

SHIPMENTS = "/api/v1/supply-chain/shipments"


def _sscc() -> str:
    return with_check_digit("0" + "".join(secrets.choice("0123456789") for _ in range(16)))


def _gtin() -> str:
    return with_check_digit("0" + "".join(secrets.choice("0123456789") for _ in range(12)))


@pytest.fixture
def chilled_product(client, auth) -> dict:
    response = client.post("/api/v1/supply-chain/products", headers=auth("FARM_OPERATOR"),
                           json={"gtin": _gtin(), "name": "Chilled sweetcorn",
                                 "category": "Chilled vegetables",
                                 "storage_temp_min_c": 0.0, "storage_temp_max_c": 4.0})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
def farm_batch(client, auth, chilled_product) -> dict:
    response = client.post("/api/v1/supply-chain/batches", headers=auth("FARM_OPERATOR"), json={
        "batch_code": unique("SHB"), "product_id": chilled_product["id"], "quantity": 1000.0,
        "unit": "kg", "origin_region": "Iowa", "origin_country": "US",
        "harvested_at": iso(now() - timedelta(days=1))})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
def cold_sensor(client, auth, farm) -> dict:
    response = client.post("/api/v1/devices", headers=auth("FARM_OPERATOR"), json={
        "device_type": "COLD_CHAIN_SENSOR", "model": "ChillProbe", "firmware_version": "2.0.0",
        "farm_id": farm.id, "interval_seconds": 300})
    assert response.status_code == 201, response.text
    device_id = response.json()["device"]["id"]
    assert client.post(f"/api/v1/devices/{device_id}/activate",
                       headers=auth("FARM_OPERATOR")).status_code == 200
    return {"id": device_id, "secret": response.json()["device_secret"]}


def _ship(client, auth, batch_id, role="FARM_OPERATOR", **extra):
    body = {"sscc": _sscc(), "batch_id": batch_id, "carrier": "Cold Freight",
            "origin_name": "Farm gate", "origin_lat": 42.0, "origin_lon": -93.6,
            "destination_name": "Plant A", "destination_lat": 41.9, "destination_lon": -93.4,
            "departed_at": iso(now() - timedelta(hours=2)), **extra}
    return client.post(SHIPMENTS, headers=auth(role), json=body)


def _batch(client, auth, role, batch_id):
    return client.get(f"/api/v1/supply-chain/batches/{batch_id}", headers=auth(role)).json()


def _steps(client, auth, role, batch_id):
    events = client.get(f"/api/v1/supply-chain/batches/{batch_id}/custody",
                        headers=auth(role)).json()["events"]
    return [e["biz_step"] for e in events]


def _reading(client, device, temperature, shipment_id=None):
    readings = {"temp_c": temperature, "humidity_pct": 85.0, "shock_g": 0.3}
    body, headers = headers_for(device["id"], device["secret"], readings)
    if shipment_id:
        body["shipment_id"] = shipment_id
    response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
    assert response.status_code == 202, response.text
    return response.json()


class TestShipmentIsTheHandOver:
    def test_shipping_moves_custody_and_the_receiver_sees_the_shipment(
            self, client, auth, orgs, farm_batch):
        shipped = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id)
        assert shipped.status_code == 201, shipped.text
        shipment = shipped.json()
        assert shipment["status"] == "IN_TRANSIT"
        assert shipment["org_id"] == orgs["FARM"].id
        assert shipment["to_org_id"] == orgs["SUPPLY"].id
        assert shipment["batch_code"] == farm_batch["batch_code"]
        assert shipment["product_name"] == "Chilled sweetcorn"

        batch = _batch(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"])
        assert batch["state"] == "IN_TRANSIT"
        assert batch["custodian_org_id"] == orgs["SUPPLY"].id
        assert _steps(client, auth, "FARM_OPERATOR", farm_batch["id"]) == ["shipping"]

        for role in ("FARM_OPERATOR", "SUPPLY_CHAIN_OPERATOR"):
            listed = client.get(f"{SHIPMENTS}?batch_id={farm_batch['id']}",
                                headers=auth(role)).json()["items"]
            assert [s["id"] for s in listed] == [shipment["id"]], role
            assert client.get(f"{SHIPMENTS}/{shipment['id']}/cold-chain",
                              headers=auth(role)).status_code == 200

    def test_an_unrelated_organisation_cannot_see_it(self, client, auth, orgs, farm_batch,
                                                     rival_auth):
        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        listed = client.get(f"{SHIPMENTS}?page_size=200", headers=rival_auth).json()["items"]
        assert shipment["id"] not in {s["id"] for s in listed}
        assert client.get(f"{SHIPMENTS}/{shipment['id']}/cold-chain",
                          headers=rival_auth).status_code == 404
        assert client.post(f"{SHIPMENTS}/{shipment['id']}/arrive", headers=rival_auth,
                           json={"arrived_at": iso(now())}).status_code == 404

    def test_receiver_marks_it_arrived_and_the_batch_is_received(self, client, auth, orgs,
                                                                 farm_batch):
        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        # The sender cannot sign for the receiver.
        refused = client.post(f"{SHIPMENTS}/{shipment['id']}/arrive",
                              headers=auth("FARM_OPERATOR"), json={"arrived_at": iso(now())})
        assert refused.status_code == 403, refused.text

        arrived = client.post(f"{SHIPMENTS}/{shipment['id']}/arrive",
                              headers=auth("SUPPLY_CHAIN_OPERATOR"),
                              json={"arrived_at": iso(now()), "location_name": "Dock 4"})
        assert arrived.status_code == 200, arrived.text
        assert arrived.json()["status"] == "DELIVERED"
        assert arrived.json()["arrived_at"]
        assert _batch(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"])["state"] \
            == "RECEIVED"
        assert _steps(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"]) \
            == ["shipping", "receiving"]

        again = client.post(f"{SHIPMENTS}/{shipment['id']}/arrive",
                            headers=auth("SUPPLY_CHAIN_OPERATOR"), json={"arrived_at": iso(now())})
        assert again.status_code == 409

    def test_a_receiving_event_closes_the_open_shipment(self, client, auth, orgs, farm_batch):
        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        received = client.post("/api/v1/supply-chain/events",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_id": farm_batch["id"], "biz_step": "receiving", "disposition": "in_storage",
            "occurred_at": iso(now())})
        assert received.status_code == 201, received.text
        listed = client.get(f"{SHIPMENTS}?batch_id={farm_batch['id']}",
                            headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        assert listed[0]["id"] == shipment["id"] and listed[0]["status"] == "DELIVERED"

    def test_an_internal_move_with_an_arrival_date_is_complete(self, client, auth, farm_batch):
        shipped = _ship(client, auth, farm_batch["id"], arrived_at=iso(now()))
        assert shipped.status_code == 201, shipped.text
        assert shipped.json()["status"] == "DELIVERED"
        assert shipped.json()["to_org_id"] is None
        assert _batch(client, auth, "FARM_OPERATOR", farm_batch["id"])["state"] == "RECEIVED"
        assert _steps(client, auth, "FARM_OPERATOR", farm_batch["id"]) \
            == ["shipping", "receiving"]

    def test_a_hand_over_cannot_be_pre_marked_arrived(self, client, auth, orgs, farm_batch):
        response = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id,
                         arrived_at=iso(now()))
        assert response.status_code == 422, response.text

    def test_shipment_after_a_plain_shipping_event_aligns_with_it(self, client, auth, orgs,
                                                                   farm_batch):
        client.post("/api/v1/supply-chain/events", headers=auth("FARM_OPERATOR"), json={
            "batch_id": farm_batch["id"], "biz_step": "shipping", "disposition": "in_transit",
            "occurred_at": iso(now() - timedelta(hours=3))})
        shipped = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id)
        assert shipped.status_code == 201, shipped.text
        # Round 6: the hand-over gets its own shipping event naming the receiver, so the chain
        # of custody records it (it used to move custody with no event naming to_org_id).
        events = client.get(f"/api/v1/supply-chain/batches/{farm_batch['id']}/custody",
                            headers=auth("FARM_OPERATOR")).json()["events"]
        assert [e["biz_step"] for e in events] == ["shipping", "shipping"]
        assert [e["to_org_id"] for e in events] == [None, orgs["SUPPLY"].id]
        assert _batch(client, auth, "SUPPLY_CHAIN_OPERATOR",
                      farm_batch["id"])["custodian_org_id"] == orgs["SUPPLY"].id

    def test_a_recalled_batch_cannot_be_shipped(self, client, auth, farm_batch):
        client.post("/api/v1/supply-chain/events", headers=auth("FARM_OPERATOR"), json={
            "batch_id": farm_batch["id"], "biz_step": "recalling", "disposition": "recalled",
            "occurred_at": iso(now())})
        response = _ship(client, auth, farm_batch["id"])
        assert response.status_code == 422, response.text


class TestColdChainBinding:
    def test_readings_bind_to_the_open_shipment_and_excursions_alert(
            self, client, auth, db, orgs, farm_batch, cold_sensor):
        from app.models import Alert, Telemetry

        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id,
                         cold_chain_device_id=cold_sensor["id"]).json()
        # The sensor sends no shipment id: the binding attaches the reading anyway.
        first = _reading(client, cold_sensor, 3.1)
        db.expire_all()
        assert db.get(Telemetry, first["telemetry_id"]).shipment_id == shipment["id"]

        _reading(client, cold_sensor, 9.5)                       # outside 0..4 °C
        _reading(client, cold_sensor, 11.0)
        db.expire_all()
        alerts = db.query(Alert).filter(Alert.entity_id == shipment["id"],
                                        Alert.category == "COMPLIANCE").all()
        assert len(alerts) == 1, "one open excursion alert per shipment, not one per reading"

        cold = client.get(f"{SHIPMENTS}/{shipment['id']}/cold-chain",
                          headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert cold["readings"] == 3 and cold["temp_max_c"] == 11.0
        assert cold["excursions"] == 2 and cold["within_limits"] is False
        listed = client.get(f"{SHIPMENTS}?batch_id={farm_batch['id']}",
                            headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        assert listed[0]["excursion"] is True
        # The receiver was told before it signs for the goods.
        notes = client.get("/api/v1/notifications?page_size=100",
                           headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["items"]
        assert any(shipment["sscc"] in n["title"] for n in notes)

    def test_a_device_cannot_tag_a_shipment_it_is_not_bound_to(
            self, client, auth, db, farm_batch, cold_sensor, provisioned_device):
        from app.models import Telemetry

        shipment = _ship(client, auth, farm_batch["id"],
                         cold_chain_device_id=cold_sensor["id"]).json()
        # A different device claims the shipment in its message.
        readings = {"soil_moisture_pct": 30.0}
        body, headers = headers_for(provisioned_device["id"], provisioned_device["secret"],
                                    readings)
        body["shipment_id"] = shipment["id"]
        response = client.post("/api/v1/telemetry/ingest", json=body, headers=headers)
        assert response.status_code == 202, response.text
        db.expire_all()
        assert db.get(Telemetry, response.json()["telemetry_id"]).shipment_id is None
        cold = client.get(f"{SHIPMENTS}/{shipment['id']}/cold-chain",
                          headers=auth("FARM_OPERATOR")).json()
        assert cold["readings"] == 0

    def test_readings_after_arrival_are_not_bound(self, client, auth, db, orgs, farm_batch,
                                                  cold_sensor):
        from app.models import Telemetry

        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id,
                         cold_chain_device_id=cold_sensor["id"]).json()
        client.post(f"{SHIPMENTS}/{shipment['id']}/arrive", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                    json={"arrived_at": iso(now() - timedelta(minutes=5))})
        late = _reading(client, cold_sensor, 3.0, shipment_id=shipment["id"])
        db.expire_all()
        assert db.get(Telemetry, late["telemetry_id"]).shipment_id is None

    def test_a_sensor_from_another_organisation_is_refused(self, client, auth, product,
                                                           cold_sensor):
        batch = client.post("/api/v1/supply-chain/batches", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                            json={"batch_code": unique("SB"), "product_id": product.id,
                                  "quantity": 10.0, "unit": "kg", "origin_region": "Iowa",
                                  "origin_country": "US", "harvested_at": iso(now())}).json()
        response = _ship(client, auth, batch["id"], role="SUPPLY_CHAIN_OPERATOR",
                         cold_chain_device_id=cold_sensor["id"])
        assert response.status_code == 404, response.text

    def test_a_sensor_travels_with_one_shipment_at_a_time(self, client, auth, chilled_product,
                                                          farm_batch, cold_sensor):
        assert _ship(client, auth, farm_batch["id"],
                     cold_chain_device_id=cold_sensor["id"]).status_code == 201
        other = client.post("/api/v1/supply-chain/batches", headers=auth("FARM_OPERATOR"), json={
            "batch_code": unique("SHB"), "product_id": chilled_product["id"], "quantity": 5.0,
            "unit": "kg", "origin_region": "Iowa", "origin_country": "US",
            "harvested_at": iso(now())}).json()
        response = _ship(client, auth, other["id"], cold_chain_device_id=cold_sensor["id"])
        assert response.status_code == 409, response.text


class TestRecall:
    def test_children_take_quantity_from_the_parent(self, client, auth, orgs, farm_batch,
                                                    product):
        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        client.post(f"{SHIPMENTS}/{shipment['id']}/arrive", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                    json={"arrived_at": iso(now())})

        def derive(quantity):
            return client.post("/api/v1/supply-chain/batches",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
                "batch_code": unique("CH"), "product_id": product.id,
                "parent_batch_id": farm_batch["id"], "quantity": quantity, "unit": "kg",
                "origin_region": "Iowa", "origin_country": "US", "harvested_at": iso(now())})

        assert derive(700.0).status_code == 201
        assert _batch(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"])["quantity"] \
            == pytest.approx(300.0)
        assert derive(700.0).status_code == 422           # only 300 kg left
        assert derive(300.0).status_code == 201

    def test_recall_reaches_the_lineage_and_flags_children(self, client, auth, db, orgs,
                                                           farm_batch, product):
        from app.models import Alert

        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        client.post(f"{SHIPMENTS}/{shipment['id']}/arrive", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                    json={"arrived_at": iso(now())})
        child = client.post("/api/v1/supply-chain/batches",
                            headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_code": unique("CH"), "product_id": product.id,
            "parent_batch_id": farm_batch["id"], "quantity": 400.0, "unit": "kg",
            "origin_region": "Iowa", "origin_country": "US", "harvested_at": iso(now())})
        assert child.status_code == 201, child.text
        child = child.json()

        # The farm owns the batch but no longer holds it; it may still recall it.
        recall = client.post("/api/v1/supply-chain/events", headers=auth("FARM_OPERATOR"), json={
            "batch_id": farm_batch["id"], "biz_step": "recalling", "disposition": "recalled",
            "occurred_at": iso(now())})
        assert recall.status_code == 201, recall.text
        assert _batch(client, auth, "FARM_OPERATOR", farm_batch["id"])["state"] == "RECALLED"

        flagged = _batch(client, auth, "SUPPLY_CHAIN_OPERATOR", child["id"])
        assert flagged["integrity_status"] == "SUSPECT"
        db.expire_all()
        assert db.query(Alert).filter(Alert.entity_id == child["id"],
                                      Alert.category == "COMPLIANCE",
                                      Alert.status == "OPEN").count() == 1

        for role in ("FARM_OPERATOR", "SUPPLY_CHAIN_OPERATOR"):
            notes = client.get("/api/v1/notifications?page_size=100",
                               headers=auth(role)).json()["items"]
            assert any(n["category"] == "RECALL" and farm_batch["batch_code"] in n["title"]
                       for n in notes), role

        # A recalled batch cannot parent new product.
        derived = client.post("/api/v1/supply-chain/batches",
                              headers=auth("SUPPLY_CHAIN_OPERATOR"), json={
            "batch_code": unique("CH"), "product_id": product.id,
            "parent_batch_id": farm_batch["id"], "quantity": 1.0, "unit": "kg",
            "origin_region": "Iowa", "origin_country": "US", "harvested_at": iso(now())})
        assert derived.status_code == 422, derived.text

    def test_an_unrelated_organisation_cannot_recall(self, client, auth, farm_batch,
                                                     rival_auth):
        response = client.post("/api/v1/supply-chain/events", headers=rival_auth, json={
            "batch_id": farm_batch["id"], "biz_step": "recalling", "disposition": "recalled",
            "occurred_at": iso(now())})
        assert response.status_code == 404
