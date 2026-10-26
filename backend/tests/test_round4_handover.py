"""Round 4: shipment and hand-over consistency, dashboard counts and links, and the
certifier's read-only batch page.

A batch on the road is counted once (awaiting arrival), and one that has reached its holder
but was not booked in is counted once more only after it arrives; any first step by the
holder (receiving, storing, processing) closes the open shipment with the arrival's side
effects and settles the hand-over notification. A certifier reading a batch through its
certificate is told so (viewer_access) and sees the batch's shipments read-only. The GMO
filter follows lineage, and the dashboard's alert and certificate tiles match the lists they
link to.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.core.security import utcnow
from app.models import Alert, Batch, Notification, SeedLot
from .conftest import unique
from .test_round3_supply import _arrive, _claim, _event, _issue
from .test_shipments_recall import _ship, chilled_product, farm_batch  # noqa: F401
from .test_supplychain_e2e import gmo_event, iso, now  # noqa: F401

API = "/api/v1"


def _ids(response) -> set[str]:
    assert response.status_code == 200, response.text
    return {row["id"] for row in response.json()["items"]}


def _shipments(client, auth, role, query):
    response = client.get(f"{API}/supply-chain/shipments?{query}&page_size=200",
                          headers=auth(role))
    assert response.status_code == 200, response.text
    return response.json()["items"]


def _supply_tiles(client, auth):
    return client.get(f"{API}/dashboard", headers=auth("SUPPLY_CHAIN_OPERATOR")
                      ).json()["supply_chain"]


def _awaiting_receipt(client, auth, role="SUPPLY_CHAIN_OPERATOR") -> set[str]:
    return _ids(client.get(f"{API}/supply-chain/batches?awaiting_receipt=true&page_size=200",
                           headers=auth(role)))


# --------------------------------------------------------------------------- #
# 1-2. The certifier's read-only batch page
# --------------------------------------------------------------------------- #
class TestViewerAccess:
    def test_each_reader_is_told_why_it_sees_the_batch(self, client, auth, orgs, farm_batch):
        cert = _issue(client, auth, orgs["FARM"].id)
        _claim(client, auth, cert, farm_batch["id"])
        expected = {"FARM_OPERATOR": "party", "CERTIFIER": "certificate",
                    "REGULATOR": "oversight"}
        for role, access in expected.items():
            batch = client.get(f"{API}/supply-chain/batches/{farm_batch['id']}",
                               headers=auth(role))
            assert batch.status_code == 200, (role, batch.text)
            assert batch.json()["viewer_access"] == access, role
            custody = client.get(f"{API}/supply-chain/batches/{farm_batch['id']}/custody",
                                 headers=auth(role)).json()
            assert custody["batch"]["viewer_access"] == access, role
        # The page hides the verify action for "certificate" because the API refuses it.
        assert client.post(f"{API}/supply-chain/batches/{farm_batch['id']}/verify",
                           headers=auth("CERTIFIER")).status_code == 404

    def test_the_receiver_is_a_party(self, client, auth, orgs, farm_batch):
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201
        batch = client.get(f"{API}/supply-chain/batches/{farm_batch['id']}",
                           headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert batch["viewer_access"] == "party"


class TestShipmentsOfAReadableBatch:
    def test_the_certifier_sees_the_shipments_of_a_certified_batch(self, client, auth, orgs,
                                                                     farm_batch,
                                                                     rival_auth):
        cert = _issue(client, auth, orgs["FARM"].id)
        _claim(client, auth, cert, farm_batch["id"])
        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        listed = _shipments(client, auth, "CERTIFIER", f"batch_id={farm_batch['id']}")
        assert [row["id"] for row in listed] == [shipment["id"]]
        # Read-only: the certifier is not the receiver, so it cannot mark it arrived.
        refused = client.post(f"{API}/supply-chain/shipments/{shipment['id']}/arrive",
                              headers=auth("CERTIFIER"), json={"arrived_at": iso(now())})
        assert refused.status_code in (403, 404)
        # A stranger to the batch still learns nothing.
        stranger = client.get(f"{API}/supply-chain/shipments?batch_id={farm_batch['id']}",
                              headers=rival_auth)
        assert stranger.status_code == 200 and stranger.json()["items"] == []

    def test_an_uncertified_batch_shows_the_certifier_nothing(self, client, auth, orgs,
                                                              farm_batch):
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201
        assert _shipments(client, auth, "CERTIFIER", f"batch_id={farm_batch['id']}") == []

    def test_the_owner_sees_an_onward_shipment_it_is_not_party_to(self, client, auth, orgs,
                                                                   farm_batch,
                                                                   second_farm_org):
        first = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        _arrive(client, auth, first["id"])
        onward = _ship(client, auth, farm_batch["id"], role="SUPPLY_CHAIN_OPERATOR",
                       to_org_id=second_farm_org.id, departed_at=iso(now())).json()
        listed = {row["id"] for row in _shipments(client, auth, "FARM_OPERATOR",
                                                   f"batch_id={farm_batch['id']}")}
        assert {first["id"], onward["id"]} <= listed
        # The intermediate processor no longer reads the batch: only its own shipments.
        mine = {row["id"] for row in _shipments(client, auth, "SUPPLY_CHAIN_OPERATOR",
                                                 f"batch_id={farm_batch['id']}")}
        assert mine == {first["id"], onward["id"]}


# --------------------------------------------------------------------------- #
# 3. Hand-overs: counted once, closed by the holder's first step
# --------------------------------------------------------------------------- #
class TestHandoverCounts:
    def test_an_in_transit_batch_is_awaiting_arrival_not_booking(self, client, auth, orgs,
                                                                farm_batch):
        before = _supply_tiles(client, auth)
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201
        after = _supply_tiles(client, auth)
        assert after["awaiting_arrival"] == before["awaiting_arrival"] + 1
        assert after["pending_handovers"] == before["pending_handovers"]
        assert farm_batch["id"] not in _awaiting_receipt(client, auth)

    def test_an_unrelated_handover_does_not_reopen_a_booked_batch(self, client, auth, orgs,
                                                                 farm_batch, chilled_product,
                                                                 second_farm_org):
        """The booking rule is per batch: a later hand-over of some other batch, anywhere on
        the platform, must not put an already booked-in batch back on the list."""
        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id,
                         departed_at=iso(now() - timedelta(hours=3))).json()
        arrived = client.post(f"{API}/supply-chain/shipments/{shipment['id']}/arrive",
                              headers=auth("SUPPLY_CHAIN_OPERATOR"),
                              json={"arrived_at": iso(now() - timedelta(hours=2))})
        assert arrived.status_code == 200, arrived.text
        booked_tiles = _supply_tiles(client, auth)
        assert farm_batch["id"] not in _awaiting_receipt(client, auth)

        other = client.post(f"{API}/supply-chain/batches", headers=auth("FARM_OPERATOR"), json={
            "batch_code": unique("SHB"), "product_id": chilled_product["id"],
            "quantity": 500.0, "unit": "kg", "origin_region": "Iowa", "origin_country": "US",
            "harvested_at": iso(now() - timedelta(days=1))}).json()
        # Handed over after the first batch was booked in: with the bug, its hand-over time
        # was taken as every batch's, so the first batch looked unbooked again.
        assert _ship(client, auth, other["id"], to_org_id=second_farm_org.id,
                     departed_at=iso(now() - timedelta(hours=1))).status_code == 201

        assert farm_batch["id"] not in _awaiting_receipt(client, auth)
        assert _supply_tiles(client, auth)["pending_handovers"] == \
            booked_tiles["pending_handovers"]

    def test_storing_instead_of_receiving_closes_the_shipment(self, client, auth, db, users,
                                                              orgs, farm_batch):
        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        before = _supply_tiles(client, auth)
        stored = _event(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"], "storing",
                        "in_storage", location_name="Cold store 2")
        assert stored.status_code == 201, stored.text
        listed = _shipments(client, auth, "FARM_OPERATOR", f"batch_id={farm_batch['id']}")
        assert listed[0]["status"] == "DELIVERED" and listed[0]["arrived_at"]
        after = _supply_tiles(client, auth)
        assert after["awaiting_arrival"] == before["awaiting_arrival"] - 1
        assert after["pending_handovers"] == before["pending_handovers"]
        assert farm_batch["id"] not in _awaiting_receipt(client, auth)
        # The arrival's side effects: the sender is told.
        db.expire_all()
        told = [n for n in db.execute(select(Notification).where(
            Notification.user_id == users["FARM_OPERATOR"].id)).scalars()
            if n.title == f"Shipment {shipment['sscc']} arrived"]
        assert told and "Cold store 2" in told[-1].body

    def test_a_handover_without_a_shipment_is_booked_in_by_storing(self, client, auth, orgs,
                                                                   farm_batch):
        """Only a shipping event may hand a batch over (round-4 release gate), so a hand-over
        made by a bare shipping event, with no shipment record, leaves the batch in transit:
        it is not yet the receiver's to book in, and the receiver's first own step books it."""
        refused = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "harvesting",
                         "in_progress", to_org_id=orgs["SUPPLY"].id)
        assert refused.status_code == 422, refused.text
        handed = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "shipping",
                        "in_transit", to_org_id=orgs["SUPPLY"].id)
        assert handed.status_code == 201, handed.text
        # In transit: counted as awaiting arrival, not as a hand-over to book in.
        assert farm_batch["id"] not in _awaiting_receipt(client, auth)
        assert farm_batch["id"] not in _awaiting_receipt(client, auth, "FARM_OPERATOR")
        stored = _event(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"], "storing",
                        "in_storage")
        assert stored.status_code == 201, stored.text
        assert farm_batch["id"] not in _awaiting_receipt(client, auth)
        batch = client.get(f"/api/v1/supply-chain/batches/{farm_batch['id']}",
                           headers=auth("SUPPLY_CHAIN_OPERATOR")).json()
        assert batch["state"] == "STORED"


# --------------------------------------------------------------------------- #
# 5. The hand-over notification
# --------------------------------------------------------------------------- #
def test_handover_notification_wording_and_settled_on_arrival(client, auth, db, users, orgs,
                                                              farm_batch):
    shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()

    def handover():
        db.expire_all()
        return [n for n in db.execute(select(Notification).where(
            Notification.user_id == users["SUPPLY_CHAIN_OPERATOR"].id,
            Notification.category == "HANDOVER",
            Notification.entity_id == farm_batch["id"])).scalars()]

    notes = handover()
    assert notes and "Mark it arrived when it reaches you" in notes[-1].body
    assert "Record its receipt" not in notes[-1].body
    assert notes[-1].read_at is None
    _arrive(client, auth, shipment["id"])
    assert all(n.read_at is not None for n in handover())


# --------------------------------------------------------------------------- #
# 4. Dashboard links: shipments, certificates, alerts
# --------------------------------------------------------------------------- #
def test_incoming_shipment_filter(client, auth, orgs, farm_batch):
    shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
    incoming = {r["id"] for r in _shipments(client, auth, "SUPPLY_CHAIN_OPERATOR",
                                             "status=IN_TRANSIT&incoming=true")}
    assert shipment["id"] in incoming
    assert shipment["id"] not in {r["id"] for r in _shipments(
        client, auth, "FARM_OPERATOR", "status=IN_TRANSIT&incoming=true")}
    assert shipment["id"] in {r["id"] for r in _shipments(
        client, auth, "FARM_OPERATOR", "status=IN_TRANSIT&incoming=false")}
    count = client.get(f"{API}/supply-chain/shipments?status=IN_TRANSIT&incoming=true",
                       headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["total"]
    assert count == _supply_tiles(client, auth)["awaiting_arrival"]


def test_certificate_filters_match_the_dashboard_tiles(client, auth, orgs, farm_batch):
    soon = client.post(f"{API}/supply-chain/certifications", headers=auth("CERTIFIER"), json={
        "cert_code": unique("R4S"), "cert_type": "SPECIALTY", "standard": "Test Std",
        "subject_org_id": orgs["FARM"].id, "scope": "Whole-farm crop production",
        "valid_from": iso(now() - timedelta(days=1)),
        "valid_to": iso(now() + timedelta(days=10))})
    assert soon.status_code == 201, soon.text
    later = _issue(client, auth, orgs["FARM"].id)
    _claim(client, auth, later, farm_batch["id"])
    headers = auth("CERTIFIER")

    def listing(query):
        response = client.get(f"{API}/supply-chain/certifications?{query}&page_size=200",
                              headers=headers)
        assert response.status_code == 200, response.text
        return response.json()

    expiring = listing("expiring_within_days=30&issued_by_me=true")
    assert soon.json()["id"] in {c["id"] for c in expiring["items"]}
    assert later["id"] not in {c["id"] for c in expiring["items"]}
    claimed = listing("claimed=true&issued_by_me=true")
    assert later["id"] in {c["id"] for c in claimed["items"]}
    assert soon.json()["id"] not in {c["id"] for c in claimed["items"]}
    assert all(c["claimed_batches"] for c in claimed["items"])
    assert all(c["status"] == "ACTIVE" for c in listing("status=ACTIVE")["items"])

    tiles = client.get(f"{API}/dashboard", headers=headers).json()["certifications"]
    window = tiles["expiry_window_days"]
    assert tiles["expiring"] == listing(
        f"expiring_within_days={window}&issued_by_me=true")["total"]
    assert tiles["issued"] == listing("issued_by_me=true")["total"]


def test_unresolved_alert_filter_matches_the_tile(client, auth, db, orgs):
    made = []
    for status in ("OPEN", "ACKNOWLEDGED", "RESOLVED"):
        alert = Alert(category="COMPLIANCE", severity="HIGH", title=unique(f"R4 {status}"),
                      status=status, org_id=orgs["FARM"].id)
        db.add(alert)
        made.append(alert)
    db.commit()
    headers = auth("FARM_OPERATOR")
    listed = client.get(f"{API}/security/alerts?status=UNRESOLVED&page_size=200",
                        headers=headers)
    ids = _ids(listed)
    assert made[0].id in ids and made[1].id in ids and made[2].id not in ids
    assert all(row["status"] in {"OPEN", "ACKNOWLEDGED"} for row in listed.json()["items"])
    tile = client.get(f"{API}/dashboard", headers=headers).json()["alerts"]
    assert tile["open"] == listed.json()["total"]
    assert sum(tile["by_severity"].values()) == tile["open"]
    # The plain status filter is unchanged.
    assert made[1].id not in _ids(client.get(f"{API}/security/alerts?status=OPEN&page_size=200",
                                             headers=headers))


# --------------------------------------------------------------------------- #
# 6. GMO lineage
# --------------------------------------------------------------------------- #
def test_gmo_filter_follows_seed_lot_and_parent_lineage(client, auth, db, orgs, product,
                                                       gmo_event):
    farm_org = orgs["FARM"].id

    def batch(**extra) -> Batch:
        row = Batch(org_id=farm_org, custodian_org_id=farm_org, batch_code=unique("R4G"),
                    verification_code=unique("V4"), product_id=product.id, quantity=10,
                    initial_quantity=10, unit="kg", **extra)
        db.add(row)
        db.flush()
        return row

    lot = SeedLot(org_id=farm_org, lot_code=unique("R4L"), crop_type="Maize",
                  variety="Test", quantity_kg=100.0, produced_at=utcnow(),
                  gmo_event_id=gmo_event["id"])
    db.add(lot)
    db.flush()
    direct = batch(gmo_event_id=gmo_event["id"])
    via_lot = batch(seed_lot_id=lot.id)
    child = batch(parent_batch_id=via_lot.id)
    grandchild = batch(parent_batch_id=child.id)
    plain = batch()
    db.commit()
    headers = auth("FARM_OPERATOR")

    gmo = client.get(f"{API}/supply-chain/batches?gmo=true&page_size=200", headers=headers)
    gmo_ids = _ids(gmo)
    assert {direct.id, via_lot.id, child.id, grandchild.id} <= gmo_ids
    assert plain.id not in gmo_ids
    assert all(row["gmo_lineage"] for row in gmo.json()["items"])
    non_gmo = client.get(f"{API}/supply-chain/batches?gmo=false&page_size=200",
                         headers=headers)
    non_gmo_ids = _ids(non_gmo)
    assert plain.id in non_gmo_ids
    assert not ({direct.id, via_lot.id, child.id, grandchild.id} & non_gmo_ids)
    assert not any(row["gmo_lineage"] for row in non_gmo.json()["items"])

    holdings = client.get(f"{API}/dashboard", headers=headers).json()["gmo_holdings"]
    assert holdings["batches"] == gmo.json()["total"]
