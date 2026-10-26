"""Round 6: supply-chain event timing, hand-over integrity and supply forms.

1. Dates more than a few minutes in the future are refused (a shipment dated years ahead
   froze the batch: arrival and even the recall were "before" it).
2. A step dated before the batch's latest recorded step (or, after the harvest, before the
   harvest) is refused in words, whether or not the batch was ever handed over. A recall is
   exempt. Recording yesterday's step today still works when it follows the last one.
3. A shipment handing over a batch already IN_TRANSIT records a shipping event naming the
   receiver, so the receiver cannot date its steps before the hand-over.
4. Only organisation types that can act on a batch on the ledger may receive one.
5. An SSCC is 18 digits with a valid GS1 check digit.
6. A bad GTIN names the problem in the field message.
9. The "Batches held" and "Awaiting your arrival" tiles agree with the lists they link to.
11. Migration 0012 adds the missing foreign keys on PostgreSQL only.
"""
from __future__ import annotations

import importlib.util
import re
from datetime import timedelta

from app import gs1
from app.services import supplychain as service
from .conftest import ROOT, unique
from .test_shipments_recall import _sscc, _ship, chilled_product, farm_batch  # noqa: F401
from .test_supplychain_e2e import iso, now

API = "/api/v1"


def _event(client, auth, role, batch_id, step, disposition, when, **extra):
    return client.post(f"{API}/supply-chain/events", headers=auth(role), json={
        "batch_id": batch_id, "biz_step": step, "disposition": disposition,
        "occurred_at": iso(when), **extra})


def _detail(response) -> str:
    return response.json().get("detail", "")


# --------------------------------------------------------------------------- #
# 1. Future dates
# --------------------------------------------------------------------------- #
class TestFutureDates:
    def test_an_event_dated_in_the_future_is_refused(self, client, auth, farm_batch):
        response = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "transforming",
                          "in_progress", now() + timedelta(days=3650))
        assert response.status_code == 422, response.text
        assert "cannot be in the future" in _detail(response)

    def test_a_clock_a_minute_fast_is_tolerated(self, client, auth, farm_batch):
        response = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "transforming",
                          "in_progress", now() + timedelta(minutes=1))
        assert response.status_code == 201, response.text

    def test_a_shipment_departing_in_the_future_is_refused(self, client, auth, orgs,
                                                           farm_batch):
        response = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id,
                         departed_at=iso(now() + timedelta(days=3650)))
        assert response.status_code == 422, response.text
        assert "departure date cannot be in the future" in _detail(response)
        # Nothing was written: the batch is still with the farm and can be recalled.
        recall = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "recalling",
                        "recalled", now())
        assert recall.status_code == 201, recall.text

    def test_a_future_arrival_is_refused(self, client, auth, orgs, farm_batch):
        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id).json()
        response = client.post(f"{API}/supply-chain/shipments/{shipment['id']}/arrive",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"),
                               json={"arrived_at": iso(now() + timedelta(days=30))})
        assert response.status_code == 422, response.text
        assert "arrival date cannot be in the future" in _detail(response)
        # An internal move entered as already arrived is checked the same way.
        internal = _ship(client, auth, _fresh_batch(client, auth, farm_batch),
                         arrived_at=iso(now() + timedelta(days=30)))
        assert internal.status_code == 422, internal.text

    def test_a_future_harvest_date_is_refused(self, client, auth, chilled_product):
        response = client.post(f"{API}/supply-chain/batches", headers=auth("FARM_OPERATOR"),
                               json={"batch_code": unique("R6F"),
                                     "product_id": chilled_product["id"], "quantity": 5.0,
                                     "unit": "kg", "origin_region": "Iowa",
                                     "origin_country": "US",
                                     "harvested_at": iso(now() + timedelta(days=400))})
        assert response.status_code == 422, response.text
        assert "harvest date cannot be in the future" in _detail(response)


def _fresh_batch(client, auth, farm_batch) -> str:
    response = client.post(f"{API}/supply-chain/batches", headers=auth("FARM_OPERATOR"), json={
        "batch_code": unique("R6B"), "product_id": farm_batch["product_id"], "quantity": 10.0,
        "unit": "kg", "origin_region": "Iowa", "origin_country": "US",
        "harvested_at": iso(now() - timedelta(days=1))})
    assert response.status_code == 201, response.text
    return response.json()["id"]


# --------------------------------------------------------------------------- #
# 2. Chronology
# --------------------------------------------------------------------------- #
class TestChronology:
    def test_a_step_before_the_last_one_is_refused_without_any_hand_over(self, client, auth,
                                                                         farm_batch):
        first = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "transforming",
                       "in_progress", now() - timedelta(hours=1))
        assert first.status_code == 201, first.text
        backdated = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "packing",
                           "in_progress", now() - timedelta(hours=5))
        assert backdated.status_code == 422, backdated.text
        detail = _detail(backdated)
        assert detail.startswith("Choose a date on or after ")
        assert "the batch's last recorded step" in detail
        # Readable: no field name, no ISO timestamp with microseconds.
        assert "occurred_at" not in detail and "+00:00" not in detail
        assert not re.search(r"\d{4}-\d{2}-\d{2}T", detail)

    def test_yesterdays_step_recorded_today_is_accepted_after_the_last_one(self, client, auth,
                                                                           farm_batch):
        first = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "transforming",
                       "in_progress", now() - timedelta(hours=20))
        assert first.status_code == 201, first.text
        late = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "packing",
                      "in_progress", now() - timedelta(hours=12))
        assert late.status_code == 201, late.text

    def test_a_post_harvest_step_before_the_harvest_is_refused(self, client, auth, farm_batch):
        response = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "transforming",
                          "in_progress", now() - timedelta(days=5))
        assert response.status_code == 422, response.text
        assert "when the batch was harvested" in _detail(response)

    def test_a_recall_is_exempt(self, client, auth, orgs, farm_batch):
        shipment = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id,
                         departed_at=iso(now() - timedelta(minutes=10)))
        assert shipment.status_code == 201, shipment.text
        # The owner recalls it with a date before the hand-over: still accepted.
        recall = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "recalling",
                        "recalled", now() - timedelta(hours=3))
        assert recall.status_code == 201, recall.text

    def test_the_human_date_rounds_up_to_the_minute(self):
        from datetime import datetime, timezone
        moment = datetime(2026, 10, 19, 3, 47, 12, 345000, tzinfo=timezone.utc)
        assert service.human_when(moment) == "19 Oct 2026, 03:48 UTC"
        exact = datetime(2026, 10, 19, 3, 47, tzinfo=timezone.utc)
        assert service.human_when(exact) == "19 Oct 2026, 03:47 UTC"


# --------------------------------------------------------------------------- #
# 3. Hand-over of a batch already in transit
# --------------------------------------------------------------------------- #
def test_the_receiver_cannot_backdate_before_a_hand_over_of_an_in_transit_batch(
        client, auth, orgs, farm_batch):
    plain = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "shipping", "in_transit",
                   now() - timedelta(hours=3))
    assert plain.status_code == 201, plain.text
    handed = _ship(client, auth, farm_batch["id"], to_org_id=orgs["SUPPLY"].id,
                   departed_at=iso(now() - timedelta(hours=2)))
    assert handed.status_code == 201, handed.text
    events = client.get(f"{API}/supply-chain/batches/{farm_batch['id']}/custody",
                        headers=auth("SUPPLY_CHAIN_OPERATOR")).json()["events"]
    assert events[-1]["to_org_id"] == orgs["SUPPLY"].id
    backdated = _event(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"], "storing",
                       "in_storage", now() - timedelta(minutes=150))
    assert backdated.status_code == 422, backdated.text
    booked = _event(client, auth, "SUPPLY_CHAIN_OPERATOR", farm_batch["id"], "storing",
                    "in_storage", now() - timedelta(minutes=30))
    assert booked.status_code == 201, booked.text


def test_an_internal_shipment_aligned_with_a_shipping_event_keeps_the_chronology(
        client, auth, farm_batch):
    plain = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "shipping", "in_transit",
                   now() - timedelta(hours=1))
    assert plain.status_code == 201, plain.text
    early = _ship(client, auth, farm_batch["id"], departed_at=iso(now() - timedelta(hours=4)))
    assert early.status_code == 422, early.text


# --------------------------------------------------------------------------- #
# 4. Receivers that can act on a batch
# --------------------------------------------------------------------------- #
class TestReceiverTypes:
    def test_matches_the_ledger_rights(self):
        from ledger.contracts import SUBMIT_RIGHTS
        assert service.RECEIVER_ORG_TYPES == (SUBMIT_RIGHTS["provenance.RecordEvent"]
                                              & SUBMIT_RIGHTS["provenance.TransferCustody"])

    def test_a_shipment_to_a_regulator_or_developer_is_refused(self, client, auth, orgs,
                                                               farm_batch):
        for org_type in ("REGULATOR", "BIOTECH"):
            response = _ship(client, auth, farm_batch["id"], to_org_id=orgs[org_type].id)
            assert response.status_code == 422, response.text
            assert "cannot receive batches" in _detail(response)
        batch = client.get(f"{API}/supply-chain/batches/{farm_batch['id']}",
                           headers=auth("FARM_OPERATOR")).json()
        assert batch["state"] != "IN_TRANSIT"
        assert batch["custodian_org_id"] == orgs["FARM"].id

    def test_a_shipping_event_to_a_regulator_is_refused(self, client, auth, orgs, farm_batch):
        response = _event(client, auth, "FARM_OPERATOR", farm_batch["id"], "shipping",
                          "in_transit", now(), to_org_id=orgs["REGULATOR"].id)
        assert response.status_code == 422, response.text
        assert "cannot receive batches" in _detail(response)

    def test_a_farm_or_processor_still_receives(self, client, auth, orgs, farm_batch):
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201


# --------------------------------------------------------------------------- #
# 5. SSCC and 6. GTIN validation
# --------------------------------------------------------------------------- #
class TestIdentifiers:
    def test_an_sscc_with_letters_is_refused(self, client, auth, farm_batch):
        response = _ship(client, auth, farm_batch["id"], sscc="ABCDEFGHJK")
        assert response.status_code == 422, response.text
        assert response.json()["errors"][0]["field"] == "sscc"
        assert "18 digits" in response.json()["errors"][0]["message"]

    def test_an_sscc_with_a_wrong_check_digit_is_refused(self, client, auth, farm_batch):
        valid = _sscc()
        wrong = valid[:-1] + str((int(valid[-1]) + 1) % 10)
        response = _ship(client, auth, farm_batch["id"], sscc=wrong)
        assert response.status_code == 422, response.text
        assert f"check digit is wrong (expected {valid[-1]}" in response.text

    def test_a_valid_sscc_printed_with_spaces_is_accepted(self, client, auth, farm_batch):
        valid = _sscc()
        response = _ship(client, auth, farm_batch["id"],
                         sscc=f"(00) {valid[:9]} {valid[9:]}")
        assert response.status_code == 201, response.text
        assert response.json()["sscc"] == valid

    def test_a_bad_gtin_names_the_problem(self, client, auth):
        response = client.post(f"{API}/supply-chain/products",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"),
                               json={"gtin": "09501101530004", "name": "Bad GTIN corn",
                                     "category": "Vegetables"})
        assert response.status_code == 422
        field = response.json()["errors"][0]
        assert field["field"] == "gtin"
        expected = gs1.check_digit("0950110153000")
        assert f"check digit is wrong (expected {expected}, got 4)" in field["message"]
        assert not field["message"].lower().startswith("value error, gtin")


# --------------------------------------------------------------------------- #
# 9. Dashboard tiles agree with their links
# --------------------------------------------------------------------------- #
class TestTilesMatchLinks:
    def test_batches_held_matches_the_held_list(self, client, auth, orgs, farm_batch):
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201
        headers = auth("SUPPLY_CHAIN_OPERATOR")
        tile = client.get(f"{API}/dashboard", headers=headers).json()["supply_chain"]["held"]
        held = client.get(f"{API}/supply-chain/batches?held=true&page_size=200",
                          headers=headers).json()
        assert held["total"] == tile
        assert farm_batch["id"] not in {row["id"] for row in held["items"]}
        assert all(row["custodian_org_id"] == orgs["SUPPLY"].id and row["state"] != "IN_TRANSIT"
                   for row in held["items"])

    def test_awaiting_arrival_matches_its_link_for_an_oversight_role(self, client, auth, orgs,
                                                                     farm_batch):
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201
        headers = auth("ADMIN")
        tile = client.get(f"{API}/dashboard",
                          headers=headers).json()["supply_chain"]["awaiting_arrival"]
        listed = client.get(f"{API}/supply-chain/shipments?status=IN_TRANSIT&incoming=true"
                            f"&page_size=200", headers=headers).json()
        assert listed["total"] == tile >= 1

    def test_awaiting_arrival_matches_its_link_for_the_receiver(self, client, auth, orgs,
                                                                farm_batch):
        assert _ship(client, auth, farm_batch["id"],
                     to_org_id=orgs["SUPPLY"].id).status_code == 201
        headers = auth("SUPPLY_CHAIN_OPERATOR")
        tile = client.get(f"{API}/dashboard",
                          headers=headers).json()["supply_chain"]["awaiting_arrival"]
        listed = client.get(f"{API}/supply-chain/shipments?status=IN_TRANSIT&incoming=true"
                            f"&page_size=200", headers=headers).json()
        assert listed["total"] == tile >= 1


# --------------------------------------------------------------------------- #
# 11. Migration 0012
# --------------------------------------------------------------------------- #
def test_migration_0012_adds_foreign_keys_on_postgresql_only():
    spec = importlib.util.spec_from_file_location(
        "r6_migrations_run", ROOT / "backend" / "migrations" / "run.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    sql = (ROOT / "backend" / "migrations" / "0012_party_column_foreign_keys.sql").read_text()
    postgres = runner._statements(sql, "postgresql")
    assert len(postgres) == 5
    assert all("ADD CONSTRAINT" in s and "REFERENCES organizations (id)" in s for s in postgres)
    assert runner._statements(sql, "sqlite") == []
    # Unmarked statements still run everywhere (every earlier migration).
    earlier = (ROOT / "backend" / "migrations" / "0008_shipment_receiver_backfill.sql").read_text()
    assert runner._statements(earlier, "sqlite") == runner._statements(earlier)
