"""Anchoring reliability: writes missed during a ledger outage are replayed in order, writes
that depend on them are queued rather than rejected, replay is idempotent, and the Fabric
mirror status is persisted and re-mirrored (services/anchoring.py)."""
from __future__ import annotations

import dataclasses
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer

import pytest
from sqlalchemy import select

from app.core import config
from app.core.database import SessionLocal
from app.models import Batch, LedgerWrite, SupplyChainEvent
from app.services import anchoring, fabric_bridge, ledger_client

from .conftest import unique
from .test_fabric_bridge import TOKEN, FakeBridge


def iso(value: datetime) -> str:
    return value.isoformat()


def now() -> datetime:
    return datetime.now(timezone.utc)


class _Switchable:
    """Stands in for ledger_client's circuit breaker; `down` forces the open-circuit path,
    which is exactly what a real outage produces after five failures."""

    def __init__(self, real) -> None:
        self.real = real
        self.down = False

    @property
    def is_open(self) -> bool:
        return self.down or self.real.is_open

    def record_success(self) -> None:
        self.real.record_success()

    def record_failure(self) -> None:
        self.real.record_failure()


@pytest.fixture
def outage(monkeypatch):
    switch = _Switchable(ledger_client._breaker)
    monkeypatch.setattr(ledger_client, "_breaker", switch)
    return switch


def _create_batch(client, auth, product) -> dict:
    response = client.post("/api/v1/supply-chain/batches", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                           json={"batch_code": unique("RETRY"), "product_id": product.id,
                                 "quantity": 1000.0, "unit": "kg", "origin_region": "Iowa",
                                 "origin_country": "US"})
    assert response.status_code == 201, response.text
    return response.json()


def _event(client, headers, batch_id, biz_step, disposition, days_ago, to_org_id=None):
    payload = {"batch_id": batch_id, "biz_step": biz_step, "disposition": disposition,
               "location_name": "Test Plant", "quantity": 1000.0, "unit": "kg",
               "occurred_at": iso(now() - timedelta(days=days_ago))}
    if to_org_id:
        payload["to_org_id"] = to_org_id
    return client.post("/api/v1/supply-chain/events", headers=headers, json=payload)


def _writes(batch_code: str) -> list[LedgerWrite]:
    with SessionLocal() as session:
        return list(session.execute(select(LedgerWrite).where(
            LedgerWrite.chain_key == f"batch:{batch_code}")
            .order_by(LedgerWrite.created_at.asc())).scalars())


def test_batch_created_during_an_outage_is_replayed_before_its_events(
        client, auth, product, orgs, outage):
    outage.down = True
    batch = _create_batch(client, auth, product)
    assert batch["anchor_status"] == "PENDING" and not batch["tx_id"]

    # The ledger is back, but the batch is still not on-chain. Before the fix this event was
    # submitted and rejected for ever ("Unknown batch"); now it is queued behind the batch.
    outage.down = False
    supply = auth("SUPPLY_CHAIN_OPERATOR")
    harvest = _event(client, supply, batch["id"], "harvesting", "in_progress", 3)
    assert harvest.status_code == 201, harvest.text
    assert harvest.json()["anchor_status"] == "PENDING"
    ship = _event(client, supply, batch["id"], "shipping", "in_transit", 2,
                  to_org_id=orgs["FARM"].id)
    assert ship.status_code == 201, ship.text
    assert ship.json()["anchor_status"] == "PENDING"

    # Only an administrator or security analyst may run the sweep.
    denied = client.post("/api/v1/blockchain/anchors/retry", headers=auth("FARM_OPERATOR"))
    assert denied.status_code == 403
    result = client.post("/api/v1/blockchain/anchors/retry", headers=auth("ADMIN"))
    assert result.status_code == 200, result.text
    assert result.json()["retry"]["anchored"] >= 4

    writes = _writes(batch["batch_code"])
    assert [w.function for w in writes] == ["CreateBatch", "RecordEvent", "RecordEvent",
                                            "TransferCustody"]
    assert all(w.anchor_status == "ANCHORED" and w.tx_id for w in writes)
    blocks = [w.block_number for w in writes]
    assert blocks == sorted(blocks), "replayed out of order"

    with SessionLocal() as session:
        stored = session.get(Batch, batch["id"])
        assert stored.anchor_status == "ANCHORED" and stored.tx_id
        events = session.execute(select(SupplyChainEvent).where(
            SupplyChainEvent.batch_id == batch["id"])).scalars().all()
        assert {e.anchor_status for e in events} == {"ANCHORED"}
        assert all(e.tx_id for e in events)
    on_chain = ledger_client.query(f"batch:{batch['batch_code']}")
    assert on_chain["state"] == "IN_TRANSIT" and on_chain["custodian"] == "FarmMSP"

    # The chain is whole again: the next custodian's event anchors immediately.
    receive = _event(client, auth("FARM_OPERATOR"), batch["id"], "receiving", "in_storage", 1)
    assert receive.status_code == 201, receive.text
    assert receive.json()["anchor_status"] == "ANCHORED"


def test_dependent_writes_wait_while_their_predecessor_still_fails(
        client, auth, product, db, outage, monkeypatch):
    outage.down = True
    batch = _create_batch(client, auth, product)
    outage.down = False
    harvest = _event(client, auth("SUPPLY_CHAIN_OPERATOR"), batch["id"], "harvesting",
                     "in_progress", 1)
    assert harvest.json()["anchor_status"] == "PENDING"

    real_submit = ledger_client._submit
    attempted: list[str] = []

    def flaky(contract, function, args, msp, retries=2):
        if args.get("batch_code") == batch["batch_code"]:
            attempted.append(function)
            if function == "CreateBatch":
                return {"ok": False, "status": "FAILED", "error": "ledger_unavailable",
                        "detail": "endorser down"}
        return real_submit(contract, function, args, msp, retries)

    monkeypatch.setattr(ledger_client, "_submit", flaky)
    counts = anchoring.retry_pending(db)
    db.commit()
    assert attempted == ["CreateBatch"], "the event must not be replayed before its batch"
    assert counts["blocked"] >= 1
    assert [w.anchor_status for w in _writes(batch["batch_code"])] == ["FAILED", "PENDING"]

    monkeypatch.setattr(ledger_client, "_submit", real_submit)
    anchoring.retry_pending(db)
    db.commit()
    assert [w.anchor_status for w in _writes(batch["batch_code"])] == ["ANCHORED", "ANCHORED"]


def test_replay_of_a_write_that_did_land_does_not_anchor_twice(
        client, auth, product, db, monkeypatch):
    """The ledger committed but the response was lost (or the request's commit failed after
    the submit): the replay must recognise the anchor instead of erroring or duplicating."""
    real_submit = ledger_client._submit

    def lost_response(contract, function, args, msp, retries=2):
        real_submit(contract, function, args, msp, retries)
        return {"ok": False, "status": "FAILED", "error": "ledger_unavailable",
                "detail": "timeout reading the response"}

    monkeypatch.setattr(ledger_client, "_submit", lost_response)
    batch = _create_batch(client, auth, product)
    assert batch["anchor_status"] == "FAILED"
    monkeypatch.setattr(ledger_client, "_submit", real_submit)

    before = ledger_client.stats()["by_function"].get("provenance.CreateBatch", 0)
    counts = anchoring.retry_pending(db)
    db.commit()
    assert counts["already_anchored"] >= 1
    assert ledger_client.stats()["by_function"].get("provenance.CreateBatch", 0) == before
    [write] = _writes(batch["batch_code"])
    assert write.anchor_status == "ANCHORED"
    with SessionLocal() as session:
        assert session.get(Batch, batch["id"]).anchor_status == "ANCHORED"

    # A second sweep finds nothing left to do for it.
    anchoring.retry_pending(db)
    db.commit()
    assert [w.attempts for w in _writes(batch["batch_code"])] == [write.attempts]


# --------------------------------------------------------------------------- #
# Fabric mirror persistence
# --------------------------------------------------------------------------- #
class FlakyBridge(FakeBridge):
    failing = False

    def do_POST(self):
        if FlakyBridge.failing:
            self.rfile.read(int(self.headers["Content-Length"]))
            payload = json.dumps({"detail": "peer unavailable"}).encode()
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        super().do_POST()


@pytest.fixture
def flaky_bridge(monkeypatch):
    FakeBridge.state = {}
    FlakyBridge.failing = False
    server = HTTPServer(("127.0.0.1", 0), FlakyBridge)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    patched = dataclasses.replace(config.get_settings(),
                                  fabric_bridge_url=f"http://127.0.0.1:{server.server_port}",
                                  fabric_bridge_token=TOKEN)
    monkeypatch.setattr(fabric_bridge, "get_settings", lambda: patched)
    yield FlakyBridge
    fabric_bridge.flush(10)
    server.shutdown()


def test_failed_fabric_mirror_is_persisted_and_re_mirrored(client, auth, product, db,
                                                           flaky_bridge):
    flaky_bridge.failing = True
    batch = _create_batch(client, auth, product)
    assert batch["anchor_status"] == "ANCHORED"
    fabric_bridge.flush(10)                      # the background mirror runs after commit

    [write] = _writes(batch["batch_code"])
    assert write.fabric_key == f"batch:{batch['batch_code']}"
    assert write.fabric_status == "FAILED" and write.fabric_attempts == 1

    status = client.get("/api/v1/blockchain/fabric", headers=auth("REGULATOR")).json()
    assert status["mirrored_failed"] >= 1, "counts must come from the database"

    flaky_bridge.failing = False
    counts = anchoring.remirror(db, limit=10_000)
    db.commit()
    assert counts["mirrored"] >= 1
    [write] = _writes(batch["batch_code"])
    assert write.fabric_status == "MIRRORED" and write.fabric_tx_id
    assert FakeBridge.state[write.fabric_key]["contentHash"] == write.args["content_hash"]

    # Re-mirroring is idempotent: Fabric already holds the hash, so no second version.
    with SessionLocal() as session:
        row = session.get(LedgerWrite, write.id)
        row.fabric_status = "FAILED"
        session.commit()
    again = anchoring.remirror(db, limit=10_000)
    db.commit()
    assert again["already_mirrored"] >= 1
    assert FakeBridge.state[write.fabric_key]["version"] == 1


def test_a_mirror_that_never_ran_is_picked_up_by_the_sweep(client, auth, product, db,
                                                           flaky_bridge, monkeypatch):
    # The API process stopped before its background mirror ran.
    monkeypatch.setattr(fabric_bridge, "mirror", lambda *a, **k: None)
    batch = _create_batch(client, auth, product)
    [write] = _writes(batch["batch_code"])
    assert write.fabric_status == "PENDING"

    # A just-anchored write may still have its mirror in flight, so it is left alone at first.
    anchoring.remirror(db, limit=10_000)
    db.commit()
    assert _writes(batch["batch_code"])[0].fabric_status == "PENDING"
    counts = anchoring.remirror(db, limit=10_000, min_age_seconds=0)
    db.commit()
    assert counts["mirrored"] >= 1
    assert _writes(batch["batch_code"])[0].fabric_status == "MIRRORED"
    assert f"batch:{batch['batch_code']}" in FakeBridge.state


def test_anchor_status_endpoint_reports_the_journal(client, auth):
    body = client.get("/api/v1/blockchain/anchors", headers=auth("REGULATOR")).json()
    assert body["anchors"].get("ANCHORED", 0) >= 1
    assert client.get("/api/v1/blockchain/anchors",
                      headers=auth("FARM_OPERATOR")).status_code == 403


def test_chain_keys_follow_the_contract_dependencies():
    assert anchoring.chain_keys("provenance", "RecordEvent",
                                {"batch_code": "B-1", "event_id": "e"}) == ("batch:B-1", [])
    assert anchoring.chain_keys("provenance", "CreateBatch",
                                {"batch_code": "B-2", "parents": ["B-1"]}) == \
        ("batch:B-2", ["batch:B-1"])
    assert anchoring.chain_keys("gmo_registry", "RegisterSeedLot",
                                {"lot_code": "L-1", "event_code": None}) == ("seedlot:L-1", [])
    assert anchoring.chain_keys("gmo_registry", "RecordApproval",
                                {"event_code": "E-1", "jurisdiction": "EU"}) == \
        ("gmoapproval:E-1:EU", ["gmo:E-1"])
