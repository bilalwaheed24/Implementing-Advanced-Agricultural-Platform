"""Round 3 infrastructure fixes: type-based ledger submit rights for admin-created
organisations, the replay lock and rejection alert, the isolated scheduler sweeps, the bounded
re-mirror, the Fabric flush and the 0008 shipment-receiver backfill."""
from __future__ import annotations

import importlib.util
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select, text

from app.core.database import SessionLocal, engine
from app.core.security import hash_password
from app.gs1 import with_check_digit
from app.models import Alert, LedgerWrite, Organization, Shipment, User
from app.services import anchoring, fabric_bridge, ledger_client

from .conftest import PASSWORD, unique

ROOT = Path(__file__).resolve().parents[2]


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat()


def _login(client, email: str) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(f"r3_{name}", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Ledger submit rights by organisation type
# --------------------------------------------------------------------------- #
class TestTypeBasedSubmitRights:
    @pytest.fixture
    def ledger(self, tmp_path):
        from ledger import Ledger

        return Ledger(tmp_path / "ledger")

    def _batch(self, ledger, msp="FarmMSP") -> str:
        code = unique("T")
        ledger.submit("provenance", "CreateBatch", {"batch_code": code, "quantity": 10}, msp)
        return code

    def test_a_new_supply_identity_can_record_events_and_endorses_them(self, ledger):
        ledger.msp.ensure("RetailMSP", "Corner Retail", "SUPPLY")
        code = self._batch(ledger)
        receipt = ledger.submit("provenance", "RecordEvent", {
            "batch_code": code, "event_id": unique("E"), "biz_step": "shipping"}, "RetailMSP")
        assert receipt["endorsers"] == ["RetailMSP"]
        assert ledger.verify_chain()["valid"]

    def test_type_is_persisted_with_the_identity(self, ledger, tmp_path):
        from ledger import Ledger

        ledger.msp.ensure("RetailMSP", "Corner Retail", "SUPPLY")
        reopened = Ledger(tmp_path / "ledger")
        assert reopened.msp.org_type("RetailMSP") == "SUPPLY"
        assert reopened.msp.org_type("FarmMSP") == "FARM"

    def test_an_untyped_identity_can_submit_nothing(self, ledger):
        ledger.msp.ensure("LegacyMSP", "Registered before types")
        code = self._batch(ledger)
        with pytest.raises(Exception, match="not authorised"):
            ledger.submit("provenance", "RecordEvent", {
                "batch_code": code, "event_id": unique("E"), "biz_step": "shipping"},
                "LegacyMSP")
        # A later ensure with the organisation's type (start_api's identity sync) fixes it.
        ledger.msp.ensure("LegacyMSP", "Registered before types", "SUPPLY")
        ledger.submit("provenance", "RecordEvent", {
            "batch_code": code, "event_id": unique("E"), "biz_step": "shipping"}, "LegacyMSP")

    def test_a_type_cannot_be_changed_by_re_registering(self, ledger):
        ledger.msp.ensure("RetailMSP", "Corner Retail", "SUPPLY")
        ledger.msp.ensure("RetailMSP", "Corner Retail", "REGULATOR")
        assert ledger.msp.org_type("RetailMSP") == "SUPPLY"
        with pytest.raises(Exception, match="not authorised"):
            ledger.submit("certification", "Issue", {
                "cert_code": unique("C"), "cert_type": "ORGANIC", "valid_from": "2026-01-01",
                "valid_to": "2027-01-01"}, "RetailMSP")

    def test_the_seeded_identities_keep_their_rights(self, ledger):
        with pytest.raises(Exception, match="not authorised"):
            ledger.submit("certification", "Issue", {
                "cert_code": unique("C"), "cert_type": "ORGANIC", "valid_from": "2026-01-01",
                "valid_to": "2027-01-01"}, "FarmMSP")
        receipt = ledger.submit("certification", "Issue", {
            "cert_code": unique("C"), "cert_type": "ORGANIC", "valid_from": "2026-01-01",
            "valid_to": "2027-01-01"}, "RegulatorMSP")
        assert receipt["endorsers"] == ["RegulatorMSP"]


def test_an_admin_created_supply_org_receives_and_acts_on_a_batch(client, auth, db, orgs):
    """The audit's failing case: a retailer created through the admin API was refused by
    the ledger ("RetailMSP is not authorised to submit provenance.RecordEvent")."""
    msp_id = f"RetailMSP-{secrets.token_hex(3)}"
    created = client.post("/api/v1/admin/organizations", headers=auth("ADMIN"), json={
        "name": f"Corner Retail {msp_id}", "org_type": "SUPPLY", "msp_id": msp_id,
        "country": "US"})
    assert created.status_code == 201, created.text
    retailer = created.json()
    email = f"{msp_id.lower()}@test.absp"
    db.add(User(email=email, full_name="Retail Operator", password_hash=hash_password(PASSWORD),
                role="SUPPLY_CHAIN_OPERATOR", org_id=retailer["id"], status="ACTIVE"))
    db.commit()
    retail = _login(client, email)

    farm = auth("FARM_OPERATOR")
    gtin = with_check_digit("0" + "".join(secrets.choice("0123456789") for _ in range(12)))
    product = client.post("/api/v1/supply-chain/products", headers=farm,
                          json={"gtin": gtin, "name": "Retail maize", "category": "Grain"})
    assert product.status_code == 201, product.text
    batch = client.post("/api/v1/supply-chain/batches", headers=farm, json={
        "batch_code": unique("RT"), "product_id": product.json()["id"], "quantity": 100.0,
        "unit": "kg", "origin_region": "Iowa", "origin_country": "US",
        "harvested_at": iso(now() - timedelta(days=1))})
    assert batch.status_code == 201, batch.text
    batch = batch.json()
    shipment = client.post("/api/v1/supply-chain/shipments", headers=farm, json={
        "sscc": str(secrets.randbelow(10**17)).zfill(18), "batch_id": batch["id"],
        "carrier": "Haulage", "origin_name": "Farm gate", "origin_lat": 42.0,
        "origin_lon": -93.6, "destination_name": "Store", "destination_lat": 41.9,
        "destination_lon": -87.6, "departed_at": iso(now() - timedelta(hours=5)),
        "to_org_id": retailer["id"]})
    assert shipment.status_code == 201, shipment.text

    arrived = client.post(f"/api/v1/supply-chain/shipments/{shipment.json()['id']}/arrive",
                          headers=retail, json={"arrived_at": iso(now() - timedelta(hours=1))})
    assert arrived.status_code == 200, arrived.text
    stored = client.post("/api/v1/supply-chain/events", headers=retail, json={
        "batch_id": batch["id"], "biz_step": "storing", "disposition": "in_storage",
        "occurred_at": iso(now())})
    assert stored.status_code == 201, stored.text
    assert stored.json()["anchor_status"] == "ANCHORED"

    with SessionLocal() as session:
        writes = session.execute(select(LedgerWrite).where(
            LedgerWrite.submitter_msp == msp_id)).scalars().all()
    assert writes and {w.anchor_status for w in writes} == {"ANCHORED"}
    assert ledger_client.get_ledger().msp.org_type(msp_id) == "SUPPLY"


def test_identity_sync_registers_types_for_existing_organisations(db, orgs):
    org = Organization(name="Pre-type retailer", org_type="SUPPLY",
                       msp_id=f"OldMSP-{secrets.token_hex(3)}", country="US",
                       trusted_issuer_types=[])
    db.add(org)
    db.commit()
    ledger_client.ensure_identity(org.msp_id, org.name)          # registered without a type
    assert ledger_client.get_ledger().msp.org_type(org.msp_id) is None
    assert ledger_client.sync_identities(db) >= 5
    assert ledger_client.get_ledger().msp.org_type(org.msp_id) == "SUPPLY"


# --------------------------------------------------------------------------- #
# Replay: one at a time, and a rejection raises a LEDGER alert
# --------------------------------------------------------------------------- #
def test_a_concurrent_replay_is_refused_not_run_twice(db):
    assert anchoring._REPLAY_LOCK.acquire(blocking=False)
    try:
        counts = anchoring.retry_pending(db)
    finally:
        anchoring._REPLAY_LOCK.release()
    assert counts["busy"] is True and counts["attempted"] == 0
    assert anchoring.retry_pending(db)["busy"] is False
    db.commit()


def test_a_rejected_replay_raises_a_ledger_alert(db, orgs):
    code = unique("GHOST")
    row = LedgerWrite(contract="provenance", function="RecordEvent",
                      args={"batch_code": code, "event_id": unique("E"), "biz_step": "shipping"},
                      submitter_msp="SupplyMSP", chain_key=f"batch:{code}", requires=[],
                      anchor_status="FAILED", attempts=1)
    db.add(row)
    db.commit()
    counts = anchoring.retry_pending(db)
    db.commit()
    assert counts["rejected"] >= 1
    db.refresh(row)
    assert row.anchor_status == "REJECTED"
    alert = db.execute(select(Alert).where(Alert.entity_id == row.id)).scalar_one()
    assert alert.category == "LEDGER"
    assert alert.kind == "ledger_replay_rejected"
    assert alert.org_id == orgs["SUPPLY"].id
    assert code in alert.title


# --------------------------------------------------------------------------- #
# Fabric: bounded re-mirror and flush
# --------------------------------------------------------------------------- #
def test_remirror_stops_at_its_time_budget(db, monkeypatch):
    rows = []
    for _ in range(3):
        rows.append(LedgerWrite(
            contract="provenance", function="CreateBatch", args={"batch_code": unique("M")},
            submitter_msp="FarmMSP", chain_key=unique("batch:M"), requires=[],
            anchor_status="ANCHORED", anchored_at=now() - timedelta(hours=1),
            fabric_key=unique("batch:M"), fabric_status="FAILED"))
    db.add_all(rows)
    db.commit()
    monkeypatch.setattr(fabric_bridge, "enabled", lambda: True)
    called: list[str] = []
    monkeypatch.setattr(anchoring, "_mirror_row", lambda row: called.append(row.id) or "failed")
    counts = anchoring.remirror(db, limit=10_000, time_budget_seconds=0)
    assert called == [] and counts["skipped"] >= 3
    db.rollback()


def test_flush_waits_for_a_mirror_to_record_its_outcome(monkeypatch):
    monkeypatch.setattr(fabric_bridge, "enabled", lambda: True)

    def slow_anchor(*args, **kwargs):
        time.sleep(0.3)
        return {"ok": True}

    monkeypatch.setattr(fabric_bridge, "anchor_now", slow_anchor)
    outcomes: list[dict] = []
    fabric_bridge.mirror("provenance", "CreateBatch",
                         {"batch_code": "B-FLUSH", "content_hash": "a" * 64}, "tx", "FarmMSP",
                         on_done=outcomes.append)
    assert fabric_bridge.flush(timeout=5) is True
    assert outcomes == [{"ok": True}]


def test_flush_gives_up_at_its_timeout(monkeypatch):
    monkeypatch.setattr(fabric_bridge, "enabled", lambda: True)
    release = threading.Event()
    monkeypatch.setattr(fabric_bridge, "anchor_now", lambda *a, **k: release.wait(5) and None)
    fabric_bridge.mirror("provenance", "CreateBatch",
                         {"batch_code": "B-SLOW", "content_hash": "b" * 64}, "tx", "FarmMSP")
    try:
        assert fabric_bridge.flush(timeout=0.1) is False
    finally:
        release.set()
        assert fabric_bridge.flush(timeout=5) is True


# --------------------------------------------------------------------------- #
# Scheduler: each sweep isolated
# --------------------------------------------------------------------------- #
def test_one_failing_sweep_does_not_skip_the_rest(monkeypatch, capsys):
    tasks = _load_script("scheduled_tasks")
    ran: list[str] = []

    def broken(db):
        db.execute(text("SELECT 1"))
        raise RuntimeError("boom")

    def healthy(db):
        ran.append("healthy")
        return "healthy sweep ok"

    monkeypatch.setattr(tasks, "SWEEPS", [("broken", broken), ("healthy", healthy)])
    assert tasks.run_once() == 1
    assert ran == ["healthy"]
    out = capsys.readouterr().out
    assert "broken sweep failed: boom" in out and "healthy sweep ok" in out


def test_scheduler_bounds_the_remirror_pass(monkeypatch):
    tasks = _load_script("scheduled_tasks")
    seen: dict = {}

    def fake_remirror(db, **kwargs):
        seen.update(kwargs)
        return {"enabled": True, "mirrored": 0, "already_mirrored": 0, "failed": 0, "skipped": 0}

    monkeypatch.setattr(tasks.anchoring, "remirror", fake_remirror)
    with SessionLocal() as session:
        tasks.sweep_remirror(session)
    assert seen["time_budget_seconds"] <= 300 and seen["limit"] <= 200


# --------------------------------------------------------------------------- #
# 0008: shipments.to_org_id backfilled from the custody trail
# --------------------------------------------------------------------------- #
def test_0008_backfills_the_receiver_from_the_shipping_event(client, auth, orgs):
    farm = auth("FARM_OPERATOR")
    gtin = with_check_digit("0" + "".join(secrets.choice("0123456789") for _ in range(12)))
    product = client.post("/api/v1/supply-chain/products", headers=farm,
                          json={"gtin": gtin, "name": "Backfill maize", "category": "Grain"})
    batch = client.post("/api/v1/supply-chain/batches", headers=farm, json={
        "batch_code": unique("BF"), "product_id": product.json()["id"], "quantity": 10.0,
        "unit": "kg", "origin_region": "Iowa", "origin_country": "US",
        "harvested_at": iso(now() - timedelta(days=1))}).json()
    shipment = client.post("/api/v1/supply-chain/shipments", headers=farm, json={
        "sscc": str(secrets.randbelow(10**17)).zfill(18), "batch_id": batch["id"],
        "carrier": "Haulage", "origin_name": "Farm gate", "origin_lat": 42.0,
        "origin_lon": -93.6, "destination_name": "Plant", "destination_lat": 41.9,
        "destination_lon": -93.4, "departed_at": iso(now() - timedelta(hours=3)),
        "to_org_id": orgs["SUPPLY"].id})
    assert shipment.status_code == 201, shipment.text
    shipment_id = shipment.json()["id"]
    with engine.begin() as connection:                     # a pre-0005 row
        connection.execute(text("UPDATE shipments SET to_org_id = NULL WHERE id = :id"),
                           {"id": shipment_id})

    spec = importlib.util.spec_from_file_location(
        "r3_migrations_run", ROOT / "backend" / "migrations" / "run.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    sql = (ROOT / "backend" / "migrations" / "0008_shipment_receiver_backfill.sql").read_text()
    statements = runner._statements(sql)
    assert len(statements) == 2 and all(s.startswith("UPDATE shipments") for s in statements)
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
    with SessionLocal() as session:
        assert session.get(Shipment, shipment_id).to_org_id == orgs["SUPPLY"].id
