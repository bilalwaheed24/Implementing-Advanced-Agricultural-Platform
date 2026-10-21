"""Hyperledger Fabric mirror: anchors are copied to the bridge and verification asks Fabric.

A tiny in-process HTTP server stands in for fabric/gateway (which is tested separately with
the chaincode logic); on a real deployment the same calls reach the Fabric network.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from app.core import config
from app.services import fabric_bridge

from .test_supplychain_e2e import gmo_event, traced_batch  # noqa: F401  (shared fixtures)

TOKEN = "bridge-test-token"


class FakeBridge(BaseHTTPRequestHandler):
    state: dict = {}

    def _send(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass

    def do_GET(self):
        url = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/health":
            return self._send(200, {"status": "ok", "network": "hyperledger-fabric",
                                    "channel": "mychannel"})
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._send(401, {"detail": "bad token"})
        record = self.state.get(query.get("key"))
        if url.path == "/verify":
            if record is None:
                return self._send(200, {"key": query["key"], "result": "NOT_ANCHORED"})
            return self._send(200, {"key": query["key"], "anchoredHash": record["contentHash"],
                                    "result": "MATCH" if record["contentHash"] == query["hash"]
                                    else "MISMATCH"})
        if url.path == "/history":
            return self._send(200, {"key": query["key"], "history": [record] if record else []})
        return self._send(404, {})

    def do_POST(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._send(401, {"detail": "bad token"})
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        version = self.state.get(body["key"], {}).get("version", 0) + 1
        self.state[body["key"]] = {"key": body["key"], "contentHash": body["content_hash"],
                                   "version": version, "fabricTxId": f"ftx-{version}"}
        return self._send(200, self.state[body["key"]])


@pytest.fixture
def bridge(monkeypatch):
    FakeBridge.state = {}
    server = HTTPServer(("127.0.0.1", 0), FakeBridge)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    settings = config.get_settings()
    import dataclasses
    patched = dataclasses.replace(settings, fabric_bridge_url=f"http://127.0.0.1:{server.server_port}",
                                  fabric_bridge_token=TOKEN)
    monkeypatch.setattr(fabric_bridge, "get_settings", lambda: patched)
    yield FakeBridge.state
    server.shutdown()


def _wait_for(state, key, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if key in state:
            return state[key]
        time.sleep(0.05)
    raise AssertionError(f"{key} was never mirrored to Fabric")


def test_key_mapping_follows_the_local_world_state_keys():
    digest = "a" * 64
    assert fabric_bridge.key_for("provenance", "CreateBatch",
                                 {"batch_code": "B-1", "content_hash": digest}) == ("batch:B-1", digest)
    assert fabric_bridge.key_for("compliance_anchor", "AnchorAuditHead",
                                 {"head_hash": digest}) == ("audithead:latest", digest)
    assert fabric_bridge.key_for("provenance", "TransferCustody", {"batch_code": "B-1"}) is None
    assert fabric_bridge.key_for("provenance", "CreateBatch", {"batch_code": "B-1"}) is None


def test_disabled_bridge_reports_disabled(monkeypatch):
    assert fabric_bridge.status()["enabled"] is False
    assert fabric_bridge.verify("batch:B-1", "a" * 64)["result"] == "DISABLED"


def _mirror_batch(db, traced_batch):
    from app.models import Batch

    row = db.get(Batch, traced_batch["id"])
    fabric_bridge.anchor_now("provenance", "CreateBatch",
                             {"batch_code": row.batch_code, "content_hash": row.content_hash},
                             "local", "FarmMSP")


def test_a_new_batch_is_mirrored_and_verified_against_fabric(client, auth, bridge, traced_batch,
                                                              db):
    key = f"batch:{traced_batch['batch_code']}"
    # traced_batch may have been created before the bridge existed; mirror it explicitly.
    _mirror_batch(db, traced_batch)
    _wait_for(bridge, key)
    result = client.post("/api/v1/blockchain/verify-record", headers=auth("REGULATOR"),
                         json={"entity_type": "BATCH", "entity_id": traced_batch["id"]}).json()
    assert result["result"] == "MATCH"
    assert result["fabric"]["result"] == "MATCH"


def test_a_database_tamper_is_caught_by_fabric_too(client, auth, bridge, traced_batch, db):
    from app.models import Batch

    _mirror_batch(db, traced_batch)
    row = db.get(Batch, traced_batch["id"])
    original = row.origin_region
    row.origin_region = "Kansas"
    db.commit()
    try:
        result = client.post("/api/v1/blockchain/verify-record", headers=auth("REGULATOR"),
                             json={"entity_type": "BATCH", "entity_id": traced_batch["id"]}).json()
        assert result["result"] == "MISMATCH"
        assert result["fabric"]["result"] == "MISMATCH"
    finally:
        row.origin_region = original
        db.commit()


def test_ledger_writes_are_mirrored_in_the_background(bridge):
    from app.services import ledger_client

    receipt = ledger_client.submit("compliance_anchor", "AnchorAuditHead",
                                   {"seq": 10_000_000, "head_hash": "e" * 64}, "RegulatorMSP")
    assert receipt["ok"]
    assert _wait_for(bridge, "audithead:latest")["contentHash"] == "e" * 64


def test_status_endpoint_reports_the_bridge(client, auth, bridge):
    body = client.get("/api/v1/blockchain/fabric", headers=auth("REGULATOR")).json()
    assert body["enabled"] is True and body["reachable"] is True
    assert body["bridge"]["network"] == "hyperledger-fabric"
