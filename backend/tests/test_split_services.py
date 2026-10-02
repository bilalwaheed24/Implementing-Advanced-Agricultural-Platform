"""Split deployment (ADR-016): the backend talking to the `ai` and `ledger` services.

No network: `urllib.request.urlopen` inside service_http is routed to in-process
TestClients of the real ai/ledger service apps, so the request encoding, service-token
header, status mapping and error handling in the clients are all exercised for real.
"""
from __future__ import annotations

import dataclasses
import io
import json
import urllib.error
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from ai import sequence_screening
from ai import service as ai_service
from ai.data.generate import benign_sequence, hazard_database, hazard_derived_sequence
from app.core.config import get_settings
from app.services import ai_client, ledger_client, service_http
from ledger import service as ledger_service

from .conftest import unique

AI_URL = "http://ai.internal:8100"
LEDGER_URL = "http://ledger.internal:8200"
TOKEN = "t" * 40


class _Response:
    def __init__(self, status: int, content: bytes) -> None:
        self.status, self._content = status, content

    def read(self) -> bytes:
        return self._content

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


@pytest.fixture
def remote(monkeypatch, tmp_path):
    """Point the clients at the services, and route their HTTP calls in-process."""
    settings = dataclasses.replace(get_settings(), ai_service_url=AI_URL,
                                   ledger_service_url=LEDGER_URL, service_token=TOKEN)
    for module in (ai_client, ledger_client, service_http):
        monkeypatch.setattr(module, "get_settings", lambda: settings)
    monkeypatch.setattr(ai_service, "SERVICE_TOKEN", TOKEN)
    monkeypatch.setattr(ledger_service, "SERVICE_TOKEN", TOKEN)
    monkeypatch.setattr(ledger_service, "DATA_DIR", tmp_path / "ledger")
    monkeypatch.setattr(ledger_service, "ALLOW_RESET", True)
    monkeypatch.setattr(ledger_service, "_ledger", None)
    ai_client.meta.cache_clear()

    clients = {AI_URL: TestClient(ai_service.app), LEDGER_URL: TestClient(ledger_service.app)}
    calls: list[dict] = []

    def fake_urlopen(request, timeout=None):                       # noqa: ANN001, ARG001
        parts = urlsplit(request.full_url)
        base = f"{parts.scheme}://{parts.netloc}"
        if base not in clients:
            raise urllib.error.URLError("connection refused")
        headers = dict(request.header_items())
        calls.append({"url": request.full_url, "headers": headers})
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        response = clients[base].request(request.get_method(), path, content=request.data,
                                         headers=headers)
        if response.status_code >= 400:
            raise urllib.error.HTTPError(request.full_url, response.status_code, "error", {},
                                         io.BytesIO(response.content))
        return _Response(response.status_code, response.content)

    monkeypatch.setattr(service_http.urllib.request, "urlopen", fake_urlopen)
    yield {"clients": clients, "calls": calls}
    ai_client.meta.cache_clear()


class TestAIService:
    def test_screening_matches_the_in_process_engine(self, remote):
        hazards = [{"id": f"h{i}", **{k: h[k] for k in ("agent_name", "hazard_class",
                                                        "severity", "sequence")}}
                   for i, h in enumerate(hazard_database())]
        query = hazard_derived_sequence(hazards[0]["sequence"], 0.05, 2)

        remote_result = ai_client.screen(query, hazards, 100_000)
        local = sequence_screening.screen(
            query, [sequence_screening.HazardRecord(**h) for h in hazards], 100_000)

        assert remote_result.verdict == local.verdict == "BLOCK"
        assert remote_result.max_identity == local.max_identity
        assert [h.identity for h in remote_result.hits] == [h.identity for h in local.hits]
        assert remote_result.normalized == sequence_screening.normalize(query)

    def test_every_call_carries_the_service_token(self, remote):
        ai_client.validate_readings("SOIL_MOISTURE", {"moisture_pct": 30})
        assert remote["calls"], "the client did not go over HTTP"
        assert all(c["headers"].get("X-service-token") == TOKEN for c in remote["calls"])

    def test_rejected_input_is_an_input_error(self, remote):
        with pytest.raises(ai_client.AIInputError, match="IUPAC"):
            ai_client.validate_sequence("ACGT" * 5 + "XYZ", 100_000)

    def test_wrong_token_is_refused(self, remote, monkeypatch):
        monkeypatch.setattr(ai_service, "SERVICE_TOKEN", "a-different-token" * 3)
        with pytest.raises(service_http.ServiceUnavailable):
            ai_client.model_cards()

    def test_unreachable_service_is_a_503_problem(self, remote, client, auth, monkeypatch):
        remote["clients"].pop(AI_URL)
        response = client.get("/api/v1/ai/model-cards", headers=auth("ADMIN"))
        assert response.status_code == 503
        assert "ai.internal" not in response.text, "internal topology must not leak"

    def test_screening_api_end_to_end(self, remote, client, auth, hazards):
        response = client.post("/api/v1/biosecurity/screenings",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"name": unique("remote"), "sequence": benign_sequence(900, 3),
                                     "intent": "drought tolerance", "organism": "Zea mays"})
        assert response.status_code == 201, response.text
        assert response.json()["verdict"] == "CLEAR"
        assert any("/v1/sequence/screen" in c["url"] for c in remote["calls"])

    def test_crop_vision_api_end_to_end(self, remote, client, auth):
        response = client.post("/api/v1/ai/crop-vision", headers=auth("FARM_OPERATOR"),
                               json={"simulate_label": "RUST"})
        assert response.status_code == 200, response.text
        assert response.json()["input_marking"] == "DEMO/SIMULATION"
        assert any("/v1/vision/classify" in c["url"] for c in remote["calls"])


class TestLedgerService:
    ARGS = {"event_code": "EV-REMOTE-1", "crop_type": "Maize", "trait": "drought tolerance",
            "donor_organism": "Bacillus subtilis", "developer": "Test Biotech",
            "screening_hash": "ab" * 32, "content_hash": "cd" * 32}

    def _anchor(self, code: str) -> dict:
        return ledger_client.submit("gmo_registry", "RegisterEvent",
                                    {**self.ARGS, "event_code": code}, "BiotechMSP")

    def test_submit_query_and_verify(self, remote):
        receipt = self._anchor("EV-REMOTE-1")
        assert receipt["ok"] is True and receipt["status"] == "ANCHORED", receipt
        assert ledger_client.query("gmo:EV-REMOTE-1") is not None
        assert ledger_client.verify_chain()["valid"] is True
        assert ledger_client.get_transaction(receipt["tx_id"])["transaction"]["tx_id"] == receipt["tx_id"]
        assert ledger_client.proof(receipt["tx_id"]) is not None
        assert ledger_client.recent_blocks(5)["height"] >= 2

    def test_contract_rejection_is_not_retried(self, remote):
        self._anchor("EV-REMOTE-DUP")
        before = len(remote["calls"])
        again = self._anchor("EV-REMOTE-DUP")
        assert again["status"] == "REJECTED"
        assert len(remote["calls"]) - before == 1

    def test_unreachable_ledger_degrades_without_raising(self, remote):
        remote["clients"].pop(LEDGER_URL)
        result = self._anchor("EV-REMOTE-DOWN")
        assert result["ok"] is False and result["status"] == "FAILED"
        assert ledger_client.query("gmo:EV-REMOTE-DOWN") is None
        assert ledger_client.stats()["height"] == 0

    def test_missing_records_are_none(self, remote):
        assert ledger_client.get_block(99_999) is None
        assert ledger_client.get_transaction("no-such-tx") is None
        assert ledger_client.query("no:such-key") is None

    def test_reset_returns_to_genesis(self, remote):
        self._anchor("EV-REMOTE-RESET")
        ledger_client.reset_store()
        assert ledger_client.stats()["height"] == 1
        assert ledger_client.query("gmo:EV-REMOTE-RESET") is None

    def test_reset_is_refused_unless_enabled(self, remote, monkeypatch):
        monkeypatch.setattr(ledger_service, "ALLOW_RESET", False)
        with pytest.raises(service_http.ServiceUnavailable):
            ledger_client.reset_store()

    def test_contracts_listing_matches_local(self, remote, monkeypatch):
        remote_listing = ledger_client.contracts()
        monkeypatch.setattr(ledger_client, "_remote", lambda: "")
        assert remote_listing == json.loads(json.dumps(ledger_client.contracts()))
