"""Ledger node service (ADR-016): the `ledger` container's HTTP surface.

The backend calls this through `backend/app/services/ledger_client.py`, which keeps its
retry, circuit-breaker and graceful-degradation behaviour in front of the network hop.
This process is the only writer of the ledger data directory.

Internal only: the compose network does not publish this port, and every call except
/health must present SERVICE_TOKEN in `X-Service-Token`. An unset SERVICE_TOKEN is a
refusal, not a bypass — see require_token().

    uvicorn ledger.service:app --host 0.0.0.0 --port 8200
"""
from __future__ import annotations

import hmac
import os
import shutil
import threading
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .chain import ContractError, EndorsementError, Ledger, LedgerError
from .contracts import CONTRACTS, ENDORSEMENT_POLICIES, SUBMIT_RIGHTS

DATA_DIR = Path(os.environ.get("LEDGER_DATA_DIR", "./ledger_data"))
CHANNEL = os.environ.get("LEDGER_CHANNEL", "agri-channel")
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")
# Demo reset (seed_demo.py --reset). Off unless explicitly enabled for a demo stack.
ALLOW_RESET = os.environ.get("LEDGER_ALLOW_RESET", "false").strip().lower() in {"1", "true", "yes"}

_lock = threading.Lock()
_ledger: Ledger | None = None


def ledger() -> Ledger:
    global _ledger
    with _lock:
        if _ledger is None:
            _ledger = Ledger(DATA_DIR, CHANNEL)
        return _ledger


def require_token(x_service_token: str = Header(default="")) -> None:
    """Fail closed.

    This used to allow every request when SERVICE_TOKEN was unset, so a misconfigured
    deployment silently exposed the whole internal API unauthenticated (audit P2). An absent
    token is now a refusal, not a bypass: the service is useless without configuration rather
    than open. Compose supplies the token via ${SERVICE_TOKEN:?}.
    """
    if not SERVICE_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="service is not configured: SERVICE_TOKEN is unset")
    if not hmac.compare_digest(x_service_token, SERVICE_TOKEN):
        raise HTTPException(status_code=401, detail="invalid service token")


app = FastAPI(title="ABSP ledger node", version="1.0.0", docs_url=None, redoc_url=None,
              openapi_url=None)


class SubmitRequest(BaseModel):
    contract: str
    function: str
    args: dict[str, Any]
    submitter_msp: str


class VerifyContentRequest(BaseModel):
    entity_hash: str
    tx_id: str | None = None


class IdentityRequest(BaseModel):
    msp_id: str
    name: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "ledger", "height": ledger().height}


@app.post("/v1/submit", dependencies=[Depends(require_token)])
def submit(payload: SubmitRequest) -> JSONResponse:
    """200 with the receipt; 409 for a deterministic contract rejection (the client must
    not retry it); 503 for an endorsement or ledger failure (the client may retry)."""
    try:
        receipt = ledger().submit(payload.contract, payload.function, payload.args,
                                  payload.submitter_msp)
    except ContractError as exc:
        return JSONResponse(status_code=409, content={"error": "contract_rejected",
                                                      "detail": str(exc)})
    except (EndorsementError, LedgerError) as exc:
        return JSONResponse(status_code=503, content={"error": "ledger_error",
                                                      "detail": str(exc)})
    return JSONResponse(status_code=200, content=receipt)


@app.get("/v1/state/{key:path}", dependencies=[Depends(require_token)])
def state(key: str) -> dict:
    value = ledger().query(key)
    if value is None:
        raise HTTPException(status_code=404, detail="state key not found")
    return {"key": key, "value": value}


@app.get("/v1/verify", dependencies=[Depends(require_token)])
def verify_chain() -> dict:
    return ledger().verify_chain()


@app.post("/v1/verify-content", dependencies=[Depends(require_token)])
def verify_content(payload: VerifyContentRequest) -> dict:
    return ledger().verify_content_hash(payload.entity_hash, payload.tx_id)


@app.get("/v1/stats", dependencies=[Depends(require_token)])
def stats() -> dict:
    return ledger().stats()


@app.get("/v1/blocks", dependencies=[Depends(require_token)])
def blocks(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    node = ledger()
    return {"height": node.height, "blocks": node.recent_blocks(limit)}


@app.get("/v1/blocks/{number}", dependencies=[Depends(require_token)])
def block(number: int) -> dict:
    found = ledger().get_block(number)
    if found is None:
        raise HTTPException(status_code=404, detail="block not found")
    return found


@app.get("/v1/transactions/{tx_id}", dependencies=[Depends(require_token)])
def transaction(tx_id: str) -> dict:
    found = ledger().get_transaction(tx_id)
    if found is None:
        raise HTTPException(status_code=404, detail="transaction not found")
    return found


@app.get("/v1/transactions/{tx_id}/proof", dependencies=[Depends(require_token)])
def proof(tx_id: str) -> dict:
    found = ledger().proof(tx_id)
    if found is None:
        raise HTTPException(status_code=404, detail="transaction not found")
    return found


@app.get("/v1/contracts", dependencies=[Depends(require_token)])
def contracts() -> dict:
    return {
        "contracts": {name: sorted(functions) for name, functions in CONTRACTS.items()},
        "endorsement_policies": ENDORSEMENT_POLICIES,
        "submit_rights": {k: sorted(v) for k, v in SUBMIT_RIGHTS.items()},
    }


@app.post("/v1/identities", dependencies=[Depends(require_token)])
def ensure_identity(payload: IdentityRequest) -> dict:
    ledger().msp.ensure(payload.msp_id, payload.name)
    return {"msp_id": payload.msp_id, "public_key": ledger().msp.public_key(payload.msp_id)}


@app.post("/v1/admin/reset", dependencies=[Depends(require_token)])
def reset() -> dict:
    """Wipe the chain and start from a fresh genesis block. Demo stacks only."""
    global _ledger
    if not ALLOW_RESET:
        raise HTTPException(status_code=403, detail="ledger reset is disabled")
    with _lock:
        _ledger = None
        if DATA_DIR.exists():
            for child in DATA_DIR.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
    return {"reset": True, "height": ledger().height}
