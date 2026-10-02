"""Backend-facing ledger client with retry, circuit breaking and graceful degradation.

An anchoring failure must never lose a business write (NFR-5, Blockchain-integration.md §13):
the record is stored with anchor_status = PENDING/FAILED and swept later.

With LEDGER_SERVICE_URL set, every call goes over HTTP to the `ledger` container (ADR-016);
without it the ledger package runs in-process (tests, run_local.sh). Callers use the
functions below and never touch the Ledger object directly, so both modes look the same.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..core.config import get_settings
from ..core.logging_conf import app_log, log_event
from . import service_http

_lock = threading.Lock()
_ledger: Any = None


def _remote() -> str:
    return get_settings().ledger_service_url


def _get(path: str) -> Any:
    """GET from the ledger service; None for 404."""
    status, body = service_http.call(_remote(), "GET", path)
    if status == 404:
        return None
    if status != 200:
        raise service_http.unavailable(_remote(), path, f"status {status}")
    return body


def _post(path: str, body: dict[str, Any]) -> Any:
    status, response = service_http.call(_remote(), "POST", path, body)
    if status != 200:
        raise service_http.unavailable(_remote(), path, f"status {status}")
    return response


def get_ledger():
    """Lazily construct the process-wide in-process ledger (local mode only)."""
    global _ledger
    with _lock:
        if _ledger is None:
            import sys

            settings = get_settings()
            root = str(settings.repo_root)
            if root not in sys.path:
                sys.path.insert(0, root)
            from ledger import Ledger                       # noqa: PLC0415

            data_dir = Path(settings.ledger_data_dir)
            if not data_dir.is_absolute():
                data_dir = settings.repo_root / data_dir
            _ledger = Ledger(data_dir, settings.ledger_channel)
        return _ledger


def reset_ledger() -> None:
    """Test hook: drop the cached ledger so the next call rebuilds it."""
    global _ledger
    with _lock:
        _ledger = None


class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown_seconds: int = 30) -> None:
        self.threshold = threshold
        self.cooldown = cooldown_seconds
        self._failures = 0
        self._opened_at = 0.0
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        with self._lock:
            if self._failures < self.threshold:
                return False
            if time.monotonic() - self._opened_at > self.cooldown:
                self._failures = 0            # half-open: allow one attempt through
                return False
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.threshold:
                self._opened_at = time.monotonic()


_breaker = CircuitBreaker()


def submit(contract: str, function: str, args: dict[str, Any], submitter_msp: str,
           retries: int = 2) -> dict[str, Any]:
    """Submit a transaction. Returns {ok, ...} and never raises to the caller.

    A contract rejection is a business error and is reported as ok=False with the
    reason; it is not retried, because retrying a rejected transaction is pointless.
    """
    if _breaker.is_open:
        return {"ok": False, "status": "PENDING", "error": "ledger_circuit_open",
                "detail": "Ledger temporarily unavailable; anchoring queued"}

    if _remote():
        return _submit_remote(contract, function, args, submitter_msp, retries)

    from ledger.chain import EndorsementError, LedgerError      # noqa: PLC0415
    from ledger.contracts import ContractError                  # noqa: PLC0415

    last_error = ""
    for attempt in range(retries + 1):
        try:
            receipt = get_ledger().submit(contract, function, args, submitter_msp)
            _breaker.record_success()
            return {"ok": True, "status": "ANCHORED", **receipt}
        except ContractError as exc:
            # Deterministic rejection: do not retry.
            log_event(app_log, logging.WARNING, "ledger contract rejection",
                      contract=contract, function=function, error=str(exc))
            return {"ok": False, "status": "REJECTED", "error": "contract_rejected",
                    "detail": str(exc)}
        except (EndorsementError, LedgerError) as exc:
            last_error = str(exc)
            if attempt < retries:
                time.sleep(0.05 * (attempt + 1))
        except Exception as exc:                               # noqa: BLE001
            last_error = str(exc)
            if attempt < retries:
                time.sleep(0.05 * (attempt + 1))

    _breaker.record_failure()
    log_event(app_log, logging.ERROR, "ledger submission failed", contract=contract,
              function=function, error=last_error)
    return {"ok": False, "status": "FAILED", "error": "ledger_unavailable", "detail": last_error}


def _submit_remote(contract: str, function: str, args: dict[str, Any], submitter_msp: str,
                   retries: int) -> dict[str, Any]:
    """Same contract as the in-process path: 409 is a contract rejection (not retried),
    anything else unsuccessful is retried, then counted against the circuit breaker."""
    body = {"contract": contract, "function": function, "args": args,
            "submitter_msp": submitter_msp}
    last_error = ""
    for attempt in range(retries + 1):
        try:
            status, response = service_http.call(_remote(), "POST", "/v1/submit", body)
        except service_http.ServiceUnavailable as exc:
            status, response = 503, {"detail": str(exc)}
        if status == 200:
            _breaker.record_success()
            return {"ok": True, "status": "ANCHORED", **response}
        detail = response.get("detail", "") if isinstance(response, dict) else str(response)
        if status == 409:
            log_event(app_log, logging.WARNING, "ledger contract rejection",
                      contract=contract, function=function, error=detail)
            return {"ok": False, "status": "REJECTED", "error": "contract_rejected",
                    "detail": detail}
        last_error = f"{status}: {detail}"
        if attempt < retries:
            time.sleep(0.05 * (attempt + 1))

    _breaker.record_failure()
    log_event(app_log, logging.ERROR, "ledger submission failed", contract=contract,
              function=function, error=last_error)
    return {"ok": False, "status": "FAILED", "error": "ledger_unavailable", "detail": last_error}


def query(state_key: str) -> Any:
    try:
        if _remote():
            found = _get(f"/v1/state/{quote(state_key, safe=':/')}")
            return None if found is None else found["value"]
        return get_ledger().query(state_key)
    except Exception:                                          # noqa: BLE001
        return None


def verify_chain() -> dict[str, Any]:
    try:
        return _get("/v1/verify") if _remote() else get_ledger().verify_chain()
    except Exception as exc:                                   # noqa: BLE001
        return {"valid": False, "error": str(exc), "height": 0}


def verify_content(entity_hash: str, tx_id: str | None) -> dict[str, Any]:
    try:
        if _remote():
            return _post("/v1/verify-content", {"entity_hash": entity_hash, "tx_id": tx_id})
        return get_ledger().verify_content_hash(entity_hash, tx_id)
    except Exception as exc:                                   # noqa: BLE001
        return {"result": "UNKNOWN", "detail": str(exc)}


def stats() -> dict[str, Any]:
    try:
        return _get("/v1/stats") if _remote() else get_ledger().stats()
    except Exception as exc:                                   # noqa: BLE001
        return {"height": 0, "error": str(exc)}


# --- explorer reads: raise ServiceUnavailable (a 503) rather than degrade -------------
def recent_blocks(limit: int) -> dict[str, Any]:
    if _remote():
        return _get(f"/v1/blocks?limit={int(limit)}")
    ledger = get_ledger()
    return {"height": ledger.height, "blocks": ledger.recent_blocks(limit)}


def get_block(number: int) -> dict[str, Any] | None:
    return _get(f"/v1/blocks/{int(number)}") if _remote() else get_ledger().get_block(number)


def get_transaction(tx_id: str) -> dict[str, Any] | None:
    if _remote():
        return _get(f"/v1/transactions/{quote(tx_id, safe='')}")
    return get_ledger().get_transaction(tx_id)


def proof(tx_id: str) -> dict[str, Any] | None:
    if _remote():
        return _get(f"/v1/transactions/{quote(tx_id, safe='')}/proof")
    return get_ledger().proof(tx_id)


def contracts() -> dict[str, Any]:
    if _remote():
        return _get("/v1/contracts")
    from ledger.contracts import CONTRACTS, ENDORSEMENT_POLICIES, SUBMIT_RIGHTS  # noqa: PLC0415

    return {
        "contracts": {name: sorted(functions) for name, functions in CONTRACTS.items()},
        "endorsement_policies": ENDORSEMENT_POLICIES,
        "submit_rights": {k: sorted(v) for k, v in SUBMIT_RIGHTS.items()},
    }


def ensure_identity(msp_id: str, name: str) -> None:
    """Give an organisation a ledger signing identity (idempotent)."""
    if _remote():
        _post("/v1/identities", {"msp_id": msp_id, "name": name})
    else:
        get_ledger().msp.ensure(msp_id, name)


def reset_store() -> None:
    """Demo reset (seed_demo.py --reset): wipe the chain back to a fresh genesis block."""
    if _remote():
        _post("/v1/admin/reset", {})
        return
    import shutil

    settings = get_settings()
    data_dir = Path(settings.ledger_data_dir)
    if not data_dir.is_absolute():
        data_dir = settings.repo_root / data_dir
    reset_ledger()
    if data_dir.exists():
        shutil.rmtree(data_dir, ignore_errors=True)


ORG_TYPE_TO_MSP = {
    "BIOTECH": "BiotechMSP",
    "FARM": "FarmMSP",
    "SUPPLY": "SupplyMSP",
    "REGULATOR": "RegulatorMSP",
}
