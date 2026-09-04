"""Backend-facing ledger client with retry, circuit breaking and graceful degradation.

An anchoring failure must never lose a business write (NFR-5, Blockchain-integration.md §13):
the record is stored with anchor_status = PENDING/FAILED and swept later.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

from ..core.config import get_settings
from ..core.logging_conf import app_log, log_event

_lock = threading.Lock()
_ledger: Any = None


def get_ledger():
    """Lazily construct the process-wide ledger."""
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


def query(state_key: str) -> Any:
    try:
        return get_ledger().query(state_key)
    except Exception:                                          # noqa: BLE001
        return None


def verify_chain() -> dict[str, Any]:
    try:
        return get_ledger().verify_chain()
    except Exception as exc:                                   # noqa: BLE001
        return {"valid": False, "error": str(exc), "height": 0}


def verify_content(entity_hash: str, tx_id: str | None) -> dict[str, Any]:
    try:
        return get_ledger().verify_content_hash(entity_hash, tx_id)
    except Exception as exc:                                   # noqa: BLE001
        return {"result": "UNKNOWN", "detail": str(exc)}


def stats() -> dict[str, Any]:
    try:
        return get_ledger().stats()
    except Exception as exc:                                   # noqa: BLE001
        return {"height": 0, "error": str(exc)}


ORG_TYPE_TO_MSP = {
    "BIOTECH": "BiotechMSP",
    "FARM": "FarmMSP",
    "SUPPLY": "SupplyMSP",
    "REGULATOR": "RegulatorMSP",
}
