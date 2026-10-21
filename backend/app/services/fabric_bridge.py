"""Mirror of ledger anchors onto a real Hyperledger Fabric network (fabric/gateway).

The platform's own ledger stays the system of record for anchoring. When FABRIC_BRIDGE_URL
is set, every successful anchor that carries a content hash is also written to the
`absp-anchor` chaincode, where two organisations' peers must endorse it. Verification can
then be repeated against Fabric, which the platform's own signing keys cannot rewrite.

A Fabric outage must never block or fail a business write: mirroring runs on a background
thread, and failures are recorded for the status page and logged.
"""
from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from ..core.config import get_settings
from ..core.logging_conf import app_log, log_event

_recent: deque[dict[str, Any]] = deque(maxlen=25)
_lock = threading.Lock()

# Local ledger function -> (key prefix, identifier arg, hash arg). The key matches the local
# ledger's own world-state key, so the two can be compared record for record.
_KEYS: dict[str, tuple[str, str, str]] = {
    "gmo_registry.RegisterEvent": ("gmo", "event_code", "content_hash"),
    "gmo_registry.RegisterSeedLot": ("seedlot", "lot_code", "content_hash"),
    "provenance.CreateBatch": ("batch", "batch_code", "content_hash"),
    "provenance.RecordEvent": ("event", "event_id", "content_hash"),
    "certification.Issue": ("cert", "cert_code", "content_hash"),
    "compliance_anchor.AnchorReport": ("report", "report_id", "content_hash"),
    "compliance_anchor.AnchorAuditHead": ("audithead", "", "head_hash"),
    "imagery.AnchorScene": ("scene", "scene_id", "file_sha256"),
}


def enabled() -> bool:
    return bool(get_settings().fabric_bridge_url)


def key_for(contract: str, function: str, args: dict[str, Any]) -> tuple[str, str] | None:
    """(fabric key, hash) for a local anchor, or None when it carries no content hash."""
    spec = _KEYS.get(f"{contract}.{function}")
    if spec is None:
        return None
    prefix, id_arg, hash_arg = spec
    digest = str(args.get(hash_arg) or "")
    identifier = str(args.get(id_arg) or "") if id_arg else "latest"
    if len(digest) != 64 or not identifier:
        return None
    return f"{prefix}:{identifier}", digest


def _call(method: str, path: str, body: dict[str, Any] | None = None,
          timeout: float = 20.0) -> tuple[int, dict[str, Any]]:
    settings = get_settings()
    request = urllib.request.Request(
        settings.fabric_bridge_url + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {settings.fabric_bridge_token}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read() or b"{}")
        except ValueError:
            return error.code, {"detail": f"HTTP {error.code}"}
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return 0, {"detail": f"bridge unreachable: {getattr(error, 'reason', error)}"}


def _record(entry: dict[str, Any]) -> None:
    with _lock:
        _recent.appendleft(entry)


def anchor_now(contract: str, function: str, args: dict[str, Any], local_tx_id: str,
               source_msp: str) -> dict[str, Any] | None:
    """Synchronous mirror of one anchor. Returns the outcome, or None when not applicable."""
    target = key_for(contract, function, args)
    if target is None or not enabled():
        return None
    key, digest = target
    status, body = _call("POST", "/anchor", {"key": key, "content_hash": digest,
                                             "local_tx_id": local_tx_id,
                                             "entity_type": key.split(":")[0],
                                             "source_msp": source_msp})
    entry = {"key": key, "content_hash": digest, "local_tx_id": local_tx_id,
             "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "ok": status == 200, "fabric_tx_id": body.get("fabricTxId"),
             "version": body.get("version"), "error": None if status == 200 else body.get("detail")}
    _record(entry)
    if status != 200:
        log_event(app_log, logging.WARNING, "fabric mirror failed", key=key, status=status,
                  detail=body.get("detail"))
    return entry


def mirror(contract: str, function: str, args: dict[str, Any], local_tx_id: str,
           source_msp: str) -> None:
    """Fire-and-forget mirror, used by ledger_client after a successful local anchor."""
    if not enabled() or key_for(contract, function, args) is None:
        return
    thread = threading.Thread(target=anchor_now, name="fabric-mirror", daemon=True,
                              args=(contract, function, dict(args), local_tx_id, source_msp))
    thread.start()


def verify(key: str, digest: str) -> dict[str, Any]:
    """Ask Fabric whether `digest` matches its anchor for `key`."""
    if not enabled():
        return {"result": "DISABLED", "detail": "FABRIC_BRIDGE_URL is not set"}
    status, body = _call("GET", "/verify?" + urlencode({"key": key, "hash": digest}), timeout=10)
    if status != 200:
        return {"result": "UNAVAILABLE", "detail": body.get("detail")}
    return {**body, "network": "hyperledger-fabric"}


def history(key: str) -> dict[str, Any]:
    if not enabled():
        return {"key": key, "history": [], "detail": "FABRIC_BRIDGE_URL is not set"}
    status, body = _call("GET", "/history?" + urlencode({"key": key}), timeout=10)
    return body if status == 200 else {"key": key, "history": [], "detail": body.get("detail")}


def status() -> dict[str, Any]:
    if not enabled():
        return {"enabled": False, "detail": "FABRIC_BRIDGE_URL is not set: the platform runs "
                                            "its single-node ledger only."}
    code, body = _call("GET", "/health", timeout=5)
    with _lock:
        recent = list(_recent)
    return {"enabled": True, "reachable": code == 200, "bridge": body, "recent": recent,
            "mirrored_ok": sum(1 for r in recent if r["ok"]),
            "mirrored_failed": sum(1 for r in recent if not r["ok"])}
