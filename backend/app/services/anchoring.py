"""Durable anchoring: journal, ordered replay and Fabric re-mirroring of ledger writes.

`ledger_client.submit(..., db=db, entity=record)` lands here. Every write is journalled in
`ledger_writes` with the exact contract call, so a write that came back PENDING/FAILED (ledger
outage, open circuit breaker) is replayed by `retry_pending` rather than left unanchored.

The ledger contracts are stateful: RecordEvent and TransferCustody need the batch on-chain,
RecordApproval needs the GMO event, a derived batch needs its parents. So each write names the
world-state key it creates or advances (`chain_key`) and the keys it requires; a new write that
touches a key with an unanchored earlier write is queued behind it instead of being submitted
and rejected ("Unknown batch ..."), and the replay walks the journal oldest first, holding back
everything behind a write that still fails.

Ledger writes happen before the request's database commit (see ledger_client). If a replayed
write was in fact anchored earlier (the ledger committed but the response was lost, or an
earlier sweep's commit failed), the contract rejects the duplicate; `_already_on_ledger` then
recognises the identical record in world state and the write is resolved as anchored, so a
replay never anchors twice and never reports an error for it.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta
from typing import Any

from sqlalchemy import event, func, select, text
from sqlalchemy.orm import Session

from ..core.logging_conf import app_log, log_event
from ..core.security import utcnow
from ..models import LedgerWrite
from . import fabric_bridge, ledger_client

UNRESOLVED = ("PENDING", "FAILED")

# Function -> (key it creates or advances, keys it requires), formatted from its args.
_CHAIN: dict[str, tuple[str, tuple[str, ...]]] = {
    "gmo_registry.RegisterEvent": ("gmo:{event_code}", ()),
    "gmo_registry.RecordApproval": ("gmoapproval:{event_code}:{jurisdiction}", ("gmo:{event_code}",)),
    "gmo_registry.RegisterSeedLot": ("seedlot:{lot_code}", ("gmo:{event_code}",)),
    "provenance.CreateBatch": ("batch:{batch_code}", ()),           # + one per parent batch
    "provenance.RecordEvent": ("batch:{batch_code}", ()),
    "provenance.TransferCustody": ("batch:{batch_code}", ()),
    "certification.Issue": ("cert:{cert_code}", ()),
    "certification.Revoke": ("cert:{cert_code}", ()),
    "compliance_anchor.AnchorReport": ("report:{report_id}", ()),
    "compliance_anchor.AnchorAuditHead": ("audithead:latest", ()),
    "imagery.AnchorScene": ("scene:{scene_id}", ()),
}


def chain_keys(contract: str, function: str, args: dict[str, Any]) -> tuple[str, list[str]]:
    """(world-state key the write creates or advances, keys that must already be anchored)."""
    name = f"{contract}.{function}"
    own, needs = _CHAIN.get(name, (name, ()))
    values = {k: "" if v is None else str(v) for k, v in args.items()}

    def fill(template: str) -> str | None:
        try:
            key = template.format(**values)
        except KeyError:
            return None
        return None if key.endswith(":") or "::" in key else key

    requires = [key for key in (fill(t) for t in needs) if key]
    if name == "provenance.CreateBatch":
        requires += [f"batch:{parent}" for parent in args.get("parents") or []]
    return fill(own) or name, requires


def _blocker(db: Session, keys: list[str]) -> LedgerWrite | None:
    """The oldest unanchored write a new write on `keys` would have to wait for."""
    return db.execute(select(LedgerWrite).where(
        LedgerWrite.chain_key.in_(keys), LedgerWrite.anchor_status.in_(UNRESOLVED))
        .order_by(LedgerWrite.created_at.asc()).limit(1)).scalar_one_or_none()


def submit(db: Session, contract: str, function: str, args: dict[str, Any], submitter_msp: str,
           entity: Any = None, retries: int = 2) -> dict[str, Any]:
    """Submit (or queue) a write and journal it. Same receipt contract as ledger_client."""
    chain_key, requires = chain_keys(contract, function, args)
    blocker = _blocker(db, [chain_key, *requires])
    if blocker is not None:
        receipt = {"ok": False, "status": "PENDING", "error": "queued_behind_unanchored_write",
                   "detail": f"Queued until {blocker.contract}.{blocker.function} for "
                             f"{blocker.chain_key} is anchored"}
    else:
        receipt = ledger_client._submit(contract, function, args, submitter_msp, retries)
    row = LedgerWrite(contract=contract, function=function, args=dict(args),
                      submitter_msp=submitter_msp, chain_key=chain_key, requires=requires,
                      entity_type=type(entity).__name__ if entity is not None else None,
                      entity_id=getattr(entity, "id", None),
                      anchor_status=receipt.get("status", "FAILED"),
                      attempts=0 if blocker is not None else 1,
                      last_error=None if receipt.get("ok") else receipt.get("detail"))
    if receipt.get("ok"):
        _mark_anchored(row, receipt)
    db.add(row)
    db.flush()                       # visible to the next write's _blocker in this request
    if row.fabric_status == "PENDING" and fabric_bridge.enabled():
        _mirror_after_commit(db, row)
    return receipt


def _mark_anchored(row: LedgerWrite, receipt: dict[str, Any] | None) -> None:
    row.anchor_status = "ANCHORED"
    row.anchored_at = utcnow()
    if receipt is not None:
        row.tx_id = receipt.get("tx_id")
        row.block_number = receipt.get("block_number")
    target = fabric_bridge.key_for(row.contract, row.function, row.args)
    if target is not None and row.fabric_status != "MIRRORED":
        row.fabric_key = target[0]
        # PENDING = owed to Fabric until a mirror succeeds. With no bridge configured the
        # status stays NULL (not owed); the key is kept so history could be backfilled.
        row.fabric_status = "PENDING" if fabric_bridge.enabled() else None


# --------------------------------------------------------------------------- #
# Fabric mirror bookkeeping
# --------------------------------------------------------------------------- #
def _mirror_after_commit(db: Session, row: LedgerWrite) -> None:
    """Start the background mirror only once the journal row is committed: the mirror thread
    records its outcome on that row, and a rolled-back request must not be mirrored at all."""
    queue = db.info.setdefault("fabric_mirror_queue", [])
    if not db.info.get("fabric_mirror_hooked"):
        event.listen(db, "after_commit", _start_queued_mirrors)
        event.listen(db, "after_rollback", _drop_queued_mirrors)
        db.info["fabric_mirror_hooked"] = True
    queue.append((row.id, row.contract, row.function, dict(row.args), row.tx_id or "",
                  row.submitter_msp))


def _start_queued_mirrors(db: Session) -> None:
    queue, db.info["fabric_mirror_queue"] = db.info.get("fabric_mirror_queue", []), []
    for write_id, contract, function, args, tx_id, msp in queue:
        fabric_bridge.mirror(contract, function, args, tx_id, msp,
                             on_done=lambda entry, write_id=write_id: _store_mirror(write_id, entry))


def _drop_queued_mirrors(db: Session) -> None:
    db.info["fabric_mirror_queue"] = []


def _store_mirror(write_id: str, entry: dict[str, Any] | None) -> None:
    """Persist a background mirror's outcome (runs on the mirror thread, own session)."""
    if entry is None:
        return
    from ..core.database import SessionLocal                         # noqa: PLC0415

    try:
        with SessionLocal() as session:
            row = session.get(LedgerWrite, write_id)
            if row is not None:
                _apply_mirror(row, entry)
                session.commit()
    except Exception as exc:                                         # noqa: BLE001
        # The re-mirror sweep picks the row up again; nothing is lost.
        log_event(app_log, logging.WARNING, "fabric mirror status not saved", write_id=write_id,
                  error=str(exc))


def _apply_mirror(row: LedgerWrite, entry: dict[str, Any]) -> None:
    row.fabric_attempts = (row.fabric_attempts or 0) + 1
    if entry.get("ok"):
        row.fabric_status = "MIRRORED"
        row.fabric_tx_id = entry.get("fabric_tx_id")
        row.fabric_error = None
        row.mirrored_at = utcnow()
    else:
        row.fabric_status = "FAILED"
        row.fabric_error = str(entry.get("error") or "mirror failed")[:2000]


def remirror(db: Session, limit: int = 200, min_age_seconds: int = 60,
             time_budget_seconds: float | None = None) -> dict[str, Any]:
    """Mirror every anchored write whose Fabric copy failed or never happened.

    A PENDING row younger than `min_age_seconds` may still have its background mirror in
    flight, so it is left alone. Fabric is asked first: a key already holding this hash is
    marked mirrored without writing a second version.

    With `time_budget_seconds` the pass stops starting new rows once the budget is spent
    (`skipped` counts the rest; the next pass takes them), so a hanging gateway cannot
    starve whatever runs after it. A row already in flight finishes within the bridge's own
    request timeout.
    """
    if not fabric_bridge.enabled():
        return {"enabled": False, "mirrored": 0, "already_mirrored": 0, "failed": 0,
                "skipped": 0}
    cutoff = utcnow() - timedelta(seconds=min_age_seconds)
    rows = db.execute(select(LedgerWrite).where(
        LedgerWrite.anchor_status == "ANCHORED", LedgerWrite.fabric_key.is_not(None),
        (LedgerWrite.fabric_status == "FAILED")
        | ((LedgerWrite.fabric_status == "PENDING") & (LedgerWrite.anchored_at <= cutoff)))
        .order_by(LedgerWrite.anchored_at.asc()).limit(limit)
        .execution_options(populate_existing=True)).scalars().all()
    counts = {"enabled": True, "mirrored": 0, "already_mirrored": 0, "failed": 0, "skipped": 0}
    deadline = None if time_budget_seconds is None else time.monotonic() + time_budget_seconds
    for index, row in enumerate(rows):
        if deadline is not None and time.monotonic() >= deadline:
            counts["skipped"] = len(rows) - index
            break
        counts[_mirror_row(row)] += 1
    db.flush()
    return counts


def _mirror_row(row: LedgerWrite) -> str:
    """Synchronously mirror one row; returns the counts bucket it falls in."""
    target = fabric_bridge.key_for(row.contract, row.function, row.args)
    if target is None:
        row.fabric_status = None
        return "already_mirrored"
    check = fabric_bridge.verify(*target)
    if check.get("result") == "MATCH":
        row.fabric_status, row.fabric_error, row.mirrored_at = "MIRRORED", None, utcnow()
        return "already_mirrored"
    entry = fabric_bridge.anchor_now(row.contract, row.function, dict(row.args),
                                     row.tx_id or "", row.submitter_msp)
    if entry is None:
        return "failed"
    _apply_mirror(row, entry)
    return "mirrored" if entry.get("ok") else "failed"


def mirror_counts(db: Session) -> dict[str, int]:
    """Durable Fabric mirror counts for the status page."""
    rows = dict(db.execute(select(LedgerWrite.fabric_status, func.count())
                           .where(LedgerWrite.fabric_status.is_not(None))
                           .group_by(LedgerWrite.fabric_status)).all())
    return {"mirrored_ok": rows.get("MIRRORED", 0), "mirrored_failed": rows.get("FAILED", 0),
            "mirror_pending": rows.get("PENDING", 0)}


def anchor_counts(db: Session) -> dict[str, int]:
    return dict(db.execute(select(LedgerWrite.anchor_status, func.count())
                           .group_by(LedgerWrite.anchor_status)).all())


# --------------------------------------------------------------------------- #
# Ordered replay
# --------------------------------------------------------------------------- #
# One replay at a time. The scheduler and POST /blockchain/anchors/retry both replay the
# journal; two replays reading the same PENDING rows would both submit them, and a write the
# contract does not reject as a duplicate (AnchorAuditHead at the same seq) would be anchored
# twice. In PostgreSQL a transaction-scoped advisory lock serialises replays across processes
# and is released when the caller commits or rolls back, i.e. only once the replay's status
# changes are visible to the next replayer. Within one process (and on SQLite, which has no
# advisory locks) a non-blocking process lock does the same.
_REPLAY_LOCK = threading.Lock()
_REPLAY_ADVISORY_KEY = 0x41425350_0001          # "ABSP" + replay


def _claim_replay(db: Session) -> bool:
    """Take the cross-process replay claim for this transaction (PostgreSQL only)."""
    if db.get_bind().dialect.name != "postgresql":
        return True
    return bool(db.execute(text("SELECT pg_try_advisory_xact_lock(:key)"),
                           {"key": _REPLAY_ADVISORY_KEY}).scalar())


def retry_pending(db: Session, limit: int = 500) -> dict[str, int]:
    """Replay unanchored writes oldest first. A write whose chain key or required keys sit
    behind a write that still fails is held back, so a batch's events are never submitted
    before the batch itself. Stops early when the ledger's circuit breaker is open.

    Only one replay runs at a time (see _REPLAY_LOCK); a call that finds another in progress
    returns at once with `busy` set rather than replaying the same rows concurrently."""
    if not _REPLAY_LOCK.acquire(blocking=False):
        return {**_EMPTY_COUNTS, "busy": True}
    try:
        if not _claim_replay(db):
            return {**_EMPTY_COUNTS, "busy": True}
        return _retry_pending(db, limit)
    finally:
        _REPLAY_LOCK.release()


_EMPTY_COUNTS = {"attempted": 0, "anchored": 0, "already_anchored": 0, "failed": 0,
                 "rejected": 0, "blocked": 0, "deferred": 0, "busy": False}


def _retry_pending(db: Session, limit: int) -> dict[str, int]:
    rows = db.execute(select(LedgerWrite).where(LedgerWrite.anchor_status.in_(UNRESOLVED))
                      .order_by(LedgerWrite.created_at.asc(), LedgerWrite.id.asc())
                      .limit(limit).execution_options(populate_existing=True)).scalars().all()
    counts = dict(_EMPTY_COUNTS)
    blocked: set[str] = set()
    for index, row in enumerate(rows):
        if row.anchor_status not in UNRESOLVED:     # resolved since it was read: never replay
            continue
        if blocked & {row.chain_key, *(row.requires or [])}:
            blocked.add(row.chain_key)
            counts["blocked"] += 1
            continue
        receipt = ledger_client._submit(row.contract, row.function, row.args, row.submitter_msp)
        if receipt.get("error") == "ledger_circuit_open":
            counts["deferred"] = len(rows) - index
            break
        counts["attempted"] += 1
        row.attempts = (row.attempts or 0) + 1
        if receipt.get("ok"):
            _resolve(db, row, receipt)
            counts["anchored"] += 1
        elif receipt.get("status") == "REJECTED":
            if _already_on_ledger(row.contract, row.function, row.args):
                _resolve(db, row, None)
                row.last_error = "Already on the ledger from an earlier attempt"
                counts["already_anchored"] += 1
            else:
                # Terminal: replaying it again would be rejected again. Later writes are not
                # held back by it; the contract judges each of them on its own.
                row.anchor_status = "REJECTED"
                row.last_error = receipt.get("detail")
                _update_entity(db, row, None, "REJECTED")
                _alert_rejected(db, row)
                counts["rejected"] += 1
        else:
            row.anchor_status = receipt.get("status", "FAILED")
            row.last_error = receipt.get("detail")
            blocked.add(row.chain_key)
            counts["failed"] += 1
    db.flush()
    if counts["anchored"] or counts["already_anchored"] or counts["rejected"]:
        log_event(app_log, logging.INFO, "anchor retry sweep", **counts)
    return counts


def _alert_rejected(db: Session, row: LedgerWrite) -> None:
    """A replay the ledger rejected leaves its record permanently unanchored: tell the
    analysts (LEDGER alert, one per affected entity, repeats folded in by `kind`)."""
    from ..models import Organization                                # noqa: PLC0415
    from . import notifications                                      # noqa: PLC0415

    org_id = db.execute(select(Organization.id).where(
        Organization.msp_id == row.submitter_msp)).scalar_one_or_none()
    entity_type = row.entity_type or "LedgerWrite"
    entity_id = row.entity_id or row.id
    try:
        notifications.raise_alert(
            db, "LEDGER", "HIGH",
            f"Ledger rejected the replayed {row.contract}.{row.function} for {row.chain_key}",
            detail=f"The record stays unanchored: {row.last_error or 'contract rejection'}",
            org_id=org_id, entity_type=entity_type, entity_id=entity_id,
            reasons=[f"{row.contract}.{row.function}", row.chain_key],
            kind="ledger_replay_rejected", open_incident=False)
    except Exception as exc:                                         # noqa: BLE001
        # The REJECTED status is already recorded; an alert failure must not undo it.
        log_event(app_log, logging.WARNING, "ledger rejection alert failed", write_id=row.id,
                  error=str(exc))
    if org_id is None:
        return
    # The LEDGER alert is security operations' only, so the organisation whose record it is
    # never heard that its record is unanchored (round 6). Tell its people who write that kind
    # of record, plainly: no alert, nothing for them to resolve.
    try:
        what = record_description(row.chain_key)
        notifications.notify_org_roles(
            db, org_id, _RECORD_WRITERS.get(row.contract, ()), "LEDGER",
            f"Could not anchor {what} on the ledger"[:255],
            f"The ledger rejected the {_FUNCTION_WORDS.get(row.function, 'write')} for {what}, "
            f"so this record is not anchored and its blockchain proof is unavailable for now. "
            f"Security analysts have been alerted and are handling it; you do not need to do "
            f"anything.",
            entity_type, entity_id, severity="WARNING", skip_oversight=True)
    except Exception as exc:                                         # noqa: BLE001
        log_event(app_log, logging.WARNING, "ledger rejection notice failed", write_id=row.id,
                  error=str(exc))


# Who in the submitting organisation hears that one of its records could not be anchored: the
# roles that write that kind of record. An organisation with none of them hears it anyway
# (notify_org_roles falls back to every active member).
_RECORD_WRITERS: dict[str, tuple[str, ...]] = {
    "provenance": ("SUPPLY_CHAIN_OPERATOR", "FARM_OPERATOR"),
    "certification": ("CERTIFIER",),
    "gmo_registry": ("BIOTECH_RESEARCHER", "BIOSAFETY_OFFICER", "REGULATOR"),
    "compliance_anchor": ("SUPPLY_CHAIN_OPERATOR", "CERTIFIER", "REGULATOR"),
    "imagery": ("FARM_OPERATOR", "AGRONOMIST"),
}
_FUNCTION_WORDS = {
    "RegisterEvent": "registration", "RecordApproval": "approval decision",
    "RegisterSeedLot": "registration", "CreateBatch": "creation", "RecordEvent": "event",
    "TransferCustody": "custody hand-over", "Issue": "issue", "Revoke": "revocation",
    "AnchorReport": "anchoring", "AnchorAuditHead": "checkpoint", "AnchorScene": "anchoring",
}
_KEY_WORDS = {
    "batch": "batch", "gmo": "GMO event", "seedlot": "seed lot", "cert": "certificate",
    "report": "compliance report", "scene": "satellite scene",
}


def record_description(chain_key: str | None) -> str:
    """ "batch:B-1024" -> "batch B-1024"; "gmoapproval:MON87411:US-USDA" -> "the USDA (US)
    approval of GMO event MON87411"; anything unknown -> "a record"."""
    from .notifications import jurisdiction_label                    # noqa: PLC0415

    parts = (chain_key or "").split(":")
    kind = parts[0]
    if kind == "gmoapproval" and len(parts) >= 3:
        return f"the {jurisdiction_label(parts[2])} approval of GMO event {parts[1]}"
    if kind == "audithead":
        return "the audit trail checkpoint"
    if kind == "report" and len(parts) >= 2:
        return f"compliance report {parts[1][:8]}"
    if kind in _KEY_WORDS and len(parts) >= 2 and parts[1]:
        return f"{_KEY_WORDS[kind]} {':'.join(parts[1:])}"
    return "a record"


def _resolve(db: Session, row: LedgerWrite, receipt: dict[str, Any] | None) -> None:
    _mark_anchored(row, receipt)
    row.last_error = None
    _update_entity(db, row, receipt, "ANCHORED")
    if row.fabric_status == "PENDING" and fabric_bridge.enabled():
        _mirror_row(row)


def _update_entity(db: Session, row: LedgerWrite, receipt: dict[str, Any] | None,
                   status: str) -> None:
    """Complete the stored record's anchor fields as its original request would have."""
    from .. import models                                            # noqa: PLC0415
    from . import gmo as gmo_service                                 # noqa: PLC0415

    model = getattr(models, row.entity_type or "", None)
    entity = db.get(model, row.entity_id) if model is not None and row.entity_id else None
    if entity is None:
        return
    if hasattr(entity, "anchor_status"):
        if receipt is not None:
            gmo_service._apply_receipt(db, entity, receipt, row.entity_type)
        else:
            entity.anchor_status = status
    elif receipt is not None:
        for field in ("tx_id", "anchor_tx_id"):        # GMOApproval / SatelliteScene
            if hasattr(entity, field):
                setattr(entity, field, receipt.get("tx_id"))
                break


def _already_on_ledger(contract: str, function: str, args: dict[str, Any]) -> bool:
    """True when world state already holds exactly what this write would have produced."""
    name = f"{contract}.{function}"
    if name == "compliance_anchor.AnchorAuditHead":
        state = ledger_client.query("audithead:latest") or {}
        return int(state.get("seq", -1)) >= int(args.get("seq", 0))     # superseded or same
    if name == "gmo_registry.RecordApproval":
        state = ledger_client.query(f"gmoapproval:{args.get('event_code')}:"
                                    f"{args.get('jurisdiction')}") or {}
        return state.get("status") == args.get("status")
    if name == "certification.Revoke":
        state = ledger_client.query(f"cert:{args.get('cert_code')}") or {}
        return state.get("status") == "REVOKED"
    if name == "provenance.TransferCustody":
        state = ledger_client.query(f"batch:{args.get('batch_code')}") or {}
        wanted = {"from": args.get("from_org"), "to": args.get("to_org"),
                  "at": args.get("occurred_at", "")}
        return wanted in (state.get("custody_history") or [])
    target = fabric_bridge.key_for(contract, function, args)
    hash_name = fabric_bridge.hash_arg(contract, function)
    if target is None or hash_name is None:
        return False
    state = ledger_client.query(target[0])
    return isinstance(state, dict) and state.get(hash_name) == target[1]
