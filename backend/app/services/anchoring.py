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
from datetime import timedelta
from typing import Any

from sqlalchemy import event, func, select
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


def remirror(db: Session, limit: int = 200, min_age_seconds: int = 60) -> dict[str, Any]:
    """Mirror every anchored write whose Fabric copy failed or never happened.

    A PENDING row younger than `min_age_seconds` may still have its background mirror in
    flight, so it is left alone. Fabric is asked first: a key already holding this hash is
    marked mirrored without writing a second version.
    """
    if not fabric_bridge.enabled():
        return {"enabled": False, "mirrored": 0, "already_mirrored": 0, "failed": 0}
    cutoff = utcnow() - timedelta(seconds=min_age_seconds)
    rows = db.execute(select(LedgerWrite).where(
        LedgerWrite.anchor_status == "ANCHORED", LedgerWrite.fabric_key.is_not(None),
        (LedgerWrite.fabric_status == "FAILED")
        | ((LedgerWrite.fabric_status == "PENDING") & (LedgerWrite.anchored_at <= cutoff)))
        .order_by(LedgerWrite.anchored_at.asc()).limit(limit)
        .execution_options(populate_existing=True)).scalars().all()
    counts = {"enabled": True, "mirrored": 0, "already_mirrored": 0, "failed": 0}
    for row in rows:
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
def retry_pending(db: Session, limit: int = 500) -> dict[str, int]:
    """Replay unanchored writes oldest first. A write whose chain key or required keys sit
    behind a write that still fails is held back, so a batch's events are never submitted
    before the batch itself. Stops early when the ledger's circuit breaker is open."""
    rows = db.execute(select(LedgerWrite).where(LedgerWrite.anchor_status.in_(UNRESOLVED))
                      .order_by(LedgerWrite.created_at.asc(), LedgerWrite.id.asc())
                      .limit(limit).execution_options(populate_existing=True)).scalars().all()
    counts = {"attempted": 0, "anchored": 0, "already_anchored": 0, "failed": 0,
              "rejected": 0, "blocked": 0, "deferred": 0}
    blocked: set[str] = set()
    for index, row in enumerate(rows):
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
