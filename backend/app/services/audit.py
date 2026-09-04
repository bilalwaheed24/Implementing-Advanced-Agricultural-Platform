"""Hash-chained, append-only audit trail (ADR-010, FR-F3, FR-X6)."""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.logging_conf import app_log, audit_log, correlation_id, log_event
from ..core.security import canonical_json, sha256_hex
from ..models import AuditLog

GENESIS_HASH = "0" * 64


def _entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    return sha256_hex(prev_hash + canonical_json(entry))


def record(db: Session, action: str, *, actor_id: str | None = None,
           actor_role: str | None = None, org_id: str | None = None,
           entity_type: str | None = None, entity_id: str | None = None,
           outcome: str = "SUCCESS", detail: dict[str, Any] | None = None,
           ip: str | None = None, user_agent: str | None = None) -> AuditLog | None:
    """Append one audit record. Never raises: an audit failure must not fail the action,
    but it is logged at ERROR so it is alarmed."""
    try:
        last = db.execute(
            select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)).scalar_one_or_none()
        seq = (last.seq + 1) if last else 1
        prev_hash = last.entry_hash if last else GENESIS_HASH
        payload = {
            "seq": seq, "action": action, "actor_id": actor_id, "actor_role": actor_role,
            "org_id": org_id, "entity_type": entity_type, "entity_id": entity_id,
            "outcome": outcome, "detail": detail or {},
        }
        entry = AuditLog(
            seq=seq, prev_hash=prev_hash, entry_hash=_entry_hash(prev_hash, payload),
            actor_id=actor_id, actor_role=actor_role, org_id=org_id, action=action,
            entity_type=entity_type, entity_id=entity_id, outcome=outcome,
            detail=detail or {}, ip=ip, user_agent=(user_agent or "")[:255],
            correlation_id=correlation_id.get(),
        )
        db.add(entry)
        db.flush()
        log_event(audit_log, logging.INFO, "audit", action=action, actor_id=actor_id,
                  entity_type=entity_type, entity_id=entity_id, outcome=outcome, seq=seq)
        return entry
    except Exception as exc:                                   # noqa: BLE001
        log_event(app_log, logging.ERROR, "audit write failed", action=action, error=str(exc))
        return None


def verify_chain(db: Session, limit: int | None = None) -> dict[str, Any]:
    """Recompute the whole chain and report the first divergence (tamper detection)."""
    query = select(AuditLog).order_by(AuditLog.seq.asc())
    if limit:
        query = query.limit(limit)
    entries = list(db.execute(query).scalars())
    prev_hash = GENESIS_HASH
    expected_seq = 1
    for entry in entries:
        if entry.seq != expected_seq:
            return {"valid": False, "entries": len(entries),
                    "first_divergence": {"seq": entry.seq, "issue": "sequence_gap",
                                         "expected_seq": expected_seq}}
        if entry.prev_hash != prev_hash:
            return {"valid": False, "entries": len(entries),
                    "first_divergence": {"seq": entry.seq, "issue": "prev_hash_mismatch"}}
        payload = {
            "seq": entry.seq, "action": entry.action, "actor_id": entry.actor_id,
            "actor_role": entry.actor_role, "org_id": entry.org_id,
            "entity_type": entry.entity_type, "entity_id": entry.entity_id,
            "outcome": entry.outcome, "detail": entry.detail or {},
        }
        if _entry_hash(entry.prev_hash, payload) != entry.entry_hash:
            return {"valid": False, "entries": len(entries),
                    "first_divergence": {"seq": entry.seq, "issue": "entry_hash_mismatch",
                                         "action": entry.action}}
        prev_hash = entry.entry_hash
        expected_seq += 1
    return {"valid": True, "entries": len(entries), "head_hash": prev_hash,
            "first_divergence": None}


def head(db: Session) -> tuple[int, str]:
    last = db.execute(select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)).scalar_one_or_none()
    return (last.seq, last.entry_hash) if last else (0, GENESIS_HASH)


def anchor_head(db: Session, submitter_msp: str = "RegulatorMSP") -> dict[str, Any]:
    """Anchor the current audit chain head to the ledger."""
    from . import ledger_client

    seq, head_hash = head(db)
    if seq == 0:
        return {"ok": False, "detail": "Audit chain is empty"}
    return ledger_client.submit("compliance_anchor", "AnchorAuditHead",
                                {"seq": seq, "head_hash": head_hash}, submitter_msp)


def count(db: Session) -> int:
    return int(db.execute(select(func.count()).select_from(AuditLog)).scalar_one())
