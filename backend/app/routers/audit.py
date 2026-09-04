"""Audit trail: listing, chain verification, anchoring and export (FR-F3, FR-X6)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.permissions import P
from ..models import AuditLog
from ..repositories import paginate
from ..schemas import AuditLogOut, Page
from ..services import audit as service

router = APIRouter(prefix="/audit", tags=["Audit"], dependencies=[Depends(rate_limit)])


@router.get("/logs", response_model=Page[AuditLogOut], summary="List audit records")
def list_logs(db: DbSession, paging: PagingDep,
              principal: Annotated[object, Depends(require_permission(P.AUDIT_READ))],
              action: str | None = Query(default=None),
              entity_id: str | None = Query(default=None),
              outcome: str | None = Query(default=None)) -> Page[AuditLogOut]:
    query = select(AuditLog).order_by(AuditLog.seq.desc())
    # The audit log is platform-wide; non-cross-tenant roles see only their own organisation.
    if not principal.is_cross_tenant:
        query = query.where(AuditLog.org_id == principal.org_id)
    if action:
        query = query.where(AuditLog.action == action)
    if entity_id:
        query = query.where(AuditLog.entity_id == entity_id)
    if outcome:
        query = query.where(AuditLog.outcome == outcome.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[AuditLogOut](items=[AuditLogOut.model_validate(r) for r in rows], total=total,
                             page=paging.page, page_size=paging.page_size)


@router.get("/verify", summary="Recompute the audit hash chain and report any divergence")
def verify(db: DbSession,
           principal: Annotated[object, Depends(require_permission(P.AUDIT_READ))]) -> dict:
    result = service.verify_chain(db)
    seq, head_hash = service.head(db)
    from ..services import ledger_client

    anchored = ledger_client.query("audithead:latest")
    return {**result, "head_seq": seq, "head_hash": head_hash,
            "anchored_head": anchored,
            "anchor_matches": bool(anchored and anchored.get("head_hash") == head_hash)}


@router.post("/anchor", summary="Anchor the current audit chain head to the ledger")
def anchor(db: DbSession,
           principal: Annotated[object, Depends(require_permission(P.AUDIT_READ))]) -> dict:
    result = service.anchor_head(db)
    db.commit()
    return result


@router.get("/export", summary="Export the audit trail as JSON evidence")
def export(db: DbSession,
           principal: Annotated[object, Depends(require_permission(P.AUDIT_READ))],
           limit: int = Query(default=1000, ge=1, le=10000)) -> JSONResponse:
    query = select(AuditLog).order_by(AuditLog.seq.asc()).limit(limit)
    if not principal.is_cross_tenant:
        query = query.where(AuditLog.org_id == principal.org_id)
    rows = list(db.execute(query).scalars())
    verification = service.verify_chain(db)
    payload = {
        "exported_by": principal.id, "records": len(rows),
        "chain_verification": verification,
        "entries": [AuditLogOut.model_validate(r).model_dump(mode="json") for r in rows],
    }
    service.record(db, "audit.export", actor_id=principal.id, actor_role=principal.role,
                   org_id=principal.org_id, detail={"records": len(rows)})
    db.commit()
    return JSONResponse(content=payload,
                        headers={"Content-Disposition": "attachment; filename=audit-export.json"})
