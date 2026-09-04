"""GMO registry, approvals, seed lots and labelling validation (FR-B1, FR-B3)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.permissions import P
from ..models import Batch, GMOApproval, GMOEvent, SeedLot
from ..repositories import get_or_404, paginate, visible
from ..schemas import (GMOApprovalCreate, GMOApprovalOut, GMOEventCreate, GMOEventOut, Page,
                       SeedLotCreate, SeedLotOut)
from ..services import gmo as service

router = APIRouter(prefix="/gmo", tags=["GMO Registry"], dependencies=[Depends(rate_limit)])


@router.post("/events", response_model=GMOEventOut, status_code=201,
             summary="Register a GMO transformation event and anchor it to the ledger")
def register_event(payload: GMOEventCreate, db: DbSession,
                   principal: Annotated[object, Depends(require_permission(P.GMO_WRITE))]
                   ) -> GMOEventOut:
    """Requires a biosecurity screening in a passing state (FR-C1 gate)."""
    event = service.register_event(
        db, principal.org_id, principal.id, principal.role, payload.event_code,
        payload.crop_type, payload.trait, payload.donor_organism, payload.developer,
        payload.description, payload.screening_id)
    db.commit()
    return GMOEventOut.model_validate(event)


@router.get("/events", response_model=Page[GMOEventOut], summary="List GMO events")
def list_events(db: DbSession, paging: PagingDep,
                principal: Annotated[object, Depends(require_permission(P.GMO_READ))],
                crop_type: str | None = Query(default=None)) -> Page[GMOEventOut]:
    query = visible(GMOEvent, principal.role, principal.org_id).order_by(
        GMOEvent.created_at.desc())
    if crop_type:
        query = query.where(GMOEvent.crop_type == crop_type)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[GMOEventOut](items=[GMOEventOut.model_validate(r) for r in rows], total=total,
                             page=paging.page, page_size=paging.page_size)


@router.get("/events/{event_id}", response_model=GMOEventOut, summary="Get a GMO event")
def get_event(event_id: str, db: DbSession,
              principal: Annotated[object, Depends(require_permission(P.GMO_READ))]) -> GMOEventOut:
    return GMOEventOut.model_validate(
        get_or_404(db, GMOEvent, event_id, principal.role, principal.org_id, name="GMO event"))


@router.get("/events/{event_id}/verify", summary="Verify a GMO event against its ledger anchor")
def verify_event(event_id: str, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.GMO_READ))]) -> dict:
    event = get_or_404(db, GMOEvent, event_id, principal.role, principal.org_id, name="GMO event")
    return service.verify_anchor(db, event)


@router.post("/events/{event_id}/approvals", response_model=GMOApprovalOut, status_code=201,
             summary="Record a jurisdictional approval")
def record_approval(event_id: str, payload: GMOApprovalCreate, db: DbSession,
                    principal: Annotated[object, Depends(require_permission(P.GMO_APPROVE))]
                    ) -> GMOApprovalOut:
    event = get_or_404(db, GMOEvent, event_id, principal.role, principal.org_id, name="GMO event")
    approval = service.record_approval(
        db, event, principal.id, principal.role, payload.jurisdiction.upper(), payload.status,
        payload.reference, payload.approved_at, payload.expires_at, principal.org_id)
    db.commit()
    return GMOApprovalOut.model_validate(approval)


@router.get("/events/{event_id}/approvals", response_model=list[GMOApprovalOut],
            summary="List approvals for a GMO event")
def list_approvals(event_id: str, db: DbSession,
                   principal: Annotated[object, Depends(require_permission(P.GMO_READ))]
                   ) -> list[GMOApprovalOut]:
    from sqlalchemy import select

    event = get_or_404(db, GMOEvent, event_id, principal.role, principal.org_id, name="GMO event")
    rows = db.execute(select(GMOApproval).where(GMOApproval.gmo_event_id == event.id)).scalars()
    return [GMOApprovalOut.model_validate(r) for r in rows]


@router.post("/seed-lots", response_model=SeedLotOut, status_code=201, summary="Create a seed lot")
def create_seed_lot(payload: SeedLotCreate, db: DbSession,
                    principal: Annotated[object, Depends(require_permission(P.GMO_WRITE))]
                    ) -> SeedLotOut:
    lot = service.create_seed_lot(
        db, principal.org_id, principal.id, principal.role, payload.lot_code,
        payload.gmo_event_id, payload.crop_type, payload.variety, payload.quantity_kg,
        payload.produced_at, payload.germination_pct)
    db.commit()
    return SeedLotOut.model_validate(lot)


@router.get("/seed-lots", response_model=Page[SeedLotOut], summary="List seed lots")
def list_seed_lots(db: DbSession, paging: PagingDep,
                   principal: Annotated[object, Depends(require_permission(P.GMO_READ))]
                   ) -> Page[SeedLotOut]:
    query = visible(SeedLot, principal.role, principal.org_id).order_by(SeedLot.created_at.desc())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[SeedLotOut](items=[SeedLotOut.model_validate(r) for r in rows], total=total,
                            page=paging.page, page_size=paging.page_size)


@router.get("/labelling/{batch_id}", summary="Validate GMO labelling for a batch")
def validate_labelling(batch_id: str, db: DbSession,
                       principal: Annotated[object, Depends(require_permission(P.GMO_READ))],
                       jurisdiction: str = Query(default="EU")) -> dict:
    batch = get_or_404(db, Batch, batch_id, principal.role, principal.org_id, name="Batch")
    return service.validate_labelling(db, batch, jurisdiction.upper())


@router.post("/labelling/{batch_id}/check-release",
             summary="Check and record whether a batch may be released into a jurisdiction")
def check_release(batch_id: str, db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.GMO_WRITE))],
                  jurisdiction: str = Query(default="EU")) -> dict:
    batch = get_or_404(db, Batch, batch_id, principal.role, principal.org_id, name="Batch")
    result = service.check_release(db, batch, jurisdiction.upper(), principal.id, principal.role)
    db.commit()
    return result
