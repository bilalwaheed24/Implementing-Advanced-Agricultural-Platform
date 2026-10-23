"""GMO registry, approvals, seed lots and labelling validation (FR-B1, FR-B3)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.errors import PermissionDenied
from ..core.permissions import P
from ..models import Batch, GMOApproval, GMOEvent, SeedLot
from ..repositories import get_or_404, paginate, visible
from ..schemas import (GMOApprovalCreate, GMOApprovalOut, GMOEventCreate, GMOEventOut, Page,
                       SeedLotCreate, SeedLotOut, TransferRequest)
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
                crop_type: str | None = Query(default=None),
                approved_only: bool = Query(
                    default=False,
                    description="Only events holding a live jurisdictional approval, which is "
                                "the precondition for producing a seed lot."),
                awaiting_decision: bool = Query(
                    default=False,
                    description="Only events still waiting for a regulator: no decision "
                                "recorded yet, or a decision left PENDING / NOT_SUBMITTED.")
                ) -> Page[GMOEventOut]:
    query = visible(GMOEvent, principal.role, principal.org_id).order_by(
        GMOEvent.created_at.desc())
    if crop_type:
        query = query.where(GMOEvent.crop_type == crop_type)
    if approved_only:
        # The same predicate gmo_service.require_approved_event applies on write (status,
        # decision date and expiry), so the seed-lot selector cannot offer an event the API
        # would then refuse.
        query = query.where(GMOEvent.id.in_(service.live_event_ids(db)))
    if awaiting_decision:
        decided = select(GMOApproval.gmo_event_id).where(
            GMOApproval.status.in_(("APPROVED", "REJECTED")))
        pending = select(GMOApproval.gmo_event_id).where(
            GMOApproval.status.in_(("PENDING", "NOT_SUBMITTED")))
        query = query.where(GMOEvent.id.in_(pending) | GMOEvent.id.not_in(decided))
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[GMOEventOut](items=_with_approvals(db, rows), total=total,
                             page=paging.page, page_size=paging.page_size)


def _approval_out(approval: GMOApproval) -> GMOApprovalOut:
    out = GMOApprovalOut.model_validate(approval)
    out.live = service.is_live(approval)
    return out


def _with_approvals(db, events: list[GMOEvent]) -> list[GMOEventOut]:
    """Attach each event's current jurisdictional decisions, in one query for the page."""
    by_event: dict[str, list[dict]] = {}
    if events:
        for approval in db.execute(select(GMOApproval).where(
                GMOApproval.gmo_event_id.in_([e.id for e in events]))
                .order_by(GMOApproval.jurisdiction.asc())).scalars():
            by_event.setdefault(approval.gmo_event_id, []).append(
                _approval_out(approval).model_dump(
                    include={"jurisdiction", "status", "approved_at", "expires_at", "live"}))
    out = []
    for event in events:
        item = GMOEventOut.model_validate(event)
        item.approvals = by_event.get(event.id, [])
        out.append(item)
    return out


@router.get("/events/{event_id}", response_model=GMOEventOut, summary="Get a GMO event")
def get_event(event_id: str, db: DbSession,
              principal: Annotated[object, Depends(require_permission(P.GMO_READ))]) -> GMOEventOut:
    return _with_approvals(db, [
        get_or_404(db, GMOEvent, event_id, principal.role, principal.org_id, name="GMO event")])[0]


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
    return _approval_out(approval)


@router.get("/events/{event_id}/approvals", response_model=list[GMOApprovalOut],
            summary="List approvals for a GMO event")
def list_approvals(event_id: str, db: DbSession,
                   principal: Annotated[object, Depends(require_permission(P.GMO_READ))]
                   ) -> list[GMOApprovalOut]:
    from sqlalchemy import select

    event = get_or_404(db, GMOEvent, event_id, principal.role, principal.org_id, name="GMO event")
    rows = db.execute(select(GMOApproval).where(GMOApproval.gmo_event_id == event.id)).scalars()
    return [_approval_out(r) for r in rows]


@router.post("/seed-lots", response_model=SeedLotOut, status_code=201, summary="Create a seed lot")
def create_seed_lot(payload: SeedLotCreate, db: DbSession,
                    principal: Annotated[object, Depends(require_permission(P.GMO_WRITE))]
                    ) -> SeedLotOut:
    lot = service.create_seed_lot(
        db, principal.org_id, principal.id, principal.role, payload.lot_code,
        payload.gmo_event_id, payload.crop_type, payload.variety, payload.quantity_kg,
        payload.produced_at, payload.germination_pct)
    db.commit()
    return _lot_out(db, lot)


def _lot_out(db, lot: SeedLot) -> SeedLotOut:
    """The event code is lineage the holder is entitled to see, even when the event itself
    belongs to the developer's organisation and is not readable through /gmo/events."""
    out = SeedLotOut.model_validate(lot)
    if lot.gmo_event_id:
        event = db.get(GMOEvent, lot.gmo_event_id)
        out.gmo_event_code = event.event_code if event else None
    return out


@router.get("/seed-lots", response_model=Page[SeedLotOut], summary="List seed lots")
def list_seed_lots(db: DbSession, paging: PagingDep,
                   principal: Annotated[object, Depends(require_permission(P.GMO_READ))]
                   ) -> Page[SeedLotOut]:
    query = visible(SeedLot, principal.role, principal.org_id).order_by(SeedLot.created_at.desc())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[SeedLotOut](items=[_lot_out(db, r) for r in rows], total=total,
                            page=paging.page, page_size=paging.page_size)


@router.post("/seed-lots/{lot_id}/transfer", response_model=SeedLotOut,
             summary="Supply a seed lot to a farm")
def transfer_seed_lot(lot_id: str, payload: TransferRequest, db: DbSession,
                      principal: Annotated[object, Depends(require_permission(P.GMO_WRITE))]
                      ) -> SeedLotOut:
    lot = get_or_404(db, SeedLot, lot_id, principal.role, principal.org_id, name="Seed lot")
    service.transfer_seed_lot(db, lot, principal.org_id, payload.to_org_id, principal.id,
                              principal.role)
    db.commit()
    return _lot_out(db, lot)


@router.get("/labelling/{batch_id}", summary="Validate GMO labelling for a batch")
def validate_labelling(batch_id: str, db: DbSession,
                       principal: Annotated[object, Depends(require_permission(P.GMO_READ))],
                       jurisdiction: str = Query(default="EU")) -> dict:
    batch = get_or_404(db, Batch, batch_id, principal.role, principal.org_id, name="Batch")
    return service.validate_labelling(db, batch, jurisdiction.upper())


@router.post("/labelling/{batch_id}/check-release",
             summary="Check and record whether a batch may be released into a jurisdiction")
def check_release(batch_id: str, db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.SUPPLY_WRITE))],
                  jurisdiction: str = Query(default="EU")) -> dict:
    """Releasing a batch is a supply-chain act by whoever holds it, so this needs SUPPLY_WRITE
    (held by the supply-chain and farm operators who release batches) rather than GMO_WRITE,
    which is the developer's registry permission. Like recording a custody event, only the
    current custodian may run it; the owner can still read the verdict through GET
    /gmo/labelling/{batch_id}."""
    batch = get_or_404(db, Batch, batch_id, principal.role, principal.org_id, name="Batch")
    if not principal.is_cross_tenant and batch.custodian_org_id != principal.org_id:
        raise PermissionDenied("Only the organisation currently holding this batch may check "
                               "its release")
    result = service.check_release(db, batch, jurisdiction.upper(), principal.id, principal.role)
    db.commit()
    return result
