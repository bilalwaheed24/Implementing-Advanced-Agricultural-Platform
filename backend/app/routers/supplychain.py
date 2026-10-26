"""Products, batches, EPCIS events, shipments, certifications and verification."""
from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import object_session

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.errors import NotFound, PermissionDenied
from ..core.permissions import P
from ..core.security import utcnow
from ..models import (Batch, Certification, CertificationLink, FraudAssessment, Organization,
                      Product, Shipment, SupplyChainEvent)
from ..repositories import get_or_404, paginate, visible
from ..schemas import (BatchCreate, BatchOut, CertificationCreate, CertificationLinkCreate,
                       CertificationOut, Page, ProductCreate, ProductOut, RevokeRequest,
                       ShipmentArrive, ShipmentCreate, ShipmentOut, SupplyChainEventCreate, SupplyChainEventOut,
                       VerificationResult)
from ..services import supplychain as service

router = APIRouter(prefix="/supply-chain", tags=["Supply Chain"],
                   dependencies=[Depends(rate_limit)])


# --- products --------------------------------------------------------------
@router.post("/products", response_model=ProductOut, status_code=201, summary="Create a product")
def create_product(payload: ProductCreate, db: DbSession,
                   principal: Annotated[object, Depends(require_permission(P.SUPPLY_WRITE))]
                   ) -> ProductOut:
    product = service.create_product(db, principal.org_id, principal.id, principal.role,
                                     **payload.model_dump())
    db.commit()
    return ProductOut.model_validate(product)


@router.get("/products", response_model=Page[ProductOut], summary="List products")
def list_products(db: DbSession, paging: PagingDep,
                  principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]
                  ) -> Page[ProductOut]:
    query = visible(Product, principal.role, principal.org_id).order_by(Product.created_at.desc())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[ProductOut](items=[ProductOut.model_validate(r) for r in rows], total=total,
                            page=paging.page, page_size=paging.page_size)


# --- batches ---------------------------------------------------------------
@router.post("/batches", response_model=BatchOut, status_code=201,
             summary="Create a traceable batch and anchor it")
def create_batch(payload: BatchCreate, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.SUPPLY_WRITE))]
                 ) -> BatchOut:
    batch = service.create_batch(db, principal.org_id, principal.id, principal.role,
                                 **payload.model_dump())
    db.commit()
    return BatchOut.model_validate(batch)


@router.get("/batches", response_model=Page[BatchOut], summary="List batches")
def list_batches(db: DbSession, paging: PagingDep,
                 principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))],
                 state: str | None = Query(default=None),
                 integrity: str | None = Query(default=None),
                 gmo: bool | None = Query(
                     default=None, description="true: only batches with a GMO lineage (a GMO "
                     "event on the batch, its seed lot or any ancestor batch); false: only "
                     "batches without one"),
                 awaiting_receipt: bool = Query(
                     default=False, description="Only batches handed over to the caller's "
                     "organisation that have reached it but that it has not booked in yet")
                 ) -> Page[BatchOut]:
    # Includes, read-only, the batches carrying a certificate the caller's organisation issued.
    query = service.readable_batches(principal.role, principal.org_id).order_by(
        Batch.created_at.desc())
    if gmo is True:
        query = query.where(Batch.id.in_(service.gmo_lineage_ids()))
    elif gmo is False:
        query = query.where(Batch.id.not_in(service.gmo_lineage_ids()))
    if awaiting_receipt:
        # Same rule as the dashboard's "Hand-overs to book in" tile (service.awaiting_booking).
        query = query.where(*service.awaiting_booking(
            None if principal.is_cross_tenant else principal.org_id))
    if state:
        query = query.where(Batch.state == state.upper())
    if integrity:
        query = query.where(Batch.integrity_status == integrity.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    gmo_ids = _gmo_lineage_of(db, [r.id for r in rows]) if rows else set()
    items = []
    for row in rows:
        item = BatchOut.model_validate(row)
        item.gmo_lineage = row.id in gmo_ids
        if _viewer_access(row, principal) == "certificate":
            _mask_custodian(db, principal, row, item)
        items.append(item)
    return Page[BatchOut](items=items, total=total, page=paging.page,
                          page_size=paging.page_size)


def _gmo_lineage_of(db, batch_ids: list[str]) -> set[str]:
    """Which of these batches have a GMO lineage."""
    return set(db.execute(select(Batch.id).where(
        Batch.id.in_(batch_ids), Batch.id.in_(service.gmo_lineage_ids()))).scalars())


def _viewer_access(batch: Batch, principal) -> str:
    """Why the caller can read the batch (see BatchOut.viewer_access)."""
    if principal.org_id in {batch.org_id, batch.custodian_org_id}:
        return "party"
    if principal.is_cross_tenant:
        return "oversight"
    return "certificate"


def _batch_out(batch: Batch, principal) -> BatchOut:
    out = BatchOut.model_validate(batch)
    out.viewer_access = _viewer_access(batch, principal)
    if out.viewer_access == "certificate":
        _mask_custodian(object_session(batch), principal, batch, out)
    return out


def _mask_custodian(db, principal, batch: Batch, out: BatchOut) -> None:
    """A certifier reading through its certificate learns the holder's name only when the
    holder is an organisation it certified (round 6, as the chain of custody)."""
    if db is None or batch.custodian_org_id not in certificate_subjects(db, principal, batch.id):
        out.custodian_name = ANOTHER_ORGANISATION


@router.get("/batches/{batch_id}", response_model=BatchOut, summary="Get a batch")
def get_batch(batch_id: str, db: DbSession,
              principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]) -> BatchOut:
    # Owner, custodian, oversight roles, and the issuer of a certificate claimed on the batch
    # (read-only: the write paths below keep plain get_or_404 and the custodian checks).
    return _batch_out(service.readable_batch(db, batch_id, principal.role, principal.org_id),
                      principal)


@router.get("/batches/{batch_id}/custody", summary="Chain of custody and lineage for a batch")
def custody(batch_id: str, db: DbSession,
            principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]) -> dict:
    batch = service.readable_batch(db, batch_id, principal.role, principal.org_id)
    events = service.chain_of_custody(db, batch)
    lineage = service.lineage(db, batch, principal.role, principal.org_id)
    out = _batch_out(batch, principal)
    context = service.batch_context(db, batch, events)
    if out.viewer_access == "certificate":
        events, context = _certificate_view(db, principal, batch, events, context)
    return {
        "batch": out.model_dump(),
        "events": [SupplyChainEventOut.model_validate(e).model_dump() for e in events],
        "lineage": [{"batch_code": b.batch_code, "state": b.state, "quantity": b.quantity}
                    for b in lineage],
        "certifications": service.authenticate_certifications(db, batch),
        "context": context,
    }


ANOTHER_ORGANISATION = "another organisation"


def certificate_subjects(db, principal, batch_id: str) -> set[str]:
    """The organisations the caller certified on a live certificate claimed on this batch."""
    return set(db.execute(service.certified_subjects(principal.org_id, batch_id)).scalars())


def event_involves(event: SupplyChainEvent, org_ids: set[str]) -> bool:
    return bool({event.org_id, event.from_org_id, event.to_org_id} & org_ids)


def _certificate_view(db, principal, batch: Batch, events, context: dict):
    """What a certifier reading the batch only through its certificate may see (round 6):
    the events its certified organisation(s) took part in, and only their names. Shipments
    were already limited that way; the chain of custody named every downstream holder ("shipping
    farm -> Retail Co") and the current custodian. Any other organisation reads as "another
    organisation"."""
    subjects = certificate_subjects(db, principal, batch.id)
    events = [e for e in events if event_involves(e, subjects)]

    def party(org: dict | None) -> dict:
        if org and org.get("id") in subjects:
            return org
        return {"id": None, "name": ANOTHER_ORGANISATION}

    context = {**context,
               "owner": party(context.get("owner")),
               "custodian": party(context.get("custodian")),
               "organisations": {k: v for k, v in (context.get("organisations") or {}).items()
                                 if k in subjects}}
    return events, context


@router.post("/batches/{batch_id}/verify", response_model=VerificationResult,
             summary="Verify supply-chain integrity and score for fraud")
def verify_batch(batch_id: str, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.SUPPLY_VERIFY))]
                 ) -> VerificationResult:
    batch = get_or_404(db, Batch, batch_id, principal.role, principal.org_id, name="Batch")
    result = service.verify_batch(db, batch, principal.id, principal.role)
    db.commit()
    return VerificationResult(**{k: v for k, v in result.items()
                                 if k in VerificationResult.model_fields})


# --- events ----------------------------------------------------------------
@router.post("/events", response_model=SupplyChainEventOut, status_code=201,
             summary="Record an EPCIS-shaped supply-chain event")
def record_event(payload: SupplyChainEventCreate, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.SUPPLY_WRITE))]
                 ) -> SupplyChainEventOut:
    batch = get_or_404(db, Batch, payload.batch_id, principal.role, principal.org_id,
                       name="Batch")
    # A recall is the one step the producer may record after a hand-over: it answers for
    # the product wherever it now is.
    recalling_owner = payload.biz_step == "recalling" and batch.org_id == principal.org_id
    if (not principal.is_cross_tenant and batch.custodian_org_id != principal.org_id
            and not recalling_owner):
        # The producer keeps read access after a hand-over, but only the organisation that
        # physically holds the batch can record what happens to it next.
        raise PermissionDenied("Only the organisation currently holding this batch may record "
                               "its next custody event")
    event = service.record_event(
        db, principal.org_id, principal.id, principal.role, batch, payload.biz_step,
        payload.disposition, payload.event_type, payload.location_gln, payload.location_name,
        payload.latitude, payload.longitude, payload.quantity, payload.unit, payload.to_org_id,
        payload.occurred_at, payload.detail)
    db.commit()
    return SupplyChainEventOut.model_validate(event)


@router.get("/events", response_model=Page[SupplyChainEventOut], summary="List events")
def list_events(db: DbSession, paging: PagingDep,
                principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))],
                batch_id: str | None = Query(default=None)) -> Page[SupplyChainEventOut]:
    query = visible(SupplyChainEvent, principal.role, principal.org_id).order_by(
        SupplyChainEvent.occurred_at.desc())
    if batch_id:
        query = query.where(SupplyChainEvent.batch_id == batch_id)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[SupplyChainEventOut](items=[SupplyChainEventOut.model_validate(r) for r in rows],
                                     total=total, page=paging.page, page_size=paging.page_size)


# --- shipments -------------------------------------------------------------
@router.post("/shipments", response_model=ShipmentOut, status_code=201, summary="Create a shipment")
def create_shipment(payload: ShipmentCreate, db: DbSession,
                    principal: Annotated[object, Depends(require_permission(P.SUPPLY_WRITE))]
                    ) -> ShipmentOut:
    """Records the batch's shipping event too, and with `to_org_id` hands the batch over."""
    shipment = service.create_shipment(db, principal.org_id, principal.id, principal.role,
                                       **payload.model_dump())
    db.commit()
    return ShipmentOut(**service.shipment_views(db, [shipment])[0])


@router.get("/shipments", response_model=Page[ShipmentOut], summary="List shipments")
def list_shipments(db: DbSession, paging: PagingDep,
                   principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))],
                   batch_id: str | None = Query(default=None),
                   status: str | None = Query(default=None),
                   incoming: bool | None = Query(
                       default=None, description="true: only shipments coming to the caller's "
                       "organisation (it is the one to mark them arrived); false: only those "
                       "it sends to another organisation")) -> Page[ShipmentOut]:
    # Visible to the sender and, for a hand-over, the receiver (Shipment.__party_columns__).
    query = visible(Shipment, principal.role, principal.org_id).order_by(
        Shipment.departed_at.desc())
    if batch_id:
        batch = db.execute(service.readable_batches(principal.role, principal.org_id).where(
            Batch.id == batch_id)).scalar_one_or_none()
        party = batch is not None and db.execute(
            visible(Batch, principal.role, principal.org_id).where(Batch.id == batch_id)
            .with_only_columns(Batch.id)).first() is not None
        if party:
            # A party to the batch (its owner, holder, oversight) reads all its shipments,
            # read-only, as it already reads the shipping and receiving events in its chain
            # of custody.
            query = select(Shipment).order_by(Shipment.departed_at.desc())
        elif batch is not None:
            # Read only through a live certificate claimed on it: the shipments the certified
            # organisation sent or received, besides those the caller is party to itself. Not
            # downstream hand-overs between holders the certifier never dealt with (round 5).
            subjects = service.certified_subjects(principal.org_id, batch_id)
            query = select(Shipment).where(or_(
                Shipment.org_id == principal.org_id, Shipment.to_org_id == principal.org_id,
                Shipment.org_id.in_(subjects), Shipment.to_org_id.in_(subjects))
            ).order_by(Shipment.departed_at.desc())
        query = query.where(Shipment.batch_id == batch_id)
    if incoming is not None and principal.org_id:
        # The receiver of an internal move (no to_org_id) is its sender. Spelled out with
        # IS NULL: `NOT (to_org_id = x OR ...)` is NULL, not true, for a row whose to_org_id
        # is NULL, so incoming=false used to drop every internal move of another sender.
        internal = Shipment.to_org_id.is_(None)
        to_me = or_(Shipment.to_org_id == principal.org_id,
                    internal & (Shipment.org_id == principal.org_id))
        not_to_me = or_(and_(Shipment.to_org_id.is_not(None),
                             Shipment.to_org_id != principal.org_id),
                        internal & (Shipment.org_id != principal.org_id))
        query = query.where(to_me if incoming else not_to_me)
    if status:
        query = query.where(Shipment.status == status.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[ShipmentOut](items=[ShipmentOut(**v) for v in service.shipment_views(db, rows)],
                             total=total, page=paging.page, page_size=paging.page_size)


@router.post("/shipments/{shipment_id}/arrive", response_model=ShipmentOut,
             summary="Mark a shipment arrived (receiver)")
def arrive_shipment(shipment_id: str, payload: ShipmentArrive, db: DbSession,
                    principal: Annotated[object, Depends(require_permission(P.SUPPLY_WRITE))]
                    ) -> ShipmentOut:
    """Sets the shipment DELIVERED and records the batch's `receiving` event."""
    shipment = get_or_404(db, Shipment, shipment_id, principal.role, principal.org_id,
                          name="Shipment")
    service.arrive_shipment(db, shipment, principal.org_id, principal.id, principal.role,
                            payload.arrived_at, payload.location_name)
    db.commit()
    return ShipmentOut(**service.shipment_views(db, [shipment])[0])


@router.get("/shipments/{shipment_id}/cold-chain", summary="Cold-chain evidence for a shipment")
def cold_chain(shipment_id: str, db: DbSession,
               principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]) -> dict:
    from ..services import cold_chain as cold_chain_service
    from ..services import telemetry as telemetry_service

    shipment = get_or_404(db, Shipment, shipment_id, principal.role, principal.org_id,
                          name="Shipment")
    service.refresh_shipment_temperatures(db, shipment)
    db.commit()
    summary = telemetry_service.shipment_summary(db, shipment.id)
    return {"shipment_id": shipment.id, "sscc": shipment.sscc, "status": shipment.status,
            "cold_chain_device_id": shipment.cold_chain_device_id, **summary,
            **cold_chain_service.summary(db, shipment, summary)}


# --- certifications --------------------------------------------------------
@router.post("/certifications", response_model=CertificationOut, status_code=201,
             summary="Issue a certification")
def issue_certification(payload: CertificationCreate, db: DbSession,
                        principal: Annotated[object, Depends(require_permission(P.CERT_ISSUE))]
                        ) -> CertificationOut:
    certification = service.issue_certification(
        db, principal.org_id, principal.id, principal.role, payload.cert_code, payload.cert_type,
        payload.standard, payload.subject_org_id, payload.scope, payload.valid_from,
        payload.valid_to)
    db.commit()
    return CertificationOut.model_validate(certification)


@router.get("/certifications/eligible-subjects",
            summary="Organisations this certifier may certify")
def eligible_subjects(db: DbSession,
                      principal: Annotated[object, Depends(require_permission(P.CERT_ISSUE))]
                      ) -> list[dict]:
    """A certifier must name a subject organisation, but the global organisation directory is
    restricted (audit P1), so this gives the issuer exactly the list it needs: active
    organisations other than its own, with business-readable labels and no MSP identity."""
    rows = db.execute(
        select(Organization).where(Organization.is_active.is_(True),
                                   Organization.id != principal.org_id)
        .order_by(Organization.name.asc())).scalars()
    return [{"id": org.id, "name": org.name, "org_type": org.org_type,
             "country": org.country} for org in rows]


@router.get("/certifications", response_model=Page[CertificationOut],
            summary="List certifications")
def list_certifications(db: DbSession, paging: PagingDep,
                        principal: Annotated[object, Depends(require_permission(P.CERT_READ))],
                        cert_type: str | None = Query(default=None),
                        status: str | None = Query(
                            default=None, description="Effective status: ACTIVE (and not "
                            "past valid_to), EXPIRED (including past valid_to before the "
                            "expiry sweep), REVOKED"),
                        expiring_within_days: int | None = Query(
                            default=None, ge=1, le=3650, description="Only certificates "
                            "still valid that end within this many days (the dashboard's "
                            "\"Expiring soon\")"),
                        claimed: bool | None = Query(
                            default=None, description="true: only certificates claimed on at "
                            "least one batch; false: only unclaimed ones"),
                        issued_by_me: bool = Query(
                            default=False, description="Only certificates the caller's "
                            "organisation issued (the dashboard tiles count these)"),
                        ) -> Page[CertificationOut]:
    query = select(Certification).order_by(Certification.created_at.desc())
    now = utcnow()
    if status:
        wanted = status.upper()
        if wanted == "ACTIVE":
            query = query.where(Certification.status == "ACTIVE", Certification.valid_to >= now)
        elif wanted == "EXPIRED":
            query = query.where((Certification.status == "EXPIRED")
                                | ((Certification.status == "ACTIVE")
                                   & (Certification.valid_to < now)))
        else:
            query = query.where(Certification.status == wanted)
    if expiring_within_days is not None:
        # The same rule as the dashboard's "Expiring soon" tile.
        query = query.where(Certification.status == "ACTIVE", Certification.valid_to >= now,
                            Certification.valid_to <= now + timedelta(days=expiring_within_days))
    if claimed is not None:
        has_claim = Certification.id.in_(select(CertificationLink.certification_id))
        query = query.where(has_claim if claimed else ~has_claim)
    if issued_by_me and not principal.is_cross_tenant:
        query = query.where(Certification.issuer_org_id == principal.org_id)
    if not principal.is_cross_tenant:
        # The issuer, the certified organisation, and the owner or holder of a batch the
        # certificate is claimed on: all three are notified when it expires or is revoked, so
        # all three must be able to find it here.
        claimed_on_mine = select(CertificationLink.certification_id).join(
            Batch, Batch.id == CertificationLink.batch_id).where(
            (Batch.org_id == principal.org_id) | (Batch.custodian_org_id == principal.org_id))
        query = query.where((Certification.issuer_org_id == principal.org_id)
                            | (Certification.subject_org_id == principal.org_id)
                            | Certification.id.in_(claimed_on_mine))
    if cert_type:
        query = query.where(Certification.cert_type == cert_type.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[CertificationOut](items=_certifications_out(db, rows, principal),
                                  total=total, page=paging.page, page_size=paging.page_size)


def _certifications_out(db, rows: list[Certification], principal) -> list[CertificationOut]:
    """Certificates as a reader needs them: the effective status (EXPIRED once past valid_to,
    even before the expiry sweep has run), the issuer and subject by name, and the batches the
    certificate is claimed on. A claimed batch the caller cannot open is listed by code only."""
    if not rows:
        return []
    ids = [r.id for r in rows]
    org_ids = {r.issuer_org_id for r in rows} | {r.subject_org_id for r in rows}
    names = {o.id: o.name for o in db.execute(
        select(Organization).where(Organization.id.in_(org_ids))).scalars()}
    claims: dict[str, list[Batch]] = {}
    for link, batch in db.execute(
            select(CertificationLink, Batch).join(Batch, Batch.id == CertificationLink.batch_id)
            .where(CertificationLink.certification_id.in_(ids))
            .order_by(Batch.batch_code.asc())).all():
        claims.setdefault(link.certification_id, []).append(batch)
    batch_ids = {b.id for batches in claims.values() for b in batches}
    readable = set()
    if batch_ids:
        readable = set(db.execute(service.readable_batches(principal.role, principal.org_id)
                                  .where(Batch.id.in_(batch_ids))
                                  .with_only_columns(Batch.id)).scalars())
    out = []
    for row in rows:
        item = CertificationOut.model_validate(row)
        item.status = service.effective_status(row)
        item.issuer_org_name = names.get(row.issuer_org_id)
        item.subject_org_name = names.get(row.subject_org_id)
        item.claimed_batches = [{"id": b.id if b.id in readable else None,
                                 "batch_code": b.batch_code}
                                for b in claims.get(row.id, [])]
        out.append(item)
    return out


@router.post("/certifications/{certification_id}/revoke", response_model=CertificationOut,
             summary="Revoke a certification")
def revoke_certification(certification_id: str, payload: RevokeRequest, db: DbSession,
                         principal: Annotated[object, Depends(require_permission(P.CERT_REVOKE))]
                         ) -> CertificationOut:
    certification = db.get(Certification, certification_id)
    if certification is None:
        raise NotFound("Certification not found")
    if certification.issuer_org_id != principal.org_id and not principal.is_cross_tenant:
        raise NotFound("Certification not found")
    service.revoke_certification(db, certification, principal.id, principal.role, payload.reason)
    db.commit()
    return _certifications_out(db, [certification], principal)[0]


@router.post("/certifications/{certification_id}/link", status_code=201,
             summary="Claim a certification on a batch")
def link_certification(certification_id: str, payload: CertificationLinkCreate, db: DbSession,
                       principal: Annotated[object, Depends(require_permission(P.SUPPLY_WRITE))]
                       ) -> dict:
    certification = db.get(Certification, certification_id)
    if certification is None:
        raise NotFound("Certification not found")
    if not principal.is_cross_tenant and certification.subject_org_id != principal.org_id:
        # An organisation claims only certifications issued to itself.
        raise PermissionDenied(f"Certification {certification.cert_code} was issued to a "
                               f"different organisation; only that organisation may claim it")
    batch = get_or_404(db, Batch, payload.batch_id, principal.role, principal.org_id,
                       name="Batch")
    link = service.link_certification(db, certification, batch, principal.id, principal.role)
    db.commit()
    return {"link_id": link.id, "certification_id": certification.id, "batch_id": batch.id}


@router.get("/fraud-assessments", response_model=Page[dict], summary="List fraud assessments")
def list_fraud(db: DbSession, paging: PagingDep,
               principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]
               ) -> Page[dict]:
    query = visible(FraudAssessment, principal.role, principal.org_id).order_by(
        FraudAssessment.created_at.desc())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    # The list showed only the batch's internal id, which is not the identifier anyone in
    # the supply chain uses. Resolve the business codes for the page in one query.
    batch_codes: dict[str, str] = {}
    batch_ids = {r.batch_id for r in rows}
    if batch_ids:
        batch_codes = {
            batch.id: batch.batch_code
            for batch in db.execute(select(Batch).where(Batch.id.in_(batch_ids))).scalars()}
    items = [{"id": r.id, "batch_id": r.batch_id,
              "batch_code": batch_codes.get(r.batch_id), "score": r.score, "level": r.level,
              "ledger_status": r.ledger_status, "reasons": r.reasons,
              "model_version": r.model_version, "created_at": r.created_at} for r in rows]
    return Page[dict](items=items, total=total, page=paging.page, page_size=paging.page_size)
