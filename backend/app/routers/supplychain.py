"""Products, batches, EPCIS events, shipments, certifications and verification."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.errors import NotFound
from ..core.permissions import P
from ..models import (Batch, Certification, CertificationLink, FraudAssessment, Product,
                      Shipment, SupplyChainEvent)
from ..repositories import get_or_404, paginate, visible
from ..schemas import (BatchCreate, BatchOut, CertificationCreate, CertificationLinkCreate,
                       CertificationOut, Page, ProductCreate, ProductOut, RevokeRequest,
                       ShipmentCreate, ShipmentOut, SupplyChainEventCreate, SupplyChainEventOut,
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
                 integrity: str | None = Query(default=None)) -> Page[BatchOut]:
    query = visible(Batch, principal.role, principal.org_id).order_by(Batch.created_at.desc())
    if state:
        query = query.where(Batch.state == state.upper())
    if integrity:
        query = query.where(Batch.integrity_status == integrity.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[BatchOut](items=[BatchOut.model_validate(r) for r in rows], total=total,
                          page=paging.page, page_size=paging.page_size)


@router.get("/batches/{batch_id}", response_model=BatchOut, summary="Get a batch")
def get_batch(batch_id: str, db: DbSession,
              principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]) -> BatchOut:
    return BatchOut.model_validate(
        get_or_404(db, Batch, batch_id, principal.role, principal.org_id, name="Batch"))


@router.get("/batches/{batch_id}/custody", summary="Chain of custody and lineage for a batch")
def custody(batch_id: str, db: DbSession,
            principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]) -> dict:
    batch = get_or_404(db, Batch, batch_id, principal.role, principal.org_id, name="Batch")
    events = service.chain_of_custody(db, batch)
    lineage = service.lineage(db, batch)
    return {
        "batch": BatchOut.model_validate(batch).model_dump(),
        "events": [SupplyChainEventOut.model_validate(e).model_dump() for e in events],
        "lineage": [{"batch_code": b.batch_code, "state": b.state, "quantity": b.quantity}
                    for b in lineage],
        "certifications": service.authenticate_certifications(db, batch),
    }


@router.post("/batches/{batch_id}/verify", response_model=VerificationResult,
             summary="Verify supply-chain integrity and score for fraud")
def verify_batch(batch_id: str, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]
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
    shipment = service.create_shipment(db, principal.org_id, principal.id, principal.role,
                                       **payload.model_dump())
    db.commit()
    return ShipmentOut.model_validate(shipment)


@router.get("/shipments", response_model=Page[ShipmentOut], summary="List shipments")
def list_shipments(db: DbSession, paging: PagingDep,
                   principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]
                   ) -> Page[ShipmentOut]:
    query = visible(Shipment, principal.role, principal.org_id).order_by(
        Shipment.departed_at.desc())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[ShipmentOut](items=[ShipmentOut.model_validate(r) for r in rows], total=total,
                             page=paging.page, page_size=paging.page_size)


@router.get("/shipments/{shipment_id}/cold-chain", summary="Cold-chain evidence for a shipment")
def cold_chain(shipment_id: str, db: DbSession,
               principal: Annotated[object, Depends(require_permission(P.SUPPLY_READ))]) -> dict:
    from ..services import telemetry as telemetry_service

    shipment = get_or_404(db, Shipment, shipment_id, principal.role, principal.org_id,
                          name="Shipment")
    service.refresh_shipment_temperatures(db, shipment)
    db.commit()
    return {"shipment_id": shipment.id, "sscc": shipment.sscc, "status": shipment.status,
            **telemetry_service.shipment_summary(db, shipment.id)}


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


@router.get("/certifications", response_model=Page[CertificationOut],
            summary="List certifications")
def list_certifications(db: DbSession, paging: PagingDep,
                        principal: Annotated[object, Depends(require_permission(P.CERT_READ))],
                        cert_type: str | None = Query(default=None)) -> Page[CertificationOut]:
    query = select(Certification).order_by(Certification.created_at.desc())
    if not principal.is_cross_tenant:
        query = query.where((Certification.issuer_org_id == principal.org_id)
                            | (Certification.subject_org_id == principal.org_id))
    if cert_type:
        query = query.where(Certification.cert_type == cert_type.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[CertificationOut](items=[CertificationOut.model_validate(r) for r in rows],
                                  total=total, page=paging.page, page_size=paging.page_size)


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
    return CertificationOut.model_validate(certification)


@router.post("/certifications/{certification_id}/link", status_code=201,
             summary="Claim a certification on a batch")
def link_certification(certification_id: str, payload: CertificationLinkCreate, db: DbSession,
                       principal: Annotated[object, Depends(require_permission(P.SUPPLY_WRITE))]
                       ) -> dict:
    certification = db.get(Certification, certification_id)
    if certification is None:
        raise NotFound("Certification not found")
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
    items = [{"id": r.id, "batch_id": r.batch_id, "score": r.score, "level": r.level,
              "ledger_status": r.ledger_status, "reasons": r.reasons,
              "model_version": r.model_version, "created_at": r.created_at} for r in rows]
    return Page[dict](items=items, total=total, page=paging.page, page_size=paging.page_size)
