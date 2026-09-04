"""Farms, fields and crops (FR-B5)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.errors import NotFound, ValidationFailed
from ..core.permissions import P
from ..models import Crop, Farm, Field, GMOEvent, SeedLot
from ..repositories import get_or_404, paginate, visible
from ..schemas import (CropCreate, CropOut, FarmCreate, FarmOut, FieldCreate, FieldOut, Page)
from ..services import audit

router = APIRouter(tags=["Farms"], dependencies=[Depends(rate_limit)])


@router.post("/farms", response_model=FarmOut, status_code=201, summary="Register a farm")
def create_farm(payload: FarmCreate, db: DbSession,
                principal: Annotated[object, Depends(require_permission(P.FARM_WRITE))]) -> FarmOut:
    farm = Farm(org_id=principal.org_id, created_by=principal.id, **payload.model_dump())
    db.add(farm)
    db.flush()
    audit.record(db, "farm.create", actor_id=principal.id, actor_role=principal.role,
                 org_id=principal.org_id, entity_type="Farm", entity_id=farm.id,
                 detail={"name": farm.name, "region": farm.region})
    db.commit()
    return FarmOut.model_validate(farm)


@router.get("/farms", response_model=Page[FarmOut], summary="List farms")
def list_farms(db: DbSession, paging: PagingDep,
               principal: Annotated[object, Depends(require_permission(P.FARM_READ))],
               region: str | None = Query(default=None)) -> Page[FarmOut]:
    query = visible(Farm, principal.role, principal.org_id).order_by(Farm.created_at.desc())
    if region:
        query = query.where(Farm.region == region)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[FarmOut](items=[FarmOut.model_validate(r) for r in rows], total=total,
                         page=paging.page, page_size=paging.page_size)


@router.get("/farms/{farm_id}", response_model=FarmOut, summary="Get a farm")
def get_farm(farm_id: str, db: DbSession,
             principal: Annotated[object, Depends(require_permission(P.FARM_READ))]) -> FarmOut:
    return FarmOut.model_validate(
        get_or_404(db, Farm, farm_id, principal.role, principal.org_id, name="Farm"))


@router.post("/fields", response_model=FieldOut, status_code=201, summary="Add a field to a farm")
def create_field(payload: FieldCreate, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.FARM_WRITE))]) -> FieldOut:
    farm = get_or_404(db, Farm, payload.farm_id, principal.role, principal.org_id, name="Farm")
    if payload.area_ha > farm.area_ha:
        raise ValidationFailed("Field area cannot exceed the farm area")
    field = Field(org_id=principal.org_id, **payload.model_dump())
    db.add(field)
    db.flush()
    audit.record(db, "field.create", actor_id=principal.id, actor_role=principal.role,
                 org_id=principal.org_id, entity_type="Field", entity_id=field.id,
                 detail={"farm_id": farm.id, "name": field.name})
    db.commit()
    return FieldOut.model_validate(field)


@router.get("/fields", response_model=Page[FieldOut], summary="List fields")
def list_fields(db: DbSession, paging: PagingDep,
                principal: Annotated[object, Depends(require_permission(P.FARM_READ))],
                farm_id: str | None = Query(default=None)) -> Page[FieldOut]:
    query = visible(Field, principal.role, principal.org_id).order_by(Field.created_at.desc())
    if farm_id:
        query = query.where(Field.farm_id == farm_id)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[FieldOut](items=[FieldOut.model_validate(r) for r in rows], total=total,
                          page=paging.page, page_size=paging.page_size)


@router.post("/crops", response_model=CropOut, status_code=201, summary="Record a planting")
def create_crop(payload: CropCreate, db: DbSession,
                principal: Annotated[object, Depends(require_permission(P.FARM_WRITE))]) -> CropOut:
    field = get_or_404(db, Field, payload.field_id, principal.role, principal.org_id, name="Field")
    if payload.gmo_event_id:
        event = db.get(GMOEvent, payload.gmo_event_id)
        if event is None:
            raise NotFound("GMO event not found")
        if event.anchor_status != "ANCHORED":
            raise ValidationFailed(
                "The GMO event is not anchored to the ledger and cannot be planted")
    if payload.seed_lot_id and db.get(SeedLot, payload.seed_lot_id) is None:
        raise NotFound("Seed lot not found")

    crop = Crop(org_id=principal.org_id, **payload.model_dump())
    db.add(crop)
    db.flush()
    audit.record(db, "crop.create", actor_id=principal.id, actor_role=principal.role,
                 org_id=principal.org_id, entity_type="Crop", entity_id=crop.id,
                 detail={"field_id": field.id, "crop_type": crop.crop_type,
                         "gmo_event_id": crop.gmo_event_id})
    db.commit()
    return CropOut.model_validate(crop)


@router.get("/crops", response_model=Page[CropOut], summary="List crops")
def list_crops(db: DbSession, paging: PagingDep,
               principal: Annotated[object, Depends(require_permission(P.FARM_READ))],
               field_id: str | None = Query(default=None)) -> Page[CropOut]:
    query = visible(Crop, principal.role, principal.org_id).order_by(Crop.created_at.desc())
    if field_id:
        query = query.where(Crop.field_id == field_id)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[CropOut](items=[CropOut.model_validate(r) for r in rows], total=total,
                         page=paging.page, page_size=paging.page_size)
