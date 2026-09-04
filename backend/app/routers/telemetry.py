"""Telemetry ingestion (device-authenticated) and the satellite pipeline (FR-A2)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Header, Query, Request, status

from ..core.config import get_settings
from ..core.deps import DbSession, PagingDep, client_ip, rate_limit, require_permission
from ..core.errors import BadRequest, ValidationFailed
from ..core.permissions import P
from ..models import Device, SatelliteScene, Telemetry
from ..repositories import get_or_404, paginate, visible
from ..schemas import (Page, SatelliteSceneCreate, SatelliteSceneOut, TelemetryBatch,
                       TelemetryIngest, TelemetryOut)
from ..services import telemetry as telemetry_service

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED,
             summary="Ingest one signed telemetry message from a device")
def ingest(payload: TelemetryIngest, request: Request, db: DbSession,
           background: BackgroundTasks,
           x_device_id: Annotated[str, Header()],
           x_device_timestamp: Annotated[str, Header()],
           x_device_nonce: Annotated[str, Header()],
           x_device_signature: Annotated[str, Header()]) -> dict:
    """Device credential, not a user token. Authenticated by HMAC over the canonical payload."""
    if x_device_nonce != payload.nonce:
        raise ValidationFailed("The nonce header does not match the message body")
    record = telemetry_service.verify_and_ingest(
        db, x_device_id, x_device_timestamp, payload.nonce, x_device_signature,
        payload.recorded_at, payload.readings, payload.shipment_id, payload.sequence,
        allow_backfill=False, ip=client_ip(request))
    db.commit()
    deferred = record.anomaly_score is None
    if deferred:
        background.add_task(telemetry_service.score_pending, record.id)
    return {"accepted": True, "telemetry_id": record.id, "quality": record.quality,
            "anomaly_score": record.anomaly_score,
            "scoring": "deferred" if deferred else "inline"}


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED,
             summary="Ingest a gateway batch; each message is individually signed")
def ingest_batch(payload: TelemetryBatch, request: Request, db: DbSession) -> dict:
    """Partial acceptance is reported per message. Backfill widens the freshness window
    for offline farms; each message still carries its own nonce, so replay is rejected."""
    settings = get_settings()
    if len(payload.messages) > settings.device_max_batch:
        raise BadRequest(f"A batch may contain at most {settings.device_max_batch} messages")

    accepted, rejected = [], []
    for index, message in enumerate(payload.messages):
        try:
            parsed = TelemetryIngest.model_validate(message)
            record = telemetry_service.verify_and_ingest(
                db, message["device_id"], message["timestamp"], parsed.nonce,
                message["signature"], parsed.recorded_at, parsed.readings, parsed.shipment_id,
                parsed.sequence, allow_backfill=True, ip=client_ip(request))
            db.commit()
            accepted.append({"index": index, "telemetry_id": record.id,
                             "anomaly_score": record.anomaly_score})
        except Exception as exc:                          # noqa: BLE001 - per-message isolation
            db.rollback()
            detail = getattr(exc, "detail", None) or type(exc).__name__
            rejected.append({"index": index, "error": str(detail)[:200]})
    return {"accepted": len(accepted), "rejected": len(rejected),
            "results": accepted, "failures": rejected}


@router.get("", response_model=Page[TelemetryOut], summary="List telemetry")
def list_telemetry(db: DbSession, paging: PagingDep,
                   principal: Annotated[object, Depends(require_permission(P.TELEMETRY_READ))],
                   device_id: str | None = Query(default=None),
                   quality: str | None = Query(default=None),
                   _limit: None = Depends(rate_limit)) -> Page[TelemetryOut]:
    query = visible(Telemetry, principal.role, principal.org_id).order_by(
        Telemetry.recorded_at.desc())
    if device_id:
        query = query.where(Telemetry.device_id == device_id)
    if quality:
        query = query.where(Telemetry.quality == quality.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[TelemetryOut](items=[TelemetryOut.model_validate(r) for r in rows], total=total,
                              page=paging.page, page_size=paging.page_size)


@router.get("/devices/{device_id}/series", summary="Time series for one device")
def device_series(device_id: str, db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.TELEMETRY_READ))],
                  hours: int = Query(default=24, ge=1, le=720),
                  _limit: None = Depends(rate_limit)) -> dict:
    device = get_or_404(db, Device, device_id, principal.role, principal.org_id, name="Device")
    org_id = None if principal.is_cross_tenant else principal.org_id
    records = telemetry_service.series(db, device.id, org_id, hours=hours)
    return {
        "device_id": device.id, "device_type": device.device_type, "hours": hours,
        "count": len(records),
        "points": [{"recorded_at": r.recorded_at, "anomaly_score": r.anomaly_score,
                    "quality": r.quality, **r.summary} for r in reversed(records)],
    }


@router.post("/satellite/scenes", response_model=SatelliteSceneOut, status_code=201,
             summary="Ingest satellite scene metadata (checksum verified)")
def ingest_scene(payload: SatelliteSceneCreate, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.TELEMETRY_WRITE))],
                 _limit: None = Depends(rate_limit)) -> SatelliteSceneOut:
    scene = telemetry_service.ingest_scene(
        db, principal.org_id, principal.id, principal.role, payload.scene_id, payload.field_id,
        payload.provider, payload.captured_at, payload.ndvi_mean, payload.ndvi_min,
        payload.ndvi_max, payload.cloud_cover_pct, payload.checksum)
    db.commit()
    return SatelliteSceneOut.model_validate(scene)


@router.get("/satellite/scenes", response_model=Page[SatelliteSceneOut],
            summary="List satellite scenes")
def list_scenes(db: DbSession, paging: PagingDep,
                principal: Annotated[object, Depends(require_permission(P.TELEMETRY_READ))],
                field_id: str | None = Query(default=None),
                _limit: None = Depends(rate_limit)) -> Page[SatelliteSceneOut]:
    query = visible(SatelliteScene, principal.role, principal.org_id).order_by(
        SatelliteScene.captured_at.desc())
    if field_id:
        query = query.where(SatelliteScene.field_id == field_id)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[SatelliteSceneOut](items=[SatelliteSceneOut.model_validate(r) for r in rows],
                                   total=total, page=paging.page, page_size=paging.page_size)


@router.get("/insights/field-stress", summary="Precision-farming field stress ranking")
def field_stress(db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.AI_READ))],
                 _limit: None = Depends(rate_limit)) -> dict:
    org_id = None if principal.is_cross_tenant else principal.org_id
    return {"ranking": telemetry_service.field_stress_ranking(db, org_id),
            "method": "Combines the latest NDVI mean with recent soil moisture per field"}
