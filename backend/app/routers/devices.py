"""Device registry, lifecycle and vulnerability management (FR-A1, FR-A4, FR-E3)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Depends, Query
from sqlalchemy import select

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.errors import NotFound
from ..core.permissions import P
from ..models import Device, DeviceVulnerability
from ..repositories import get_or_404, paginate, visible
from ..schemas import (DeviceAction, DeviceCreate, DeviceOut, DeviceProvisionOut, Page,
                       VulnerabilityCreate, VulnerabilityOut)
from ..services import devices as device_service

router = APIRouter(prefix="/devices", tags=["Devices"], dependencies=[Depends(rate_limit)])


@router.post("", response_model=DeviceProvisionOut, status_code=201,
             summary="Register and provision a device; the secret is returned once")
def register_device(payload: DeviceCreate, db: DbSession,
                    principal: Annotated[object, Depends(require_permission(P.DEVICE_WRITE))]
                    ) -> DeviceProvisionOut:
    device, secret = device_service.register_device(
        db, principal.org_id, principal.id, principal.role, payload.device_type, payload.model,
        payload.firmware_version, payload.farm_id, payload.field_id, payload.serial_number,
        payload.interval_seconds)
    db.commit()
    return DeviceProvisionOut(device=DeviceOut.model_validate(device), device_secret=secret)


@router.get("", response_model=Page[DeviceOut], summary="List devices")
def list_devices(db: DbSession, paging: PagingDep,
                 principal: Annotated[object, Depends(require_permission(P.DEVICE_READ))],
                 farm_id: str | None = Query(default=None),
                 device_type: str | None = Query(default=None),
                 status_filter: str | None = Query(default=None, alias="status")) -> Page[DeviceOut]:
    query = visible(Device, principal.role, principal.org_id).order_by(Device.created_at.desc())
    if farm_id:
        query = query.where(Device.farm_id == farm_id)
    if device_type:
        query = query.where(Device.device_type == device_type)
    if status_filter:
        query = query.where(Device.status == status_filter)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[DeviceOut](items=[DeviceOut.model_validate(r) for r in rows], total=total,
                           page=paging.page, page_size=paging.page_size)


@router.get("/posture", summary="Fleet security and vulnerability posture")
def posture(db: DbSession,
            principal: Annotated[object, Depends(require_permission(P.DEVICE_READ))]) -> dict:
    org_id = None if principal.is_cross_tenant else principal.org_id
    return device_service.fleet_posture(db, org_id)


@router.get("/vulnerabilities", response_model=Page[VulnerabilityOut],
            summary="List device vulnerabilities")
def list_vulnerabilities(db: DbSession, paging: PagingDep,
                         principal: Annotated[object, Depends(require_permission(P.DEVICE_READ))],
                         severity: str | None = Query(default=None),
                         status_filter: str | None = Query(default=None, alias="status")
                         ) -> Page[VulnerabilityOut]:
    query = visible(DeviceVulnerability, principal.role, principal.org_id).order_by(
        DeviceVulnerability.discovered_at.desc())
    if severity:
        query = query.where(DeviceVulnerability.severity == severity.upper())
    if status_filter:
        query = query.where(DeviceVulnerability.status == status_filter.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[VulnerabilityOut](items=[VulnerabilityOut.model_validate(r) for r in rows],
                                  total=total, page=paging.page, page_size=paging.page_size)


@router.post("/vulnerabilities", response_model=VulnerabilityOut, status_code=201,
             summary="Record a vulnerability against a device")
def add_vulnerability(payload: VulnerabilityCreate, db: DbSession,
                      principal: Annotated[object, Depends(require_permission(P.DEVICE_WRITE))]
                      ) -> VulnerabilityOut:
    device = get_or_404(db, Device, payload.device_id, principal.role, principal.org_id,
                        name="Device")
    vulnerability = device_service.add_vulnerability(
        db, device, principal.id, principal.role, payload.cve_id, payload.title,
        payload.severity, payload.cvss, payload.affected_versions, payload.fixed_in)
    db.commit()
    return VulnerabilityOut.model_validate(vulnerability)


@router.post("/vulnerabilities/{vulnerability_id}/remediate", response_model=VulnerabilityOut,
             summary="Mark a vulnerability remediated")
def remediate(vulnerability_id: str, db: DbSession,
              principal: Annotated[object, Depends(require_permission(P.DEVICE_WRITE))],
              new_firmware: Annotated[str | None, Body(embed=True, max_length=40)] = None
              ) -> VulnerabilityOut:
    vulnerability = get_or_404(db, DeviceVulnerability, vulnerability_id, principal.role,
                               principal.org_id, name="Vulnerability")
    device_service.remediate_vulnerability(db, vulnerability, principal.id, principal.role,
                                           new_firmware)
    db.commit()
    return VulnerabilityOut.model_validate(vulnerability)


@router.get("/{device_id}", response_model=DeviceOut, summary="Get a device")
def get_device(device_id: str, db: DbSession,
               principal: Annotated[object, Depends(require_permission(P.DEVICE_READ))]) -> DeviceOut:
    return DeviceOut.model_validate(
        get_or_404(db, Device, device_id, principal.role, principal.org_id, name="Device"))


@router.post("/{device_id}/activate", response_model=DeviceOut, summary="Activate a device")
def activate(device_id: str, db: DbSession,
             principal: Annotated[object, Depends(require_permission(P.DEVICE_WRITE))]) -> DeviceOut:
    device = get_or_404(db, Device, device_id, principal.role, principal.org_id, name="Device")
    device_service.transition(db, device, "ACTIVE", principal.id, principal.role)
    db.commit()
    return DeviceOut.model_validate(device)


@router.post("/{device_id}/suspend", response_model=DeviceOut, summary="Suspend a device")
def suspend(device_id: str, payload: DeviceAction, db: DbSession,
            principal: Annotated[object, Depends(require_permission(P.DEVICE_CONTAIN))]) -> DeviceOut:
    device = get_or_404(db, Device, device_id, principal.role, principal.org_id, name="Device")
    device_service.transition(db, device, "SUSPENDED", principal.id, principal.role,
                              payload.reason)
    db.commit()
    return DeviceOut.model_validate(device)


@router.post("/{device_id}/quarantine", response_model=DeviceOut,
             summary="Quarantine a device and revoke its credential (containment action)")
def quarantine(device_id: str, payload: DeviceAction, db: DbSession,
               principal: Annotated[object, Depends(require_permission(P.DEVICE_CONTAIN))]
               ) -> DeviceOut:
    device = get_or_404(db, Device, device_id, principal.role, principal.org_id, name="Device")
    device_service.transition(db, device, "QUARANTINED", principal.id, principal.role,
                              payload.reason)
    db.commit()
    return DeviceOut.model_validate(device)


@router.post("/{device_id}/retire", response_model=DeviceOut, summary="Retire a device")
def retire(device_id: str, payload: DeviceAction, db: DbSession,
           principal: Annotated[object, Depends(require_permission(P.DEVICE_CONTAIN))]) -> DeviceOut:
    device = get_or_404(db, Device, device_id, principal.role, principal.org_id, name="Device")
    device_service.transition(db, device, "RETIRED", principal.id, principal.role, payload.reason)
    db.commit()
    return DeviceOut.model_validate(device)


@router.post("/{device_id}/rotate-secret", summary="Issue a new device secret and revoke the old")
def rotate_secret(device_id: str, db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.DEVICE_WRITE))]) -> dict:
    device = get_or_404(db, Device, device_id, principal.role, principal.org_id, name="Device")
    secret = device_service.rotate_secret(db, device, principal.id, principal.role)
    db.commit()
    return {"device_id": device.id, "device_secret": secret,
            "warning": "The previous secret is now invalid. This value is shown once."}


@router.post("/sweep/health", summary="Raise alerts for devices that have stopped reporting")
def sweep_health(db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.DEVICE_WRITE))]) -> dict:
    silent = device_service.sweep_silent_devices(db)
    db.commit()
    return {"silent_devices": [d.id for d in silent], "count": len(silent)}
