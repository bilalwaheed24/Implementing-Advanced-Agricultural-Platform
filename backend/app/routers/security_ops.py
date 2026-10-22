"""Alerts, incidents and agricultural data-theft detection (FR-A3, FR-X4)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.errors import PermissionDenied
from ..core.logging_conf import security_event
from ..core.permissions import P, has_permission
from ..models import Alert, Incident, User
from ..repositories import get_or_404, paginate, visible
from ..schemas import AlertOut, IncidentOut, IncidentUpdate, Page
from ..services import notifications, security_ops as service

router = APIRouter(prefix="/security", tags=["Security Operations"],
                   dependencies=[Depends(rate_limit)])


@router.get("/alerts", response_model=Page[AlertOut], summary="List alerts")
def list_alerts(db: DbSession, paging: PagingDep,
                principal: Annotated[object, Depends(require_permission(P.ALERT_READ))],
                severity: str | None = Query(default=None),
                category: str | None = Query(default=None),
                status_filter: str | None = Query(default=None, alias="status"),
                entity_id: str | None = Query(default=None, max_length=36),
                incident_id: str | None = Query(default=None, max_length=36)) -> Page[AlertOut]:
    query = visible(Alert, principal.role, principal.org_id).order_by(Alert.created_at.desc())
    if severity:
        query = query.where(Alert.severity == severity.upper())
    if category:
        query = query.where(Alert.category == category.upper())
    if status_filter:
        query = query.where(Alert.status == status_filter.upper())
    if entity_id:
        query = query.where(Alert.entity_id == entity_id)
    if incident_id:
        query = query.where(Alert.incident_id == incident_id)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[AlertOut](items=[AlertOut.model_validate(r) for r in rows], total=total,
                          page=paging.page, page_size=paging.page_size)


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertOut,
             summary="Acknowledge an alert")
def acknowledge(alert_id: str, db: DbSession,
                principal: Annotated[object, Depends(require_permission(P.ALERT_WRITE))]) -> AlertOut:
    alert = get_or_404(db, Alert, alert_id, principal.role, principal.org_id, name="Alert")
    notifications.acknowledge(db, alert, principal.id)
    db.commit()
    return AlertOut.model_validate(alert)


@router.post("/alerts/{alert_id}/resolve", response_model=AlertOut, summary="Resolve an alert")
def resolve(alert_id: str, db: DbSession,
            principal: Annotated[object, Depends(require_permission(P.ALERT_WRITE))]) -> AlertOut:
    alert = get_or_404(db, Alert, alert_id, principal.role, principal.org_id, name="Alert")
    notifications.resolve(db, alert, principal.id)
    db.commit()
    return AlertOut.model_validate(alert)


@router.get("/incidents", response_model=Page[IncidentOut], summary="List incidents")
def list_incidents(db: DbSession, paging: PagingDep,
                   principal: Annotated[object, Depends(require_permission(P.INCIDENT_READ))],
                   status_filter: str | None = Query(default=None, alias="status"),
                   severity: str | None = Query(default=None),
                   entity_id: str | None = Query(default=None, max_length=36)
                   ) -> Page[IncidentOut]:
    query = visible(Incident, principal.role, principal.org_id).order_by(
        Incident.created_at.desc())
    if status_filter:
        query = query.where(Incident.status == status_filter.upper())
    if severity:
        query = query.where(Incident.severity == severity.upper())
    if entity_id:
        query = query.where(Incident.entity_id == entity_id)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[IncidentOut](items=[IncidentOut.model_validate(r) for r in rows], total=total,
                             page=paging.page, page_size=paging.page_size)


@router.get("/incidents/{incident_id}", summary="Incident detail with its timeline")
def get_incident(incident_id: str, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.INCIDENT_READ))]) -> dict:
    incident = get_or_404(db, Incident, incident_id, principal.role, principal.org_id,
                          name="Incident")
    events = service.timeline(db, incident.id)
    people = _user_names(db, {incident.assignee_id} | {e.actor_id for e in events})
    return {"incident": IncidentOut.model_validate(incident).model_dump(),
            "assignee": ({"id": incident.assignee_id, "name": people.get(incident.assignee_id)}
                         if incident.assignee_id else None),
            "can_update": _may_update_incident(principal, incident),
            "alerts": [AlertOut.model_validate(a).model_dump()
                       for a in notifications.linked_alerts(db, incident.id)],
            "timeline": [{"action": e.action, "detail": e.detail, "actor_id": e.actor_id,
                          "actor_name": people.get(e.actor_id),
                          "created_at": e.created_at} for e in events]}


# A biosafety officer is notified of BIOSECURITY and DURC alerts and is the role that clears
# or upholds the screening behind them, so it may work those incidents (triage, notes,
# resolution) without holding incident:write for every other category.
BIOSAFETY_INCIDENT_CATEGORIES = frozenset({"BIOSECURITY", "DURC"})


def _may_update_incident(principal, incident: Incident) -> bool:
    if has_permission(principal.role, P.INCIDENT_WRITE):
        return True
    return (has_permission(principal.role, P.BIOSECURITY_REVIEW)
            and incident.category in BIOSAFETY_INCIDENT_CATEGORIES)


def _user_names(db, user_ids: set[str | None]) -> dict[str, str]:
    ids = [i for i in user_ids if i]
    if not ids:
        return {}
    return {u.id: u.full_name for u in db.execute(select(User).where(User.id.in_(ids))).scalars()}


@router.patch("/incidents/{incident_id}", response_model=IncidentOut, summary="Update an incident")
def update_incident(incident_id: str, payload: IncidentUpdate, db: DbSession,
                    principal: Annotated[object, Depends(require_permission(P.INCIDENT_READ))]
                    ) -> IncidentOut:
    """Requires incident:write, or biosecurity:review for a BIOSECURITY/DURC incident.

    The route dependency asserts the caller can read incidents at all; the write check needs
    the incident's category, so it is made once the (tenant-scoped) row is loaded.
    """
    incident = get_or_404(db, Incident, incident_id, principal.role, principal.org_id,
                          name="Incident")
    if not _may_update_incident(principal, incident):
        security_event("authorisation denied", actor_id=principal.id, role=principal.role,
                       required=P.INCIDENT_WRITE.value, incident_id=incident.id)
        raise PermissionDenied(f"This action requires the '{P.INCIDENT_WRITE.value}' permission")
    service.update_incident(db, incident, principal.id, principal.role, payload.status,
                            payload.root_cause, payload.note, payload.assignee_id)
    db.commit()
    return IncidentOut.model_validate(incident)


@router.get("/data-theft/evaluate", summary="Score a principal's access pattern for exfiltration")
def evaluate_principal(db: DbSession,
                       principal: Annotated[object, Depends(require_permission(P.ALERT_READ))],
                       principal_id: str | None = Query(default=None)) -> dict:
    target = principal_id or principal.id
    if target != principal.id and not principal.is_cross_tenant \
            and principal.role != "SECURITY_ANALYST":
        from ..core.errors import PermissionDenied

        raise PermissionDenied("Evaluating another principal requires an analyst role")
    return {"principal_id": target,
            **service.evaluate_principal(db, target, principal.org_id)}


@router.post("/data-theft/sweep", summary="Score every recently active principal")
def sweep(db: DbSession,
          principal: Annotated[object, Depends(require_permission(P.ALERT_WRITE))],
          hours: int = Query(default=24, ge=1, le=168)) -> dict:
    # Oversight roles sweep the platform; a tenant role sweeps only its own organisation.
    scope = None if principal.is_cross_tenant else principal.org_id
    findings = service.sweep_data_theft(db, hours, org_id=scope)
    db.commit()
    return {"findings": findings, "count": len(findings), "window_hours": hours}


@router.get("/dashboard", summary="Security operations dashboard")
def dashboard(db: DbSession,
              principal: Annotated[object, Depends(require_permission(P.ALERT_READ))]) -> dict:
    org_id = None if principal.is_cross_tenant else principal.org_id
    return service.security_dashboard(db, org_id)
