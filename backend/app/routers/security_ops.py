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
from ..services import audit, notifications, security_ops as service

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
    labels = _source_labels(db, rows)
    return Page[AlertOut](items=[_alert_out(r, labels) for r in rows], total=total,
                          page=paging.page, page_size=paging.page_size)


def _alert_out(alert: Alert, labels: dict[tuple[str, str], str]) -> AlertOut:
    out = AlertOut.model_validate(alert)
    out.source_label = labels.get((alert.entity_type or "", alert.entity_id or ""))
    return out


# How the record an alert is about is named on screen ("Field North 40", "Batch B-1024")
# instead of a type and an id prefix. Only rows the caller can already see are listed, and
# naming the record they are about discloses nothing the alert's own title does not.
def _source_labels(db, alerts: list[Alert]) -> dict[tuple[str, str], str]:
    from ..models import (Batch, Certification, CrisprAssessment, Device, Farm, Field,
                          GMOApproval, GMOEvent, SequenceScreening, Shipment)

    namers = {
        "Field": (Field, lambda r: r.name),
        "Farm": (Farm, lambda r: r.name),
        "Batch": (Batch, lambda r: r.batch_code),
        "Shipment": (Shipment, lambda r: r.sscc),
        "Certification": (Certification, lambda r: r.cert_code),
        "SequenceScreening": (SequenceScreening, lambda r: r.name),
        "CrisprAssessment": (CrisprAssessment, lambda r: f"{r.target_gene} in {r.organism}"),
        "GMOEvent": (GMOEvent, lambda r: r.event_code),
        "Device": (Device, lambda r: (f"{r.device_type.replace('_', ' ').title()} "
                                      f"{r.serial_number or r.id[:8]}")),
        "User": (User, lambda r: r.full_name or r.email),
    }
    wanted: dict[str, set[str]] = {}
    for alert in alerts:
        if alert.entity_type and alert.entity_id:
            wanted.setdefault(alert.entity_type, set()).add(alert.entity_id)
    labels: dict[tuple[str, str], str] = {}
    for entity_type, ids in wanted.items():
        if entity_type == "GMOApproval":
            for approval in db.execute(select(GMOApproval).where(
                    GMOApproval.id.in_(ids))).scalars():
                event = db.get(GMOEvent, approval.gmo_event_id)
                labels[(entity_type, approval.id)] = (
                    f"{event.event_code if event else 'event'} in {approval.jurisdiction}")
            continue
        if entity_type not in namers:
            continue
        model, name = namers[entity_type]
        for row in db.execute(select(model).where(model.id.in_(ids))).scalars():
            try:
                labels[(entity_type, row.id)] = str(name(row))[:120]
            except Exception:                                   # noqa: BLE001
                continue                       # a label is a nicety; never fail the list
    return labels


def _audit_alert(db, principal, alert: Alert, action: str, previous: str) -> None:
    audit.record(db, f"alert.{action}", actor_id=principal.id, actor_role=principal.role,
                 org_id=alert.org_id, entity_type="Alert", entity_id=alert.id,
                 detail={"category": alert.category, "kind": alert.kind,
                         "from": previous, "to": alert.status,
                         "incident_id": alert.incident_id})


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertOut,
             summary="Acknowledge an alert")
def acknowledge(alert_id: str, db: DbSession,
                principal: Annotated[object, Depends(require_permission(P.ALERT_WRITE))]) -> AlertOut:
    alert = get_or_404(db, Alert, alert_id, principal.role, principal.org_id, name="Alert")
    previous = alert.status
    notifications.acknowledge(db, alert, principal.id)
    _audit_alert(db, principal, alert, "acknowledge", previous)
    db.commit()
    return _alert_out(alert, _source_labels(db, [alert]))


@router.post("/alerts/{alert_id}/resolve", response_model=AlertOut, summary="Resolve an alert")
def resolve(alert_id: str, db: DbSession,
            principal: Annotated[object, Depends(require_permission(P.ALERT_WRITE))]) -> AlertOut:
    alert = get_or_404(db, Alert, alert_id, principal.role, principal.org_id, name="Alert")
    previous = alert.status
    notifications.resolve(db, alert, principal.id)
    _audit_alert(db, principal, alert, "resolve", previous)
    db.commit()
    return _alert_out(alert, _source_labels(db, [alert]))


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
            # An entry without an actor was written by the platform itself (an alert opening
            # or joining the incident, a sweep, a resolved check), and is labelled so.
            "timeline": [{"action": e.action, "detail": e.detail, "actor_id": e.actor_id,
                          "actor_name": people.get(e.actor_id),
                          "actor_label": (people.get(e.actor_id) or "a user") if e.actor_id
                          else "system",
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
