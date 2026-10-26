"""Alerts, incidents and agricultural data-theft detection (FR-A3, FR-X4)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.errors import PermissionDenied
from ..core.logging_conf import security_event
from ..core.permissions import (OVERSIGHT_ALERT_CATEGORIES, P, has_permission,
                                is_security_oversight)
from ..models import Alert, Incident, User
from ..repositories import get_or_404, paginate, visible
from ..schemas import AlertOut, IncidentOut, IncidentUpdate, Page
from ..services import audit, notifications, security_ops as service


class AlertListOut(AlertOut):
    # The incident the alert joined, named by its title ("Incident 948f7fea" told nobody
    # anything). None when the alert has no incident.
    incident_label: str | None = None


class IncidentListOut(IncidentOut):
    # The record the incident is about, named for people ("pw-f74f8f", "GW2 in wheat");
    # None where it has no readable name.
    entity_label: str | None = None


router = APIRouter(prefix="/security", tags=["Security Operations"],
                   dependencies=[Depends(rate_limit)])


@router.get("/alerts", response_model=Page[AlertListOut], summary="List alerts")
def list_alerts(db: DbSession, paging: PagingDep,
                principal: Annotated[object, Depends(require_permission(P.ALERT_READ))],
                severity: str | None = Query(default=None),
                category: str | None = Query(default=None),
                status_filter: str | None = Query(default=None, alias="status"),
                entity_id: str | None = Query(default=None, max_length=36),
                incident_id: str | None = Query(default=None, max_length=36)
                ) -> Page[AlertListOut]:
    query = visible(Alert, principal.role, principal.org_id).order_by(Alert.created_at.desc())
    if severity:
        query = query.where(Alert.severity == severity.upper())
    if category:
        query = query.where(Alert.category == category.upper())
    if status_filter and status_filter.upper() == "UNRESOLVED":
        # OPEN or ACKNOWLEDGED: what the dashboard's "Open alerts" tile counts.
        query = query.where(Alert.status.in_(("OPEN", "ACKNOWLEDGED")))
    elif status_filter:
        query = query.where(Alert.status == status_filter.upper())
    if entity_id:
        query = query.where(Alert.entity_id == entity_id)
    if incident_id:
        query = query.where(Alert.incident_id == incident_id)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    labels = _source_labels(db, rows)
    incident_titles = _incident_titles(db, {r.incident_id for r in rows})
    items = []
    for row in rows:
        out = AlertListOut.model_validate(_alert_out(row, labels).model_dump())
        out.incident_label = incident_titles.get(row.incident_id)
        items.append(out)
    return Page[AlertListOut](items=items, total=total, page=paging.page,
                              page_size=paging.page_size)


def _incident_title(title: str | None) -> str | None:
    # Incidents opened from an alert were titled "Incident: <alert title>"; the prefix only
    # repeats what the link already says.
    text = (title or "").strip()
    if text.lower().startswith("incident:"):
        text = text[len("incident:"):].strip()
    return text[:120] or None


def _incident_titles(db, incident_ids: set[str | None]) -> dict[str, str]:
    ids = [i for i in incident_ids if i]
    if not ids:
        return {}
    return {i.id: _incident_title(i.title) or i.id[:8]
            for i in db.execute(select(Incident).where(Incident.id.in_(ids))).scalars()}


def _alert_out(alert: Alert, labels: dict[tuple[str, str], str]) -> AlertOut:
    out = AlertOut.model_validate(alert)
    out.source_label = labels.get((alert.entity_type or "", alert.entity_id or ""))
    return out


# How the record an alert is about is named on screen ("Field North 40", "Batch B-1024")
# instead of a type and an id prefix. Only rows the caller can already see are listed, and
# naming the record they are about discloses nothing the alert's own title does not.
def _source_labels(db, alerts) -> dict[tuple[str, str], str]:
    # Works on any rows carrying entity_type/entity_id (alerts and incidents alike).
    from ..models import (Batch, Certification, CrisprAssessment, Device, Farm, Field,
                          GMOApproval, GMOEvent, SeedLot, SequenceScreening, Shipment)
    from ..services.devices import device_label

    namers = {
        "Field": (Field, lambda r: r.name),
        "Farm": (Farm, lambda r: r.name),
        "Batch": (Batch, lambda r: r.batch_code),
        "Shipment": (Shipment, lambda r: r.sscc),
        "Certification": (Certification, lambda r: r.cert_code),
        "SequenceScreening": (SequenceScreening, lambda r: r.name),
        "CrisprAssessment": (CrisprAssessment, lambda r: f"{r.target_gene} in {r.organism}"),
        "SeedLot": (SeedLot, lambda r: r.lot_code),
        "Incident": (Incident, lambda r: _incident_title(r.title) or r.id[:8]),
        "GMOEvent": (GMOEvent, lambda r: r.event_code),
        "Device": (Device, device_label),
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
                    f"{event.event_code if event else 'event'} in "
                    f"{notifications.jurisdiction_label(approval.jurisdiction)}")
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


def _require_alert_authority(principal, alert: Alert) -> None:
    """DATA_THEFT and LEDGER alerts are worked by security operations only (round 4).

    A DATA_THEFT alert is filed under the suspect's own organisation, so alert:write in that
    tenant let a colleague, or the suspect, clear "Possible data exfiltration by ..." and close
    the incident with it. Since round 5 a tenant cannot even read such an alert
    (repositories.oversight_conditions), so for a tenant this is a second line of defence.

    For a regulator or a biosafety officer it is the only one: both may now read these alerts
    across tenants (permissions.OVERSIGHT_ALERT_READER_ROLES), so get_or_404 hands them the
    row, and a biosafety officer holds alert:write for her own categories. Reading one is
    oversight; clearing it is still security operations' call, so they are refused here."""
    if alert.category in OVERSIGHT_ALERT_CATEGORIES and not is_security_oversight(principal.role):
        security_event("authorisation denied", actor_id=principal.id, role=principal.role,
                       required="security oversight", alert_id=alert.id,
                       category=alert.category)
        raise PermissionDenied(
            f"{alert.category.replace('_', ' ').title()} alerts are acknowledged and resolved "
            f"by security operations (a security analyst or an administrator)")


def _require_security_oversight(principal, action: str) -> None:
    if not is_security_oversight(principal.role):
        security_event("authorisation denied", actor_id=principal.id, role=principal.role,
                       required="security oversight", action=action)
        raise PermissionDenied(f"{action} is restricted to security analysts and administrators")


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertOut,
             summary="Acknowledge an alert")
def acknowledge(alert_id: str, db: DbSession,
                principal: Annotated[object, Depends(require_permission(P.ALERT_WRITE))]) -> AlertOut:
    alert = get_or_404(db, Alert, alert_id, principal.role, principal.org_id, name="Alert")
    _require_alert_authority(principal, alert)
    previous = alert.status
    notifications.acknowledge(db, alert, principal.id)
    _audit_alert(db, principal, alert, "acknowledge", previous)
    db.commit()
    return _alert_out(alert, _source_labels(db, [alert]))


@router.post("/alerts/{alert_id}/resolve", response_model=AlertOut, summary="Resolve an alert")
def resolve(alert_id: str, db: DbSession,
            principal: Annotated[object, Depends(require_permission(P.ALERT_WRITE))]) -> AlertOut:
    alert = get_or_404(db, Alert, alert_id, principal.role, principal.org_id, name="Alert")
    _require_alert_authority(principal, alert)
    previous = alert.status
    # Resolving the last alert closes its incident only for someone who may update that
    # incident; otherwise the incident stays open for the people who work incidents (round 4).
    incident = db.get(Incident, alert.incident_id) if alert.incident_id else None
    close_incident = incident is None or _may_update_incident(principal, incident)
    notifications.resolve(db, alert, principal.id, close_incident=close_incident)
    _audit_alert(db, principal, alert, "resolve", previous)
    db.commit()
    return _alert_out(alert, _source_labels(db, [alert]))


@router.get("/incidents", response_model=Page[IncidentListOut], summary="List incidents")
def list_incidents(db: DbSession, paging: PagingDep,
                   principal: Annotated[object, Depends(require_permission(P.INCIDENT_READ))],
                   status_filter: str | None = Query(default=None, alias="status"),
                   severity: str | None = Query(default=None),
                   entity_id: str | None = Query(default=None, max_length=36)
                   ) -> Page[IncidentListOut]:
    query = visible(Incident, principal.role, principal.org_id).order_by(
        Incident.created_at.desc())
    if status_filter:
        query = query.where(Incident.status == status_filter.upper())
    if severity:
        query = query.where(Incident.severity == severity.upper())
    if entity_id:
        query = query.where(Incident.entity_id == entity_id)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    labels = _source_labels(db, rows)
    items = []
    for row in rows:
        out = IncidentListOut.model_validate(row)
        out.entity_label = labels.get((row.entity_type or "", row.entity_id or ""))
        items.append(out)
    return Page[IncidentListOut](items=items, total=total, page=paging.page,
                                 page_size=paging.page_size)


@router.get("/incidents/{incident_id}", summary="Incident detail with its timeline")
def get_incident(incident_id: str, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.INCIDENT_READ))]) -> dict:
    incident = get_or_404(db, Incident, incident_id, principal.role, principal.org_id,
                          name="Incident")
    events = service.timeline(db, incident.id)
    people = _user_names(db, {incident.assignee_id} | {e.actor_id for e in events})
    linked = notifications.linked_alerts(db, incident.id)
    labels = _source_labels(db, [incident, *linked])
    incident_out = IncidentListOut.model_validate(incident)
    incident_out.entity_label = labels.get((incident.entity_type or "",
                                            incident.entity_id or ""))
    return {"incident": incident_out.model_dump(),
            "assignee": ({"id": incident.assignee_id, "name": people.get(incident.assignee_id)}
                         if incident.assignee_id else None),
            "can_update": _may_update_incident(principal, incident),
            "alerts": [_alert_out(a, labels).model_dump() for a in linked],
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
    # Per-user exfiltration scores are an investigation tool. A tenant role, or a regulator or
    # biosafety officer reading across tenants, has no business scoring colleagues, and a
    # self-score tells an insider how close to the threshold it is running (round 4).
    _require_security_oversight(principal, "Data-theft scoring")
    target = principal_id or principal.id
    return {"principal_id": target,
            **service.evaluate_principal(db, target, principal.org_id)}


@router.post("/data-theft/sweep", summary="Score every recently active principal")
def sweep(db: DbSession,
          principal: Annotated[object, Depends(require_permission(P.ALERT_WRITE))],
          hours: int = Query(default=24, ge=1, le=168)) -> dict:
    # Security operations only: the findings name users and their scores, and the alerts it
    # raises are ones a tenant may not resolve. Both security roles are platform-wide.
    _require_security_oversight(principal, "The data-theft sweep")
    findings = service.sweep_data_theft(db, hours, org_id=None)
    db.commit()
    return {"findings": findings, "count": len(findings), "window_hours": hours}


@router.get("/dashboard", summary="Security operations dashboard")
def dashboard(db: DbSession,
              principal: Annotated[object, Depends(require_permission(P.ALERT_READ))]) -> dict:
    org_id = None if principal.is_cross_tenant else principal.org_id
    return service.security_dashboard(db, org_id, role=principal.role,
                                      viewer_org_id=principal.org_id)
