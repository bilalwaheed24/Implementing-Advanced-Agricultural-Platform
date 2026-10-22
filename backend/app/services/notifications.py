"""Alerts, incidents and user notifications (FR-X4)."""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.permissions import CROSS_TENANT_ROLES, Role
from ..core.security import ensure_aware, utcnow
from ..core.errors import Conflict
from ..models import Alert, Incident, IncidentEvent, Notification, User

# Which roles are notified for each alert category.
CATEGORY_ROLES: dict[str, tuple[Role, ...]] = {
    "DEVICE_ANOMALY": (Role.SECURITY_ANALYST, Role.FARM_OPERATOR),
    "DEVICE_HEALTH": (Role.FARM_OPERATOR, Role.AGRONOMIST),
    "DEVICE_AUTH": (Role.SECURITY_ANALYST, Role.FARM_OPERATOR),
    "DATA_THEFT": (Role.SECURITY_ANALYST, Role.ADMIN),
    "BIOSECURITY": (Role.BIOSAFETY_OFFICER, Role.SECURITY_ANALYST),
    "DURC": (Role.BIOSAFETY_OFFICER, Role.REGULATOR),
    "FRAUD": (Role.SECURITY_ANALYST, Role.CERTIFIER, Role.SUPPLY_CHAIN_OPERATOR),
    "COMPLIANCE": (Role.REGULATOR, Role.SUPPLY_CHAIN_OPERATOR),
    "CERTIFICATION": (Role.CERTIFIER, Role.SUPPLY_CHAIN_OPERATOR),
    "LEDGER": (Role.SECURITY_ANALYST, Role.ADMIN),
    "AGRONOMY": (Role.AGRONOMIST, Role.FARM_OPERATOR),
}

SEVERITY_ORDER = {"INFO": 0, "WARNING": 1, "HIGH": 2, "CRITICAL": 3}


# An alert is "open" — still needing attention, and so the one a repeat occurrence is folded
# into — in every state but RESOLVED. Counting only OPEN let an acknowledged alert be raised
# again by the next sweep.
UNRESOLVED_ALERT_STATES = ("OPEN", "ACKNOWLEDGED")
ACTIVE_INCIDENT_STATES = ("OPEN", "TRIAGED", "CONTAINED")

# A plain recurrence is written to the incident timeline at most this often (an escalation
# always is), so a sensor misbehaving every 15 minutes does not bury the timeline either.
RECURRENCE_EVENT_INTERVAL = timedelta(hours=1)


def find_open_alert(db: Session, category: str, entity_id: str,
                    kind: str | None = None) -> Alert | None:
    """The unresolved alert of this category (and kind, when given) against this entity."""
    query = select(Alert).where(Alert.category == category, Alert.entity_id == entity_id,
                                Alert.status.in_(UNRESOLVED_ALERT_STATES))
    if kind is not None:
        query = query.where(Alert.kind == kind)
    return db.execute(query.order_by(Alert.created_at.desc()).limit(1)).scalars().first()


def has_open_alert(db: Session, category: str, entity_id: str,
                   kind: str | None = None) -> bool:
    """True when this entity already has an unresolved alert of this category (and kind).

    Scheduled sweeps run repeatedly; without this check every run would raise the same
    alert again and bury the analyst in duplicates. Pass `kind` to narrow the match, so an
    open low-battery DEVICE_HEALTH alert does not suppress a "stopped reporting" one.
    """
    return find_open_alert(db, category, entity_id, kind) is not None


def find_active_incident(db: Session, entity_type: str | None, entity_id: str | None,
                         org_id: str | None) -> Incident | None:
    """The incident still being worked for this entity, if there is one."""
    if not entity_id:
        return None
    query = select(Incident).where(Incident.entity_id == entity_id,
                                   Incident.status.in_(ACTIVE_INCIDENT_STATES))
    if entity_type:
        query = query.where(Incident.entity_type == entity_type)
    if org_id:
        query = query.where(Incident.org_id == org_id)
    return db.execute(query.order_by(Incident.created_at.desc()).limit(1)).scalars().first()


def raise_alert(db: Session, category: str, severity: str, title: str, *,
                detail: str = "", org_id: str | None = None, entity_type: str | None = None,
                entity_id: str | None = None, reasons: Iterable[Any] = (),
                notify: bool = True, open_incident: bool | None = None,
                kind: str | None = None) -> Alert:
    """Raise an alert, or fold a repeat into the one already open.

    With a `kind` and an entity, an unresolved alert of the same (category, entity, kind)
    absorbs the occurrence: its count and last_seen_at advance, its severity can only rise,
    and its incident gets a timeline entry — instead of a new alert, a new incident and a new
    round of notifications for every faulty reading. The existing alert is returned.

    An incident-worthy alert joins the incident already active for the same entity, if any,
    so the containment of a device (say) lands on the incident that prompted it.
    """
    if kind is not None and entity_id:
        existing = find_open_alert(db, category, entity_id, kind)
        if existing is not None:
            return _record_recurrence(db, existing, severity, detail, reasons, notify,
                                      open_incident)

    alert = Alert(category=category, severity=severity, title=title[:255], detail=detail,
                  org_id=org_id, entity_type=entity_type, entity_id=entity_id,
                  reasons=list(reasons)[:12], kind=kind, occurrences=1,
                  last_seen_at=utcnow())
    db.add(alert)
    db.flush()

    should_open = (SEVERITY_ORDER.get(severity, 0) >= 2) if open_incident is None else open_incident
    if should_open:
        _attach_to_incident(db, alert)

    if notify:
        fan_out(db, category, severity, title, detail, org_id, entity_type, entity_id)
    return alert


def _record_recurrence(db: Session, alert: Alert, severity: str, detail: str,
                       reasons: Iterable[Any], notify: bool,
                       open_incident: bool | None) -> Alert:
    now = utcnow()
    previous_seen = alert.last_seen_at or alert.created_at
    escalated = SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(alert.severity, 0)
    alert.occurrences = (alert.occurrences or 1) + 1
    alert.last_seen_at = now
    if detail:
        alert.detail = detail
    if escalated:
        alert.severity = severity
        reasons = list(reasons)
        if reasons:
            alert.reasons = reasons[:12]
    db.flush()

    if alert.incident_id is None:
        should_open = (SEVERITY_ORDER.get(alert.severity, 0) >= 2) if open_incident is None \
            else open_incident
        if should_open:
            _attach_to_incident(db, alert)
    else:
        incident = db.get(Incident, alert.incident_id)
        if incident is not None and incident.status in ACTIVE_INCIDENT_STATES:
            if escalated:
                if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(incident.severity, 0):
                    incident.severity = severity
                add_incident_event(db, incident.id, "ESCALATED",
                                   f"Alert '{alert.title}' recurred at {severity} "
                                   f"(occurrence {alert.occurrences}). {detail}".strip(), None)
            elif now - ensure_aware(previous_seen) >= RECURRENCE_EVENT_INTERVAL:
                add_incident_event(db, incident.id, "RECURRED",
                                   f"Alert '{alert.title}' recurred "
                                   f"(occurrence {alert.occurrences}). {detail}".strip(), None)

    # Re-notify only when the situation got worse; a repeat is already on everyone's list.
    if notify and escalated:
        fan_out(db, alert.category, alert.severity, alert.title, alert.detail, alert.org_id,
                alert.entity_type, alert.entity_id)
    return alert


def _attach_to_incident(db: Session, alert: Alert) -> Incident:
    incident = find_active_incident(db, alert.entity_type, alert.entity_id, alert.org_id)
    if incident is None:
        incident = open_incident_for(db, alert)
    else:
        if SEVERITY_ORDER.get(alert.severity, 0) > SEVERITY_ORDER.get(incident.severity, 0):
            incident.severity = alert.severity
        add_incident_event(db, incident.id, "ALERT_ATTACHED",
                           f"{alert.severity} {alert.category} alert attached: {alert.title}",
                           None)
    alert.incident_id = incident.id
    db.flush()
    return incident


def open_incident_for(db: Session, alert: Alert) -> Incident:
    incident = Incident(title=f"Incident: {alert.title}"[:255], severity=alert.severity,
                        org_id=alert.org_id, summary=alert.detail or alert.title,
                        category=alert.category, entity_type=alert.entity_type,
                        entity_id=alert.entity_id, source_alert_id=alert.id)
    db.add(incident)
    db.flush()
    db.add(IncidentEvent(incident_id=incident.id, action="OPENED",
                         detail=f"Opened automatically from {alert.severity} alert "
                                f"in category {alert.category}"))
    db.flush()
    return incident


def notify_org(db: Session, org_id: str, category: str, title: str, body: str,
               entity_type: str | None, entity_id: str | None, severity: str = "INFO") -> int:
    """Notify every active user of one organisation, e.g. that a record was handed to it."""
    recipients = list(db.execute(select(User).where(
        User.org_id == org_id, User.status == "ACTIVE", User.deleted_at.is_(None))).scalars())
    for user in recipients:
        db.add(Notification(user_id=user.id, severity=severity, category=category,
                            title=title[:255], body=body, entity_type=entity_type,
                            entity_id=entity_id))
    db.flush()
    return len(recipients)


def fan_out(db: Session, category: str, severity: str, title: str, body: str,
            org_id: str | None, entity_type: str | None, entity_id: str | None) -> int:
    """Notify every active user holding a role that owns this alert category."""
    roles = [r.value for r in CATEGORY_ROLES.get(category, (Role.ADMIN,))]
    query = select(User).where(User.role.in_(roles), User.status == "ACTIVE",
                               User.deleted_at.is_(None))
    recipients = list(db.execute(query).scalars())
    # Org-scoped categories notify only the owning organisation, plus the platform-wide
    # oversight roles defined once in core.permissions.
    platform_roles = {r.value for r in CROSS_TENANT_ROLES}
    sent = 0
    for user in recipients:
        if org_id and user.org_id != org_id and user.role not in platform_roles:
            continue
        db.add(Notification(user_id=user.id, severity=severity, category=category,
                            title=title[:255], body=body, entity_type=entity_type,
                            entity_id=entity_id))
        sent += 1
    db.flush()
    return sent


# Alert lifecycle. Previously both transitions were applied unconditionally, so resolve
# followed by acknowledge moved a RESOLVED alert back to ACKNOWLEDGED — a silent reopen that
# left resolved_at set (audit P2). OPEN -> RESOLVED is permitted: a responder who has already
# dealt with the cause should not have to acknowledge first.
ALERT_TRANSITIONS: dict[str, frozenset[str]] = {
    "OPEN": frozenset({"ACKNOWLEDGED", "RESOLVED"}),
    "ACKNOWLEDGED": frozenset({"RESOLVED"}),
    "RESOLVED": frozenset(),            # terminal
}


def _require_alert_transition(alert: Alert, target: str) -> None:
    allowed = ALERT_TRANSITIONS.get(alert.status, frozenset())
    if target == alert.status:
        raise Conflict(f"Alert is already {alert.status}")
    if target not in allowed:
        raise Conflict(
            f"Alert is {alert.status}; it cannot move to {target}. "
            f"Allowed from here: {', '.join(sorted(allowed)) or 'nothing, this is final'}.")


def acknowledge(db: Session, alert: Alert, actor_id: str) -> Alert:
    _require_alert_transition(alert, "ACKNOWLEDGED")
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_by = actor_id
    alert.acknowledged_at = utcnow()
    db.flush()
    if alert.incident_id:
        add_incident_event(db, alert.incident_id, "ALERT_ACKNOWLEDGED",
                           f"Alert acknowledged: {alert.title}", actor_id)
    return alert


def resolve(db: Session, alert: Alert, actor_id: str | None = None) -> Alert:
    """Resolve an alert. When it was the last unresolved alert on an active incident, the
    incident is resolved with it: nothing is left on it to respond to."""
    _require_alert_transition(alert, "RESOLVED")
    alert.status = "RESOLVED"
    alert.resolved_at = utcnow()
    db.flush()
    if alert.incident_id:
        incident = db.get(Incident, alert.incident_id)
        if incident is not None and incident.status in ACTIVE_INCIDENT_STATES:
            add_incident_event(db, incident.id, "ALERT_RESOLVED",
                               f"Alert resolved: {alert.title}", actor_id)
            remaining = db.execute(select(Alert.id).where(
                Alert.incident_id == incident.id,
                Alert.status.in_(UNRESOLVED_ALERT_STATES)).limit(1)).first()
            if remaining is None:
                incident.status = "RESOLVED"
                incident.closed_at = utcnow()
                db.flush()
                add_incident_event(db, incident.id, "RESOLVED",
                                   "Resolved automatically: every linked alert is resolved.",
                                   actor_id)
    return alert


def linked_alerts(db: Session, incident_id: str) -> list[Alert]:
    return list(db.execute(select(Alert).where(Alert.incident_id == incident_id)
                           .order_by(Alert.created_at.asc())).scalars())


def sync_alerts_from_incident(db: Session, incident: Incident, actor_id: str | None) -> int:
    """Carry an incident's status onto its alerts; returns how many alerts changed.

    RESOLVED/CLOSED resolves every unresolved alert; TRIAGED/CONTAINED acknowledges every
    OPEN one (someone is demonstrably working it). Reopening leaves the alerts as they are.
    """
    changed = 0
    now = utcnow()
    for alert in linked_alerts(db, incident.id):
        if incident.status in {"RESOLVED", "CLOSED"} and alert.status != "RESOLVED":
            alert.status = "RESOLVED"
            alert.resolved_at = now
            changed += 1
        elif incident.status in {"TRIAGED", "CONTAINED"} and alert.status == "OPEN":
            alert.status = "ACKNOWLEDGED"
            alert.acknowledged_by = actor_id
            alert.acknowledged_at = now
            changed += 1
    db.flush()
    return changed


def add_incident_event(db: Session, incident_id: str, action: str, detail: str,
                       actor_id: str | None) -> IncidentEvent:
    event = IncidentEvent(incident_id=incident_id, action=action, detail=detail,
                          actor_id=actor_id)
    db.add(event)
    db.flush()
    return event
