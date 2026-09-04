"""Alerts, incidents and user notifications (FR-X4)."""
from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.permissions import CROSS_TENANT_ROLES, Role
from ..core.security import utcnow
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


def raise_alert(db: Session, category: str, severity: str, title: str, *,
                detail: str = "", org_id: str | None = None, entity_type: str | None = None,
                entity_id: str | None = None, reasons: Iterable[Any] = (),
                notify: bool = True, open_incident: bool | None = None) -> Alert:
    alert = Alert(category=category, severity=severity, title=title[:255], detail=detail,
                  org_id=org_id, entity_type=entity_type, entity_id=entity_id,
                  reasons=list(reasons)[:12])
    db.add(alert)
    db.flush()

    should_open = (SEVERITY_ORDER.get(severity, 0) >= 2) if open_incident is None else open_incident
    if should_open:
        incident = open_incident_for(db, alert)
        alert.incident_id = incident.id

    if notify:
        fan_out(db, category, severity, title, detail, org_id, entity_type, entity_id)
    return alert


def open_incident_for(db: Session, alert: Alert) -> Incident:
    incident = Incident(title=f"Incident: {alert.title}"[:255], severity=alert.severity,
                        org_id=alert.org_id, summary=alert.detail or alert.title)
    db.add(incident)
    db.flush()
    db.add(IncidentEvent(incident_id=incident.id, action="OPENED",
                         detail=f"Opened automatically from {alert.severity} alert "
                                f"in category {alert.category}"))
    db.flush()
    return incident


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


def acknowledge(db: Session, alert: Alert, actor_id: str) -> Alert:
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_by = actor_id
    alert.acknowledged_at = utcnow()
    db.flush()
    return alert


def resolve(db: Session, alert: Alert) -> Alert:
    alert.status = "RESOLVED"
    alert.resolved_at = utcnow()
    db.flush()
    return alert


def add_incident_event(db: Session, incident_id: str, action: str, detail: str,
                       actor_id: str | None) -> IncidentEvent:
    event = IncidentEvent(incident_id=incident_id, action=action, detail=detail,
                          actor_id=actor_id)
    db.add(event)
    db.flush()
    return event
