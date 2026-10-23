"""Alerts, incidents and user notifications (FR-X4)."""
from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.permissions import CROSS_TENANT_ROLES, Role
from ..core.security import utcnow
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


def has_open_alert(db: Session, category: str, entity_id: str) -> bool:
    """True when this entity already has an open alert of this category.

    Scheduled sweeps run repeatedly; without this check every run would raise the same
    alert again and bury the analyst in duplicates.
    """
    return db.execute(select(Alert.id).where(
        Alert.category == category, Alert.entity_id == entity_id,
        Alert.status == "OPEN").limit(1)).first() is not None


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
    return alert


def resolve(db: Session, alert: Alert) -> Alert:
    _require_alert_transition(alert, "RESOLVED")
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


# --------------------------------------------------------------------------- #
# Targeted notifications: the people a record concerns, not only a category's roles
# --------------------------------------------------------------------------- #
def _active_users():
    return select(User).where(User.status == "ACTIVE", User.deleted_at.is_(None))


def _send(db: Session, recipients: Iterable[User], category: str, title: str, body: str,
          entity_type: str | None, entity_id: str | None, severity: str) -> int:
    sent = 0
    seen: set[str] = set()
    for user in recipients:
        if user.id in seen:
            continue
        seen.add(user.id)
        db.add(Notification(user_id=user.id, severity=severity, category=category,
                            title=title[:255], body=body, entity_type=entity_type,
                            entity_id=entity_id))
        sent += 1
    db.flush()
    return sent


def notify_user(db: Session, user_id: str | None, category: str, title: str, body: str,
                entity_type: str | None, entity_id: str | None, severity: str = "INFO") -> int:
    """Notify one person, e.g. the researcher whose submission was decided."""
    if not user_id:
        return 0
    user = db.execute(_active_users().where(User.id == user_id)).scalar_one_or_none()
    return _send(db, [user] if user else [], category, title, body, entity_type, entity_id,
                 severity)


def notify_roles(db: Session, roles: Iterable[Role | str], category: str, title: str, body: str,
                 entity_type: str | None, entity_id: str | None, severity: str = "INFO") -> int:
    """Notify every active holder of the given roles, in any organisation (e.g. regulators)."""
    names = [r.value if isinstance(r, Role) else str(r) for r in roles]
    recipients = db.execute(_active_users().where(User.role.in_(names))).scalars()
    return _send(db, recipients, category, title, body, entity_type, entity_id, severity)


def notify_parties(db: Session, org_ids: Iterable[str | None], category: str, title: str,
                   body: str, entity_type: str | None, entity_id: str | None,
                   severity: str = "INFO", *, include_oversight: bool = False) -> int:
    """Notify every active user of each party organisation, once per user.

    `fan_out` reaches only the roles that own an alert category, inside the alert's single
    organisation. A record about a batch concerns its owner and its current custodian — a farm
    and a processor whose users often hold none of those roles — so the category route alone
    left the people who must act uninformed. `include_oversight` also notifies the
    platform-wide roles that own the category, as `fan_out` would.
    """
    parties = {org_id for org_id in org_ids if org_id}
    recipients: list[User] = []
    if parties:
        recipients += list(db.execute(
            _active_users().where(User.org_id.in_(parties))).scalars())
    if include_oversight:
        platform = {r.value for r in CROSS_TENANT_ROLES}
        roles = [r.value for r in CATEGORY_ROLES.get(category, (Role.ADMIN,))
                 if r.value in platform]
        if roles:
            recipients += list(db.execute(
                _active_users().where(User.role.in_(roles))).scalars())
    return _send(db, recipients, category, title, body, entity_type, entity_id, severity)


def alert_parties(db: Session, category: str, severity: str, title: str, *,
                  party_org_ids: Iterable[str | None], detail: str = "",
                  org_id: str | None = None, entity_type: str | None = None,
                  entity_id: str | None = None, reasons: Iterable[Any] = (),
                  open_incident: bool | None = None) -> Alert:
    """Raise an alert owned by `org_id` and notify every party organisation plus the
    platform oversight roles for the category, each user once."""
    alert = raise_alert(db, category, severity, title, detail=detail, org_id=org_id,
                        entity_type=entity_type, entity_id=entity_id, reasons=reasons,
                        notify=False, open_incident=open_incident)
    notify_parties(db, [org_id, *party_org_ids], category, title, detail, entity_type,
                   entity_id, severity, include_oversight=True)
    return alert


def resolve_entity_alerts(db: Session, entity_type: str, entity_id: str, actor_id: str | None,
                          note: str) -> list[Alert]:
    """Resolve the open alerts raised for one record once its cause has been dealt with, and
    record the resolution on any incident opened from them.

    The incident moves to RESOLVED when none of its alerts remain open; an analyst can still
    reopen it from there (security_ops.INCIDENT_TRANSITIONS)."""
    alerts = list(db.execute(select(Alert).where(
        Alert.entity_type == entity_type, Alert.entity_id == entity_id,
        Alert.status.in_(("OPEN", "ACKNOWLEDGED")))).scalars())
    incidents: set[str] = set()
    for alert in alerts:
        resolve(db, alert)
        if alert.incident_id:
            incidents.add(alert.incident_id)
    for incident_id in sorted(incidents):
        add_incident_event(db, incident_id, "RESOLVED", note, actor_id)
        incident = db.get(Incident, incident_id)
        still_open = db.execute(select(Alert.id).where(
            Alert.incident_id == incident_id,
            Alert.status.in_(("OPEN", "ACKNOWLEDGED"))).limit(1)).first()
        if incident is not None and still_open is None \
                and incident.status in {"OPEN", "TRIAGED", "CONTAINED"}:
            incident.status = "RESOLVED"
            incident.closed_at = utcnow()
    db.flush()
    return alerts
