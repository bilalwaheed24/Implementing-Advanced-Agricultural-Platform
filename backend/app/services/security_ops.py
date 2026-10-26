"""Agricultural data-theft detection and incident response (FR-A3, Security.md §18, §20)."""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..core.errors import Conflict, ValidationFailed
from ..core.permissions import (CROSS_TENANT_ROLES, OVERSIGHT_ALERT_CATEGORIES, P,
                               cross_tenant_categories,
                               has_permission, is_security_oversight)
from ..core.security import ensure_aware as _aware, utcnow
from ..models import AccessRecord, Alert, Device, Incident, IncidentEvent, User
from . import audit, notifications

# Signal weights. Configuration, not constants buried in branches.
SIGNAL_WEIGHTS = {
    "volume_spike": 0.30,
    "max_page_size_streak": 0.20,
    "off_hours_access": 0.15,
    "unfamiliar_scope": 0.20,
    "repeated_exports": 0.25,
    "cross_tenant_attempts": 0.45,
    "permission_denials": 0.15,
}

# What each signal means, in the words an analyst reads on the alert.
SIGNAL_LABELS = {
    "volume_spike": "Unusually many requests in a short time",
    "max_page_size_streak": "Repeated maximum-size page reads",
    "off_hours_access": "Most activity outside working hours",
    "unfamiliar_scope": "Access spread across an unusually wide range of data",
    "repeated_exports": "Repeated exports or bulk reads",
    "cross_tenant_attempts": "Attempts to open other organisations' records",
    "permission_denials": "Many requests refused for lack of permission",
}

EXPORT_ROUTES = ("/export", "/audit", "/telemetry", "/reports")
BASELINE_WINDOW_HOURS = 24
BURST_WINDOW_MINUTES = 10
BURST_THRESHOLD = 120
DETECTION_THRESHOLD = 0.5
# A single probe of a foreign record is usually a stale or shared link; deliberate probing
# repeats. Fewer attempts than this are not a signal.
CROSS_TENANT_MIN_ATTEMPTS = 3
# ... unless it is sustained: this many foreign-record probes across the baseline window are a
# signal even when none falls inside the recent burst window (round 6).
CROSS_TENANT_SUSTAINED_ATTEMPTS = 10
PERMISSION_DENIAL_MIN = 20
UNFAMILIAR_SCOPE_MIN_ROUTES = 25
_ID_SEGMENT = re.compile(r"^(?:[0-9a-fA-F-]{8,}|\d+)$")


def route_shape(route: str) -> str:
    """A route with record identifiers replaced: /batches/1f2e.../events -> /batches/{id}/events."""
    return "/".join("{id}" if _ID_SEGMENT.match(part) else part
                    for part in (route or "").split("/"))
# Signals that indicate intent on their own. The rest describe ordinary heavy use as well: a
# farm operator clicking through the app produces a burst of maximum-size lookups (the web app
# loads its dropdowns with page_size=200) and the odd refused page. Without an intent signal,
# an alert therefore needs a volume spike AND at least two harvesting signals.
# max_page_size_streak and permission_denials still add to the score but never corroborate.
INTENT_SIGNALS = frozenset({"cross_tenant_attempts"})
HARVEST_SIGNALS = frozenset({"repeated_exports", "unfamiliar_scope", "off_hours_access"})
CORROBORATING_HARVEST_SIGNALS = 2


def record_access(db: Session, principal_id: str, org_id: str | None, route: str, method: str,
                  page_size: int, result_count: int, status_code: int, ip: str | None,
                  cross_tenant_attempt: bool = False) -> None:
    """Cheap append; the scoring pass reads it. Failures never affect the request."""
    try:
        db.add(AccessRecord(principal_id=principal_id, org_id=org_id, route=route[:200],
                            method=method, page_size=page_size, result_count=result_count,
                            status_code=status_code, hour=utcnow().hour, ip=ip,
                            cross_tenant_attempt=cross_tenant_attempt))
        db.flush()
    except Exception:                                   # noqa: BLE001
        db.rollback()


def evaluate_principal(db: Session, principal_id: str, org_id: str | None,
                       not_before: Any = None) -> dict[str, Any]:
    """Score one principal's recent access pattern for data-exfiltration indicators.

    `not_before` narrows the window further: records older than it are left out (the sweep
    passes the time an earlier finding was resolved, so it is not raised again from the
    same records)."""
    now = utcnow()
    since = now - timedelta(hours=BASELINE_WINDOW_HOURS)
    if not_before is not None and _aware(not_before) > since:
        since = _aware(not_before)
    records = list(db.execute(
        select(AccessRecord).where(AccessRecord.principal_id == principal_id,
                                   AccessRecord.created_at >= since)
        .order_by(AccessRecord.created_at.desc()).limit(5000)).scalars())
    if not records:
        # Same response shape in every branch: a caller must never have to guess
        # which keys are present.
        return {"score": 0.0, "level": "INFO", "flagged": False, "signals": [],
                "requests_examined": 0, "distinct_routes": 0,
                "threshold": DETECTION_THRESHOLD}

    signals: list[dict[str, Any]] = []

    burst_cutoff = now - timedelta(minutes=BURST_WINDOW_MINUTES)
    burst = [r for r in records if _aware(r.created_at) >= burst_cutoff]
    if len(burst) > BURST_THRESHOLD:
        signals.append({"signal": "volume_spike",
                        "detail": f"{len(burst)} requests in the last {BURST_WINDOW_MINUTES} minutes",
                        "value": len(burst)})

    recent = records[:25]
    maxed = [r for r in recent if r.page_size >= 200]
    if len(maxed) >= 10:
        signals.append({"signal": "max_page_size_streak",
                        "detail": f"{len(maxed)} of the last {len(recent)} requests used the "
                                  f"maximum page size",
                        "value": len(maxed)})

    hours = [r.hour for r in records]
    off_hours = [h for h in hours if h < 5 or h >= 23]
    if len(off_hours) > max(10, len(hours) * 0.4):
        signals.append({"signal": "off_hours_access",
                        "detail": f"{len(off_hours)} of {len(hours)} requests fell outside "
                                  f"normal working hours",
                        "value": len(off_hours)})

    routes = {r.route for r in records}
    export_hits = [r for r in records if any(marker in r.route for marker in EXPORT_ROUTES)]
    if len(export_hits) > 40:
        signals.append({"signal": "repeated_exports",
                        "detail": f"{len(export_hits)} requests to export or bulk-read endpoints",
                        "value": len(export_hits)})

    # The recorder marks a 403 as well as a foreign-record probe. A 403 is a permission
    # refusal inside the caller's own organisation (a page their role cannot use), not an
    # attempt on another tenant's data, so it is counted separately and weighs far less.
    cross_tenant = [r for r in records if r.cross_tenant_attempt and r.status_code != 403]
    # Probing is a signal when it is happening now (CROSS_TENANT_MIN_ATTEMPTS inside the same
    # short window as the volume check) or was sustained over the baseline window. A few stale
    # links opened hours ago (an end-to-end check's 404s) no longer turn a later burst of
    # ordinary page loads into an exfiltration finding (round 6).
    recent_cross = [r for r in cross_tenant if _aware(r.created_at) >= burst_cutoff]
    if len(recent_cross) >= CROSS_TENANT_MIN_ATTEMPTS \
            or len(cross_tenant) >= CROSS_TENANT_SUSTAINED_ATTEMPTS:
        signals.append({"signal": "cross_tenant_attempts",
                        "detail": f"{len(cross_tenant)} attempts to open another "
                                  f"organisation's records"
                                  + (f" ({len(recent_cross)} in the last "
                                     f"{BURST_WINDOW_MINUTES} minutes)" if recent_cross else ""),
                        "value": len(cross_tenant)})
    denied = [r for r in records if r.status_code == 403]
    if len(denied) >= PERMISSION_DENIAL_MIN:
        signals.append({"signal": "permission_denials",
                        "detail": f"{len(denied)} requests refused for lack of permission",
                        "value": len(denied)})

    # Breadth counts kinds of data, not pages: /batches/<id> for thirty batches is one route
    # shape, so clicking through detail pages in the web app does not read as harvesting.
    shapes = {route_shape(r.route) for r in records}
    if len(shapes) > UNFAMILIAR_SCOPE_MIN_ROUTES and len(records) > 200:
        signals.append({"signal": "unfamiliar_scope",
                        "detail": f"Access spread across {len(shapes)} distinct kinds of data",
                        "value": len(shapes)})

    score = 0.0
    for signal in signals:
        weight = SIGNAL_WEIGHTS.get(signal["signal"], 0.1)
        score = score + weight - score * weight        # probabilistic OR
    score = round(min(1.0, score), 4)
    names = {s["signal"] for s in signals}
    corroborated = (bool(names & INTENT_SIGNALS)
                    or ("volume_spike" in names
                        and len(names & HARVEST_SIGNALS) >= CORROBORATING_HARVEST_SIGNALS))
    flagged = score >= DETECTION_THRESHOLD and corroborated
    if flagged:
        level = "CRITICAL" if score >= 0.8 else "HIGH"
    else:
        # Heavy but uncorroborated use is shown as a warning on evaluation; it never opens
        # an incident.
        level = "WARNING" if score >= 0.3 else "INFO"
    for signal in signals:
        signal["label"] = SIGNAL_LABELS.get(signal["signal"], signal["signal"])

    return {"score": score, "level": level, "flagged": flagged, "signals": signals,
            "requests_examined": len(records), "distinct_routes": len(routes),
            "threshold": DETECTION_THRESHOLD}




def sweep_data_theft(db: Session, hours: int = 24,
                     org_id: str | None = None) -> list[dict[str, Any]]:
    """Score principals active in the window and raise alerts above threshold.

    `org_id` restricts the sweep to one organisation. A tenant-triggered sweep must pass it:
    the results carry principal ids, scores and signal detail, and without scoping a farm
    operator received that for users of other tenants (audit P1). The scheduled platform-wide
    task calls this with org_id=None deliberately. Since round 4 only security operations may
    trigger it over HTTP (routers/security_ops.sweep), and they sweep the whole platform.
    """
    since = utcnow() - timedelta(hours=hours)
    query = (select(AccessRecord.principal_id, AccessRecord.org_id)
             .where(AccessRecord.created_at >= since))
    if org_id is not None:
        query = query.where(AccessRecord.org_id == org_id)
    principals = db.execute(
        query.group_by(AccessRecord.principal_id, AccessRecord.org_id)).all()

    findings: list[dict[str, Any]] = []
    for principal_id, org_id in principals:
        verdict = evaluate_principal(db, principal_id, org_id)
        if verdict["flagged"]:
            findings.append({"principal_id": principal_id, **verdict})
            # Any unresolved alert of this kind counts: an acknowledged one is being looked at
            # already. Matched on kind, so an open account-lockout alert (also DATA_THEFT on
            # the same user) no longer hides an exfiltration finding.
            if notifications.has_open_alert(db, "DATA_THEFT", principal_id,
                                            kind=EXFILTRATION_KIND):
                continue
            # An analyst resolved a finding inside the scoring window: the same records would
            # raise it again on every sweep (round 4). Only activity since that resolution
            # counts towards a new alert.
            resolved_at = _last_resolved(db, principal_id, EXFILTRATION_KIND)
            if resolved_at is not None and _aware(resolved_at) >= \
                    utcnow() - timedelta(hours=BASELINE_WINDOW_HOURS):
                fresh = evaluate_principal(db, principal_id, org_id, not_before=resolved_at)
                if not fresh["flagged"]:
                    continue
                verdict = fresh
            notifications.raise_alert(
                db, "DATA_THEFT", verdict["level"],
                f"Possible data exfiltration by {_principal_label(db, principal_id)}",
                detail="; ".join(s["detail"] for s in verdict["signals"][:3]),
                org_id=org_id, entity_type="User", entity_id=principal_id,
                reasons=[s["label"] for s in verdict["signals"]],
                kind=EXFILTRATION_KIND)
    return findings


EXFILTRATION_KIND = "exfiltration"


def _last_resolved(db: Session, principal_id: str, kind: str):
    """When the latest resolved DATA_THEFT alert of this kind on this principal was resolved."""
    return db.execute(select(func.max(Alert.resolved_at)).where(
        Alert.category == "DATA_THEFT", Alert.entity_id == principal_id, Alert.kind == kind,
        Alert.status == "RESOLVED")).scalar_one_or_none()


def _principal_label(db: Session, principal_id: str) -> str:
    """ "Jane Doe (jane@farm.example)" for the alert title, rather than an id prefix."""
    user = db.get(User, principal_id)
    if user is None:
        return f"an unknown account ({principal_id[:8]})"
    if user.full_name and user.email:
        return f"{user.full_name} ({user.email})"
    return user.full_name or user.email or principal_id[:8]


# --------------------------------------------------------------------------- #
# Incident response
# --------------------------------------------------------------------------- #
# Incident lifecycle. Membership of the set used to be the only check, so CLOSED -> OPEN was
# accepted and closed_at was never cleared (audit P2). Reopening is still possible — security
# work genuinely reopens — but only from RESOLVED, and never from CLOSED.
INCIDENT_STATES = frozenset({"OPEN", "TRIAGED", "CONTAINED", "RESOLVED", "CLOSED"})
INCIDENT_TRANSITIONS: dict[str, frozenset[str]] = {
    "OPEN": frozenset({"TRIAGED", "CONTAINED", "RESOLVED"}),
    "TRIAGED": frozenset({"CONTAINED", "RESOLVED"}),
    "CONTAINED": frozenset({"RESOLVED"}),
    "RESOLVED": frozenset({"CLOSED", "OPEN"}),      # reopen on new evidence
    "CLOSED": frozenset(),                          # terminal
}


def update_incident(db: Session, incident: Incident, actor_id: str, actor_role: str,
                    status: str | None, root_cause: str | None,
                    note: str | None, assignee_id: str | None = None) -> Incident:
    changes: dict[str, Any] = {}
    if assignee_id is not None:
        # "" unassigns. An assignee must be an active account that can see the incident:
        # a member of its organisation, or a platform-wide oversight role.
        if assignee_id:
            assignee = db.get(User, assignee_id)
            if assignee is None or assignee.status != "ACTIVE" or assignee.deleted_at is not None \
                    or not _assignee_can_see(assignee, incident):
                raise ValidationFailed("Assignee must be an active user who can see this incident")
            if not has_permission(assignee.role, P.INCIDENT_READ):
                raise ValidationFailed("Assignee's role cannot read incidents")
            # A data-theft or ledger incident is security operations' to work, and a
            # data-theft one is filed under the suspect's own organisation, so anyone there
            # who reads incidents (the suspect included) used to be assignable (round 6).
            if _is_oversight_incident(db, incident) and not is_security_oversight(assignee.role):
                raise ValidationFailed(
                    "A data-theft or ledger incident can be assigned only to a security analyst "
                    "or an administrator")
        changes["assignee_id"] = {"from": incident.assignee_id, "to": assignee_id or None}
        incident.assignee_id = assignee_id or None
    if status:
        if status not in INCIDENT_STATES:
            raise ValidationFailed(f"status must be one of {sorted(INCIDENT_STATES)}")
        if status != incident.status:
            allowed = INCIDENT_TRANSITIONS.get(incident.status, frozenset())
            if status not in allowed:
                raise Conflict(
                    f"Incident is {incident.status}; it cannot move to {status}. "
                    f"Allowed from here: "
                    f"{', '.join(sorted(allowed)) or 'nothing, this is final'}.")
        changes["status"] = {"from": incident.status, "to": status}
        incident.status = status
        # closed_at tracks the close, so reopening must clear it rather than leave a
        # resolved timestamp on an open incident (audit P2).
        incident.closed_at = utcnow() if status in {"RESOLVED", "CLOSED"} else None
    if root_cause:
        incident.root_cause = root_cause
        changes["root_cause"] = True
    db.flush()
    if "status" in changes and changes["status"]["from"] != changes["status"]["to"]:
        # Status flows to the alerts the incident was opened from (and those attached since),
        # so a resolved incident does not leave its alerts open on the alert board.
        changes["alerts_synced"] = notifications.sync_alerts_from_incident(db, incident,
                                                                           actor_id)
    if status:
        action = status
    elif note and not root_cause and "assignee_id" not in changes:
        action = "NOTE"
    elif "assignee_id" in changes and not root_cause:
        action = "ASSIGNED"
    else:
        action = "UPDATED"
    default_detail = root_cause or ("Assignee changed" if "assignee_id" in changes
                                    else "Incident updated")
    notifications.add_incident_event(db, incident.id, action, note or default_detail, actor_id)
    audit.record(db, "incident.update", actor_id=actor_id, actor_role=actor_role,
                 org_id=incident.org_id, entity_type="Incident", entity_id=incident.id,
                 detail=changes)
    return incident


def _assignee_can_see(assignee: User, incident: Incident) -> bool:
    """Whether `assignee` can open `incident` (the rules of repositories.visible)."""
    if incident.org_id is None or assignee.org_id in {incident.org_id, incident.custodian_org_id}:
        return True
    if assignee.role not in {r.value for r in CROSS_TENANT_ROLES}:
        return False
    limited = cross_tenant_categories(assignee.role)
    return not limited or incident.category in limited


def _is_oversight_incident(db: Session, incident: Incident) -> bool:
    """An incident of a security-oversight category, or carrying an alert of one."""
    categories = sorted(OVERSIGHT_ALERT_CATEGORIES)
    if incident.category in OVERSIGHT_ALERT_CATEGORIES:
        return True
    return db.execute(select(Alert.id).where(
        or_(Alert.incident_id == incident.id, Alert.id == incident.source_alert_id),
        Alert.category.in_(categories)).limit(1)).first() is not None


def timeline(db: Session, incident_id: str) -> list[IncidentEvent]:
    return list(db.execute(
        select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.created_at.asc())).scalars())


def security_dashboard(db: Session, org_id: str | None,
                       role: str | None = None,
                       viewer_org_id: str | None = None) -> dict[str, Any]:
    """Counts for the security board. With a `role` outside SECURITY_OVERSIGHT_ROLES, alerts
    and incidents that role may not read (DATA_THEFT, LEDGER) are left out of every count.

    A category-limited cross-tenant role (a biosafety officer, round 6) counts its categories
    across tenants plus `viewer_org_id`'s own alerts, and only its own organisation's devices
    and request volume."""
    from ..repositories import oversight_conditions                  # noqa: PLC0415

    alert_query = select(Alert)
    incident_query = select(Incident)
    if role is not None:
        alert_query = alert_query.where(*oversight_conditions(Alert, role, viewer_org_id))
        incident_query = incident_query.where(
            *oversight_conditions(Incident, role, viewer_org_id))
    device_query = select(Device).where(Device.deleted_at.is_(None))
    if role is not None and cross_tenant_categories(role) and viewer_org_id:
        device_query = device_query.where(Device.org_id == viewer_org_id)
    if org_id:
        alert_query = alert_query.where(or_(Alert.org_id == org_id,
                                            Alert.custodian_org_id == org_id))
        incident_query = incident_query.where(or_(Incident.org_id == org_id,
                                                  Incident.custodian_org_id == org_id))
        device_query = device_query.where(Device.org_id == org_id)

    # A tenant sees its own organisation's request volume, not the platform's (round 4).
    access_query = (select(func.count()).select_from(AccessRecord)
                    .where(AccessRecord.created_at >= utcnow() - timedelta(hours=24)))
    if org_id:
        access_query = access_query.where(AccessRecord.org_id == org_id)
    elif role is not None and cross_tenant_categories(role) and viewer_org_id:
        access_query = access_query.where(AccessRecord.org_id == viewer_org_id)

    alerts = list(db.execute(alert_query).scalars())
    incidents = list(db.execute(incident_query).scalars())
    devices = list(db.execute(device_query).scalars())

    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    # "Open" means unresolved: an acknowledged alert still needs attention, and the alert
    # board, dedupe and incident sync all treat it so (notifications.UNRESOLVED_ALERT_STATES).
    unresolved = notifications.UNRESOLVED_ALERT_STATES
    for alert in alerts:
        if alert.status in unresolved:
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
            by_category[alert.category] = by_category.get(alert.category, 0) + 1

    return {
        "alerts_total": len(alerts),
        "alerts_open": sum(1 for a in alerts if a.status in unresolved),
        "open_by_severity": by_severity,
        "open_by_category": by_category,
        "incidents_open": sum(1 for i in incidents if i.status not in {"RESOLVED", "CLOSED"}),
        "incidents_total": len(incidents),
        "devices_quarantined": sum(1 for d in devices if d.status == "QUARANTINED"),
        "devices_total": len(devices),
        "access_records_24h": int(db.execute(access_query).scalar_one()),
    }
