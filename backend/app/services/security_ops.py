"""Agricultural data-theft detection and incident response (FR-A3, Security.md §18, §20)."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.security import ensure_aware as _aware, utcnow
from ..models import AccessRecord, Alert, Device, Incident, IncidentEvent
from . import audit, notifications

# Signal weights. Configuration, not constants buried in branches.
SIGNAL_WEIGHTS = {
    "volume_spike": 0.30,
    "max_page_size_streak": 0.20,
    "off_hours_access": 0.15,
    "unfamiliar_scope": 0.20,
    "repeated_exports": 0.25,
    "cross_tenant_attempts": 0.45,
}

EXPORT_ROUTES = ("/export", "/audit", "/telemetry", "/reports")
BASELINE_WINDOW_HOURS = 24
BURST_WINDOW_MINUTES = 10
BURST_THRESHOLD = 120
DETECTION_THRESHOLD = 0.5


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


def evaluate_principal(db: Session, principal_id: str, org_id: str | None) -> dict[str, Any]:
    """Score one principal's recent access pattern for data-exfiltration indicators."""
    now = utcnow()
    since = now - timedelta(hours=BASELINE_WINDOW_HOURS)
    records = list(db.execute(
        select(AccessRecord).where(AccessRecord.principal_id == principal_id,
                                   AccessRecord.created_at >= since)
        .order_by(AccessRecord.created_at.desc()).limit(5000)).scalars())
    if not records:
        # Same response shape in every branch: a caller must never have to guess
        # which keys are present.
        return {"score": 0.0, "level": "INFO", "signals": [], "requests_examined": 0,
                "distinct_routes": 0, "threshold": DETECTION_THRESHOLD}

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

    cross_tenant = [r for r in records if r.cross_tenant_attempt]
    if cross_tenant:
        signals.append({"signal": "cross_tenant_attempts",
                        "detail": f"{len(cross_tenant)} attempt(s) to access another "
                                  f"organisation's data",
                        "value": len(cross_tenant)})

    if len(routes) > 25 and len(records) > 200:
        signals.append({"signal": "unfamiliar_scope",
                        "detail": f"Access spread across {len(routes)} distinct routes",
                        "value": len(routes)})

    score = 0.0
    for signal in signals:
        weight = SIGNAL_WEIGHTS.get(signal["signal"], 0.1)
        score = score + weight - score * weight        # probabilistic OR
    score = round(min(1.0, score), 4)
    level = "CRITICAL" if score >= 0.8 else "HIGH" if score >= DETECTION_THRESHOLD else \
        "WARNING" if score >= 0.3 else "INFO"

    return {"score": score, "level": level, "signals": signals,
            "requests_examined": len(records), "distinct_routes": len(routes),
            "threshold": DETECTION_THRESHOLD}




def sweep_data_theft(db: Session, hours: int = 24) -> list[dict[str, Any]]:
    """Score every principal active in the window and raise alerts above threshold."""
    since = utcnow() - timedelta(hours=hours)
    principals = db.execute(
        select(AccessRecord.principal_id, AccessRecord.org_id)
        .where(AccessRecord.created_at >= since)
        .group_by(AccessRecord.principal_id, AccessRecord.org_id)).all()

    findings: list[dict[str, Any]] = []
    for principal_id, org_id in principals:
        verdict = evaluate_principal(db, principal_id, org_id)
        if verdict["score"] >= DETECTION_THRESHOLD:
            findings.append({"principal_id": principal_id, **verdict})
            existing = db.execute(
                select(Alert).where(Alert.category == "DATA_THEFT",
                                    Alert.entity_id == principal_id,
                                    Alert.status == "OPEN")).scalar_one_or_none()
            if existing is None:
                notifications.raise_alert(
                    db, "DATA_THEFT", verdict["level"],
                    f"Possible agricultural data exfiltration by principal {principal_id[:8]}",
                    detail="; ".join(s["detail"] for s in verdict["signals"][:3]),
                    org_id=org_id, entity_type="User", entity_id=principal_id,
                    reasons=[s["signal"] for s in verdict["signals"]])
    return findings


# --------------------------------------------------------------------------- #
# Incident response
# --------------------------------------------------------------------------- #
def update_incident(db: Session, incident: Incident, actor_id: str, actor_role: str,
                    status: str | None, root_cause: str | None,
                    note: str | None) -> Incident:
    changes: dict[str, Any] = {}
    if status:
        allowed = {"OPEN", "TRIAGED", "CONTAINED", "RESOLVED", "CLOSED"}
        if status not in allowed:
            from ..core.errors import ValidationFailed

            raise ValidationFailed(f"status must be one of {sorted(allowed)}")
        changes["status"] = {"from": incident.status, "to": status}
        incident.status = status
        if status in {"RESOLVED", "CLOSED"}:
            incident.closed_at = utcnow()
    if root_cause:
        incident.root_cause = root_cause
        changes["root_cause"] = True
    db.flush()
    notifications.add_incident_event(db, incident.id, status or "UPDATED",
                                     note or root_cause or "Incident updated", actor_id)
    audit.record(db, "incident.update", actor_id=actor_id, actor_role=actor_role,
                 org_id=incident.org_id, entity_type="Incident", entity_id=incident.id,
                 detail=changes)
    return incident


def timeline(db: Session, incident_id: str) -> list[IncidentEvent]:
    return list(db.execute(
        select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.created_at.asc())).scalars())


def security_dashboard(db: Session, org_id: str | None) -> dict[str, Any]:
    alert_query = select(Alert)
    incident_query = select(Incident)
    device_query = select(Device).where(Device.deleted_at.is_(None))
    if org_id:
        alert_query = alert_query.where(Alert.org_id == org_id)
        incident_query = incident_query.where(Incident.org_id == org_id)
        device_query = device_query.where(Device.org_id == org_id)

    alerts = list(db.execute(alert_query).scalars())
    incidents = list(db.execute(incident_query).scalars())
    devices = list(db.execute(device_query).scalars())

    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for alert in alerts:
        if alert.status == "OPEN":
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
            by_category[alert.category] = by_category.get(alert.category, 0) + 1

    return {
        "alerts_total": len(alerts),
        "alerts_open": sum(1 for a in alerts if a.status == "OPEN"),
        "open_by_severity": by_severity,
        "open_by_category": by_category,
        "incidents_open": sum(1 for i in incidents if i.status not in {"RESOLVED", "CLOSED"}),
        "incidents_total": len(incidents),
        "devices_quarantined": sum(1 for d in devices if d.status == "QUARANTINED"),
        "devices_total": len(devices),
        "access_records_24h": int(db.execute(
            select(func.count()).select_from(AccessRecord)
            .where(AccessRecord.created_at >= utcnow() - timedelta(hours=24))).scalar_one()),
    }
