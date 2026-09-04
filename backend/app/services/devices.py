"""Device registry, provisioning, health, lifecycle and vulnerability management.

FR-A1 (device security), FR-A4 (health monitoring), FR-E3 (vulnerability management).
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.errors import Conflict, NotFound, ValidationFailed
from ..core.logging_conf import security_event
from ..core.security import (decrypt_at_rest, encrypt_at_rest, ensure_aware,
                             generate_device_secret, utcnow)
from ..models import Device, DeviceVulnerability, Farm, Field
from . import audit, notifications

LIFECYCLE: dict[str, set[str]] = {
    "PROVISIONED": {"ACTIVE", "RETIRED"},
    "ACTIVE": {"SUSPENDED", "QUARANTINED", "RETIRED"},
    "SUSPENDED": {"ACTIVE", "QUARANTINED", "RETIRED"},
    "QUARANTINED": {"RETIRED", "SUSPENDED"},
    "RETIRED": set(),
}


def register_device(db: Session, org_id: str, actor_id: str, actor_role: str,
                    device_type: str, model: str, firmware_version: str, farm_id: str,
                    field_id: str | None, serial_number: str | None,
                    interval_seconds: int) -> tuple[Device, str]:
    farm = db.execute(select(Farm).where(Farm.id == farm_id, Farm.org_id == org_id,
                                         Farm.deleted_at.is_(None))).scalar_one_or_none()
    if farm is None:
        raise NotFound("Farm not found")
    if field_id:
        field = db.execute(select(Field).where(Field.id == field_id, Field.farm_id == farm_id,
                                               Field.deleted_at.is_(None))).scalar_one_or_none()
        if field is None:
            raise ValidationFailed("Field does not belong to the specified farm")

    secret = generate_device_secret()
    device = Device(org_id=org_id, farm_id=farm_id, field_id=field_id, device_type=device_type,
                    model=model, firmware_version=firmware_version, serial_number=serial_number,
                    secret_enc="", interval_seconds=interval_seconds,
                    status="PROVISIONED", created_by=actor_id)
    db.add(device)
    db.flush()
    # The device id is the AES-GCM associated data, so a ciphertext cannot be moved
    # from one device row to another.
    device.secret_enc = encrypt_at_rest(secret, device.id)
    db.flush()
    audit.record(db, "device.register", actor_id=actor_id, actor_role=actor_role, org_id=org_id,
                 entity_type="Device", entity_id=device.id,
                 detail={"device_type": device_type, "farm_id": farm_id, "model": model})
    return device, secret


def rotate_secret(db: Session, device: Device, actor_id: str, actor_role: str) -> str:
    secret = generate_device_secret()
    device.secret_enc = encrypt_at_rest(secret, device.id)
    device.secret_rotated_at = utcnow()
    device.auth_failures = 0
    db.flush()
    audit.record(db, "device.rotate_secret", actor_id=actor_id, actor_role=actor_role,
                 org_id=device.org_id, entity_type="Device", entity_id=device.id)
    return secret


def transition(db: Session, device: Device, new_status: str, actor_id: str, actor_role: str,
               reason: str = "") -> Device:
    current = device.status
    if new_status == current:
        return device
    if new_status not in LIFECYCLE.get(current, set()):
        raise Conflict(f"Illegal device transition {current} -> {new_status}; allowed: "
                       f"{sorted(LIFECYCLE.get(current, set()))}")
    device.status = new_status
    if new_status == "QUARANTINED":
        device.quarantine_reason = reason
        # Containment: replace the credential with an unknown value so the device's
        # existing secret can never authenticate again.
        device.secret_enc = encrypt_at_rest(generate_device_secret(), device.id)
    db.flush()
    audit.record(db, f"device.{new_status.lower()}", actor_id=actor_id, actor_role=actor_role,
                 org_id=device.org_id, entity_type="Device", entity_id=device.id,
                 detail={"from": current, "to": new_status, "reason": reason})
    if new_status == "QUARANTINED":
        notifications.raise_alert(
            db, "DEVICE_AUTH", "HIGH", f"Device {device.id[:8]} quarantined",
            detail=f"{device.device_type} quarantined: {reason}. Its credential has been revoked.",
            org_id=device.org_id, entity_type="Device", entity_id=device.id)
    return device


def load_secret(device: Device) -> str | None:
    """Recover the device secret for HMAC verification. Returns None if undecryptable."""
    try:
        return decrypt_at_rest(device.secret_enc, device.id)
    except Exception:                                   # noqa: BLE001 - treat as auth failure
        return None


def authenticate_device(db: Session, device_id: str, secret: str) -> Device:
    """Resolve and authenticate a device by presented secret.

    Raises NotFound for every failure mode so an attacker cannot distinguish
    'unknown device' from 'wrong secret'.
    """
    import hmac

    device = db.get(Device, device_id)
    if device is None or device.deleted_at is not None:
        security_event("device authentication: unknown device", device_id=device_id)
        raise NotFound("Device authentication failed")
    if device.status != "ACTIVE":
        security_event("device authentication: device not active", device_id=device_id,
                       status=device.status)
        raise NotFound("Device authentication failed")
    stored = load_secret(device)
    if stored is None or not hmac.compare_digest(stored, secret):
        record_auth_failure(db, device)
        raise NotFound("Device authentication failed")
    return device


def record_auth_failure(db: Session, device: Device) -> None:
    """Increment and PERSIST the failure counter.

    Callers raise immediately afterwards, and the route does not commit on an error
    path, so the increment must be committed here or the counter never advances and
    repeated spoofing attempts are never detected.
    """
    device.auth_failures += 1
    db.flush()
    security_event("device authentication failure", level=logging.WARNING,
                   device_id=device.id, failures=device.auth_failures)
    if device.auth_failures in (5, 20):
        notifications.raise_alert(
            db, "DEVICE_AUTH", "HIGH" if device.auth_failures >= 20 else "WARNING",
            f"Repeated authentication failures from device {device.id[:8]}",
            detail=f"{device.auth_failures} consecutive failures. Possible spoofing attempt or "
                   f"a device holding a stale credential.",
            org_id=device.org_id, entity_type="Device", entity_id=device.id)
    db.commit()


def update_health(db: Session, device: Device, readings: dict[str, Any]) -> None:
    device.last_seen_at = utcnow()
    device.auth_failures = 0
    battery = readings.get("battery_pct")
    if isinstance(battery, (int, float)) and not isinstance(battery, bool):
        device.battery_pct = float(battery)
        if device.battery_pct < 15:
            notifications.raise_alert(
                db, "DEVICE_HEALTH", "WARNING", f"Low battery on device {device.id[:8]}",
                detail=f"Battery at {device.battery_pct:.0f}%.", org_id=device.org_id,
                entity_type="Device", entity_id=device.id, open_incident=False)
    signal = readings.get("signal_dbm")
    if isinstance(signal, (int, float)) and not isinstance(signal, bool):
        device.signal_dbm = float(signal)
    db.flush()


def sweep_silent_devices(db: Session, missed_intervals: int = 3) -> list[Device]:
    """Raise an alert for every active device that has missed several reporting intervals."""
    now = utcnow()
    silent: list[Device] = []
    for device in db.execute(select(Device).where(Device.status == "ACTIVE",
                                                  Device.deleted_at.is_(None))).scalars():
        if device.last_seen_at is None:
            continue
        last_seen = ensure_aware(device.last_seen_at)
        threshold = timedelta(seconds=device.interval_seconds * missed_intervals)
        if now - last_seen > threshold:
            silent.append(device)
            notifications.raise_alert(
                db, "DEVICE_HEALTH", "WARNING", f"Device {device.id[:8]} has stopped reporting",
                detail=f"No telemetry for {int((now - last_seen).total_seconds() // 60)} minutes "
                       f"(expected every {device.interval_seconds}s).",
                org_id=device.org_id, entity_type="Device", entity_id=device.id,
                open_incident=False)
    return silent


# --------------------------------------------------------------------------- #
# Vulnerability management (FR-E3)
# --------------------------------------------------------------------------- #
def add_vulnerability(db: Session, device: Device, actor_id: str, actor_role: str, cve_id: str,
                      title: str, severity: str, cvss: float | None,
                      affected_versions: str | None, fixed_in: str | None) -> DeviceVulnerability:
    existing = db.execute(select(DeviceVulnerability).where(
        DeviceVulnerability.device_id == device.id,
        DeviceVulnerability.cve_id == cve_id,
        DeviceVulnerability.status == "OPEN")).scalar_one_or_none()
    if existing:
        raise Conflict(f"{cve_id} is already open against this device")
    vulnerability = DeviceVulnerability(
        device_id=device.id, org_id=device.org_id, cve_id=cve_id, title=title,
        severity=severity, cvss=cvss, affected_versions=affected_versions, fixed_in=fixed_in)
    db.add(vulnerability)
    db.flush()
    audit.record(db, "device.vulnerability_add", actor_id=actor_id, actor_role=actor_role,
                 org_id=device.org_id, entity_type="Device", entity_id=device.id,
                 detail={"cve_id": cve_id, "severity": severity})
    if severity in {"HIGH", "CRITICAL"}:
        notifications.raise_alert(
            db, "DEVICE_HEALTH", severity,
            f"{severity} vulnerability {cve_id} on device {device.id[:8]}",
            detail=title, org_id=device.org_id, entity_type="Device", entity_id=device.id)
    return vulnerability


def remediate_vulnerability(db: Session, vulnerability: DeviceVulnerability, actor_id: str,
                            actor_role: str, new_firmware: str | None) -> DeviceVulnerability:
    vulnerability.status = "REMEDIATED"
    vulnerability.remediated_at = utcnow()
    if new_firmware:
        device = db.get(Device, vulnerability.device_id)
        if device:
            device.firmware_version = new_firmware
    db.flush()
    audit.record(db, "device.vulnerability_remediate", actor_id=actor_id, actor_role=actor_role,
                 org_id=vulnerability.org_id, entity_type="DeviceVulnerability",
                 entity_id=vulnerability.id,
                 detail={"cve_id": vulnerability.cve_id, "firmware": new_firmware})
    return vulnerability


def fleet_posture(db: Session, org_id: str | None) -> dict[str, Any]:
    """Vulnerability posture across the connected-equipment fleet."""
    device_query = select(Device).where(Device.deleted_at.is_(None))
    vulnerability_query = select(DeviceVulnerability)
    if org_id:
        device_query = device_query.where(Device.org_id == org_id)
        vulnerability_query = vulnerability_query.where(DeviceVulnerability.org_id == org_id)

    devices = list(db.execute(device_query).scalars())
    vulnerabilities = list(db.execute(vulnerability_query).scalars())

    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for device in devices:
        by_status[device.status] = by_status.get(device.status, 0) + 1
        by_type[device.device_type] = by_type.get(device.device_type, 0) + 1

    open_by_severity: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    remediated = 0
    affected_devices: set[str] = set()
    for vulnerability in vulnerabilities:
        if vulnerability.status == "OPEN":
            open_by_severity[vulnerability.severity] = open_by_severity.get(vulnerability.severity, 0) + 1
            affected_devices.add(vulnerability.device_id)
        else:
            remediated += 1

    total_open = sum(open_by_severity.values())
    return {
        "devices_total": len(devices),
        "devices_by_status": by_status,
        "devices_by_type": by_type,
        "vulnerabilities_open": total_open,
        "vulnerabilities_remediated": remediated,
        "open_by_severity": open_by_severity,
        "devices_affected": len(affected_devices),
        "devices_clean": max(0, len(devices) - len(affected_devices)),
        "remediation_rate": round(remediated / max(1, remediated + total_open), 4),
    }


def device_count(db: Session, org_id: str | None) -> int:
    query = select(func.count()).select_from(Device).where(Device.deleted_at.is_(None))
    if org_id:
        query = query.where(Device.org_id == org_id)
    return int(db.execute(query).scalar_one())
