"""Authenticated telemetry ingestion and the satellite pipeline (FR-A2, FR-A5).

Every message crossing trust boundary TB-3 is authenticated (HMAC), replay-checked
(nonce + timestamp window), schema- and range-validated, encrypted at rest, and
scored for anomalies.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.errors import Conflict, NotFound, ValidationFailed
from ..core.logging_conf import security_event
from ..core.security import (canonical_json, content_hash, decrypt_at_rest, encrypt_at_rest,
                             ensure_aware as _aware, nonce_cache, sha256_hex,
                             timestamp_within_window, utcnow, verify_device_signature)
from ..models import AIAnalysis, Device, SatelliteScene, Telemetry
from . import audit, devices as device_service, notifications




def verify_and_ingest(db: Session, device_id: str, timestamp_header: str, nonce: str,
                      signature: str, recorded_at: datetime, readings: dict[str, Any],
                      shipment_id: str | None = None, sequence: int | None = None,
                      allow_backfill: bool = False, ip: str | None = None,
                      score_inline: bool | None = None) -> Telemetry:
    """Full ingestion path. Order of checks matters: identity, freshness, replay, then content."""
    from ai.anomaly import score as anomaly_score, validate_readings

    settings = get_settings()

    # 1. device identity and status
    device = db.get(Device, device_id)
    if device is None or device.deleted_at is not None or device.status != "ACTIVE":
        security_event("telemetry rejected: unknown or inactive device",
                       device_id=device_id, ip=ip)
        raise NotFound("Device authentication failed")

    # 2. HMAC over the canonical payload, using the stored secret
    if not _signature_valid(db, device, timestamp_header, nonce, readings, signature):
        raise NotFound("Device authentication failed")

    # 3. freshness
    window = (settings.device_backfill_window_seconds if allow_backfill
              else settings.device_timestamp_window_seconds)
    if not timestamp_within_window(timestamp_header, window):
        security_event("telemetry rejected: timestamp outside the accepted window",
                       device_id=device_id, ip=ip)
        raise ValidationFailed("Message timestamp is outside the accepted window")

    # 4. replay: in-memory cache first, then the unique constraint as the durable guard
    if not nonce_cache.check_and_add(f"{device_id}:{nonce}"):
        security_event("telemetry rejected: replayed nonce", level=logging.WARNING,
                       device_id=device_id, ip=ip)
        raise Conflict("Replay detected: this nonce has already been used")
    existing = db.execute(select(Telemetry).where(Telemetry.device_id == device_id,
                                                  Telemetry.nonce == nonce)).scalar_one_or_none()
    if existing is not None:
        security_event("telemetry rejected: replayed nonce (persisted)", level=logging.WARNING,
                       device_id=device_id, ip=ip)
        raise Conflict("Replay detected: this nonce has already been used")

    if sequence is not None and sequence <= device.last_sequence and device.last_sequence > 0:
        security_event("telemetry rejected: non-monotonic sequence", device_id=device_id,
                       received=sequence, last=device.last_sequence)
        raise Conflict("Message sequence number is not monotonic")

    # 5. schema and physical-range validation
    problems = validate_readings(device.device_type, readings)
    quality = "OK"
    if problems:
        quality = "QUARANTINED"
        security_event("telemetry quarantined: failed range validation", device_id=device_id,
                       problems=problems[:5])

    # 6. persist, encrypted at rest
    payload = canonical_json(readings)
    record = Telemetry(
        device_id=device.id, org_id=device.org_id, field_id=device.field_id,
        shipment_id=shipment_id, recorded_at=_aware(recorded_at), nonce=nonce,
        payload_enc="", payload_hash=sha256_hex(payload),
        summary=_summary(readings), quality=quality,
        backfilled=allow_backfill)
    db.add(record)
    db.flush()
    record.payload_enc = encrypt_at_rest(payload, record.id)

    if sequence is not None:
        device.last_sequence = sequence
    device_service.update_health(db, device, readings)

    # 7. anomaly scoring — inline, or deferred to a background task
    if score_inline is None:
        score_inline = settings.telemetry_inline_scoring
    if not score_inline:
        db.flush()
        return record

    previous = _previous_readings(db, device.id, record.id)
    _score_and_persist(db, device, record, readings, previous, settings, problems)
    db.flush()
    return record


def _score_and_persist(db: Session, device: Device, record: Telemetry,
                       readings: dict[str, Any], previous: dict[str, Any] | None,
                       settings, problems: list[str] | None = None) -> dict[str, Any]:
    """Score a reading, store the analysis, and alert if it crosses the threshold."""
    from ai.anomaly import score as anomaly_score

    problems = problems or []
    verdict = anomaly_score(device.device_type, readings, previous,
                            seconds_since_previous=None,
                            hour=_aware(record.recorded_at).hour,
                            model_dir=str(settings.repo_root / "ai" / "models"))
    if problems:
        verdict = {**verdict, "score": max(verdict["score"], 0.9), "level": "CRITICAL",
                   "reasons": problems[:6] + verdict["reasons"][:2]}
    record.anomaly_score = verdict["score"]

    db.add(AIAnalysis(org_id=device.org_id, analysis_type="TELEMETRY_ANOMALY",
                      subject_type="Telemetry", subject_id=record.id, score=verdict["score"],
                      level=verdict["level"], reasons=verdict["reasons"],
                      evidence={"device_type": device.device_type,
                                "summary": record.summary, "validation_problems": problems[:5]},
                      model_version=verdict["model_version"], degraded=verdict["degraded"]))

    if verdict["score"] >= settings.anomaly_alert_threshold:
        if record.quality == "OK":
            record.quality = "SUSPECT"
        notifications.raise_alert(
            db, "DEVICE_ANOMALY", verdict["level"],
            f"Anomalous telemetry from {device.device_type} {device.id[:8]}",
            detail="; ".join(verdict["reasons"][:3]), org_id=device.org_id,
            entity_type="Device", entity_id=device.id, reasons=verdict["reasons"])
    db.flush()
    return verdict


def _signature_valid(db: Session, device: Device, timestamp: str, nonce: str,
                     readings: Any, signature: str) -> bool:
    """Recompute the HMAC with the device's secret and compare in constant time."""
    secret = device_service.load_secret(device)
    if secret is None:
        security_event("telemetry rejected: device credential is unreadable", device_id=device.id)
        device_service.record_auth_failure(db, device)
        return False
    if not verify_device_signature(secret, device.id, timestamp, nonce, readings, signature):
        device_service.record_auth_failure(db, device)
        security_event("telemetry rejected: HMAC verification failed", level=logging.WARNING,
                       device_id=device.id)
        return False
    return True


def _summary(readings: dict[str, Any]) -> dict[str, Any]:
    """Non-sensitive numeric projection used for charts and analytics."""
    return {k: round(float(v), 4) for k, v in readings.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)}


def _previous_readings(db: Session, device_id: str, exclude_id: str) -> dict[str, Any] | None:
    previous = db.execute(
        select(Telemetry).where(Telemetry.device_id == device_id, Telemetry.id != exclude_id)
        .order_by(Telemetry.recorded_at.desc()).limit(1)).scalar_one_or_none()
    return previous.summary if previous else None


def decrypt_payload(record: Telemetry) -> dict[str, Any]:
    import json

    return json.loads(decrypt_at_rest(record.payload_enc, record.id))


def series(db: Session, device_id: str, org_id: str | None, hours: int = 24,
           limit: int = 500) -> list[Telemetry]:
    since = utcnow() - timedelta(hours=hours)
    query = (select(Telemetry).where(Telemetry.device_id == device_id,
                                     Telemetry.recorded_at >= since)
             .order_by(Telemetry.recorded_at.desc()).limit(limit))
    if org_id:
        query = query.where(Telemetry.org_id == org_id)
    return list(db.execute(query).scalars())


def shipment_summary(db: Session, shipment_id: str) -> dict[str, Any]:
    """Cold-chain evidence bound to a shipment (FR-D1)."""
    records = list(db.execute(
        select(Telemetry).where(Telemetry.shipment_id == shipment_id)).scalars())
    temperatures = [r.summary.get("temp_c") for r in records
                    if isinstance(r.summary.get("temp_c"), (int, float))]
    if not temperatures:
        return {"readings": len(records), "temp_min_c": None, "temp_max_c": None}
    return {"readings": len(records), "temp_min_c": round(min(temperatures), 2),
            "temp_max_c": round(max(temperatures), 2),
            "temp_mean_c": round(sum(temperatures) / len(temperatures), 2)}


# --------------------------------------------------------------------------- #
# Satellite pipeline
# --------------------------------------------------------------------------- #
def ingest_scene(db: Session, org_id: str, actor_id: str, actor_role: str, scene_id: str,
                 field_id: str, provider: str, captured_at: datetime, ndvi_mean: float,
                 ndvi_min: float, ndvi_max: float, cloud_cover_pct: float,
                 checksum: str) -> SatelliteScene:
    from ..models import Field

    field = db.execute(select(Field).where(Field.id == field_id, Field.org_id == org_id,
                                           Field.deleted_at.is_(None))).scalar_one_or_none()
    if field is None:
        raise NotFound("Field not found")
    if db.execute(select(SatelliteScene).where(
            SatelliteScene.scene_id == scene_id)).scalar_one_or_none():
        raise Conflict("Scene already ingested")
    if not (ndvi_min <= ndvi_mean <= ndvi_max):
        raise ValidationFailed("NDVI statistics are inconsistent: min <= mean <= max is required")

    expected = content_hash({"scene_id": scene_id, "field_id": field_id,
                             "captured_at": _aware(captured_at).isoformat(),
                             "ndvi_mean": ndvi_mean})
    if checksum != expected:
        security_event("satellite scene rejected: checksum mismatch", scene_id=scene_id)
        raise ValidationFailed("Scene checksum does not match its metadata")

    scene = SatelliteScene(scene_id=scene_id, org_id=org_id, field_id=field_id, provider=provider,
                           captured_at=_aware(captured_at), ndvi_mean=ndvi_mean,
                           ndvi_min=ndvi_min, ndvi_max=ndvi_max,
                           cloud_cover_pct=cloud_cover_pct, checksum=checksum, is_simulated=True)
    db.add(scene)
    db.flush()
    audit.record(db, "satellite.ingest", actor_id=actor_id, actor_role=actor_role, org_id=org_id,
                 entity_type="SatelliteScene", entity_id=scene.id,
                 detail={"scene_id": scene_id, "field_id": field_id})

    if ndvi_mean < 0.35 and cloud_cover_pct < 40:
        notifications.raise_alert(
            db, "AGRONOMY", "WARNING", f"Low vegetation index on field {field.name}",
            detail=f"NDVI mean {ndvi_mean:.2f} indicates crop stress in this field.",
            org_id=org_id, entity_type="Field", entity_id=field_id, open_incident=False)
    return scene


def scene_checksum(scene_id: str, field_id: str, captured_at: datetime, ndvi_mean: float) -> str:
    """Helper used by the simulator and tests to produce a valid checksum."""
    return content_hash({"scene_id": scene_id, "field_id": field_id,
                         "captured_at": _aware(captured_at).isoformat(), "ndvi_mean": ndvi_mean})


def field_stress_ranking(db: Session, org_id: str | None, limit: int = 10) -> list[dict[str, Any]]:
    """Precision-farming insight: rank fields by vegetation index and soil moisture."""
    from ..models import Field

    query = select(SatelliteScene).order_by(SatelliteScene.captured_at.desc()).limit(400)
    if org_id:
        query = query.where(SatelliteScene.org_id == org_id)
    latest: dict[str, SatelliteScene] = {}
    for scene in db.execute(query).scalars():
        latest.setdefault(scene.field_id, scene)

    ranking: list[dict[str, Any]] = []
    for field_id, scene in latest.items():
        field = db.get(Field, field_id)
        moisture_values = [
            t.summary.get("soil_moisture_pct") for t in db.execute(
                select(Telemetry).where(Telemetry.field_id == field_id)
                .order_by(Telemetry.recorded_at.desc()).limit(20)).scalars()
            if isinstance(t.summary.get("soil_moisture_pct"), (int, float))]
        moisture = round(sum(moisture_values) / len(moisture_values), 2) if moisture_values else None
        stress = round((1 - scene.ndvi_mean) * 0.7
                       + (0.3 * (1 - min(1.0, (moisture or 30) / 40)) if moisture is not None else 0.1), 4)
        ranking.append({
            "field_id": field_id, "field_name": field.name if field else "unknown",
            "ndvi_mean": scene.ndvi_mean, "soil_moisture_pct": moisture,
            "captured_at": scene.captured_at, "stress_index": stress,
            "level": "HIGH" if stress > 0.55 else "MODERATE" if stress > 0.4 else "LOW",
        })
    ranking.sort(key=lambda item: item["stress_index"], reverse=True)
    return ranking[:limit]


def score_pending(telemetry_id: str) -> None:
    """Score one stored reading. Runs as a background task when inline scoring is off.

    Opens its own session: the request's session is already closed by the time this runs.
    Never raises — a scoring failure must not affect the accepted message.
    """
    from ..core.database import SessionLocal

    try:
        with SessionLocal() as db:
            record = db.get(Telemetry, telemetry_id)
            if record is None or record.anomaly_score is not None:
                return
            device = db.get(Device, record.device_id)
            if device is None:
                return
            settings = get_settings()
            readings = decrypt_payload(record)
            verdict = _score_and_persist(db, device, record, readings,
                                         _previous_readings(db, device.id, record.id), settings)
            db.commit()
            _ = verdict
    except Exception:                                    # noqa: BLE001
        security_event("deferred anomaly scoring failed", telemetry_id=telemetry_id)
