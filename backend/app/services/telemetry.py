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
from . import ai_client, audit, cold_chain, devices as device_service, notifications




def verify_and_ingest(db: Session, device_id: str, timestamp_header: str, nonce: str,
                      signature: str, recorded_at: datetime, readings: dict[str, Any],
                      shipment_id: str | None = None, sequence: int | None = None,
                      allow_backfill: bool = False, ip: str | None = None,
                      score_inline: bool | None = None) -> Telemetry:
    """Full ingestion path. Order of checks matters: identity, freshness, replay, then content."""
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
    problems = ai_client.validate_readings(device.device_type, readings)
    quality = "OK"
    if problems:
        quality = "QUARANTINED"
        security_event("telemetry quarantined: failed range validation", device_id=device_id,
                       problems=problems[:5])

    # 6. persist, encrypted at rest. The shipment comes from the device's cold-chain binding;
    #    a shipment id the device sends is only honoured when it is bound to this device.
    shipment = cold_chain.bind_shipment(db, device, shipment_id, recorded_at)
    payload = canonical_json(readings)
    record = Telemetry(
        device_id=device.id, org_id=device.org_id, field_id=device.field_id,
        shipment_id=shipment.id if shipment else None, recorded_at=_aware(recorded_at),
        nonce=nonce,
        payload_enc="", payload_hash=sha256_hex(payload),
        summary=_summary(readings), quality=quality,
        backfilled=allow_backfill)
    db.add(record)
    db.flush()
    record.payload_enc = encrypt_at_rest(payload, record.id)
    if shipment is not None and quality == "OK":
        # Running temperature range and the storage-range excursion alert (FR-D1).
        cold_chain.record_reading(db, shipment, record)

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
    try:
        _score_and_persist(db, device, record, readings, previous, settings, problems)
    except ai_client.service_http.ServiceUnavailable:
        # The reading is already validated and stored; losing the AI service must not
        # lose the message (NFR-5). It stays unscored (anomaly_score NULL) for a rescore.
        security_event("inline anomaly scoring unavailable; reading stored unscored",
                       device_id=device.id, telemetry_id=record.id)
    db.flush()
    return record


def _score_and_persist(db: Session, device: Device, record: Telemetry,
                       readings: dict[str, Any], previous: dict[str, Any] | None,
                       settings, problems: list[str] | None = None) -> dict[str, Any]:
    """Score a reading, store the analysis, and alert if it crosses the threshold."""
    problems = problems or []
    verdict = ai_client.anomaly_score(device.device_type, readings, previous,
                                      seconds_since_previous=None,
                                      hour=_aware(record.recorded_at).hour)
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
        # kind="anomaly": while this device's anomaly alert is unresolved, further anomalous
        # readings are counted on it (and noted on its incident) instead of each raising a
        # new alert and incident — a faulty sensor otherwise produced ~96 of each a day.
        notifications.raise_alert(
            db, "DEVICE_ANOMALY", verdict["level"],
            f"Anomalous telemetry from {device.device_type} {device.id[:8]}",
            detail="; ".join(verdict["reasons"][:3]), org_id=device.org_id,
            entity_type="Device", entity_id=device.id, reasons=verdict["reasons"],
            kind="anomaly")
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
                 checksum: str, source: str = "SATELLITE", index_name: str = "NDVI",
                 file_sha256: str | None = None,
                 footprint_geojson: dict[str, Any] | None = None) -> SatelliteScene:
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

    expected = scene_checksum(scene_id, field_id, captured_at, ndvi_mean, file_sha256)
    if checksum != expected:
        security_event("satellite scene rejected: checksum mismatch", scene_id=scene_id)
        raise ValidationFailed("Scene checksum does not match its metadata")

    scene = SatelliteScene(scene_id=scene_id, org_id=org_id, field_id=field_id, provider=provider,
                           captured_at=_aware(captured_at), ndvi_mean=ndvi_mean,
                           ndvi_min=ndvi_min, ndvi_max=ndvi_max,
                           cloud_cover_pct=cloud_cover_pct, checksum=checksum,
                           # A scene that arrives with the hash of a real image file (an
                           # OpenDroneMap orthophoto) is not simulated metadata.
                           is_simulated=file_sha256 is None, source=source,
                           index_name=index_name, file_sha256=file_sha256,
                           footprint_geojson=footprint_geojson)
    db.add(scene)
    db.flush()
    audit.record(db, "satellite.ingest", actor_id=actor_id, actor_role=actor_role, org_id=org_id,
                 entity_type="SatelliteScene", entity_id=scene.id,
                 detail={"scene_id": scene_id, "field_id": field_id, "source": source,
                         "file_sha256": file_sha256})

    if file_sha256:
        from ..models import Organization
        from . import ledger_client

        organization = db.get(Organization, org_id)
        receipt = ledger_client.submit(
            "imagery", "AnchorScene",
            {"scene_id": scene_id, "field": field.name, "source": source,
             "index_name": index_name, "file_sha256": file_sha256, "content_hash": checksum},
            organization.msp_id if organization else "FarmMSP", db=db, entity=scene)
        if receipt.get("ok"):
            scene.anchor_tx_id = receipt.get("tx_id")
        else:
            security_event("scene file hash not anchored", scene_id=scene_id,
                           reason=receipt.get("error") or receipt.get("detail"))

    # VARI (RGB cameras) sits lower than NDVI for the same healthy crop, so it has its own line.
    threshold = 0.35 if index_name == "NDVI" else 0.05
    # One alert per field (kind="low_ndvi"): each further low scene folds into it, and a
    # clear scene at or above the line resolves it. A cloudy scene says nothing either way.
    if cloud_cover_pct < 40:
        if ndvi_mean < threshold:
            notifications.raise_alert(
                db, "AGRONOMY", "WARNING", f"Low vegetation index on field {field.name}",
                detail=f"{index_name} mean {ndvi_mean:.2f} from {source.lower()} imagery "
                       f"indicates crop stress in this field.",
                org_id=org_id, entity_type="Field", entity_id=field_id, open_incident=False,
                kind="low_ndvi")
        else:
            notifications.resolve_alerts(
                db, "AGRONOMY", field_id, kind="low_ndvi", actor_id=actor_id,
                note=f"A later scene shows {index_name} mean {ndvi_mean:.2f}, above the "
                     f"crop-stress line")
    return scene


def scene_checksum(scene_id: str, field_id: str, captured_at: datetime, ndvi_mean: float,
                   file_sha256: str | None = None) -> str:
    """Checksum binding a scene's metadata (and, for real imagery, its file hash) together."""
    payload = {"scene_id": scene_id, "field_id": field_id,
               "captured_at": _aware(captured_at).isoformat(), "ndvi_mean": ndvi_mean}
    if file_sha256:
        payload["file_sha256"] = file_sha256
    return content_hash(payload)


def fields_geojson(db: Session, org_id: str | None) -> dict[str, Any]:
    """Every field as a GeoJSON Feature with its latest vegetation index, plus the footprint of
    each drone orthophoto. Opens directly in QGIS (Layer > Add Vector Layer). Coordinates are
    WGS84 (EPSG:4326), which is what the GeoJSON standard requires."""
    from ..models import Farm, Field

    field_query = select(Field).where(Field.deleted_at.is_(None))
    scene_query = select(SatelliteScene).order_by(SatelliteScene.captured_at.desc()).limit(1000)
    if org_id:
        field_query = field_query.where(Field.org_id == org_id)
        scene_query = scene_query.where(SatelliteScene.org_id == org_id)
    scenes = list(db.execute(scene_query).scalars())
    latest: dict[str, SatelliteScene] = {}
    for scene in scenes:
        latest.setdefault(scene.field_id, scene)
    stress = {row["field_id"]: row for row in field_stress_ranking(db, org_id, limit=1000)}

    features: list[dict[str, Any]] = []
    for field in db.execute(field_query).scalars():
        farm = db.get(Farm, field.farm_id)
        geometry = field.boundary_geojson or (
            {"type": "Point", "coordinates": [farm.longitude, farm.latitude]} if farm else None)
        scene = latest.get(field.id)
        ranked = stress.get(field.id, {})
        features.append({"type": "Feature", "geometry": geometry, "properties": {
            "layer": "field", "field_id": field.id, "field": field.name,
            "farm": farm.name if farm else None, "area_ha": field.area_ha,
            "soil_type": field.soil_type,
            "index_name": scene.index_name if scene else None,
            "index_mean": scene.ndvi_mean if scene else None,
            "cloud_cover_pct": scene.cloud_cover_pct if scene else None,
            "captured_at": scene.captured_at.isoformat() if scene else None,
            "source": scene.source if scene else None,
            "stress_index": ranked.get("stress_index"), "stress_level": ranked.get("level")}})
    for scene in scenes:
        if scene.footprint_geojson:
            features.append({"type": "Feature", "geometry": scene.footprint_geojson, "properties": {
                "layer": "drone_footprint", "scene_id": scene.scene_id,
                "field_id": scene.field_id, "source": scene.source,
                "index_name": scene.index_name, "index_mean": scene.ndvi_mean,
                "file_sha256": scene.file_sha256, "anchor_tx_id": scene.anchor_tx_id,
                "captured_at": scene.captured_at.isoformat()}})
    return {"type": "FeatureCollection", "name": "absp_fields", "features": features}


def field_stress_ranking(db: Session, org_id: str | None, limit: int = 10) -> list[dict[str, Any]]:
    """Precision-farming insight: rank fields by vegetation index and soil moisture."""
    from ..models import Field

    # NDVI scenes only: VARI from an RGB drone camera sits on a different scale, so mixing the
    # two would rank a healthy drone-mapped field as stressed. Drone VARI has its own alert.
    query = (select(SatelliteScene)
             .where((SatelliteScene.index_name == "NDVI") | SatelliteScene.index_name.is_(None))
             .order_by(SatelliteScene.captured_at.desc()).limit(400))
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


def rescore_unscored(db: Session, limit: int = 200, org_id: str | None = None,
                     min_age: timedelta = timedelta(minutes=2)) -> int:
    """Score stored readings that were never scored (the AI service was down at ingest, or a
    deferred task was lost). Run by the health sweep; returns how many were scored.

    Readings younger than `min_age` are left to their own background task. The pass stops at
    the first ServiceUnavailable: the service is still down, and the rest wait for the next
    sweep. The caller commits.
    """
    settings = get_settings()
    query = (select(Telemetry).where(Telemetry.anomaly_score.is_(None),
                                     Telemetry.received_at <= utcnow() - min_age)
             .order_by(Telemetry.recorded_at.asc()).limit(limit))
    if org_id is not None:
        query = query.where(Telemetry.org_id == org_id)
    scored = 0
    for record in list(db.execute(query).scalars()):
        device = db.get(Device, record.device_id)
        if device is None:
            continue
        previous = db.execute(
            select(Telemetry).where(Telemetry.device_id == device.id,
                                    Telemetry.recorded_at < record.recorded_at)
            .order_by(Telemetry.recorded_at.desc()).limit(1)).scalars().first()
        try:
            readings = decrypt_payload(record)
            problems = ai_client.validate_readings(device.device_type, readings)
            _score_and_persist(db, device, record, readings,
                               previous.summary if previous else None, settings, problems)
        except ai_client.service_http.ServiceUnavailable:
            security_event("rescore paused: anomaly scoring is still unavailable",
                           telemetry_id=record.id)
            break
        except Exception:                                # noqa: BLE001 - one bad row must not stop the pass
            security_event("rescore of a stored reading failed", telemetry_id=record.id)
            continue
        scored += 1
    db.flush()
    return scored
