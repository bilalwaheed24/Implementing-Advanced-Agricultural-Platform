"""SQLAlchemy 2.0 ORM models — the data model specified in docs/Backend.md §4.

Conventions:
  * UUID string primary keys
  * created_at on every table; updated_at on mutable tables
  * org_id on tenant tables (scoping enforced in repositories.py)
  * traceability and audit tables are append-only (no delete endpoints exist)
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON, Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer,
    String, Text, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .core.security import new_id, utcnow


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


def _pk() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=new_id)


def _created() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


def _updated() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# --------------------------------------------------------------------------- #
# Identity and tenancy
# --------------------------------------------------------------------------- #
class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    org_type: Mapped[str] = mapped_column(String(40), nullable=False)   # BIOTECH|FARM|SUPPLY|REGULATOR
    msp_id: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    country: Mapped[str | None] = mapped_column(String(2))
    gln: Mapped[str | None] = mapped_column(String(13))
    trusted_issuer_types: Mapped[list[Any]] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()

    users: Mapped[list["User"]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = _pk()
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", nullable=False)  # PENDING|ACTIVE|SUSPENDED
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()

    organization: Mapped[Organization] = relationship(back_populates="users")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = _pk()
    jti: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    family_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = _created()


# --------------------------------------------------------------------------- #
# Farm domain
# --------------------------------------------------------------------------- #
class Farm(Base):
    __tablename__ = "farms"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    region: Mapped[str] = mapped_column(String(120), nullable=False)
    country: Mapped[str] = mapped_column(String(2), nullable=False)
    latitude: Mapped[float] = mapped_column(Float, nullable=False)
    longitude: Mapped[float] = mapped_column(Float, nullable=False)
    area_ha: Mapped[float] = mapped_column(Float, nullable=False)
    gln: Mapped[str | None] = mapped_column(String(13))
    created_by: Mapped[str | None] = mapped_column(String(36))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    __table_args__ = (
        CheckConstraint("area_ha >= 0", name="ck_farm_area_positive"),
        Index("ix_farms_org_created", "org_id", "created_at"),
    )

    fields: Mapped[list["Field"]] = relationship(back_populates="farm")


class Field(Base):
    __tablename__ = "fields"
    id: Mapped[str] = _pk()
    farm_id: Mapped[str] = mapped_column(ForeignKey("farms.id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    area_ha: Mapped[float] = mapped_column(Float, nullable=False)
    soil_type: Mapped[str | None] = mapped_column(String(60))
    boundary_geojson: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()

    farm: Mapped[Farm] = relationship(back_populates="fields")


class Crop(Base):
    __tablename__ = "crops"
    id: Mapped[str] = _pk()
    field_id: Mapped[str] = mapped_column(ForeignKey("fields.id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    crop_type: Mapped[str] = mapped_column(String(80), nullable=False)
    variety: Mapped[str | None] = mapped_column(String(120))
    gmo_event_id: Mapped[str | None] = mapped_column(ForeignKey("gmo_events.id"), index=True)
    seed_lot_id: Mapped[str | None] = mapped_column(ForeignKey("seed_lots.id"))
    planted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expected_harvest: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="PLANTED", nullable=False)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


# --------------------------------------------------------------------------- #
# Devices and telemetry
# --------------------------------------------------------------------------- #
class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    farm_id: Mapped[str] = mapped_column(ForeignKey("farms.id"), nullable=False, index=True)
    field_id: Mapped[str | None] = mapped_column(ForeignKey("fields.id"), index=True)
    device_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(120), nullable=False)
    serial_number: Mapped[str | None] = mapped_column(String(120))
    firmware_version: Mapped[str] = mapped_column(String(40), nullable=False)
    # AES-256-GCM ciphertext, key from the environment/KMS. HMAC verification requires
    # the secret back, so it is encrypted (reversible) rather than hashed (one-way).
    secret_enc: Mapped[str] = mapped_column(Text, nullable=False)
    secret_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), default="PROVISIONED", nullable=False, index=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=900, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sequence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    battery_pct: Mapped[float | None] = mapped_column(Float)
    signal_dbm: Mapped[float | None] = mapped_column(Float)
    auth_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    quarantine_reason: Mapped[str | None] = mapped_column(Text)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class DeviceVulnerability(Base):
    __tablename__ = "device_vulnerabilities"
    id: Mapped[str] = _pk()
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    cve_id: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # LOW..CRITICAL
    cvss: Mapped[float | None] = mapped_column(Float)
    affected_versions: Mapped[str | None] = mapped_column(String(120))
    fixed_in: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20), default="OPEN", nullable=False, index=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()


class Telemetry(Base):
    __tablename__ = "telemetry"
    id: Mapped[str] = _pk()
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    field_id: Mapped[str | None] = mapped_column(ForeignKey("fields.id"), index=True)
    shipment_id: Mapped[str | None] = mapped_column(ForeignKey("shipments.id"), index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_enc: Mapped[str] = mapped_column(Text, nullable=False)          # AES-GCM at rest
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)     # non-sensitive, for charts
    anomaly_score: Mapped[float | None] = mapped_column(Float, index=True)
    quality: Mapped[str] = mapped_column(String(16), default="OK", nullable=False)  # OK|SUSPECT|QUARANTINED
    backfilled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    __table_args__ = (
        UniqueConstraint("device_id", "nonce", name="uq_telemetry_device_nonce"),
        Index("ix_telemetry_device_recorded", "device_id", "recorded_at"),
    )


class SatelliteScene(Base):
    __tablename__ = "satellite_scenes"
    id: Mapped[str] = _pk()
    scene_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    field_id: Mapped[str] = mapped_column(ForeignKey("fields.id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(60), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ndvi_mean: Mapped[float] = mapped_column(Float, nullable=False)
    ndvi_min: Mapped[float] = mapped_column(Float, nullable=False)
    ndvi_max: Mapped[float] = mapped_column(Float, nullable=False)
    cloud_cover_pct: Mapped[float] = mapped_column(Float, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = _created()


# --------------------------------------------------------------------------- #
# AI, alerts, incidents
# --------------------------------------------------------------------------- #
class AIAnalysis(Base):
    __tablename__ = "ai_analyses"
    id: Mapped[str] = _pk()
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True)
    analysis_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(40), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    model_version: Mapped[str] = mapped_column(String(60), nullable=False)
    degraded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = _created()


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = _pk()
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True)
    category: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="")
    entity_type: Mapped[str | None] = mapped_column(String(40))
    entity_id: Mapped[str | None] = mapped_column(String(36), index=True)
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="OPEN", nullable=False, index=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(36))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True)
    created_at: Mapped[datetime] = _created()


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = _pk()
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="OPEN", nullable=False, index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    root_cause: Mapped[str | None] = mapped_column(Text)
    opened_by: Mapped[str | None] = mapped_column(String(36))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    id: Mapped[str] = _pk()
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="")
    actor_id: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = _created()


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = _pk()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="")
    entity_type: Mapped[str | None] = mapped_column(String(40))
    entity_id: Mapped[str | None] = mapped_column(String(36))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()


class AccessRecord(Base):
    """Signals for agricultural data-theft detection (FR-A3)."""
    __tablename__ = "access_records"
    id: Mapped[str] = _pk()
    principal_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    org_id: Mapped[str | None] = mapped_column(String(36), index=True)
    route: Mapped[str] = mapped_column(String(200), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    page_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, default=200, nullable=False)
    hour: Mapped[int] = mapped_column(Integer, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    cross_tenant_attempt: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = _created()


# --------------------------------------------------------------------------- #
# Biosecurity
# --------------------------------------------------------------------------- #
class HazardSequence(Base):
    __tablename__ = "hazard_sequences"
    id: Mapped[str] = _pk()
    agent_name: Mapped[str] = mapped_column(String(160), nullable=False)
    hazard_class: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)         # 1..5
    description: Mapped[str] = mapped_column(Text, default="")
    sequence: Mapped[str] = mapped_column(Text, nullable=False)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = _created()
    __table_args__ = (CheckConstraint("severity BETWEEN 1 AND 5", name="ck_hazard_severity"),)


class SequenceScreening(Base):
    __tablename__ = "sequence_screenings"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    submitted_by: Mapped[str] = mapped_column(String(36), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    intent: Mapped[str] = mapped_column(String(80), nullable=False)
    organism: Mapped[str | None] = mapped_column(String(160))
    sequence_enc: Mapped[str] = mapped_column(Text, nullable=False)        # AES-GCM at rest
    sequence_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sequence_length: Mapped[int] = mapped_column(Integer, nullable=False)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False, index=True)   # CLEAR|FLAG|BLOCK
    max_identity: Mapped[float] = mapped_column(Float, default=0.0)
    hazard_classes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False,
                                               server_default="[]")
    status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    durc_flag: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(36))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_rationale: Mapped[str | None] = mapped_column(Text)
    engine_version: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class ScreeningHit(Base):
    __tablename__ = "screening_hits"
    id: Mapped[str] = _pk()
    screening_id: Mapped[str] = mapped_column(ForeignKey("sequence_screenings.id"), nullable=False, index=True)
    hazard_id: Mapped[str] = mapped_column(ForeignKey("hazard_sequences.id"), nullable=False)
    agent_name: Mapped[str] = mapped_column(String(160), nullable=False)
    hazard_class: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    identity: Mapped[float] = mapped_column(Float, nullable=False)
    align_length: Mapped[int] = mapped_column(Integer, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    query_start: Mapped[int] = mapped_column(Integer, nullable=False)
    query_end: Mapped[int] = mapped_column(Integer, nullable=False)
    subject_start: Mapped[int] = mapped_column(Integer, nullable=False)
    subject_end: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = _created()


class CrisprAssessment(Base):
    __tablename__ = "crispr_assessments"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    submitted_by: Mapped[str] = mapped_column(String(36), nullable=False)
    target_gene: Mapped[str] = mapped_column(String(120), nullable=False)
    organism: Mapped[str] = mapped_column(String(160), nullable=False)
    guide_rna: Mapped[str] = mapped_column(String(64), nullable=False)
    pam: Mapped[str] = mapped_column(String(16), nullable=False)
    edit_type: Mapped[str] = mapped_column(String(24), nullable=False)
    intent: Mapped[str] = mapped_column(String(80), nullable=False)
    off_target_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    off_targets: Mapped[list[Any]] = mapped_column(JSON, default=list)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    durc_flag: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(24), default="PENDING_REVIEW", nullable=False, index=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(36))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_rationale: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


# --------------------------------------------------------------------------- #
# GMO registry
# --------------------------------------------------------------------------- #
class GMOEvent(Base):
    __tablename__ = "gmo_events"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    event_code: Mapped[str] = mapped_column(String(40), unique=True, nullable=False, index=True)
    crop_type: Mapped[str] = mapped_column(String(80), nullable=False)
    trait: Mapped[str] = mapped_column(String(200), nullable=False)
    donor_organism: Mapped[str] = mapped_column(String(200), nullable=False)
    developer: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    screening_id: Mapped[str | None] = mapped_column(ForeignKey("sequence_screenings.id"))
    content_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    tx_id: Mapped[str | None] = mapped_column(String(64), index=True)
    block_number: Mapped[int | None] = mapped_column(Integer)
    anchor_status: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class GMOApproval(Base):
    __tablename__ = "gmo_approvals"
    id: Mapped[str] = _pk()
    gmo_event_id: Mapped[str] = mapped_column(ForeignKey("gmo_events.id"), nullable=False, index=True)
    jurisdiction: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False)   # APPROVED|PENDING|REJECTED|NOT_SUBMITTED
    reference: Mapped[str | None] = mapped_column(String(120))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tx_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = _created()
    __table_args__ = (UniqueConstraint("gmo_event_id", "jurisdiction", name="uq_gmo_jurisdiction"),)


class SeedLot(Base):
    __tablename__ = "seed_lots"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    lot_code: Mapped[str] = mapped_column(String(60), unique=True, nullable=False, index=True)
    gmo_event_id: Mapped[str | None] = mapped_column(ForeignKey("gmo_events.id"), index=True)
    crop_type: Mapped[str] = mapped_column(String(80), nullable=False)
    variety: Mapped[str] = mapped_column(String(120), nullable=False)
    quantity_kg: Mapped[float] = mapped_column(Float, nullable=False)
    produced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    germination_pct: Mapped[float | None] = mapped_column(Float)
    content_hash: Mapped[str | None] = mapped_column(String(64))
    tx_id: Mapped[str | None] = mapped_column(String(64), index=True)
    anchor_status: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False)
    created_at: Mapped[datetime] = _created()
    __table_args__ = (CheckConstraint("quantity_kg >= 0", name="ck_seedlot_qty"),)


# --------------------------------------------------------------------------- #
# Supply chain
# --------------------------------------------------------------------------- #
class Product(Base):
    __tablename__ = "products"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    gtin: Mapped[str] = mapped_column(String(14), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    organic_claim: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    non_gmo_claim: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    storage_temp_min_c: Mapped[float | None] = mapped_column(Float)
    storage_temp_max_c: Mapped[float | None] = mapped_column(Float)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class Batch(Base):
    __tablename__ = "batches"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    batch_code: Mapped[str] = mapped_column(String(60), unique=True, nullable=False, index=True)
    verification_code: Mapped[str] = mapped_column(String(40), unique=True, nullable=False, index=True)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), nullable=False, index=True)
    parent_batch_id: Mapped[str | None] = mapped_column(ForeignKey("batches.id"), index=True)
    seed_lot_id: Mapped[str | None] = mapped_column(ForeignKey("seed_lots.id"), index=True)
    crop_id: Mapped[str | None] = mapped_column(ForeignKey("crops.id"))
    farm_id: Mapped[str | None] = mapped_column(ForeignKey("farms.id"), index=True)
    gmo_event_id: Mapped[str | None] = mapped_column(ForeignKey("gmo_events.id"), index=True)
    state: Mapped[str] = mapped_column(String(24), default="CREATED", nullable=False, index=True)
    quantity: Mapped[float] = mapped_column(Float, nullable=False)          # current, mutable
    # Quantity at creation. Immutable, and therefore part of the anchored content hash:
    # the current quantity legitimately falls through processing loss, so hashing it
    # would make every downstream event look like tampering.
    initial_quantity: Mapped[float] = mapped_column(Float, nullable=False)
    unit: Mapped[str] = mapped_column(String(12), default="kg", nullable=False)
    custodian_org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    origin_region: Mapped[str | None] = mapped_column(String(120))
    origin_country: Mapped[str | None] = mapped_column(String(2))
    harvested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    content_hash: Mapped[str | None] = mapped_column(String(64))
    tx_id: Mapped[str | None] = mapped_column(String(64), index=True)
    anchor_status: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False)
    integrity_status: Mapped[str] = mapped_column(String(16), default="UNVERIFIED", nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    __table_args__ = (CheckConstraint("quantity >= 0", name="ck_batch_qty"),)


class SupplyChainEvent(Base):
    """EPCIS-shaped event: what / when / where / why / who. Append-only."""
    __tablename__ = "supply_chain_events"
    id: Mapped[str] = _pk()
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(24), nullable=False)     # OBJECT|AGGREGATION|TRANSFORMATION
    biz_step: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    disposition: Mapped[str] = mapped_column(String(40), nullable=False)
    location_gln: Mapped[str | None] = mapped_column(String(13))
    location_name: Mapped[str | None] = mapped_column(String(200))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    quantity: Mapped[float | None] = mapped_column(Float)
    unit: Mapped[str | None] = mapped_column(String(12))
    from_org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"))
    to_org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tx_id: Mapped[str | None] = mapped_column(String(64), index=True)
    block_number: Mapped[int | None] = mapped_column(Integer)
    anchor_status: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False)
    recorded_by: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = _created()
    __table_args__ = (Index("ix_events_batch_time", "batch_id", "occurred_at"),)


class Shipment(Base):
    __tablename__ = "shipments"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    sscc: Mapped[str] = mapped_column(String(18), unique=True, nullable=False, index=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), nullable=False, index=True)
    carrier: Mapped[str] = mapped_column(String(160), nullable=False)
    origin_name: Mapped[str] = mapped_column(String(200), nullable=False)
    origin_lat: Mapped[float] = mapped_column(Float, nullable=False)
    origin_lon: Mapped[float] = mapped_column(Float, nullable=False)
    destination_name: Mapped[str] = mapped_column(String(200), nullable=False)
    destination_lat: Mapped[float] = mapped_column(Float, nullable=False)
    destination_lon: Mapped[float] = mapped_column(Float, nullable=False)
    departed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    arrived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), default="IN_TRANSIT", nullable=False, index=True)
    temp_min_c: Mapped[float | None] = mapped_column(Float)
    temp_max_c: Mapped[float | None] = mapped_column(Float)
    cold_chain_device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class Certification(Base):
    __tablename__ = "certifications"
    id: Mapped[str] = _pk()
    cert_code: Mapped[str] = mapped_column(String(60), unique=True, nullable=False, index=True)
    cert_type: Mapped[str] = mapped_column(String(24), nullable=False, index=True)   # ORGANIC|NON_GMO|SPECIALTY
    standard: Mapped[str] = mapped_column(String(80), nullable=False)
    issuer_org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    subject_org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(Text)
    content_hash: Mapped[str | None] = mapped_column(String(64))
    tx_id: Mapped[str | None] = mapped_column(String(64), index=True)
    anchor_status: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class CertificationLink(Base):
    __tablename__ = "certification_links"
    id: Mapped[str] = _pk()
    certification_id: Mapped[str] = mapped_column(ForeignKey("certifications.id"), nullable=False, index=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), nullable=False, index=True)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at: Mapped[datetime] = _created()
    __table_args__ = (UniqueConstraint("certification_id", "batch_id", name="uq_cert_batch"),)


class FraudAssessment(Base):
    __tablename__ = "fraud_assessments"
    id: Mapped[str] = _pk()
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list)
    ledger_status: Mapped[str] = mapped_column(String(16), default="UNKNOWN", nullable=False)
    model_version: Mapped[str] = mapped_column(String(60), default="")
    created_at: Mapped[datetime] = _created()


class ComplianceReport(Base):
    __tablename__ = "compliance_reports"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    report_type: Mapped[str] = mapped_column(String(40), default="COMPLIANCE", nullable=False)
    subject_type: Mapped[str] = mapped_column(String(40), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    jurisdiction: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    results: Mapped[list[Any]] = mapped_column(JSON, default=list)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    content_hash: Mapped[str | None] = mapped_column(String(64))
    tx_id: Mapped[str | None] = mapped_column(String(64), index=True)
    anchor_status: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False)
    generated_by: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = _created()


# --------------------------------------------------------------------------- #
# Ledger index and audit
# --------------------------------------------------------------------------- #
class BlockchainTx(Base):
    __tablename__ = "blockchain_txs"
    id: Mapped[str] = _pk()
    tx_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    block_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    contract: Mapped[str] = mapped_column(String(40), nullable=False)
    function: Mapped[str] = mapped_column(String(60), nullable=False)
    submitter_msp: Mapped[str] = mapped_column(String(40), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    created_at: Mapped[datetime] = _created()


class AuditLog(Base):
    """Append-only hash-chained audit trail (ADR-010). Never updated or deleted."""
    __tablename__ = "audit_logs"
    id: Mapped[str] = _pk()
    seq: Mapped[int] = mapped_column(Integer, unique=True, nullable=False, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), index=True)
    actor_role: Mapped[str | None] = mapped_column(String(40))
    org_id: Mapped[str | None] = mapped_column(String(36), index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(40))
    entity_id: Mapped[str | None] = mapped_column(String(36), index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="SUCCESS", nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = _created()


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    version: Mapped[str] = mapped_column(String(20), primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
