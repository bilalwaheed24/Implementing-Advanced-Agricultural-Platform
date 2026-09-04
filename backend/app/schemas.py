"""Pydantic request/response models — validation at every trust boundary.

No `email-validator` package is available (constraint C-3), so email validation is
an explicit pattern rather than `EmailStr`.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
GTIN_PATTERN = re.compile(r"^\d{8,14}$")
EVENT_CODE_PATTERN = re.compile(r"^[A-Z]{2,4}-[0-9A-ZØ]{3,7}-[0-9]$")   # OECD-style unique identifier

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


# --------------------------------------------------------------------------- #
# Auth and identity
# --------------------------------------------------------------------------- #
class RegisterRequest(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    full_name: str = Field(min_length=2, max_length=200)
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(default="FARM_OPERATOR")
    org_id: str = Field(min_length=1, max_length=36)

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_PATTERN.match(value):
            raise ValueError("Invalid email address")
        return value


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _lower(cls, value: str) -> str:
        return value.strip().lower()


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=4096)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(ORMModel):
    id: str
    email: str
    full_name: str
    role: str
    status: str
    org_id: str
    last_login_at: datetime | None = None
    created_at: datetime


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=200)
    role: str | None = None
    status: str | None = None


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    org_type: str
    msp_id: str = Field(min_length=3, max_length=40)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    gln: str | None = Field(default=None, max_length=13)
    trusted_issuer_types: list[str] = Field(default_factory=list)

    @field_validator("org_type")
    @classmethod
    def _type(cls, value: str) -> str:
        allowed = {"BIOTECH", "FARM", "SUPPLY", "REGULATOR"}
        if value.upper() not in allowed:
            raise ValueError(f"org_type must be one of {sorted(allowed)}")
        return value.upper()


class OrganizationOut(ORMModel):
    id: str
    name: str
    org_type: str
    msp_id: str
    country: str | None = None
    gln: str | None = None
    trusted_issuer_types: list[Any] = Field(default_factory=list)
    is_active: bool
    created_at: datetime


# --------------------------------------------------------------------------- #
# Farm domain
# --------------------------------------------------------------------------- #
class FarmCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    region: str = Field(min_length=2, max_length=120)
    country: str = Field(min_length=2, max_length=2)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    area_ha: float = Field(gt=0, le=1_000_000)
    gln: str | None = Field(default=None, max_length=13)


class FarmOut(ORMModel):
    id: str
    org_id: str
    name: str
    region: str
    country: str
    latitude: float
    longitude: float
    area_ha: float
    gln: str | None = None
    created_at: datetime


class FieldCreate(BaseModel):
    farm_id: str
    name: str = Field(min_length=1, max_length=120)
    area_ha: float = Field(gt=0, le=100_000)
    soil_type: str | None = Field(default=None, max_length=60)
    boundary_geojson: dict[str, Any] | None = None


class FieldOut(ORMModel):
    id: str
    farm_id: str
    org_id: str
    name: str
    area_ha: float
    soil_type: str | None = None
    created_at: datetime


class CropCreate(BaseModel):
    field_id: str
    crop_type: str = Field(min_length=2, max_length=80)
    variety: str | None = Field(default=None, max_length=120)
    gmo_event_id: str | None = None
    seed_lot_id: str | None = None
    planted_at: datetime | None = None
    expected_harvest: datetime | None = None


class CropOut(ORMModel):
    id: str
    field_id: str
    crop_type: str
    variety: str | None = None
    gmo_event_id: str | None = None
    seed_lot_id: str | None = None
    planted_at: datetime | None = None
    expected_harvest: datetime | None = None
    status: str
    created_at: datetime


# --------------------------------------------------------------------------- #
# Devices and telemetry
# --------------------------------------------------------------------------- #
DEVICE_TYPES = {"DRONE", "SOIL_SENSOR", "WEATHER_STATION", "YIELD_MONITOR",
                "IRRIGATION_CONTROLLER", "COLD_CHAIN_SENSOR"}


class DeviceCreate(BaseModel):
    device_type: str
    model: str = Field(min_length=1, max_length=120)
    firmware_version: str = Field(min_length=1, max_length=40)
    farm_id: str
    field_id: str | None = None
    serial_number: str | None = Field(default=None, max_length=120)
    interval_seconds: int = Field(default=900, ge=5, le=86400)

    @field_validator("device_type")
    @classmethod
    def _type(cls, value: str) -> str:
        if value.upper() not in DEVICE_TYPES:
            raise ValueError(f"device_type must be one of {sorted(DEVICE_TYPES)}")
        return value.upper()


class DeviceOut(ORMModel):
    id: str
    org_id: str
    farm_id: str
    field_id: str | None = None
    device_type: str
    model: str
    firmware_version: str
    status: str
    interval_seconds: int
    last_seen_at: datetime | None = None
    battery_pct: float | None = None
    signal_dbm: float | None = None
    auth_failures: int
    quarantine_reason: str | None = None
    created_at: datetime


class DeviceProvisionOut(BaseModel):
    device: DeviceOut
    device_secret: str
    warning: str = ("Store this secret now. It is shown once and cannot be retrieved. "
                    "Rotating the secret invalidates the previous one immediately.")


class DeviceAction(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class VulnerabilityCreate(BaseModel):
    device_id: str
    cve_id: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=255)
    severity: str
    cvss: float | None = Field(default=None, ge=0, le=10)
    affected_versions: str | None = Field(default=None, max_length=120)
    fixed_in: str | None = Field(default=None, max_length=40)

    @field_validator("severity")
    @classmethod
    def _severity(cls, value: str) -> str:
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if value.upper() not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return value.upper()


class VulnerabilityOut(ORMModel):
    id: str
    device_id: str
    cve_id: str
    title: str
    severity: str
    cvss: float | None = None
    affected_versions: str | None = None
    fixed_in: str | None = None
    status: str
    discovered_at: datetime
    remediated_at: datetime | None = None


class TelemetryIngest(BaseModel):
    """Device-authenticated payload. Headers carry the identity and signature."""
    recorded_at: datetime
    nonce: str = Field(min_length=8, max_length=64)
    readings: dict[str, Any]
    sequence: int | None = Field(default=None, ge=0)
    shipment_id: str | None = None

    @field_validator("readings")
    @classmethod
    def _readings(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not value:
            raise ValueError("readings must not be empty")
        if len(value) > 40:
            raise ValueError("readings may contain at most 40 channels")
        return value


class TelemetryBatch(BaseModel):
    messages: list[dict[str, Any]] = Field(min_length=1, max_length=500)


class TelemetryOut(ORMModel):
    id: str
    device_id: str
    recorded_at: datetime
    received_at: datetime
    summary: dict[str, Any]
    anomaly_score: float | None = None
    quality: str
    backfilled: bool


class SatelliteSceneCreate(BaseModel):
    scene_id: str = Field(min_length=3, max_length=80)
    field_id: str
    provider: str = Field(min_length=2, max_length=60)
    captured_at: datetime
    ndvi_mean: float = Field(ge=-1, le=1)
    ndvi_min: float = Field(ge=-1, le=1)
    ndvi_max: float = Field(ge=-1, le=1)
    cloud_cover_pct: float = Field(ge=0, le=100)
    checksum: str = Field(min_length=64, max_length=64)


class SatelliteSceneOut(ORMModel):
    id: str
    scene_id: str
    field_id: str
    provider: str
    captured_at: datetime
    ndvi_mean: float
    ndvi_min: float
    ndvi_max: float
    cloud_cover_pct: float
    is_simulated: bool


# --------------------------------------------------------------------------- #
# AI
# --------------------------------------------------------------------------- #
class AIAnalysisOut(ORMModel):
    id: str
    analysis_type: str
    subject_type: str
    subject_id: str
    score: float
    level: str
    reasons: list[Any]
    evidence: dict[str, Any]
    model_version: str
    degraded: bool
    created_at: datetime


class CropImageRequest(BaseModel):
    """Demo input: a synthetic class label, or a flat pixel array."""
    field_id: str | None = None
    simulate_label: str | None = None
    pixels: list[float] | None = Field(default=None, max_length=48 * 48 * 3)
    size: int = Field(default=48, ge=8, le=256)


class AlertOut(ORMModel):
    id: str
    category: str
    severity: str
    title: str
    detail: str
    entity_type: str | None = None
    entity_id: str | None = None
    reasons: list[Any]
    status: str
    incident_id: str | None = None
    created_at: datetime


class IncidentOut(ORMModel):
    id: str
    title: str
    severity: str
    status: str
    summary: str
    root_cause: str | None = None
    created_at: datetime


class IncidentUpdate(BaseModel):
    status: str | None = None
    root_cause: str | None = Field(default=None, max_length=2000)
    note: str | None = Field(default=None, max_length=2000)


class NotificationOut(ORMModel):
    id: str
    severity: str
    category: str
    title: str
    body: str
    entity_type: str | None = None
    entity_id: str | None = None
    read_at: datetime | None = None
    created_at: datetime


# --------------------------------------------------------------------------- #
# Biosecurity
# --------------------------------------------------------------------------- #
class ScreeningCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    sequence: str = Field(min_length=11, max_length=200_000)
    intent: str = Field(min_length=3, max_length=80)
    organism: str | None = Field(default=None, max_length=160)


class ScreeningHitOut(ORMModel):
    agent_name: str
    hazard_class: str
    severity: int
    identity: float
    align_length: int
    score: float
    query_start: int
    query_end: int
    subject_start: int
    subject_end: int


class ScreeningOut(ORMModel):
    id: str
    name: str
    intent: str
    organism: str | None = None
    sequence_hash: str
    sequence_length: int
    verdict: str
    max_identity: float
    hazard_classes: list[Any]
    status: str
    durc_flag: bool
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_rationale: str | None = None
    engine_version: str
    created_at: datetime


class ScreeningDetail(ScreeningOut):
    hits: list[ScreeningHitOut] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)

    @field_validator("reasons", mode="before")
    @classmethod
    def _tolerate_missing_reasons(cls, value: Any) -> Any:
        """Screenings recorded before migration 0001 have no stored reasons."""
        return [] if value is None else value


class ReviewDecision(BaseModel):
    decision: str
    rationale: str = Field(min_length=10, max_length=2000)

    @field_validator("decision")
    @classmethod
    def _decision(cls, value: str) -> str:
        allowed = {"APPROVE", "REJECT"}
        if value.upper() not in allowed:
            raise ValueError(f"decision must be one of {sorted(allowed)}")
        return value.upper()


class CrisprCreate(BaseModel):
    target_gene: str = Field(min_length=1, max_length=120)
    organism: str = Field(min_length=2, max_length=160)
    organism_class: str
    guide_rna: str = Field(min_length=17, max_length=25)
    pam: str = Field(min_length=2, max_length=8)
    edit_type: str
    intent: str = Field(min_length=3, max_length=200)
    reference_sequence: str | None = Field(default=None, max_length=200_000)


class CrisprOut(ORMModel):
    id: str
    target_gene: str
    organism: str
    guide_rna: str
    pam: str
    edit_type: str
    intent: str
    off_target_count: int
    off_targets: list[Any]
    risk_score: float
    risk_level: str
    durc_flag: bool
    reasons: list[Any]
    status: str
    reviewed_by: str | None = None
    review_rationale: str | None = None
    created_at: datetime


class HazardCreate(BaseModel):
    agent_name: str = Field(min_length=3, max_length=160)
    hazard_class: str
    severity: int = Field(ge=1, le=5)
    description: str = Field(default="", max_length=2000)
    sequence: str = Field(min_length=20, max_length=100_000)


class HazardOut(ORMModel):
    id: str
    agent_name: str
    hazard_class: str
    severity: int
    description: str
    is_synthetic: bool
    created_at: datetime


# --------------------------------------------------------------------------- #
# GMO
# --------------------------------------------------------------------------- #
class GMOEventCreate(BaseModel):
    event_code: str = Field(min_length=5, max_length=40)
    crop_type: str = Field(min_length=2, max_length=80)
    trait: str = Field(min_length=2, max_length=200)
    donor_organism: str = Field(min_length=2, max_length=200)
    developer: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=4000)
    screening_id: str

    @field_validator("event_code")
    @classmethod
    def _code(cls, value: str) -> str:
        value = value.strip().upper()
        if not EVENT_CODE_PATTERN.match(value):
            raise ValueError("event_code must follow the OECD unique identifier format, "
                             "for example ABS-01234-5")
        return value


class GMOEventOut(ORMModel):
    id: str
    event_code: str
    crop_type: str
    trait: str
    donor_organism: str
    developer: str
    description: str
    screening_id: str | None = None
    content_hash: str | None = None
    tx_id: str | None = None
    block_number: int | None = None
    anchor_status: str
    created_at: datetime


class GMOApprovalCreate(BaseModel):
    jurisdiction: str = Field(min_length=2, max_length=40)
    status: str
    reference: str | None = Field(default=None, max_length=120)
    approved_at: datetime | None = None
    expires_at: datetime | None = None

    @field_validator("status")
    @classmethod
    def _status(cls, value: str) -> str:
        allowed = {"APPROVED", "PENDING", "REJECTED", "NOT_SUBMITTED"}
        if value.upper() not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return value.upper()


class GMOApprovalOut(ORMModel):
    id: str
    gmo_event_id: str
    jurisdiction: str
    status: str
    reference: str | None = None
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    tx_id: str | None = None


class SeedLotCreate(BaseModel):
    lot_code: str = Field(min_length=3, max_length=60)
    gmo_event_id: str | None = None
    crop_type: str = Field(min_length=2, max_length=80)
    variety: str = Field(min_length=1, max_length=120)
    quantity_kg: float = Field(gt=0, le=10_000_000)
    produced_at: datetime
    germination_pct: float | None = Field(default=None, ge=0, le=100)


class SeedLotOut(ORMModel):
    id: str
    lot_code: str
    gmo_event_id: str | None = None
    crop_type: str
    variety: str
    quantity_kg: float
    produced_at: datetime
    germination_pct: float | None = None
    tx_id: str | None = None
    anchor_status: str
    created_at: datetime


# --------------------------------------------------------------------------- #
# Supply chain
# --------------------------------------------------------------------------- #
class ProductCreate(BaseModel):
    gtin: str
    name: str = Field(min_length=2, max_length=200)
    category: str = Field(min_length=2, max_length=80)
    organic_claim: bool = False
    non_gmo_claim: bool = False
    storage_temp_min_c: float | None = Field(default=None, ge=-60, le=60)
    storage_temp_max_c: float | None = Field(default=None, ge=-60, le=60)

    @field_validator("gtin")
    @classmethod
    def _gtin(cls, value: str) -> str:
        value = value.strip()
        if not GTIN_PATTERN.match(value):
            raise ValueError("gtin must be 8 to 14 digits")
        return value


class ProductOut(ORMModel):
    id: str
    gtin: str
    name: str
    category: str
    organic_claim: bool
    non_gmo_claim: bool
    storage_temp_min_c: float | None = None
    storage_temp_max_c: float | None = None
    created_at: datetime


class BatchCreate(BaseModel):
    batch_code: str = Field(min_length=3, max_length=60)
    product_id: str
    quantity: float = Field(gt=0, le=100_000_000)
    unit: str = Field(default="kg", max_length=12)
    parent_batch_id: str | None = None
    seed_lot_id: str | None = None
    crop_id: str | None = None
    farm_id: str | None = None
    gmo_event_id: str | None = None
    origin_region: str | None = Field(default=None, max_length=120)
    origin_country: str | None = Field(default=None, min_length=2, max_length=2)
    harvested_at: datetime | None = None


class BatchOut(ORMModel):
    id: str
    batch_code: str
    verification_code: str
    product_id: str
    parent_batch_id: str | None = None
    seed_lot_id: str | None = None
    farm_id: str | None = None
    gmo_event_id: str | None = None
    state: str
    quantity: float
    unit: str
    custodian_org_id: str
    origin_region: str | None = None
    origin_country: str | None = None
    harvested_at: datetime | None = None
    tx_id: str | None = None
    anchor_status: str
    integrity_status: str
    created_at: datetime


BIZ_STEPS = {"commissioning", "harvesting", "transforming", "packing", "shipping",
             "receiving", "storing", "retail_selling", "recalling"}


class SupplyChainEventCreate(BaseModel):
    batch_id: str
    biz_step: str
    disposition: str = Field(min_length=2, max_length=40)
    event_type: str = Field(default="OBJECT", max_length=24)
    location_gln: str | None = Field(default=None, max_length=13)
    location_name: str | None = Field(default=None, max_length=200)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    quantity: float | None = Field(default=None, ge=0)
    unit: str | None = Field(default=None, max_length=12)
    to_org_id: str | None = None
    occurred_at: datetime
    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("biz_step")
    @classmethod
    def _step(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in BIZ_STEPS:
            raise ValueError(f"biz_step must be one of {sorted(BIZ_STEPS)}")
        return value


class SupplyChainEventOut(ORMModel):
    id: str
    batch_id: str
    org_id: str
    event_type: str
    biz_step: str
    disposition: str
    location_gln: str | None = None
    location_name: str | None = None
    quantity: float | None = None
    unit: str | None = None
    from_org_id: str | None = None
    to_org_id: str | None = None
    occurred_at: datetime
    content_hash: str
    tx_id: str | None = None
    anchor_status: str
    created_at: datetime


class ShipmentCreate(BaseModel):
    sscc: str = Field(min_length=8, max_length=18)
    batch_id: str
    carrier: str = Field(min_length=2, max_length=160)
    origin_name: str = Field(min_length=2, max_length=200)
    origin_lat: float = Field(ge=-90, le=90)
    origin_lon: float = Field(ge=-180, le=180)
    destination_name: str = Field(min_length=2, max_length=200)
    destination_lat: float = Field(ge=-90, le=90)
    destination_lon: float = Field(ge=-180, le=180)
    departed_at: datetime
    arrived_at: datetime | None = None
    cold_chain_device_id: str | None = None


class ShipmentOut(ORMModel):
    id: str
    sscc: str
    batch_id: str
    carrier: str
    origin_name: str
    destination_name: str
    departed_at: datetime
    arrived_at: datetime | None = None
    status: str
    temp_min_c: float | None = None
    temp_max_c: float | None = None
    cold_chain_device_id: str | None = None


class CertificationCreate(BaseModel):
    cert_code: str = Field(min_length=3, max_length=60)
    cert_type: str
    standard: str = Field(min_length=2, max_length=80)
    subject_org_id: str
    scope: str = Field(min_length=3, max_length=255)
    valid_from: datetime
    valid_to: datetime

    @field_validator("cert_type")
    @classmethod
    def _type(cls, value: str) -> str:
        allowed = {"ORGANIC", "NON_GMO", "SPECIALTY"}
        if value.upper() not in allowed:
            raise ValueError(f"cert_type must be one of {sorted(allowed)}")
        return value.upper()


class CertificationOut(ORMModel):
    id: str
    cert_code: str
    cert_type: str
    standard: str
    issuer_org_id: str
    subject_org_id: str
    scope: str
    valid_from: datetime
    valid_to: datetime
    status: str
    revoked_at: datetime | None = None
    revoke_reason: str | None = None
    tx_id: str | None = None
    anchor_status: str


class CertificationLinkCreate(BaseModel):
    batch_id: str


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class VerificationResult(BaseModel):
    integrity_status: str
    fraud_score: float
    fraud_level: str
    ledger_status: str
    reasons: list[dict[str, Any]]
    events_checked: int
    certifications_checked: int
    verified_at: datetime


# --------------------------------------------------------------------------- #
# Compliance
# --------------------------------------------------------------------------- #
class ComplianceRequest(BaseModel):
    subject_type: str = Field(default="BATCH")
    subject_id: str
    jurisdiction: str = Field(default="US-USDA", max_length=40)


class ComplianceRuleResult(BaseModel):
    rule_id: str
    title: str
    citation: str
    passed: bool
    severity: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    detail: str = ""


class ComplianceReportOut(ORMModel):
    id: str
    report_type: str
    subject_type: str
    subject_id: str
    jurisdiction: str
    status: str
    results: list[Any]
    summary: dict[str, Any]
    content_hash: str | None = None
    tx_id: str | None = None
    anchor_status: str
    created_at: datetime


class EIARequest(BaseModel):
    gmo_event_id: str
    cultivation_area_ha: float = Field(gt=0, le=1_000_000)
    adjacent_wild_relatives: bool = False
    pesticide_change_pct: float = Field(default=0.0, ge=-100, le=500)
    notes: str = Field(default="", max_length=2000)


# --------------------------------------------------------------------------- #
# Blockchain and audit
# --------------------------------------------------------------------------- #
class VerifyRecordRequest(BaseModel):
    entity_type: str
    entity_id: str


class AuditLogOut(ORMModel):
    id: str
    seq: int
    prev_hash: str
    entry_hash: str
    actor_id: str | None = None
    actor_role: str | None = None
    org_id: str | None = None
    action: str
    entity_type: str | None = None
    entity_id: str | None = None
    outcome: str
    detail: dict[str, Any]
    ip: str | None = None
    correlation_id: str | None = None
    created_at: datetime


# --------------------------------------------------------------------------- #
# Public verification (consumer)
# --------------------------------------------------------------------------- #
class PublicJourneyStage(BaseModel):
    stage: str
    occurred_at: datetime
    location: str | None = None
    organization_type: str | None = None
    verified: bool


class PublicVerification(BaseModel):
    verification_code: str
    product_name: str
    product_category: str
    batch_state: str
    origin_region: str | None = None
    origin_country: str | None = None
    harvested_at: datetime | None = None
    gmo_status: str
    gmo_event_code: str | None = None
    certifications: list[dict[str, Any]]
    journey: list[PublicJourneyStage]
    ledger_verified: bool
    integrity_status: str
    disclaimer: str
