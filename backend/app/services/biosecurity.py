"""Sequence screening, CRISPR risk assessment and DURC monitoring (FR-C1..C4)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.errors import Conflict, NotFound, ValidationFailed
from ..core.security import content_hash, decrypt_at_rest, encrypt_at_rest, sha256_hex, utcnow
from ..models import CrisprAssessment, HazardSequence, ScreeningHit, SequenceScreening
from . import audit, notifications

# Screening lifecycle
STATUS_APPROVED_AUTO = "APPROVED_AUTO"
STATUS_PENDING_REVIEW = "PENDING_REVIEW"
STATUS_BLOCKED = "BLOCKED"
STATUS_APPROVED_REVIEW = "APPROVED_BY_REVIEW"
STATUS_REJECTED = "REJECTED"

PASSING_STATUSES = {STATUS_APPROVED_AUTO, STATUS_APPROVED_REVIEW}

DURC_INTENT_MARKERS = ("virulence", "host range", "host-range", "pathogenicity", "toxin",
                       "gene drive", "resistance to control")


def _hazard_records(db: Session) -> list:
    from ai.sequence_screening import HazardRecord

    return [HazardRecord(id=h.id, agent_name=h.agent_name, hazard_class=h.hazard_class,
                         severity=h.severity, sequence=h.sequence)
            for h in db.execute(select(HazardSequence)).scalars()]


def submit_screening(db: Session, org_id: str, actor_id: str, actor_role: str, name: str,
                     sequence: str, intent: str, organism: str | None) -> SequenceScreening:
    from ai.sequence_screening import ENGINE_VERSION, SequenceError, normalize, screen

    settings = get_settings()
    try:
        result = screen(sequence, _hazard_records(db), settings.max_sequence_length)
    except SequenceError as exc:
        raise ValidationFailed(str(exc)) from exc

    cleaned = normalize(sequence)
    durc = _durc_flag(intent, result.hazard_classes)

    if result.verdict == "BLOCK":
        status = STATUS_BLOCKED
    elif result.verdict == "FLAG" or durc:
        status = STATUS_PENDING_REVIEW
    else:
        status = STATUS_APPROVED_AUTO

    record = SequenceScreening(
        org_id=org_id, submitted_by=actor_id, name=name, intent=intent, organism=organism,
        sequence_enc="", sequence_hash=sha256_hex(cleaned), sequence_length=len(cleaned),
        verdict=result.verdict, max_identity=result.max_identity,
        hazard_classes=result.hazard_classes, reasons=result.reasons, status=status,
        durc_flag=durc, engine_version=ENGINE_VERSION)
    db.add(record)
    db.flush()
    record.sequence_enc = encrypt_at_rest(cleaned, record.id)

    for hit in result.hits:
        db.add(ScreeningHit(
            screening_id=record.id, hazard_id=hit.hazard_id, agent_name=hit.agent_name,
            hazard_class=hit.hazard_class, severity=hit.severity, identity=hit.identity,
            align_length=hit.align_length, score=hit.score, query_start=hit.query_start,
            query_end=hit.query_end, subject_start=hit.subject_start,
            subject_end=hit.subject_end))
    db.flush()

    audit.record(db, "biosecurity.screening_submit", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="SequenceScreening", entity_id=record.id,
                 detail={"verdict": result.verdict, "status": status, "durc": durc,
                         "sequence_hash": record.sequence_hash, "hits": len(result.hits)})

    if status in (STATUS_BLOCKED, STATUS_PENDING_REVIEW):
        severity = "CRITICAL" if status == STATUS_BLOCKED else "HIGH"
        notifications.raise_alert(
            db, "DURC" if durc else "BIOSECURITY", severity,
            f"Sequence screening {result.verdict}: {name}",
            detail="; ".join(result.reasons[:3]), org_id=org_id,
            entity_type="SequenceScreening", entity_id=record.id, reasons=result.reasons)

    return record


def _durc_flag(intent: str, hazard_classes: list[str]) -> bool:
    lowered = intent.lower()
    concerning_intent = any(marker in lowered for marker in DURC_INTENT_MARKERS)
    concerning_class = any(c in {"PLANT_PATHOGEN", "VIRULENCE_FACTOR", "TOXIN", "DUAL_USE_MARKER"}
                           for c in hazard_classes)
    return concerning_intent and concerning_class


def get_hits(db: Session, screening_id: str) -> list[ScreeningHit]:
    return list(db.execute(
        select(ScreeningHit).where(ScreeningHit.screening_id == screening_id)
        .order_by(ScreeningHit.score.desc())).scalars())


def review_screening(db: Session, screening: SequenceScreening, actor_id: str, actor_role: str,
                     decision: str, rationale: str) -> SequenceScreening:
    """Only a biosafety officer can release a BLOCKED record (Security.md §14)."""
    if screening.status in PASSING_STATUSES or screening.status == STATUS_REJECTED:
        raise Conflict(f"Screening has already been resolved as {screening.status}")
    screening.status = STATUS_APPROVED_REVIEW if decision == "APPROVE" else STATUS_REJECTED
    screening.reviewed_by = actor_id
    screening.reviewed_at = utcnow()
    screening.review_rationale = rationale
    db.flush()
    audit.record(db, "biosecurity.screening_review", actor_id=actor_id, actor_role=actor_role,
                 org_id=screening.org_id, entity_type="SequenceScreening",
                 entity_id=screening.id,
                 detail={"decision": decision, "previous_verdict": screening.verdict,
                         "rationale": rationale[:500]})
    return screening


def decrypt_sequence(screening: SequenceScreening) -> str:
    return decrypt_at_rest(screening.sequence_enc, screening.id)


def review_queue(db: Session) -> list[SequenceScreening]:
    return list(db.execute(
        select(SequenceScreening)
        .where(SequenceScreening.status.in_([STATUS_PENDING_REVIEW, STATUS_BLOCKED]))
        .order_by(SequenceScreening.created_at.desc())).scalars())


# --------------------------------------------------------------------------- #
# CRISPR
# --------------------------------------------------------------------------- #
def assess_crispr(db: Session, org_id: str, actor_id: str, actor_role: str, target_gene: str,
                  organism: str, organism_class: str, guide_rna: str, pam: str, edit_type: str,
                  intent: str, reference_sequence: str | None) -> CrisprAssessment:
    from ai.crispr_risk import CrisprInputError, assess

    reference = ""
    if reference_sequence:
        from ai.sequence_screening import SequenceError, validate

        try:
            reference = validate(reference_sequence, get_settings().max_sequence_length)
        except SequenceError as exc:
            raise ValidationFailed(f"Reference sequence: {exc}") from exc

    try:
        result = assess(target_gene, organism, organism_class, guide_rna, pam, edit_type,
                        intent, reference)
    except CrisprInputError as exc:
        raise ValidationFailed(str(exc)) from exc

    status = ("PENDING_REVIEW" if result.risk_level in {"HIGH", "PROHIBITED"} or result.durc_flag
              else "APPROVED_AUTO")
    record = CrisprAssessment(
        org_id=org_id, submitted_by=actor_id, target_gene=target_gene, organism=organism,
        guide_rna=guide_rna.upper(), pam=pam.upper(), edit_type=edit_type.upper(), intent=intent,
        off_target_count=result.off_target_count, off_targets=result.off_targets,
        risk_score=result.risk_score, risk_level=result.risk_level, durc_flag=result.durc_flag,
        reasons=result.reasons, status=status)
    db.add(record)
    db.flush()
    audit.record(db, "biosecurity.crispr_assess", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="CrisprAssessment", entity_id=record.id,
                 detail={"risk_level": result.risk_level, "durc": result.durc_flag,
                         "off_targets": result.off_target_count})

    if status == "PENDING_REVIEW":
        notifications.raise_alert(
            db, "DURC" if result.durc_flag else "BIOSECURITY",
            "CRITICAL" if result.risk_level == "PROHIBITED" else "HIGH",
            f"Gene-edit proposal requires review: {target_gene} in {organism}",
            detail="; ".join(result.reasons[:3]), org_id=org_id,
            entity_type="CrisprAssessment", entity_id=record.id, reasons=result.reasons)
    return record


def review_crispr(db: Session, assessment: CrisprAssessment, actor_id: str, actor_role: str,
                  decision: str, rationale: str) -> CrisprAssessment:
    if assessment.status in {"APPROVED_AUTO", "APPROVED_BY_REVIEW", "REJECTED"}:
        raise Conflict(f"Assessment has already been resolved as {assessment.status}")
    assessment.status = "APPROVED_BY_REVIEW" if decision == "APPROVE" else "REJECTED"
    assessment.reviewed_by = actor_id
    assessment.reviewed_at = utcnow()
    assessment.review_rationale = rationale
    db.flush()
    audit.record(db, "biosecurity.crispr_review", actor_id=actor_id, actor_role=actor_role,
                 org_id=assessment.org_id, entity_type="CrisprAssessment",
                 entity_id=assessment.id,
                 detail={"decision": decision, "risk_level": assessment.risk_level,
                         "rationale": rationale[:500]})
    return assessment


# --------------------------------------------------------------------------- #
# Hazard database
# --------------------------------------------------------------------------- #
def add_hazard(db: Session, actor_id: str, actor_role: str, agent_name: str, hazard_class: str,
               severity: int, description: str, sequence: str) -> HazardSequence:
    from ai.sequence_screening import SequenceError, validate

    try:
        cleaned = validate(sequence, get_settings().max_sequence_length)
    except SequenceError as exc:
        raise ValidationFailed(str(exc)) from exc
    allowed = {"PLANT_PATHOGEN", "TOXIN", "ANTIBIOTIC_RESISTANCE", "VIRULENCE_FACTOR",
               "DUAL_USE_MARKER"}
    if hazard_class.upper() not in allowed:
        raise ValidationFailed(f"hazard_class must be one of {sorted(allowed)}")
    hazard = HazardSequence(agent_name=agent_name, hazard_class=hazard_class.upper(),
                            severity=severity, description=description, sequence=cleaned,
                            is_synthetic=True)
    db.add(hazard)
    db.flush()
    audit.record(db, "biosecurity.hazard_add", actor_id=actor_id, actor_role=actor_role,
                 entity_type="HazardSequence", entity_id=hazard.id,
                 detail={"agent_name": agent_name, "hazard_class": hazard_class,
                         "severity": severity})
    return hazard


def statistics(db: Session, org_id: str | None) -> dict[str, Any]:
    query = select(SequenceScreening)
    crispr_query = select(CrisprAssessment)
    if org_id:
        query = query.where(SequenceScreening.org_id == org_id)
        crispr_query = crispr_query.where(CrisprAssessment.org_id == org_id)
    screenings = list(db.execute(query).scalars())
    assessments = list(db.execute(crispr_query).scalars())
    by_verdict: dict[str, int] = {}
    for item in screenings:
        by_verdict[item.verdict] = by_verdict.get(item.verdict, 0) + 1
    by_risk: dict[str, int] = {}
    for item in assessments:
        by_risk[item.risk_level] = by_risk.get(item.risk_level, 0) + 1
    return {
        "screenings_total": len(screenings),
        "screenings_by_verdict": by_verdict,
        "pending_review": sum(1 for s in screenings if s.status == STATUS_PENDING_REVIEW),
        "blocked": sum(1 for s in screenings if s.status == STATUS_BLOCKED),
        "durc_flagged": sum(1 for s in screenings if s.durc_flag)
                        + sum(1 for a in assessments if a.durc_flag),
        "crispr_total": len(assessments),
        "crispr_by_risk": by_risk,
        "hazard_database_size": int(
            db.execute(select(func.count()).select_from(HazardSequence)).scalar_one()),
    }


def content_digest(screening: SequenceScreening) -> str:
    return content_hash({"sequence_hash": screening.sequence_hash, "verdict": screening.verdict,
                         "engine_version": screening.engine_version})
