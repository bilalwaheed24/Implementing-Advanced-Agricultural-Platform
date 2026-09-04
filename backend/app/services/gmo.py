"""GMO registry, jurisdictional approvals, seed lots and labelling validation.

FR-B1 (registration + blockchain tracking), FR-B3 (labelling compliance), FR-B5 (lifecycle).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.errors import Conflict, NotFound, ValidationFailed
from ..core.security import content_hash, utcnow
from ..models import Batch, GMOApproval, GMOEvent, Organization, SeedLot, SequenceScreening
from . import audit, biosecurity, ledger_client, notifications


def _msp_for(db: Session, org_id: str) -> str:
    organization = db.get(Organization, org_id)
    if organization is None:
        raise NotFound("Organisation not found")
    return organization.msp_id


def event_content(event: GMOEvent) -> dict[str, Any]:
    return {"event_code": event.event_code, "crop_type": event.crop_type, "trait": event.trait,
            "donor_organism": event.donor_organism, "developer": event.developer,
            "description": event.description}


def register_event(db: Session, org_id: str, actor_id: str, actor_role: str, event_code: str,
                   crop_type: str, trait: str, donor_organism: str, developer: str,
                   description: str, screening_id: str) -> GMOEvent:
    """A GMO event cannot be registered without a screening in a passing state (FR-C1 gate)."""
    if db.execute(select(GMOEvent).where(GMOEvent.event_code == event_code)).scalar_one_or_none():
        raise Conflict(f"GMO event {event_code} is already registered")

    screening = db.get(SequenceScreening, screening_id)
    if screening is None:
        raise ValidationFailed("A biosecurity screening is required before registration")
    if screening.org_id != org_id:
        raise ValidationFailed("The screening belongs to another organisation")
    if screening.status not in biosecurity.PASSING_STATUSES:
        raise ValidationFailed(
            f"Screening {screening_id} is in state {screening.status}. A GMO event may only be "
            f"registered from a screening that has passed biosecurity review.")

    event = GMOEvent(org_id=org_id, event_code=event_code, crop_type=crop_type, trait=trait,
                     donor_organism=donor_organism, developer=developer, description=description,
                     screening_id=screening_id, created_by=actor_id)
    db.add(event)
    db.flush()

    digest = content_hash(event_content(event))
    event.content_hash = digest
    receipt = ledger_client.submit(
        "gmo_registry", "RegisterEvent",
        {"event_code": event_code, "crop_type": crop_type, "trait": trait,
         "donor_organism": donor_organism, "developer": developer,
         "screening_hash": screening.sequence_hash, "content_hash": digest},
        _msp_for(db, org_id))
    _apply_receipt(db, event, receipt, "GMOEvent")

    audit.record(db, "gmo.register_event", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="GMOEvent", entity_id=event.id,
                 detail={"event_code": event_code, "anchor_status": event.anchor_status,
                         "tx_id": event.tx_id})
    return event


def _apply_receipt(db: Session, entity: Any, receipt: dict[str, Any], entity_type: str) -> None:
    from ..models import BlockchainTx

    entity.anchor_status = receipt.get("status", "FAILED")
    if receipt.get("ok"):
        entity.tx_id = receipt["tx_id"]
        if hasattr(entity, "block_number"):
            entity.block_number = receipt["block_number"]
        db.add(BlockchainTx(
            tx_id=receipt["tx_id"], block_number=receipt["block_number"],
            contract=receipt.get("contract", ""), function=receipt.get("function", ""),
            submitter_msp=(receipt.get("endorsers") or [""])[0],
            content_hash=getattr(entity, "content_hash", "") or "",
            entity_type=entity_type, entity_id=entity.id))
    db.flush()


def record_approval(db: Session, event: GMOEvent, actor_id: str, actor_role: str,
                    jurisdiction: str, status: str, reference: str | None,
                    approved_at: datetime | None, expires_at: datetime | None,
                    submitter_org_id: str) -> GMOApproval:
    """Record a jurisdictional approval and anchor it.

    Only a regulator organisation may submit `gmo_registry.RecordApproval`. Checking that
    here turns what was a silent non-anchoring (the record saved with tx_id NULL) into an
    explicit error the caller can act on.
    """
    submitter = db.get(Organization, submitter_org_id)
    if submitter is None or submitter.org_type != "REGULATOR":
        raise ValidationFailed(
            "A jurisdictional approval must be recorded by a regulator organisation; "
            f"{submitter.name if submitter else 'the caller'} is not one")
    existing = db.execute(select(GMOApproval).where(
        GMOApproval.gmo_event_id == event.id,
        GMOApproval.jurisdiction == jurisdiction)).scalar_one_or_none()
    if existing:
        existing.status = status
        existing.reference = reference
        existing.approved_at = approved_at
        existing.expires_at = expires_at
        approval = existing
    else:
        approval = GMOApproval(gmo_event_id=event.id, jurisdiction=jurisdiction, status=status,
                               reference=reference, approved_at=approved_at, expires_at=expires_at)
        db.add(approval)
    db.flush()

    receipt = ledger_client.submit(
        "gmo_registry", "RecordApproval",
        {"event_code": event.event_code, "jurisdiction": jurisdiction, "status": status,
         "reference": reference or ""}, _msp_for(db, submitter_org_id))
    if receipt.get("ok"):
        approval.tx_id = receipt["tx_id"]
    elif receipt.get("status") == "REJECTED":
        raise ValidationFailed(f"The ledger rejected the approval: {receipt.get('detail', '')}")
    db.flush()

    audit.record(db, "gmo.record_approval", actor_id=actor_id, actor_role=actor_role,
                 org_id=event.org_id, entity_type="GMOEvent", entity_id=event.id,
                 detail={"jurisdiction": jurisdiction, "status": status,
                         "anchored": bool(receipt.get("ok"))})
    return approval


def create_seed_lot(db: Session, org_id: str, actor_id: str, actor_role: str, lot_code: str,
                    gmo_event_id: str | None, crop_type: str, variety: str, quantity_kg: float,
                    produced_at: datetime, germination_pct: float | None) -> SeedLot:
    if db.execute(select(SeedLot).where(SeedLot.lot_code == lot_code)).scalar_one_or_none():
        raise Conflict(f"Seed lot {lot_code} already exists")
    event = None
    if gmo_event_id:
        event = db.get(GMOEvent, gmo_event_id)
        if event is None:
            raise NotFound("GMO event not found")

    lot = SeedLot(org_id=org_id, lot_code=lot_code, gmo_event_id=gmo_event_id,
                  crop_type=crop_type, variety=variety, quantity_kg=quantity_kg,
                  produced_at=produced_at, germination_pct=germination_pct)
    db.add(lot)
    db.flush()
    digest = content_hash({"lot_code": lot_code, "crop_type": crop_type, "variety": variety,
                           "quantity_kg": quantity_kg,
                           "gmo_event": event.event_code if event else None})
    lot.content_hash = digest
    receipt = ledger_client.submit(
        "gmo_registry", "RegisterSeedLot",
        {"lot_code": lot_code, "event_code": event.event_code if event else None,
         "quantity_kg": quantity_kg, "content_hash": digest}, _msp_for(db, org_id))
    _apply_receipt(db, lot, receipt, "SeedLot")

    audit.record(db, "gmo.create_seed_lot", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="SeedLot", entity_id=lot.id,
                 detail={"lot_code": lot_code, "quantity_kg": quantity_kg})
    return lot


# --------------------------------------------------------------------------- #
# Labelling validation (FR-B3)
# --------------------------------------------------------------------------- #
LABELLING_RULES = {
    "EU": {"threshold_pct": 0.9, "citation": "Regulation (EC) 1829/2003 Art. 12-13",
           "label_text": "This product contains genetically modified organisms"},
    "US-USDA": {"threshold_pct": 5.0, "citation": "USDA National Bioengineered Food Disclosure Standard",
                "label_text": "Bioengineered food"},
    "US-FDA": {"threshold_pct": 5.0, "citation": "FDA Guidance on Foods Derived from New Plant Varieties",
               "label_text": "Bioengineered food ingredient"},
    "CODEX": {"threshold_pct": 1.0, "citation": "Codex Alimentarius CAC/GL 1-1979 (labelling)",
              "label_text": "Produced using modern biotechnology"},
}


def validate_labelling(db: Session, batch: Batch, jurisdiction: str,
                       declared_gmo_pct: float | None = None) -> dict[str, Any]:
    """Decide whether a batch requires a GMO label, and whether its claims are legal."""
    rule = LABELLING_RULES.get(jurisdiction.upper())
    if rule is None:
        raise ValidationFailed(f"No labelling rule set for jurisdiction {jurisdiction}; "
                               f"known: {sorted(LABELLING_RULES)}")

    lineage_event = _lineage_gmo_event(db, batch)
    gmo_pct = declared_gmo_pct if declared_gmo_pct is not None else (100.0 if lineage_event else 0.0)
    requires_label = bool(lineage_event) and gmo_pct > rule["threshold_pct"]

    findings: list[dict[str, Any]] = []
    approved = None
    if lineage_event:
        approval = db.execute(select(GMOApproval).where(
            GMOApproval.gmo_event_id == lineage_event.id,
            GMOApproval.jurisdiction == jurisdiction.upper())).scalar_one_or_none()
        approved = approval.status == "APPROVED" if approval else False
        if not approved:
            findings.append({
                "rule": "approval_required", "passed": False, "citation": rule["citation"],
                "detail": f"GMO event {lineage_event.event_code} is not approved in "
                          f"{jurisdiction} (status: {approval.status if approval else 'NOT_SUBMITTED'})"})
        else:
            findings.append({"rule": "approval_required", "passed": True,
                             "citation": rule["citation"],
                             "detail": f"GMO event {lineage_event.event_code} is approved in {jurisdiction}"})

    findings.append({
        "rule": "disclosure_threshold", "passed": True, "citation": rule["citation"],
        "detail": (f"GMO content {gmo_pct:.1f}% against a {rule['threshold_pct']}% threshold: "
                   f"{'label required' if requires_label else 'no label required'}")})

    return {
        "jurisdiction": jurisdiction.upper(),
        "gmo_event_code": lineage_event.event_code if lineage_event else None,
        "gmo_content_pct": gmo_pct,
        "threshold_pct": rule["threshold_pct"],
        "requires_label": requires_label,
        "required_label_text": rule["label_text"] if requires_label else None,
        "approved_in_jurisdiction": approved,
        "citation": rule["citation"],
        "findings": findings,
        "compliant": (not lineage_event) or bool(approved),
    }


def _lineage_gmo_event(db: Session, batch: Batch) -> GMOEvent | None:
    """Walk the batch lineage (parents, seed lot) to find a GMO event."""
    seen: set[str] = set()
    current: Batch | None = batch
    while current is not None and current.id not in seen:
        seen.add(current.id)
        if current.gmo_event_id:
            return db.get(GMOEvent, current.gmo_event_id)
        if current.seed_lot_id:
            lot = db.get(SeedLot, current.seed_lot_id)
            if lot and lot.gmo_event_id:
                return db.get(GMOEvent, lot.gmo_event_id)
        current = db.get(Batch, current.parent_batch_id) if current.parent_batch_id else None
    return None


def lineage_gmo_event(db: Session, batch: Batch) -> GMOEvent | None:
    return _lineage_gmo_event(db, batch)


def check_release(db: Session, batch: Batch, jurisdiction: str, actor_id: str,
                  actor_role: str) -> dict[str, Any]:
    """Block a non-compliant release and record why."""
    result = validate_labelling(db, batch, jurisdiction)
    audit.record(db, "gmo.labelling_check", actor_id=actor_id, actor_role=actor_role,
                 org_id=batch.org_id, entity_type="Batch", entity_id=batch.id,
                 outcome="SUCCESS" if result["compliant"] else "FAILURE",
                 detail={"jurisdiction": jurisdiction, "compliant": result["compliant"],
                         "requires_label": result["requires_label"]})
    if not result["compliant"]:
        notifications.raise_alert(
            db, "COMPLIANCE", "HIGH",
            f"Labelling non-compliance on batch {batch.batch_code}",
            detail=f"Release into {jurisdiction} blocked: "
                   + "; ".join(f["detail"] for f in result["findings"] if not f["passed"]),
            org_id=batch.org_id, entity_type="Batch", entity_id=batch.id)
    return result


def verify_anchor(db: Session, event: GMOEvent) -> dict[str, Any]:
    digest = content_hash(event_content(event))
    result = ledger_client.verify_content(digest, event.tx_id)
    return {**result, "computed_hash": digest, "stored_hash": event.content_hash,
            "verified_at": utcnow()}
