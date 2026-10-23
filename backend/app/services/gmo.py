"""GMO registry, jurisdictional approvals, seed lots and labelling validation.

FR-B1 (registration + blockchain tracking), FR-B3 (labelling compliance), FR-B5 (lifecycle).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.errors import Conflict, NotFound, PermissionDenied, ValidationFailed
from ..core.permissions import Role
from ..core.security import content_hash, ensure_aware as _aware, utcnow
from ..models import (Batch, Crop, Farm, Field, GMOApproval, GMOEvent, Organization, SeedLot,
                      SequenceScreening)
from ..repositories import get_or_404
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


# Legal transitions for a jurisdictional approval. A withdrawn or rejected decision must be
# re-submitted through the regulator's own process rather than flipped back to APPROVED.
APPROVAL_TRANSITIONS: dict[str, frozenset[str]] = {
    "NOT_SUBMITTED": frozenset({"PENDING", "APPROVED", "REJECTED"}),
    "PENDING": frozenset({"APPROVED", "REJECTED"}),
    "APPROVED": frozenset({"REJECTED"}),        # withdrawal of a granted approval
    "REJECTED": frozenset({"PENDING"}),         # resubmission, not a direct flip to APPROVED
}

# Approval states that permit a GMO event to be taken forward into seed lots and batches.
APPROVED_STATUSES = frozenset({"APPROVED"})


def is_live(approval: GMOApproval | None, now: datetime | None = None) -> bool:
    """True when an approval currently permits the event: APPROVED, already in force (no
    future decision date) and not yet expired. The single definition every check uses —
    seed lots, plantings, batches, labelling and the selectors that offer events."""
    if approval is None or approval.status not in APPROVED_STATUSES:
        return False
    now = now or utcnow()
    return ((approval.approved_at is None or _aware(approval.approved_at) <= now)
            and (approval.expires_at is None or _aware(approval.expires_at) > now))


def live_event_ids(db: Session, now: datetime | None = None) -> set[str]:
    """Ids of the GMO events holding at least one live approval."""
    now = now or utcnow()
    return {a.gmo_event_id for a in db.execute(select(GMOApproval).where(
        GMOApproval.status.in_(APPROVED_STATUSES))).scalars() if is_live(a, now)}


def require_registerable_event(db: Session, gmo_event_id: str, actor_role: str,
                               org_id: str | None) -> GMOEvent:
    """Resolve a client-supplied GMO event id within the caller's visibility.

    `db.get()` here would let a caller attach another tenant's GMO event — and therefore its
    trait, donor organism and developer — to their own seed lot or batch (audit P1).
    """
    return get_or_404(db, GMOEvent, gmo_event_id, actor_role, org_id, name="GMO event")


def require_approved_event(db: Session, gmo_event_id: str, actor_role: str,
                           org_id: str | None) -> GMOEvent:
    """As above, and additionally require a live jurisdictional approval.

    Registering an event only proves it passed biosecurity screening. Propagating it into
    planting material is a separate regulated step, so a seed lot must descend from an event a
    regulator has actually approved somewhere (audit P1, §15).
    """
    event = require_registerable_event(db, gmo_event_id, actor_role, org_id)
    require_live_approval(db, event, "A seed lot")
    return event


def require_live_approval(db: Session, event: GMOEvent, use: str) -> None:
    """Require an APPROVED, unexpired jurisdictional approval before `use` may carry the event.

    Applies to every downstream use — seed lots, plantings and batches — so a farm or a
    processor cannot propagate an event the regulator has not approved, or whose approval
    has lapsed.
    """
    approvals = list(db.execute(
        select(GMOApproval).where(GMOApproval.gmo_event_id == event.id)).scalars())
    if not approvals:
        raise ValidationFailed(
            f"GMO event {event.event_code} has no jurisdictional approval on record. {use} "
            f"may only carry an approved event.")
    now = utcnow()
    live = [a for a in approvals if is_live(a, now)]
    if not live:
        states = sorted({a.status for a in approvals})
        raise ValidationFailed(
            f"GMO event {event.event_code} is not approved in any jurisdiction "
            f"(recorded states: {', '.join(states)}; expired approvals do not count).")


def register_event(db: Session, org_id: str, actor_id: str, actor_role: str, event_code: str,
                   crop_type: str, trait: str, donor_organism: str, developer: str,
                   description: str, screening_id: str) -> GMOEvent:
    """A GMO event cannot be registered without a screening in a passing state (FR-C1 gate)."""
    if db.execute(select(GMOEvent).where(GMOEvent.event_code == event_code)).scalar_one_or_none():
        raise Conflict(f"GMO event {event_code} is already registered")

    # Scoped so a foreign screening id is a plain 404 rather than a message confirming that
    # it exists and belongs to someone else (audit P2, existence oracle).
    screening = get_or_404(db, SequenceScreening, screening_id, actor_role, org_id,
                           name="Screening")
    if screening.org_id != org_id:
        raise NotFound("Screening not found")
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
        _msp_for(db, org_id), db=db, entity=event)
    _apply_receipt(db, event, receipt, "GMOEvent")

    audit.record(db, "gmo.register_event", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="GMOEvent", entity_id=event.id,
                 detail={"event_code": event_code, "anchor_status": event.anchor_status,
                         "tx_id": event.tx_id})
    # Registration does not make an event usable: a regulator must take a jurisdictional
    # decision first, so the regulators are told there is one waiting.
    notifications.notify_roles(
        db, [Role.REGULATOR], "GMO",
        f"GMO event {event_code} awaits a jurisdictional decision",
        f"{developer} registered {crop_type} event {event_code} ({trait}). No jurisdiction has "
        f"approved it yet, so it cannot be propagated into seed lots or batches.",
        "GMOEvent", event.id)
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
    previous_status = None
    # Whether the event was usable in this jurisdiction before the decision, so a decision that
    # makes it usable again (re-approval after a withdrawal, renewal after an expiry) is seen.
    was_live = is_live(existing)
    if existing:
        previous_status = existing.status
        # A regulatory decision must not be silently rewritten (audit P2, §24). Only the
        # transitions a regulator can legitimately make are allowed, and the prior value is
        # recorded in the audit trail below.
        allowed = APPROVAL_TRANSITIONS.get(existing.status, frozenset())
        if status != existing.status and status not in allowed:
            raise Conflict(
                f"Approval for {jurisdiction} is {existing.status}; it cannot move to {status}. "
                f"Allowed: {', '.join(sorted(allowed)) or 'no further change'}.")
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
         "reference": reference or ""}, _msp_for(db, submitter_org_id), db=db, entity=approval)
    if receipt.get("ok"):
        approval.tx_id = receipt["tx_id"]
    elif receipt.get("status") == "REJECTED":
        raise ValidationFailed(f"The ledger rejected the approval: {receipt.get('detail', '')}")
    db.flush()

    audit.record(db, "gmo.record_approval", actor_id=actor_id, actor_role=actor_role,
                 org_id=event.org_id, entity_type="GMOEvent", entity_id=event.id,
                 detail={"jurisdiction": jurisdiction, "status": status,
                         "previous_status": previous_status,
                         "anchored": bool(receipt.get("ok"))})

    # The developer is told every decision on its event.
    expiry = f", expires {_aware(expires_at).date().isoformat()}" if expires_at else ""
    notifications.notify_org(
        db, event.org_id, "GMO",
        f"GMO event {event.event_code}: {jurisdiction} decision {status}",
        f"The regulator recorded {status} for {jurisdiction}"
        + (f" (previously {previous_status})" if previous_status else "")
        + f"{expiry}. Reference: {reference or 'none'}.",
        "GMOEvent", event.id, severity="WARNING" if status == "REJECTED" else "INFO")

    if previous_status in APPROVED_STATUSES and status not in APPROVED_STATUSES:
        approval_lost(db, event, approval, "withdrawn", actor_id=actor_id,
                      already_notified={event.org_id})
    elif not was_live and is_live(approval) and _loss_was_announced(db, approval):
        approval_restored(db, event, approval, actor_id=actor_id,
                          already_notified={event.org_id})
    return approval


def affected_holdings(db: Session, event: GMOEvent) -> tuple[list[SeedLot], list[Batch]]:
    """Every seed lot and batch whose lineage carries `event`.

    Seed lots name the event directly. Batches carry it directly, through their seed lot, or
    through a parent batch, so the walk descends from those roots and keeps a descendant only
    while `lineage_gmo_event` still resolves to this event (a child naming another event of its
    own is not affected).
    """
    lots = list(db.execute(select(SeedLot).where(SeedLot.gmo_event_id == event.id)).scalars())
    lot_ids = [lot.id for lot in lots]
    roots = select(Batch).where(Batch.gmo_event_id == event.id)
    if lot_ids:
        roots = select(Batch).where((Batch.gmo_event_id == event.id)
                                    | Batch.seed_lot_id.in_(lot_ids))
    found: dict[str, Batch] = {}
    frontier = [b for b in db.execute(roots).scalars()
                if (_lineage_gmo_event(db, b) or event).id == event.id]
    while frontier:
        for batch in frontier:
            found[batch.id] = batch
        children = db.execute(select(Batch).where(
            Batch.parent_batch_id.in_([b.id for b in frontier]))).scalars()
        frontier = [c for c in children if c.id not in found
                    and (_lineage_gmo_event(db, c) or event).id == event.id]
    return lots, list(found.values())


_LIVE_CROP_STATUSES = ("PLANTED", "GROWING")


def affected_crops(db: Session, event: GMOEvent,
                   lots: list[SeedLot] | None = None) -> list[tuple[Crop, Farm | None]]:
    """Plantings in the ground that carry `event`, with their farm.

    A crop names the event directly (planting from a GMO seed lot copies the lot's event onto
    the crop) or may be planted with an event and no seed lot at all, so it is not reached
    through `affected_holdings`. Harvested and failed crops are left out: what was harvested
    is carried on by its batches.
    """
    lot_ids = [lot.id for lot in (lots if lots is not None else db.execute(
        select(SeedLot).where(SeedLot.gmo_event_id == event.id)).scalars())]
    condition = Crop.gmo_event_id == event.id
    if lot_ids:
        condition = condition | Crop.seed_lot_id.in_(lot_ids)
    crops = list(db.execute(select(Crop).where(
        condition, Crop.status.in_(_LIVE_CROP_STATUSES))).scalars())
    out = []
    for crop in crops:
        field = db.get(Field, crop.field_id)
        out.append((crop, db.get(Farm, field.farm_id) if field else None))
    return out


def _holdings_by_party(db: Session, event: GMOEvent, lots: list[SeedLot],
                       batches: list[Batch], crops: list[tuple[Crop, Farm | None]]
                       ) -> dict[str, list[tuple[str, str, str]]]:
    """org id -> what of theirs carries the event, as (label, entity type, entity id), each
    entity one the organisation can open. The developer is always included."""
    parties: dict[str, list[tuple[str, str, str]]] = {event.org_id: []}
    for batch in batches:
        for org_id in {batch.org_id, batch.custodian_org_id}:
            parties.setdefault(org_id, []).append(
                (f"batch {batch.batch_code}", "Batch", batch.id))
    for lot in lots:
        for org_id in {lot.org_id, lot.custodian_org_id or lot.org_id}:
            parties.setdefault(org_id, []).append(
                (f"seed lot {lot.lot_code}", "SeedLot", lot.id))
    for crop, farm in crops:
        where = f" at {farm.name}" if farm else ""
        parties.setdefault(crop.org_id, []).append(
            (f"{crop.crop_type} crop{where}", "Farm" if farm else "Crop",
             farm.id if farm else crop.id))
    return parties


def _notify_holders(db: Session, event: GMOEvent, parties: dict[str, list[tuple[str, str, str]]],
                    title: str, tail: str, empty: str, severity: str,
                    skip: set[str]) -> None:
    """One notification per organisation, naming what of theirs is affected and linking to it.

    The developer's notification links to its GMO event. Everyone else's links to their own
    affected batch, seed lot or farm: a farm or a processor cannot open the developer's event.
    """
    for org_id, items in parties.items():
        if org_id in skip and not items:
            continue
        labels = sorted({label for label, _, _ in items})
        held = (f"Affected: {', '.join(labels[:20])}"
                + (" and more." if len(labels) > 20 else ".")) if items else empty
        if org_id == event.org_id or not items:
            entity_type, entity_id = "GMOEvent", event.id
        else:
            _, entity_type, entity_id = items[0]
        notifications.notify_org(db, org_id, "COMPLIANCE", title, f"{held} {tail}",
                                 entity_type, entity_id, severity=severity)


def _loss_was_announced(db: Session, approval: GMOApproval) -> bool:
    """True when a withdrawal or expiry of this approval was propagated (approval_lost raises
    a COMPLIANCE alert about the approval), so holders were warned and should hear it is back."""
    from ..models import Alert

    return db.execute(select(Alert.id).where(
        Alert.category == "COMPLIANCE", Alert.entity_type == "GMOApproval",
        Alert.entity_id == approval.id).limit(1)).first() is not None


def approval_restored(db: Session, event: GMOEvent, approval: GMOApproval, *,
                      actor_id: str | None = None,
                      already_notified: set[str] | None = None) -> dict[str, Any]:
    """Tell the holders warned of a withdrawal or expiry that the event is approved again."""
    lots, batches = affected_holdings(db, event)
    crops = affected_crops(db, event, lots)
    parties = _holdings_by_party(db, event, lots, batches, crops)
    expiry = (f" until {_aware(approval.expires_at).date().isoformat()}"
              if approval.expires_at else "")
    _notify_holders(
        db, event, parties,
        f"GMO approval restored: {event.event_code} in {approval.jurisdiction}",
        f"{event.event_code} is approved again in {approval.jurisdiction}{expiry}. Re-run the "
        f"compliance check before releasing affected stock there.",
        "No seed lot, crop or batch carries the event.", "INFO",
        already_notified or set())
    audit.record(db, "gmo.approval_restored", actor_id=actor_id, actor_role=None,
                 org_id=event.org_id, entity_type="GMOEvent", entity_id=event.id,
                 detail={"jurisdiction": approval.jurisdiction, "organisations": len(parties)})
    return {"event_code": event.event_code, "jurisdiction": approval.jurisdiction,
            "organisations": sorted(parties)}


def approval_lost(db: Session, event: GMOEvent, approval: GMOApproval, how: str, *,
                  actor_id: str | None = None,
                  already_notified: set[str] | None = None) -> dict[str, Any]:
    """Propagate a withdrawn or expired approval to everyone carrying the event.

    The approval gate only stops *new* seed lots and batches. Material already produced still
    carries the event, and whoever owns or holds it may now be unable to plant, sell or release
    it in that jurisdiction — so each party is told, and each affected batch gets a COMPLIANCE
    alert in its owner's organisation that a compliance re-evaluation will confirm or clear.
    """
    lots, batches = affected_holdings(db, event)
    crops = affected_crops(db, event, lots)
    still_live = sorted(a.jurisdiction for a in db.execute(select(GMOApproval).where(
        GMOApproval.gmo_event_id == event.id)).scalars() if is_live(a))
    remaining = (f"Still approved in: {', '.join(still_live)}." if still_live
                 else "It is no longer approved in any jurisdiction.")
    title = f"GMO approval {how}: {event.event_code} in {approval.jurisdiction}"

    # One record of the lapse itself, owned by the developer, so a regulator scanning alerts
    # sees it and the expiry sweep can tell it has already been handled.
    notifications.raise_alert(
        db, "COMPLIANCE", "HIGH", title,
        detail=f"{len(lots)} seed lot(s) and {len(batches)} batch(es) carry the event. "
               f"{remaining}",
        org_id=event.org_id, entity_type="GMOApproval", entity_id=approval.id,
        notify=False, open_incident=False)
    for batch in batches:
        notifications.raise_alert(
            db, "COMPLIANCE", "HIGH",
            f"Batch {batch.batch_code}: GMO approval {how} for {event.event_code} "
            f"in {approval.jurisdiction}",
            detail=f"The batch's lineage carries {event.event_code}. Re-evaluate its compliance "
                   f"before releasing it into {approval.jurisdiction}. {remaining}",
            org_id=batch.org_id, entity_type="Batch", entity_id=batch.id,
            notify=False, open_incident=False)

    # One notification per organisation concerned, saying what of theirs is affected (seed
    # lots, batches, and crops in the ground, which a grower may have planted with the event
    # and no seed lot) and linking to it.
    parties = _holdings_by_party(db, event, lots, batches, crops)
    _notify_holders(db, event, parties, title, remaining,
                    "No seed lot, crop or batch carries the event yet.", "HIGH",
                    already_notified or set())

    audit.record(db, f"gmo.approval_{how}", actor_id=actor_id, actor_role=None,
                 org_id=event.org_id, entity_type="GMOEvent", entity_id=event.id,
                 detail={"jurisdiction": approval.jurisdiction, "seed_lots": len(lots),
                         "batches": len(batches), "crops": len(crops),
                         "organisations": len(parties)})
    return {"event_code": event.event_code, "jurisdiction": approval.jurisdiction,
            "seed_lots": [lot.id for lot in lots], "batches": [b.id for b in batches],
            "crops": [crop.id for crop, _ in crops], "organisations": sorted(parties)}


def sweep_expired_approvals(db: Session) -> list[dict[str, Any]]:
    """Propagate every approval that has expired since it was last handled.

    Idempotent without extra state: an expired approval counts as handled once a COMPLIANCE
    alert for it exists that was raised at or after its expiry. A renewed approval has a new
    expiry date, so its later lapse is handled again.
    """
    from ..models import Alert

    now = utcnow()
    results = []
    for approval in db.execute(select(GMOApproval).where(
            GMOApproval.status.in_(APPROVED_STATUSES),
            GMOApproval.expires_at.is_not(None))).scalars():
        expires_at = _aware(approval.expires_at)
        if expires_at > now:
            continue
        handled = any(_aware(created) >= expires_at for created in db.execute(
            select(Alert.created_at).where(Alert.category == "COMPLIANCE",
                                           Alert.entity_type == "GMOApproval",
                                           Alert.entity_id == approval.id)).scalars())
        if handled:
            continue
        event = db.get(GMOEvent, approval.gmo_event_id)
        if event is not None:
            results.append(approval_lost(db, event, approval, "expired"))
    return results


def create_seed_lot(db: Session, org_id: str, actor_id: str, actor_role: str, lot_code: str,
                    gmo_event_id: str | None, crop_type: str, variety: str, quantity_kg: float,
                    produced_at: datetime, germination_pct: float | None) -> SeedLot:
    if db.execute(select(SeedLot).where(SeedLot.lot_code == lot_code)).scalar_one_or_none():
        raise Conflict(f"Seed lot {lot_code} already exists")
    event = None
    if gmo_event_id:
        event = require_approved_event(db, gmo_event_id, actor_role, org_id)

    lot = SeedLot(org_id=org_id, lot_code=lot_code, gmo_event_id=gmo_event_id,
                  crop_type=crop_type, variety=variety, quantity_kg=quantity_kg,
                  produced_at=produced_at, germination_pct=germination_pct,
                  custodian_org_id=org_id)
    db.add(lot)
    db.flush()
    digest = content_hash({"lot_code": lot_code, "crop_type": crop_type, "variety": variety,
                           "quantity_kg": quantity_kg,
                           "gmo_event": event.event_code if event else None})
    lot.content_hash = digest
    receipt = ledger_client.submit(
        "gmo_registry", "RegisterSeedLot",
        {"lot_code": lot_code, "event_code": event.event_code if event else None,
         "quantity_kg": quantity_kg, "content_hash": digest}, _msp_for(db, org_id),
        db=db, entity=lot)
    _apply_receipt(db, lot, receipt, "SeedLot")

    audit.record(db, "gmo.create_seed_lot", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="SeedLot", entity_id=lot.id,
                 detail={"lot_code": lot_code, "quantity_kg": quantity_kg})
    return lot


def transfer_seed_lot(db: Session, lot: SeedLot, from_org_id: str, to_org_id: str,
                      actor_id: str, actor_role: str) -> SeedLot:
    """Supply a seed lot to a farm. Only the current holder may hand it on."""
    holder = lot.custodian_org_id or lot.org_id
    if holder != from_org_id:
        raise PermissionDenied("Only the organisation currently holding the seed lot may "
                               "transfer it")
    receiving = db.get(Organization, to_org_id)
    if receiving is None or not receiving.is_active:
        raise NotFound("Receiving organisation not found")
    if receiving.org_type != "FARM":
        raise ValidationFailed("Seed lots are supplied to farms")
    if to_org_id == holder:
        raise ValidationFailed("The seed lot is already held by that organisation")
    lot.custodian_org_id = to_org_id
    db.flush()
    audit.record(db, "gmo.seed_lot_transfer", actor_id=actor_id, actor_role=actor_role,
                 org_id=from_org_id, entity_type="SeedLot", entity_id=lot.id,
                 detail={"lot_code": lot.lot_code, "to_org": receiving.msp_id})
    notifications.notify_org(
        db, to_org_id, "HANDOVER", f"Seed lot {lot.lot_code} supplied to you",
        f"{lot.crop_type} {lot.variety}, {lot.quantity_kg:g} kg. You can now plant from it.",
        "SeedLot", lot.id)
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
        # The same predicate as the seed-lot and batch gates: an expired approval, or one
        # whose decision date is still in the future, does not permit release.
        approved = is_live(approval)
        if not approved:
            state = approval.status if approval else "NOT_SUBMITTED"
            if approval is not None and approval.status in APPROVED_STATUSES:
                state = ("expired" if approval.expires_at
                         and _aware(approval.expires_at) <= utcnow() else "not yet in force")
            findings.append({
                "rule": "approval_required", "passed": False, "citation": rule["citation"],
                "detail": f"GMO event {lineage_event.event_code} is not approved in "
                          f"{jurisdiction} (status: {state})"})
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
        # The holder trying to release it and the owner both need to know.
        notifications.alert_parties(
            db, "COMPLIANCE", "HIGH",
            f"Labelling non-compliance on batch {batch.batch_code}",
            detail=f"Release into {jurisdiction} blocked: "
                   + "; ".join(f["detail"] for f in result["findings"] if not f["passed"]),
            org_id=batch.org_id, party_org_ids=[batch.custodian_org_id],
            entity_type="Batch", entity_id=batch.id)
    return result


def verify_anchor(db: Session, event: GMOEvent) -> dict[str, Any]:
    digest = content_hash(event_content(event))
    result = ledger_client.verify_content(digest, event.tx_id)
    return {**result, "computed_hash": digest, "stored_hash": event.content_hash,
            "verified_at": utcnow()}
