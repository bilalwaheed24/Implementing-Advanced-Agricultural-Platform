"""Products, batches, EPCIS events, shipments, certifications, fraud and verification.

FR-B2 (provenance), FR-D1 (traceability + IoT), FR-D2 (certification authentication),
FR-D3 (fraud detection), FR-D4 (consumer verification).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session, aliased

from ..core.config import get_settings
from ..core.errors import Conflict, NotFound, PermissionDenied, ValidationFailed
from ..core.permissions import CROSS_TENANT_ROLES
from ..core.security import ensure_aware as _aware, content_hash, utcnow, verification_code
from ..repositories import get_or_404, visible
from ..models import (Batch, Certification, CertificationLink, Crop, Device, Farm, Field,
                      FraudAssessment, GMOApproval, GMOEvent, Organization, Product, SeedLot,
                      Notification, Shipment, SupplyChainEvent, User)
from . import ai_client, audit, cold_chain, gmo as gmo_service, ledger_client, notifications, telemetry as telemetry_service

BIZ_STEP_TO_STATE = {
    "commissioning": "CREATED", "harvesting": "HARVESTED", "transforming": "PROCESSED",
    "packing": "PACKAGED", "shipping": "IN_TRANSIT", "receiving": "RECEIVED",
    "storing": "STORED", "retail_selling": "RETAILED", "recalling": "RECALLED",
}

# Legal batch state transitions, enforced here as well as in the chaincode.
#
# The chaincode is the authority on-chain, but relying on it alone left a gap: the DB only
# refused a transition when the ledger came back REJECTED, and `ledger_client.submit` returns
# PENDING — not REJECTED — when the circuit breaker is open or the retries are exhausted. In
# that degraded state an illegal transition was still written to the database (audit P1).
# `tests/test_supplychain_e2e.py` asserts this table is identical to
# `ledger.contracts.BATCH_TRANSITIONS`, so the two cannot drift apart.
BATCH_TRANSITIONS: dict[str, frozenset[str]] = {
    "CREATED": frozenset({"HARVESTED", "PROCESSED", "IN_TRANSIT", "RECALLED"}),
    "HARVESTED": frozenset({"PROCESSED", "IN_TRANSIT", "STORED", "RECALLED"}),
    "PROCESSED": frozenset({"PACKAGED", "IN_TRANSIT", "STORED", "RECALLED"}),
    "PACKAGED": frozenset({"IN_TRANSIT", "STORED", "RECALLED"}),
    "IN_TRANSIT": frozenset({"RECEIVED", "STORED", "RECALLED"}),
    "RECEIVED": frozenset({"PROCESSED", "PACKAGED", "IN_TRANSIT", "STORED", "RETAILED",
                           "RECALLED"}),
    "STORED": frozenset({"IN_TRANSIT", "PROCESSED", "PACKAGED", "RETAILED", "RECALLED"}),
    "RETAILED": frozenset({"CONSUMED", "RECALLED"}),
    "CONSUMED": frozenset(),
    "RECALLED": frozenset(),
}


def require_batch_transition(current: str, target: str) -> None:
    """Reject an illegal batch state change before anything is written or submitted."""
    if target == current:
        return
    allowed = BATCH_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise ValidationFailed(
            f"Illegal transition {current} -> {target}; allowed: "
            f"{', '.join(sorted(allowed)) or 'none, this state is final'}")


def _is_cross_tenant(role: str) -> bool:
    return role in {r.value for r in CROSS_TENANT_ROLES}


def _require_exists(db: Session, model: type, entity_id: str, name: str) -> Any:
    """Referential-integrity check for a cross-organisation provenance reference.

    Deliberately not org-scoped: see the rules in `create_batch`. It stops a client planting a
    dangling or soft-deleted id, which is what would otherwise produce orphan lineage, and
    reveals nothing beyond whether the identifier resolves.
    """
    row = db.get(model, entity_id)
    if row is None or getattr(row, "deleted_at", None) is not None:
        raise NotFound(f"{name} not found")
    return row


def _msp_for(db: Session, org_id: str) -> str:
    organization = db.get(Organization, org_id)
    if organization is None:
        raise NotFound("Organisation not found")
    return organization.msp_id


# --------------------------------------------------------------------------- #
# Read access for certifiers
# --------------------------------------------------------------------------- #
def certified_by(org_id: str | None) -> Any:
    """SQL condition: the batch carries a certificate `org_id` issued.

    A certifier is not a party to the batches its certificates are claimed on, yet it is told
    about them (claims, expiry, revocation, compliance) and must be able to check the claim. It
    therefore reads those batches, read-only: this widens the read paths only (`readable_batch`,
    the batch list, verify-record), never the paths that record events, ship or verify.
    """
    if org_id is None:
        return None
    return Batch.id.in_(
        select(CertificationLink.batch_id)
        .join(Certification, Certification.id == CertificationLink.certification_id)
        .where(Certification.issuer_org_id == org_id))


def readable_batch(db: Session, batch_id: str, role: str, org_id: str | None) -> Batch:
    """A batch the caller may read: its owner, its custodian, a cross-tenant role, or the issuer
    of a certificate claimed on it. 404 otherwise, as `get_or_404`."""
    return get_or_404(db, Batch, batch_id, role, org_id, name="Batch",
                      also=certified_by(org_id))


def readable_batches(role: str, org_id: str | None):
    """SELECT of every batch `readable_batch` would return for the caller."""
    return visible(Batch, role, org_id, also=certified_by(org_id))


# --------------------------------------------------------------------------- #
# Release gate: what may be shipped or put on sale
# --------------------------------------------------------------------------- #
# Business steps that put a batch in front of a buyer, and how the refusal names them.
RELEASE_STEPS = {"shipping": "shipped", "retail_selling": "put on sale"}
# The one step that may carry a receiver (to_org_id) and so move custody. It is a release
# step, so a hand-over always passes require_releasable.
HANDOVER_STEP = "shipping"


def _recalled_ancestor(db: Session, batch: Batch, max_depth: int = 12) -> Batch | None:
    seen = {batch.id}
    current, depth = batch, 0
    while current.parent_batch_id and depth < max_depth:
        current = db.get(Batch, current.parent_batch_id)
        if current is None or current.id in seen:
            return None
        if current.state == "RECALLED":
            return current
        seen.add(current.id)
        depth += 1
    return None


def require_releasable(db: Session, batch: Batch, action: str) -> None:
    """Refuse to ship or sell a batch that must not reach a buyer (422 with the reason).

    Recalled, made from a recalled batch (the SUSPECT descendants `propagate_recall` flags),
    integrity FAILED, or carrying a GMO event with no live approval anywhere (the same
    `require_live_approval` gate that stops new seed lots and batches). A recall itself is never
    gated: it is how such a batch is taken out of the chain.
    """
    code = batch.batch_code
    if batch.state == "RECALLED":
        raise ValidationFailed(f"Batch {code} has been recalled and cannot be {action}.")
    recalled = _recalled_ancestor(db, batch)
    if recalled is not None:
        raise ValidationFailed(
            f"Batch {code} is made from recalled batch {recalled.batch_code} and cannot be "
            f"{action}. Quarantine the stock, or recall it too.")
    if batch.integrity_status == "FAILED":
        raise ValidationFailed(
            f"Batch {code} failed integrity verification and cannot be {action}. Investigate "
            f"the failure and re-run the verification first.")
    event = gmo_service.lineage_gmo_event(db, batch)
    if event is not None:
        try:
            gmo_service.require_live_approval(db, event, f"A batch {action}")
        except ValidationFailed as exc:
            raise ValidationFailed(f"Batch {code} cannot be {action}: {exc.detail}") from exc




# --------------------------------------------------------------------------- #
# Products and batches
# --------------------------------------------------------------------------- #
def create_product(db: Session, org_id: str, actor_id: str, actor_role: str, **kwargs) -> Product:
    if db.execute(select(Product).where(Product.gtin == kwargs["gtin"],
                                        Product.deleted_at.is_(None))).scalar_one_or_none():
        raise Conflict(f"A product with GTIN {kwargs['gtin']} already exists")
    low, high = kwargs.get("storage_temp_min_c"), kwargs.get("storage_temp_max_c")
    if low is not None and high is not None and low > high:
        raise ValidationFailed("storage_temp_min_c must not exceed storage_temp_max_c")
    product = Product(org_id=org_id, **kwargs)
    db.add(product)
    db.flush()
    audit.record(db, "supply.create_product", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="Product", entity_id=product.id,
                 detail={"gtin": product.gtin, "name": product.name})
    return product


def batch_content(batch: Batch, product: Product) -> dict[str, Any]:
    """Immutable provenance facts only (ADR-011).

    Deliberately excludes `state` and the current `quantity`: both change legitimately
    as the batch moves through the chain, and each change is anchored by its own
    supply-chain event. Hashing mutable state here would report every processing step
    as tampering.
    """
    return {"batch_code": batch.batch_code, "product_gtin": product.gtin,
            "initial_quantity": batch.initial_quantity, "unit": batch.unit,
            "origin_region": batch.origin_region, "origin_country": batch.origin_country,
            "gmo_event_id": batch.gmo_event_id, "seed_lot_id": batch.seed_lot_id}


def create_batch(db: Session, org_id: str, actor_id: str, actor_role: str, batch_code: str,
                 product_id: str, quantity: float, unit: str, parent_batch_id: str | None,
                 seed_lot_id: str | None, crop_id: str | None, farm_id: str | None,
                 gmo_event_id: str | None, origin_region: str | None,
                 origin_country: str | None, harvested_at: datetime | None) -> Batch:
    if db.execute(select(Batch).where(Batch.batch_code == batch_code)).scalar_one_or_none():
        raise Conflict(f"Batch {batch_code} already exists")
    # Every id below arrives from the request body, so each is resolved rather than trusted.
    # Two different rules apply, because a supply chain legitimately spans organisations:
    #
    #   * Custody-bearing references are scoped to the caller. A batch's own product and its
    #     parent batch are read back out through the batch and lineage views, so accepting a
    #     foreign id there discloses another tenant's record (audit P1). get_or_404 returns 404,
    #     not 403, so a foreign id is indistinguishable from a nonexistent one.
    #
    #   * Provenance references crossing organisations are checked for existence only. A
    #     processor's batch genuinely points at the grower's farm and the developer's GMO event
    #     — that is what traceability means — and requiring same-org ownership there would make
    #     the food chain unrepresentable. Only the identifier is stored; the referenced record's
    #     contents stay protected by the scoped read paths on /farms and /gmo/events.
    product = get_or_404(db, Product, product_id, actor_role, org_id, name="Product")

    parent = None
    if parent_batch_id:
        parent = get_or_404(db, Batch, parent_batch_id, actor_role, org_id, name="Parent batch")
        if not _is_cross_tenant(actor_role) and parent.custodian_org_id != org_id:
            raise PermissionDenied("A batch can only be derived from a batch you currently hold")
        if parent.state in {"RECALLED", "CONSUMED"}:
            # A recalled lot must not re-enter the chain under a new code.
            raise ValidationFailed(
                f"Batch {parent.batch_code} is {parent.state} and cannot be used as a parent")
        if quantity > parent.quantity + 1e-9:
            raise ValidationFailed(
                f"Quantity {quantity} exceeds the parent batch quantity {parent.quantity}")
    if crop_id:
        # A grower harvesting its own crop: the batch inherits the crop's farm, seed lot and
        # GMO event, so lineage is recorded from the planting rather than retyped — and a
        # different value sent alongside it is refused, as create_crop refuses a mismatch.
        crop = db.execute(visible(Crop, actor_role, org_id).where(
            Crop.id == crop_id)).scalar_one_or_none()
        if crop is not None:
            field = db.get(Field, crop.field_id)
            crop_farm = field.farm_id if field else None
            for label, given, planted in (("farm", farm_id, crop_farm),
                                          ("seed lot", seed_lot_id, crop.seed_lot_id),
                                          ("GMO event", gmo_event_id, crop.gmo_event_id)):
                if given and planted and given != planted:
                    raise ValidationFailed(
                        f"The {label} does not match the harvested crop's {label}")
            farm_id = farm_id or crop_farm
            seed_lot_id = seed_lot_id or crop.seed_lot_id
            gmo_event_id = gmo_event_id or crop.gmo_event_id
        else:
            _require_exists(db, Crop, crop_id, "Crop")
    lot = _require_exists(db, SeedLot, seed_lot_id, "Seed lot") if seed_lot_id else None
    if farm_id:
        _require_exists(db, Farm, farm_id, "Farm")
    # The GMO event the batch will carry, from wherever its lineage brings it in: named
    # directly, through the seed lot, or through the parent batch. Each route needs the
    # same live approval, or a lapsed event could enter the chain by the side door.
    if gmo_event_id:
        event = _require_exists(db, GMOEvent, gmo_event_id, "GMO event")
        if lot is not None and lot.gmo_event_id and lot.gmo_event_id != gmo_event_id:
            raise ValidationFailed("The GMO event does not match the seed lot's GMO event")
    elif lot is not None and lot.gmo_event_id:
        event = db.get(GMOEvent, lot.gmo_event_id)
    elif parent is not None:
        event = gmo_service.lineage_gmo_event(db, parent)
    else:
        event = None
    if event is not None:
        gmo_service.require_live_approval(db, event, "A batch")

    batch = Batch(org_id=org_id, batch_code=batch_code, verification_code=verification_code(),
                  product_id=product_id, parent_batch_id=parent_batch_id, seed_lot_id=seed_lot_id,
                  crop_id=crop_id, farm_id=farm_id, gmo_event_id=gmo_event_id,
                  quantity=quantity, initial_quantity=quantity, unit=unit,
                  custodian_org_id=org_id,
                  origin_region=origin_region, origin_country=origin_country,
                  harvested_at=_aware(harvested_at), created_by=actor_id)
    db.add(batch)
    if parent is not None:
        # The child takes its quantity out of the parent (quantity conservation): otherwise
        # every child could claim the parent's full amount.
        parent.quantity = max(0.0, parent.quantity - quantity)
    db.flush()

    digest = content_hash(batch_content(batch, product))
    batch.content_hash = digest
    lineage_event = gmo_service.lineage_gmo_event(db, batch)
    receipt = ledger_client.submit(
        "provenance", "CreateBatch",
        {"batch_code": batch_code, "product": product.gtin, "quantity": quantity, "unit": unit,
         "origin": f"{origin_region or ''},{origin_country or ''}",
         "parents": [parent.batch_code] if parent else [],
         "gmo_event": lineage_event.event_code if lineage_event else None,
         "content_hash": digest},
        _msp_for(db, org_id), db=db, entity=batch)
    gmo_service._apply_receipt(db, batch, receipt, "Batch")

    audit.record(db, "supply.create_batch", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="Batch", entity_id=batch.id,
                 detail={"batch_code": batch_code, "quantity": quantity,
                         "anchor_status": batch.anchor_status})
    return batch


def event_content(event: SupplyChainEvent, batch: Batch) -> dict[str, Any]:
    return {"batch_code": batch.batch_code, "biz_step": event.biz_step,
            "disposition": event.disposition, "location_gln": event.location_gln,
            "quantity": event.quantity, "occurred_at": _aware(event.occurred_at).isoformat()}


def record_event(db: Session, org_id: str, actor_id: str, actor_role: str, batch: Batch,
                 biz_step: str, disposition: str, event_type: str, location_gln: str | None,
                 location_name: str | None, latitude: float | None, longitude: float | None,
                 quantity: float | None, unit: str | None, to_org_id: str | None,
                 occurred_at: datetime, detail: dict[str, Any]) -> SupplyChainEvent:
    """Append an EPCIS-shaped event, anchor it, and advance the batch state."""
    if to_org_id and to_org_id != batch.custodian_org_id and biz_step != HANDOVER_STEP:
        # Custody moves only with a shipping event, which passes the release gate below. Any
        # other step carrying a receiver handed over a FAILED or recalled batch that
        # POST /shipments had just refused (round 4).
        raise ValidationFailed(
            f"to_org_id hands the batch to another organisation, which only a "
            f"'{HANDOVER_STEP}' event may do; '{biz_step}' cannot carry a receiver")
    if biz_step in RELEASE_STEPS:
        require_releasable(db, batch, RELEASE_STEPS[biz_step])
    if quantity is not None and quantity > batch.quantity + 1e-9:
        raise ValidationFailed(
            f"Event quantity {quantity} exceeds the batch quantity {batch.quantity} "
            f"(quantity conservation)")
    # Checked here, not only by the chaincode, so a degraded ledger cannot let an illegal
    # transition reach the database (see BATCH_TRANSITIONS above).
    target_state = BIZ_STEP_TO_STATE.get(biz_step)
    if target_state:
        require_batch_transition(batch.state, target_state)

    event = SupplyChainEvent(
        batch_id=batch.id, org_id=org_id, event_type=event_type, biz_step=biz_step,
        disposition=disposition, location_gln=location_gln, location_name=location_name,
        latitude=latitude, longitude=longitude, quantity=quantity, unit=unit,
        from_org_id=batch.custodian_org_id, to_org_id=to_org_id,
        occurred_at=_aware(occurred_at), detail=detail, content_hash="", recorded_by=actor_id)
    db.add(event)
    db.flush()
    event.content_hash = content_hash(event_content(event, batch))

    receipt = ledger_client.submit(
        "provenance", "RecordEvent",
        {"batch_code": batch.batch_code, "event_id": event.id, "biz_step": biz_step,
         "disposition": disposition, "location_gln": location_gln or "",
         "quantity": quantity, "occurred_at": _aware(occurred_at).isoformat(),
         "content_hash": event.content_hash},
        _msp_for(db, org_id), db=db, entity=event)

    if receipt.get("status") == "REJECTED":
        # The contract enforces the lifecycle; surface its reason to the caller. A batch whose
        # own anchor is still pending does not land here: the event is queued behind it
        # (services/anchoring.py) and comes back PENDING.
        db.expunge(event)
        raise ValidationFailed(receipt.get("detail", "Ledger rejected the event"))

    gmo_service._apply_receipt(db, event, receipt, "SupplyChainEvent")

    new_state = BIZ_STEP_TO_STATE.get(biz_step)
    if new_state:
        batch.state = new_state
    if quantity is not None:
        batch.quantity = quantity

    if to_org_id and to_org_id != batch.custodian_org_id and new_state != "RECALLED":
        transfer_custody(db, batch, org_id, to_org_id, occurred_at)

    if biz_step in SHIPMENT_CLOSING_STEPS:
        # Receipt recorded directly closes the shipment that was carrying the batch, so the
        # shipment and the batch never disagree about whether the goods have arrived, with the
        # same side effects as marking the shipment arrived (sender told, temperatures, audit).
        _deliver_open_shipments(db, batch, occurred_at, org_id, actor_id, actor_role,
                                location_name)

    db.flush()
    audit.record(db, "supply.record_event", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="SupplyChainEvent", entity_id=event.id,
                 detail={"batch_code": batch.batch_code, "biz_step": biz_step,
                         "anchor_status": event.anchor_status})
    if new_state == "RECALLED":
        propagate_recall(db, batch, actor_id, actor_role, org_id)
    return event


def _related_batches(db: Session, batch: Batch, max_depth: int = 12
                     ) -> tuple[list[Batch], list[Batch]]:
    """Every ancestor and every descendant of a batch, across organisations.

    Deliberately unscoped: a recall has to reach whoever holds product made from the batch,
    whichever organisation that is. Only codes are disclosed, in the notifications.
    """
    ancestors: list[Batch] = []
    seen = {batch.id}
    current, depth = batch, 0
    while current.parent_batch_id and depth < max_depth:
        current = db.get(Batch, current.parent_batch_id)
        if current is None or current.id in seen:
            break
        ancestors.append(current)
        seen.add(current.id)
        depth += 1
    descendants: list[Batch] = []
    frontier, depth = [batch.id], 0
    while frontier and depth < max_depth:
        children = [child for child in db.execute(select(Batch).where(
            Batch.parent_batch_id.in_(frontier))).scalars() if child.id not in seen]
        for child in children:
            seen.add(child.id)
        descendants.extend(children)
        frontier = [child.id for child in children]
        depth += 1
    return ancestors, descendants


def propagate_recall(db: Session, batch: Batch, actor_id: str | None, actor_role: str | None,
                     org_id: str) -> dict[str, Any]:
    """Tell every party to a recalled batch, and flag every batch made from it.

    The owner, the custodian and the owners and holders of every parent and child batch are
    notified, and so is every organisation that handled one of those batches on the way: named
    as sender or receiver on a custody event, or as either end of a shipment. An intermediate
    processor that passed the batch on may still hold part of it, or know where it went. Each
    descendant batch is marked SUSPECT and carries an open COMPLIANCE alert, so product derived
    from a recalled lot is visible as such wherever it now is.
    """
    ancestors, descendants = _related_batches(db, batch)
    title = f"Batch {batch.batch_code} has been recalled"
    related_batches = [batch, *ancestors, *descendants]
    # org -> the batch its notification should point at (one the org can open).
    recipients: dict[str, Batch] = {}
    for related in related_batches:
        for party in (related.org_id, related.custodian_org_id):
            if party and party not in recipients:
                recipients[party] = related
    for party, subject in recipients.items():
        body = (f"{batch.batch_code} was recalled. "
                + (f"Your batch {subject.batch_code} is in its lineage; "
                   f"check and quarantine the stock." if subject.id != batch.id
                   else "Stop distribution and quarantine the stock."))
        notifications.notify_org(db, party, "RECALL", title, body, "Batch", subject.id,
                                 severity="HIGH")
    # Earlier holders. They can no longer open the batch, so the notification points at a
    # shipment they were party to where there is one, and otherwise carries the codes only.
    by_id = {b.id: b for b in related_batches}
    handlers: dict[str, tuple[Batch, Shipment | None]] = {}
    for event in db.execute(select(SupplyChainEvent).where(
            SupplyChainEvent.batch_id.in_(list(by_id)))
            .order_by(SupplyChainEvent.occurred_at.asc())).scalars():
        for party in (event.from_org_id, event.to_org_id):
            if party and party not in recipients and party not in handlers:
                handlers[party] = (by_id[event.batch_id], None)
    for shipment in db.execute(select(Shipment).where(
            Shipment.batch_id.in_(list(by_id))).order_by(Shipment.departed_at.asc())).scalars():
        for party in (shipment.org_id, shipment.to_org_id):
            if not party or party in recipients:
                continue
            handled, known = handlers.get(party, (by_id[shipment.batch_id], None))
            handlers[party] = (handled, known or shipment)
    for party, (handled, shipment) in handlers.items():
        body = (f"{batch.batch_code} was recalled. Your organisation handled batch "
                f"{handled.batch_code}"
                + (" (this batch)" if handled.id == batch.id else ", which is in its lineage")
                + ". Check whether any of that stock is still with you and tell whoever you "
                  "passed it to.")
        notifications.notify_org(db, party, "RECALL", title, body,
                                 "Shipment" if shipment else None,
                                 shipment.id if shipment else None, severity="HIGH")
    # Matched on kind: any other open COMPLIANCE alert on the batch (a failed evaluation, a
    # cold-chain excursion) used to suppress the recall alert entirely.
    # notify=False: every user of the owner and custodian organisations has just had the
    # RECALL notification above, so the category fan-out told their supply-chain operators and
    # regulators twice (round 4). The platform-wide COMPLIANCE oversight roles, which the
    # RECALL round does not reach, are told here instead.
    if not notifications.has_open_alert(db, "COMPLIANCE", batch.id, kind="recall"):
        notifications.raise_alert(
            db, "COMPLIANCE", "HIGH", title,
            detail=f"{len(descendants)} derived batch(es) flagged.", org_id=batch.org_id,
            entity_type="Batch", entity_id=batch.id, reasons=["Batch recalled"], notify=False,
            kind="recall", party_org_id=batch.custodian_org_id)
        notifications.notify_parties(
            db, [], "COMPLIANCE", title, f"{len(descendants)} derived batch(es) flagged.",
            "Batch", batch.id, "HIGH", include_oversight=True,
            exclude_org_ids=set(recipients) | set(handlers))
    for child in descendants:
        if child.integrity_status != "FAILED":
            child.integrity_status = "SUSPECT"
        if not notifications.has_open_alert(db, "COMPLIANCE", child.id,
                                            kind="parent_recalled"):
            notifications.raise_alert(
                db, "COMPLIANCE", "HIGH",
                f"Batch {child.batch_code} derives from recalled batch {batch.batch_code}",
                detail="Quarantine the stock and decide whether to recall it too.",
                org_id=child.org_id, entity_type="Batch", entity_id=child.id,
                reasons=["Made from a recalled batch"], notify=False,
                kind="parent_recalled", party_org_id=child.custodian_org_id)
    db.flush()
    audit.record(db, "supply.recall_propagated", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="Batch", entity_id=batch.id,
                 detail={"batch_code": batch.batch_code,
                         "descendants": [b.batch_code for b in descendants],
                         "ancestors": [b.batch_code for b in ancestors],
                         "organisations_notified": len(recipients) + len(handlers)})
    return {"descendants": descendants, "ancestors": ancestors,
            "organisations": [*recipients, *handlers]}


# The holder's first step after a shipment that shows the goods have reached it. Receiving is
# the usual one, but a receiver that books the batch straight into storage (or processes it)
# has equally taken delivery: each closes the open shipment with the arrival's side effects,
# so a shipment can no longer stay IN_TRANSIT forever behind a `storing` event.
SHIPMENT_CLOSING_STEPS = frozenset({"receiving", "storing", "transforming"})
# The steps that book a handed-over batch in ("Hand-overs to book in").
BOOKING_STEPS = SHIPMENT_CLOSING_STEPS


def awaiting_booking(org_id: str | None) -> list[Any]:
    """SQL conditions: a batch handed over to `org_id` (any holder when None) that has reached
    it but that it has not booked in yet.

    Held by someone other than its originator, not on the road (a batch IN_TRANSIT is counted
    under "awaiting arrival" instead, by its shipment), and with no receiving, storing or
    transforming event recorded by the holder since custody last moved to it.
    """
    handover = aliased(SupplyChainEvent)
    handed_at = (select(func.max(handover.occurred_at))
                 .where(handover.batch_id == Batch.id,
                        handover.to_org_id == Batch.custodian_org_id)
                 # Tied to the outer batch explicitly: nested inside `booked`, it was otherwise
                 # given its own FROM batches and took the latest hand-over on the platform.
                 .correlate(Batch)
                 .scalar_subquery())
    booked = select(SupplyChainEvent.id).where(
        SupplyChainEvent.batch_id == Batch.id,
        SupplyChainEvent.org_id == Batch.custodian_org_id,
        SupplyChainEvent.biz_step.in_(BOOKING_STEPS),
        or_(handed_at.is_(None), SupplyChainEvent.occurred_at >= handed_at)).correlate(Batch)
    conditions = [Batch.custodian_org_id != Batch.org_id, Batch.state != "IN_TRANSIT",
                  ~booked.exists()]
    if org_id is not None:
        conditions.append(Batch.custodian_org_id == org_id)
    return conditions


def gmo_lineage_ids() -> Any:
    """SELECT of the ids of every batch with a GMO lineage, matching `lineage_gmo_event`: a GMO
    event named on the batch, carried by its seed lot, or inherited from any ancestor batch.

    A recursive CTE from the batches that carry an event themselves down through their
    descendants; UNION (not UNION ALL) also stops a corrupted parent cycle from looping.
    """
    lot = aliased(SeedLot)
    roots = (select(Batch.id.label("id"))
             .outerjoin(lot, lot.id == Batch.seed_lot_id)
             .where(or_(Batch.gmo_event_id.is_not(None), lot.gmo_event_id.is_not(None)))
             .cte("gmo_lineage", recursive=True))
    child = aliased(Batch)
    tree = roots.union(select(child.id).where(child.parent_batch_id == roots.c.id))
    return select(tree.c.id)


def _deliver_open_shipments(db: Session, batch: Batch, arrived_at: datetime, org_id: str,
                            actor_id: str | None, actor_role: str | None,
                            location_name: str | None = None) -> None:
    arrived = _aware(arrived_at)
    for shipment in list(db.execute(select(Shipment).where(
            Shipment.batch_id == batch.id, Shipment.status == "IN_TRANSIT")).scalars()):
        shipment.status = "DELIVERED"
        shipment.arrived_at = max(arrived, _aware(shipment.departed_at))
        db.flush()
        _shipment_arrived(db, shipment, org_id, actor_id, actor_role, location_name)
    db.flush()


def _shipment_arrived(db: Session, shipment: Shipment, org_id: str, actor_id: str | None,
                      actor_role: str | None, location_name: str | None) -> None:
    """Side effects of a shipment arriving, however its arrival was recorded: the shipment's
    temperature range is fixed from its readings, the arrival is audited, and the sender of a
    hand-over is told."""
    refresh_shipment_temperatures(db, shipment)
    audit.record(db, "supply.shipment_arrived", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="Shipment", entity_id=shipment.id,
                 detail={"sscc": shipment.sscc, "batch_id": shipment.batch_id})
    if shipment.to_org_id and shipment.org_id != org_id:
        notifications.notify_org(
            db, shipment.org_id, "SHIPMENT", f"Shipment {shipment.sscc} arrived",
            f"Received at {location_name or shipment.destination_name}.", "Shipment",
            shipment.id)
    if shipment.to_org_id:
        _settle_handover_notifications(db, shipment.to_org_id, shipment.batch_id)


def _settle_handover_notifications(db: Session, receiver_org_id: str, batch_id: str) -> None:
    """The receiver's "handed over to you" notification asks it to mark the batch arrived;
    once it has arrived nothing is left to do, so it is marked read for every user of the
    receiving organisation rather than lingering in the unread count."""
    db.execute(
        update(Notification)
        .where(Notification.category == "HANDOVER", Notification.entity_type == "Batch",
               Notification.entity_id == batch_id, Notification.read_at.is_(None),
               Notification.user_id.in_(select(User.id).where(User.org_id == receiver_org_id)))
        .values(read_at=utcnow())
        .execution_options(synchronize_session=False))


def transfer_custody(db: Session, batch: Batch, from_org_id: str, to_org_id: str,
                     occurred_at: datetime) -> dict[str, Any]:
    receiving = db.get(Organization, to_org_id)
    if receiving is None or not receiving.is_active:
        raise NotFound("Receiving organisation not found")
    receipt = ledger_client.submit(
        "provenance", "TransferCustody",
        {"batch_code": batch.batch_code, "from_org": _msp_for(db, from_org_id),
         "to_org": receiving.msp_id, "occurred_at": _aware(occurred_at).isoformat()},
        _msp_for(db, from_org_id), db=db)
    if receipt.get("status") == "REJECTED":
        # The contract refused the hand-over: fail the whole request (nothing is committed),
        # so the caller is never told a transfer happened when it did not.
        raise ValidationFailed(receipt.get("detail", "The ledger rejected the custody transfer"))
    # Anchored, or PENDING/FAILED because the ledger is degraded: the database is the system
    # of record for who holds the batch, exactly as for every other write that anchors
    # asynchronously, so the hand-over takes effect and the ledger status is audited.
    batch.custodian_org_id = to_org_id
    db.flush()
    # The batch's open alerts and active incidents follow it to the new holder, and the
    # previous holder, which can no longer open the batch, stops seeing them (round 4).
    notifications.sync_custodian(db, "Batch", batch.id, batch.org_id, to_org_id)
    if not receipt.get("ok"):
        audit.record(db, "supply.custody_transfer_unanchored", actor_id=None, actor_role=None,
                     org_id=from_org_id, entity_type="Batch", entity_id=batch.id,
                     detail={"batch_code": batch.batch_code, "to_org": receiving.msp_id,
                             "ledger_status": receipt.get("status")})
    notifications.notify_org(
        db, to_org_id, "HANDOVER", f"Batch {batch.batch_code} handed over to you",
        f"{batch.quantity:g} {batch.unit}. "
        + ("Mark it arrived when it reaches you." if batch.state == "IN_TRANSIT"
           else "Record its receipt to continue the chain of custody."), "Batch", batch.id)
    return receipt


def batch_context(db: Session, batch: Batch, events: list[SupplyChainEvent]) -> dict[str, Any]:
    """Who the batch belongs to, who holds it, where it was grown and its GMO lineage.

    Every party to a batch needs this to act on it, but the farm, the developer's GMO event and
    the other organisations are not readable through their own scoped endpoints. Only
    names, codes and approval states are returned, never the underlying records.
    """
    org_ids = {batch.org_id, batch.custodian_org_id}
    org_ids |= {e.from_org_id for e in events if e.from_org_id}
    org_ids |= {e.to_org_id for e in events if e.to_org_id}
    organisations = {o.id: o.name for o in db.execute(
        select(Organization).where(Organization.id.in_(org_ids))).scalars()}
    farm = db.get(Farm, batch.farm_id) if batch.farm_id else None
    if farm is not None and farm.org_id not in {batch.org_id, batch.custodian_org_id}:
        # A farm id is accepted on existence alone when a batch is created, so naming a
        # stranger's farm must not be a way to read its name and location back.
        farm = None
    event = gmo_service.lineage_gmo_event(db, batch)
    gmo = None
    if event is not None:
        approvals = db.execute(select(GMOApproval).where(
            GMOApproval.gmo_event_id == event.id)).scalars()
        gmo = {"event_code": event.event_code, "crop_type": event.crop_type,
               "trait": event.trait, "developer": event.developer,
               "approvals": [{"jurisdiction": a.jurisdiction, "status": a.status,
                              "expires_at": a.expires_at.isoformat() if a.expires_at else None}
                             for a in approvals]}
    product = db.get(Product, batch.product_id)
    return {
        "owner": {"id": batch.org_id, "name": organisations.get(batch.org_id)},
        "custodian": {"id": batch.custodian_org_id,
                      "name": organisations.get(batch.custodian_org_id)},
        "organisations": organisations,
        "farm": {"name": farm.name, "region": farm.region, "country": farm.country}
                if farm else None,
        "product": {"name": product.name, "gtin": product.gtin} if product else None,
        "gmo": gmo,
    }


def chain_of_custody(db: Session, batch: Batch) -> list[SupplyChainEvent]:
    return list(db.execute(
        select(SupplyChainEvent).where(SupplyChainEvent.batch_id == batch.id)
        .order_by(SupplyChainEvent.occurred_at.asc())).scalars())


def lineage(db: Session, batch: Batch, role: str | None = None, org_id: str | None = None,
            max_depth: int = 12) -> list[Batch]:
    """Walk the parent chain inside the caller's visibility only.

    Batches created before the ownership checks in `create_batch` may still carry a foreign
    parent_batch_id, so the walk stops at the first ancestor the caller may not see rather than
    disclosing its code, state and quantity (audit P1). Called without an explicit scope — as
    the compliance rules do — it scopes to the batch's own organisation, which is the right
    boundary for a report about that batch.
    """
    scope_role = role or ""          # not a known Role, so visible() falls back to org scoping
    scope_org = org_id if org_id is not None else batch.org_id
    chain, current, depth = [], batch, 0
    seen: set[str] = set()
    while current and depth < max_depth and current.id not in seen:
        chain.append(current)
        seen.add(current.id)
        if not current.parent_batch_id:
            break
        query = visible(Batch, scope_role, scope_org).where(Batch.id == current.parent_batch_id)
        current = db.execute(query).scalar_one_or_none()
        depth += 1
    return chain


# --------------------------------------------------------------------------- #
# Shipments
# --------------------------------------------------------------------------- #
def create_shipment(db: Session, org_id: str, actor_id: str, actor_role: str, *,
                    to_org_id: str | None = None, **kwargs) -> Shipment:
    """Ship a batch: the `shipping` event, the custody hand-over and the shipment, together.

    Recording a hand-over first and the shipment afterwards could not work, because the
    hand-over moves custody and only the holder may ship. So the shipment is the hand-over:
    custody moves to `to_org_id` when the shipment is created, and the receiver marks it
    arrived (`arrive_shipment`), which records the batch's `receiving` event.
    """
    if db.execute(select(Shipment).where(Shipment.sscc == kwargs["sscc"])).scalar_one_or_none():
        raise Conflict(f"Shipment {kwargs['sscc']} already exists")
    # A shipment must reference a batch the caller actually holds (audit P1). Visibility is
    # not enough: the producer still sees a batch after handing it over, but no longer holds it.
    batch = get_or_404(db, Batch, kwargs["batch_id"], actor_role, org_id, name="Batch")
    if not _is_cross_tenant(actor_role) and batch.custodian_org_id != org_id:
        raise PermissionDenied("Only the organisation currently holding this batch may ship it")
    require_releasable(db, batch, "shipped")
    arrived = _aware(kwargs.get("arrived_at"))
    departed = _aware(kwargs["departed_at"])
    if arrived and arrived < departed:
        raise ValidationFailed("arrived_at must not precede departed_at")
    if to_org_id == batch.custodian_org_id:
        to_org_id = None                     # shipping to yourself is an internal move
    if to_org_id:
        receiver = db.get(Organization, to_org_id)
        if receiver is None or not receiver.is_active:
            raise NotFound("Receiving organisation not found")
        if arrived:
            raise ValidationFailed(
                "A shipment to another organisation is marked arrived by the receiver; "
                "leave arrived_at empty")
    device_id = kwargs.get("cold_chain_device_id")
    if device_id:
        device = db.get(Device, device_id)
        if (device is None or device.deleted_at is not None
                or device.org_id not in {org_id, batch.custodian_org_id}):
            raise NotFound("Cold-chain sensor not found")
        busy = db.execute(select(Shipment.sscc).where(
            Shipment.cold_chain_device_id == device_id,
            Shipment.status == "IN_TRANSIT")).first()
        if busy is not None and not arrived:
            raise Conflict(f"That sensor is already travelling with shipment {busy[0]}")
    require_batch_transition(batch.state, "IN_TRANSIT")

    # The batch's shipping event, carrying the hand-over. If the holder already recorded a
    # shipping event without a hand-over, the shipment aligns with it instead of repeating it.
    already_shipping = batch.state == "IN_TRANSIT"
    if not already_shipping:
        record_event(db, org_id, actor_id, actor_role, batch, "shipping", "in_transit", "OBJECT",
                     None, kwargs["origin_name"], kwargs["origin_lat"], kwargs["origin_lon"],
                     None, None, to_org_id, departed, {"sscc": kwargs["sscc"]})
    elif to_org_id:
        transfer_custody(db, batch, org_id, to_org_id, departed)

    kwargs["departed_at"] = departed
    kwargs["arrived_at"] = None
    shipment = Shipment(org_id=org_id, to_org_id=to_org_id, status="IN_TRANSIT", **kwargs)
    db.add(shipment)
    db.flush()
    audit.record(db, "supply.create_shipment", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="Shipment", entity_id=shipment.id,
                 detail={"sscc": shipment.sscc, "batch_id": shipment.batch_id,
                         "to_org_id": to_org_id})
    if arrived:
        # A completed internal move entered after the fact.
        arrive_shipment(db, shipment, org_id, actor_id, actor_role, arrived)
    return shipment


def arrive_shipment(db: Session, shipment: Shipment, org_id: str, actor_id: str,
                    actor_role: str, arrived_at: datetime,
                    location_name: str | None = None) -> Shipment:
    """The receiver marks a shipment arrived, which records the batch's `receiving` event."""
    if shipment.status != "IN_TRANSIT":
        raise Conflict(f"Shipment {shipment.sscc} is {shipment.status}, not in transit")
    receiver = shipment.to_org_id or shipment.org_id
    if not _is_cross_tenant(actor_role) and org_id != receiver:
        raise PermissionDenied("Only the receiving organisation may mark this shipment arrived")
    arrived = _aware(arrived_at)
    if arrived < _aware(shipment.departed_at):
        raise ValidationFailed("arrived_at must not precede departed_at")
    batch = db.get(Batch, shipment.batch_id)
    # Closed first, so the receiving event's own shipment sync finds nothing left to close.
    shipment.status = "DELIVERED"
    shipment.arrived_at = arrived
    db.flush()
    if batch is not None and batch.state == "IN_TRANSIT":
        record_event(db, batch.custodian_org_id if _is_cross_tenant(actor_role) else org_id,
                     actor_id, actor_role, batch, "receiving", "in_storage", "OBJECT", None,
                     location_name or shipment.destination_name, shipment.destination_lat,
                     shipment.destination_lon, None, None, None, arrived,
                     {"sscc": shipment.sscc})
    _shipment_arrived(db, shipment, org_id, actor_id, actor_role, location_name)
    return shipment


def shipment_views(db: Session, shipments: list[Shipment]) -> list[dict[str, Any]]:
    """Shipments with their batch code, product and cold-chain verdict, for display."""
    batch_ids = {s.batch_id for s in shipments}
    batches = {b.id: b for b in db.execute(
        select(Batch).where(Batch.id.in_(batch_ids))).scalars()} if batch_ids else {}
    product_ids = {b.product_id for b in batches.values()}
    products = {p.id: p for p in db.execute(
        select(Product).where(Product.id.in_(product_ids))).scalars()} if product_ids else {}
    views = []
    for shipment in shipments:
        batch = batches.get(shipment.batch_id)
        product = products.get(batch.product_id) if batch else None
        low = product.storage_temp_min_c if product else None
        high = product.storage_temp_max_c if product else None
        excursion = None
        if shipment.temp_min_c is not None and (low is not None or high is not None):
            excursion = (cold_chain.outside(shipment.temp_min_c, low, high)
                         or cold_chain.outside(shipment.temp_max_c, low, high))
        views.append({
            **{column: getattr(shipment, column) for column in (
                "id", "sscc", "batch_id", "org_id", "to_org_id", "carrier", "origin_name",
                "destination_name", "departed_at", "arrived_at", "status", "temp_min_c",
                "temp_max_c", "cold_chain_device_id")},
            "batch_code": batch.batch_code if batch else None,
            "product_name": product.name if product else None,
            "storage_temp_min_c": low, "storage_temp_max_c": high, "excursion": excursion})
    return views


def refresh_shipment_temperatures(db: Session, shipment: Shipment) -> Shipment:
    summary = telemetry_service.shipment_summary(db, shipment.id)
    shipment.temp_min_c = summary.get("temp_min_c")
    shipment.temp_max_c = summary.get("temp_max_c")
    db.flush()
    return shipment


# --------------------------------------------------------------------------- #
# Certifications (FR-D2)
# --------------------------------------------------------------------------- #
def issue_certification(db: Session, issuer_org_id: str, actor_id: str, actor_role: str,
                        cert_code: str, cert_type: str, standard: str, subject_org_id: str,
                        scope: str, valid_from: datetime, valid_to: datetime) -> Certification:
    if db.execute(select(Certification).where(
            Certification.cert_code == cert_code)).scalar_one_or_none():
        raise Conflict(f"Certification {cert_code} already exists")
    # Four-eyes at organisation level (audit P0-3). A certification is an independent
    # attestation about somebody else; an ORGANIC or NON_GMO claim a body issues to itself
    # carries no assurance, and it reaches the public verification page as if it did.
    if issuer_org_id == subject_org_id:
        raise ValidationFailed(
            "An organisation cannot certify itself. The subject of a certification must be a "
            "different organisation from the issuer.")
    issuer = db.get(Organization, issuer_org_id)
    if issuer is None:
        raise NotFound("Issuing organisation not found")
    trusted = [t.upper() for t in (issuer.trusted_issuer_types or [])]
    if cert_type not in trusted:
        raise ValidationFailed(
            f"{issuer.name} is not a trusted issuer for {cert_type} certifications "
            f"(trusted for: {trusted or 'none'})")
    if db.get(Organization, subject_org_id) is None:
        raise NotFound("Subject organisation not found")
    valid_from, valid_to = _aware(valid_from), _aware(valid_to)
    if valid_to <= valid_from:
        raise ValidationFailed("valid_to must be after valid_from")

    certification = Certification(
        cert_code=cert_code, cert_type=cert_type, standard=standard,
        issuer_org_id=issuer_org_id, subject_org_id=subject_org_id, scope=scope,
        valid_from=valid_from, valid_to=valid_to, status="ACTIVE")
    db.add(certification)
    db.flush()
    digest = content_hash({"cert_code": cert_code, "cert_type": cert_type, "standard": standard,
                           "subject": subject_org_id, "scope": scope,
                           "valid_from": valid_from.isoformat(), "valid_to": valid_to.isoformat()})
    certification.content_hash = digest
    receipt = ledger_client.submit(
        "certification", "Issue",
        {"cert_code": cert_code, "cert_type": cert_type, "standard": standard,
         "subject": subject_org_id, "valid_from": valid_from.isoformat(),
         "valid_to": valid_to.isoformat(), "content_hash": digest},
        _msp_for(db, issuer_org_id), db=db, entity=certification)
    if receipt.get("status") == "REJECTED":
        # The chaincode restricts certification.Issue to RegulatorMSP. Recording the rejection
        # as an anchor_status left an ACTIVE certification in the database that the ledger had
        # refused, so the two diverged silently and the record still read as issued (audit P2).
        raise ValidationFailed(
            f"The ledger refused to anchor this certification: "
            f"{receipt.get('detail', 'rejected by the certification contract')}")
    gmo_service._apply_receipt(db, certification, receipt, "Certification")

    audit.record(db, "cert.issue", actor_id=actor_id, actor_role=actor_role, org_id=issuer_org_id,
                 entity_type="Certification", entity_id=certification.id,
                 detail={"cert_code": cert_code, "cert_type": cert_type,
                         "subject_org_id": subject_org_id})
    notifications.notify_org(
        db, subject_org_id, "CERTIFICATION",
        f"Certification {cert_code} issued to you",
        f"{issuer.name} issued {notifications.with_article(notifications.human_status(cert_type))} "
        f"certification ({standard}) for: {scope}. "
        f"Valid from {notifications.human_date(valid_from)} to "
        f"{notifications.human_date(valid_to)}. You can now "
        f"claim it on batches you own or hold.", "Certification", certification.id)
    return certification


def effective_status(certification: Certification, now: datetime | None = None) -> str:
    """The status a reader should see. A certificate stored ACTIVE but past its valid_to is
    EXPIRED even before the scheduled sweep has persisted that."""
    if certification.status == "ACTIVE" \
            and _aware(certification.valid_to) < (now or utcnow()):
        return "EXPIRED"
    return certification.status


def linked_batches(db: Session, certification: Certification) -> list[Batch]:
    return list(db.execute(select(Batch).join(
        CertificationLink, CertificationLink.batch_id == Batch.id).where(
        CertificationLink.certification_id == certification.id)
        .order_by(Batch.batch_code.asc())).scalars())


def certification_parties(db: Session, certification: Certification,
                          batches: list[Batch] | None = None) -> set[str]:
    """Everyone a change to the certificate concerns: the issuer, the certified organisation,
    and the owner and holder of every batch it is claimed on."""
    batches = linked_batches(db, certification) if batches is None else batches
    parties = {certification.issuer_org_id, certification.subject_org_id}
    for batch in batches:
        parties |= {batch.org_id, batch.custodian_org_id}
    return {p for p in parties if p}


def revoke_certification(db: Session, certification: Certification, actor_id: str,
                         actor_role: str, reason: str) -> Certification:
    if certification.status != "ACTIVE":
        raise Conflict(f"Certification is {certification.status}, not ACTIVE")
    certification.status = "REVOKED"
    certification.revoked_at = utcnow()
    certification.revoke_reason = reason
    db.flush()
    receipt = ledger_client.submit(
        "certification", "Revoke", {"cert_code": certification.cert_code, "reason": reason},
        _msp_for(db, certification.issuer_org_id), db=db)
    db.flush()
    audit.record(db, "cert.revoke", actor_id=actor_id, actor_role=actor_role,
                 org_id=certification.issuer_org_id, entity_type="Certification",
                 entity_id=certification.id,
                 detail={"reason": reason, "anchored": bool(receipt.get("ok"))})

    batches = linked_batches(db, certification)
    for batch in batches:
        # A VERIFIED verdict was reached while this certificate was valid, so it no longer
        # stands. UNVERIFIED rather than SUSPECT: a revocation is not evidence that the batch
        # itself was tampered with, and SUSPECT is the fraud model's verdict, which drives fraud
        # alerts and dashboards. UNVERIFIED says "re-verify"; the next integrity check sees the
        # revoked claim and reaches an evidence-based verdict. A worse verdict is left alone.
        if batch.integrity_status == "VERIFIED":
            batch.integrity_status = "UNVERIFIED"
        notifications.raise_alert(
            db, "CERTIFICATION", "HIGH",
            f"Certification {certification.cert_code} revoked; batch {batch.batch_code} affected",
            detail=reason, org_id=batch.org_id, entity_type="Batch", entity_id=batch.id,
            notify=False, kind=f"cert_revoked:{certification.cert_code}"[:80],
            party_org_id=batch.custodian_org_id)
    db.flush()
    claimed = ", ".join(b.batch_code for b in batches[:20]) or "no batch"
    notifications.notify_parties(
        db, certification_parties(db, certification, batches), "CERTIFICATION",
        f"Certification {certification.cert_code} revoked",
        f"Reason: {reason}. Claimed on: {claimed}. Those batches must be re-verified and may "
        f"no longer carry the {certification.cert_type} claim.",
        "Certification", certification.id, severity="HIGH", include_oversight=True)
    return certification


def sweep_certification_expiry(db: Session, warn_days: int = 30) -> dict[str, int]:
    """Expire certificates past valid_to and warn about those expiring within `warn_days`.

    Both reach the certified organisation and every holder of a batch the certificate is
    claimed on, not only the issuer. Safe to run repeatedly: an expiry happens once (the status
    leaves ACTIVE) and a warning is skipped while one is still open for the certificate.
    """
    from datetime import timedelta

    now = utcnow()
    horizon = now + timedelta(days=warn_days)
    expired = warned = 0
    for certification in list(db.execute(select(Certification).where(
            Certification.status == "ACTIVE",
            Certification.valid_to <= horizon)).scalars()):
        valid_to = _aware(certification.valid_to)
        batches = linked_batches(db, certification)
        claimed = ", ".join(b.batch_code for b in batches[:20]) or "no batch"
        if valid_to < now:
            certification.status = "EXPIRED"
            # Treated as revocation treats it (see revoke_certification): a VERIFIED verdict
            # reached while the certificate was valid no longer stands, so the batch reads
            # UNVERIFIED until it is re-verified. Not SUSPECT: an expiry is not evidence of
            # tampering. A worse verdict is left alone.
            for batch in batches:
                if batch.integrity_status == "VERIFIED":
                    batch.integrity_status = "UNVERIFIED"
            db.flush()
            audit.record(db, "cert.expire", actor_id=None, actor_role=None,
                         org_id=certification.issuer_org_id, entity_type="Certification",
                         entity_id=certification.id,
                         detail={"cert_code": certification.cert_code,
                                 "valid_to": valid_to.isoformat()})
            # The "expires soon" warning has been overtaken by the expiry itself.
            notifications.resolve_entity_alerts(db, "Certification", certification.id, None,
                                                "Superseded: the certificate has expired")
            notifications.raise_alert(
                db, "CERTIFICATION", "WARNING",
                f"Certification {certification.cert_code} has expired",
                detail=f"Valid until {notifications.human_date(valid_to)}. Claimed on: {claimed}.",
                org_id=certification.subject_org_id, entity_type="Certification",
                entity_id=certification.id, notify=False, open_incident=False)
            notifications.notify_parties(
                db, certification_parties(db, certification, batches), "CERTIFICATION",
                f"Certification {certification.cert_code} has expired",
                f"It was valid until {notifications.human_date(valid_to)} and no longer authenticates. "
                f"Claimed on: {claimed}.", "Certification", certification.id,
                severity="WARNING")
            expired += 1
            continue
        if notifications.has_open_alert(db, "CERTIFICATION", certification.id):
            continue
        notifications.raise_alert(
            db, "CERTIFICATION", "WARNING",
            f"Certification {certification.cert_code} expires soon",
            detail=f"Valid until {notifications.human_date(valid_to)}. Claimed on: {claimed}.",
            org_id=certification.issuer_org_id, entity_type="Certification",
            entity_id=certification.id, notify=False, open_incident=False)
        notifications.notify_parties(
            db, certification_parties(db, certification, batches), "CERTIFICATION",
            f"Certification {certification.cert_code} expires soon",
            f"Valid until {notifications.human_date(valid_to)}. Claimed on: {claimed}.",
            "Certification", certification.id, severity="WARNING")
        warned += 1
    return {"expired": expired, "expiring": warned}


def link_certification(db: Session, certification: Certification, batch: Batch, actor_id: str,
                       actor_role: str) -> CertificationLink:
    # BOLA fix: a certification may only be claimed on a batch owned by the organisation
    # it was actually issued to. Without this, any organisation holding a batch could
    # attach ANY other organisation's certification id to it, forging an organic/non-GMO/
    # specialty claim they were never issued — the exact failure FR-D2 exists to prevent.
    # Unguessable UUIDs are not an authorisation boundary; this check is.
    # The producer and the current custodian are both parties to the batch: a processor that
    # received it may claim its own processing certification on it.
    if certification.subject_org_id not in {batch.org_id, batch.custodian_org_id}:
        raise PermissionDenied(
            f"Certification {certification.cert_code} was issued to a different "
            f"organisation and cannot be claimed on this batch")
    status = effective_status(certification)
    if status != "ACTIVE":
        raise ValidationFailed(
            f"Certification {certification.cert_code} is {status}, not ACTIVE, "
            f"and cannot be linked")
    if db.execute(select(CertificationLink).where(
            CertificationLink.certification_id == certification.id,
            CertificationLink.batch_id == batch.id)).scalar_one_or_none():
        raise Conflict("This certification is already linked to the batch")

    # Claim conflict is rejected at link time, not merely flagged later.
    lineage_event = gmo_service.lineage_gmo_event(db, batch)
    if lineage_event and certification.cert_type in {"NON_GMO", "ORGANIC"}:
        raise ValidationFailed(
            f"A {certification.cert_type} certification cannot be claimed on batch "
            f"{batch.batch_code}: its lineage contains GMO event {lineage_event.event_code}")

    link = CertificationLink(certification_id=certification.id, batch_id=batch.id)
    db.add(link)
    db.flush()
    audit.record(db, "cert.link", actor_id=actor_id, actor_role=actor_role, org_id=batch.org_id,
                 entity_type="Batch", entity_id=batch.id,
                 detail={"cert_code": certification.cert_code})
    return link


def authenticate_certifications(db: Session, batch: Batch,
                                as_of: datetime | None = None) -> list[dict[str, Any]]:
    """Validate every certification claimed on a batch (FR-D2)."""
    now = as_of or utcnow()
    results: list[dict[str, Any]] = []
    for link in db.execute(select(CertificationLink).where(
            CertificationLink.batch_id == batch.id)).scalars():
        certification = db.get(Certification, link.certification_id)
        if certification is None:
            continue
        issuer = db.get(Organization, certification.issuer_org_id)
        trusted = certification.cert_type in [t.upper() for t in (issuer.trusted_issuer_types or [])] \
            if issuer else False
        valid_from, valid_to = _aware(certification.valid_from), _aware(certification.valid_to)
        in_window = valid_from <= now <= valid_to
        active = certification.status == "ACTIVE"
        scope_ok = True     # scope is free text in this implementation; see Known Limitations
        results.append({
            "cert_code": certification.cert_code, "cert_type": certification.cert_type,
            "standard": certification.standard,
            "status": effective_status(certification, now),
            "issuer": issuer.name if issuer else "unknown", "issuer_trusted": trusted,
            "valid_from": valid_from, "valid_to": valid_to, "within_validity": in_window,
            "scope_matches": scope_ok,
            "authentic": bool(active and in_window and trusted and scope_ok),
            "anchor_status": certification.anchor_status, "tx_id": certification.tx_id,
        })
    return results


# --------------------------------------------------------------------------- #
# Verification and fraud (FR-D3)
# --------------------------------------------------------------------------- #
def verify_batch(db: Session, batch: Batch, actor_id: str | None = None,
                 actor_role: str | None = None) -> dict[str, Any]:
    settings = get_settings()
    product = db.get(Product, batch.product_id)
    events = chain_of_custody(db, batch)
    certifications = authenticate_certifications(db, batch)
    shipments = list(db.execute(select(Shipment).where(Shipment.batch_id == batch.id)).scalars())

    # Ledger integrity: recompute each anchored record's hash and compare.
    ledger_status = "MATCH"
    mismatches: list[str] = []
    if batch.tx_id and product:
        result = ledger_client.verify_content(content_hash(batch_content(batch, product)),
                                              batch.tx_id)
        if result.get("result") == "MISMATCH":
            ledger_status = "MISMATCH"
            mismatches.append(f"batch:{batch.batch_code}")
    for event in events:
        if not event.tx_id:
            continue
        result = ledger_client.verify_content(content_hash(event_content(event, batch)),
                                              event.tx_id)
        if result.get("result") == "MISMATCH":
            ledger_status = "MISMATCH"
            mismatches.append(f"event:{event.id}")

    # Independent second opinion from the Hyperledger Fabric network, when connected.
    # Informational: it does not change the fraud score, which the local check already drives.
    fabric_status = None
    if product is not None:
        from . import fabric_bridge                                   # noqa: PLC0415

        if fabric_bridge.enabled():
            fabric_status = fabric_bridge.verify(
                f"batch:{batch.batch_code}", content_hash(batch_content(batch, product))
            ).get("result")

    telemetry_summary: dict[str, Any] = {}
    for shipment in shipments:
        summary = telemetry_service.shipment_summary(db, shipment.id)
        if summary.get("temp_max_c") is not None:
            telemetry_summary = summary
            break

    lineage_event = gmo_service.lineage_gmo_event(db, batch)
    duplicate = db.execute(select(Batch).where(Batch.batch_code == batch.batch_code,
                                               Batch.id != batch.id)).scalar_one_or_none()

    context = {
        "batch": {"quantity": batch.quantity,
                  "initial_quantity": batch.initial_quantity,
                  "gmo_event_id": batch.gmo_event_id,
                  "gmo_event_code": lineage_event.event_code if lineage_event else None},
        "events": [{"biz_step": e.biz_step, "occurred_at": _aware(e.occurred_at),
                    "quantity": e.quantity} for e in events],
        "certifications": [{"cert_code": c["cert_code"], "cert_type": c["cert_type"],
                            "status": c["status"], "valid_from": c["valid_from"],
                            "valid_to": c["valid_to"]} for c in certifications],
        "shipments": [{"origin_lat": s.origin_lat, "origin_lon": s.origin_lon,
                       "destination_lat": s.destination_lat, "destination_lon": s.destination_lon,
                       "departed_at": _aware(s.departed_at), "arrived_at": _aware(s.arrived_at)}
                      for s in shipments],
        "product": {"organic_claim": product.organic_claim if product else False,
                    "non_gmo_claim": product.non_gmo_claim if product else False,
                    "storage_temp_min_c": product.storage_temp_min_c if product else None,
                    "storage_temp_max_c": product.storage_temp_max_c if product else None},
        "telemetry_summary": telemetry_summary,
        "ledger_status": ledger_status,
        "unanchored_events": sum(1 for e in events if not e.tx_id),
        "duplicate_batch_code": bool(duplicate),
    }

    verdict = ai_client.evaluate_fraud(context,
                                       suspect_threshold=settings.fraud_suspect_threshold,
                                       fail_threshold=settings.fraud_fail_threshold)

    integrity = {"VERIFIED": "VERIFIED", "SUSPECT": "SUSPECT", "FAILED": "FAILED"}[verdict["level"]]
    batch.integrity_status = integrity
    # Stored for both parties to the batch: the owner, and the custodian — usually the
    # processor that ran the check, which otherwise could not read its own result.
    db.add(FraudAssessment(batch_id=batch.id, org_id=batch.org_id,
                           custodian_org_id=batch.custodian_org_id, score=verdict["score"],
                           level=verdict["level"], reasons=verdict["reasons"],
                           ledger_status=ledger_status, model_version=verdict["model_version"]))
    db.flush()

    if actor_id:
        audit.record(db, "supply.verify_batch", actor_id=actor_id, actor_role=actor_role,
                     org_id=batch.org_id, entity_type="Batch", entity_id=batch.id,
                     outcome="SUCCESS" if integrity == "VERIFIED" else "FAILURE",
                     detail={"integrity": integrity, "fraud_score": verdict["score"],
                             "ledger_status": ledger_status,
                             "rules": verdict["rules_triggered"]})

    if integrity != "VERIFIED":
        # kind="fraud": re-verifying a batch that still fails folds into the open alert
        # (escalating it from SUSPECT to FAILED) instead of stacking another one.
        notifications.alert_parties(
            db, "FRAUD", "CRITICAL" if integrity == "FAILED" else "HIGH",
            f"Supply-chain integrity check flagged batch {batch.batch_code}",
            detail=f"Verdict: {integrity.lower()}. "
                   + "; ".join(r["detail"] for r in verdict["reasons"][:3]),
            org_id=batch.org_id, party_org_ids=[batch.custodian_org_id],
            entity_type="Batch", entity_id=batch.id,
            reasons=[r["rule"] for r in verdict["reasons"]], kind="fraud",
            party_org_id=batch.custodian_org_id)
    else:
        notifications.resolve_alerts(
            db, "FRAUD", batch.id, kind="fraud", actor_id=actor_id,
            note="A later integrity check verified the batch")

    return {
        "integrity_status": integrity, "fraud_score": verdict["score"],
        "fraud_level": verdict["level"], "ledger_status": ledger_status,
        "fabric_status": fabric_status,
        "ledger_mismatches": mismatches, "reasons": verdict["reasons"],
        "events_checked": len(events), "certifications_checked": len(certifications),
        "verified_at": utcnow(), "model_version": verdict["model_version"],
    }


# --------------------------------------------------------------------------- #
# Public consumer verification (FR-D4)
# --------------------------------------------------------------------------- #
STAGE_LABELS = {
    "commissioning": "Created", "harvesting": "Harvested", "transforming": "Processed",
    "packing": "Packaged", "shipping": "Shipped", "receiving": "Received",
    "storing": "Stored", "retail_selling": "On sale", "recalling": "Recalled",
}

DISCLAIMER = ("Provenance is recorded on a permissioned ledger operated for this demonstration "
              "(single-node ordering). Verification confirms that records have not been altered "
              "since they were anchored.")


def public_verification(db: Session, code: str) -> dict[str, Any]:
    """Unauthenticated projection. Exposes no farmer identity, coordinates or commercial terms."""
    batch = db.execute(select(Batch).where(Batch.verification_code == code)).scalar_one_or_none()
    if batch is None:
        raise NotFound("No product found for this verification code")

    product = db.get(Product, batch.product_id)
    events = chain_of_custody(db, batch)
    certifications = authenticate_certifications(db, batch)
    lineage_event = gmo_service.lineage_gmo_event(db, batch)

    journey = []
    for event in events:
        organization = db.get(Organization, event.org_id)
        journey.append({
            "stage": STAGE_LABELS.get(event.biz_step, event.biz_step),
            "occurred_at": _aware(event.occurred_at),
            "location": event.location_name,          # place name only, never coordinates
            "organization_type": organization.org_type if organization else None,
            "verified": event.anchor_status == "ANCHORED",
        })

    chain = ledger_client.verify_chain()
    return {
        "verification_code": code,
        "product_name": product.name if product else "Unknown",
        "product_category": product.category if product else "Unknown",
        "batch_state": batch.state,
        "origin_region": batch.origin_region,
        "origin_country": batch.origin_country,
        "harvested_at": _aware(batch.harvested_at),
        "gmo_status": "CONTAINS_GMO" if lineage_event else "NO_GMO_RECORDED",
        "gmo_event_code": lineage_event.event_code if lineage_event else None,
        "certifications": [
            {"type": c["cert_type"], "standard": c["standard"], "status": c["status"],
             "authentic": c["authentic"], "valid_to": c["valid_to"]} for c in certifications],
        "journey": journey,
        "ledger_verified": bool(chain.get("valid")) and batch.anchor_status == "ANCHORED",
        "integrity_status": batch.integrity_status,
        "disclaimer": DISCLAIMER,
    }
