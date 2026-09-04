"""Products, batches, EPCIS events, shipments, certifications, fraud and verification.

FR-B2 (provenance), FR-D1 (traceability + IoT), FR-D2 (certification authentication),
FR-D3 (fraud detection), FR-D4 (consumer verification).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.errors import Conflict, NotFound, PermissionDenied, ValidationFailed
from ..core.security import ensure_aware as _aware, content_hash, utcnow, verification_code
from ..models import (Batch, Certification, CertificationLink, FraudAssessment, Organization,
                      Product, Shipment, SupplyChainEvent)
from . import audit, gmo as gmo_service, ledger_client, notifications, telemetry as telemetry_service

BIZ_STEP_TO_STATE = {
    "commissioning": "CREATED", "harvesting": "HARVESTED", "transforming": "PROCESSED",
    "packing": "PACKAGED", "shipping": "IN_TRANSIT", "receiving": "RECEIVED",
    "storing": "STORED", "retail_selling": "RETAILED", "recalling": "RECALLED",
}


def _msp_for(db: Session, org_id: str) -> str:
    organization = db.get(Organization, org_id)
    if organization is None:
        raise NotFound("Organisation not found")
    return organization.msp_id




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
    product = db.get(Product, product_id)
    if product is None or product.deleted_at is not None:
        raise NotFound("Product not found")

    parent = None
    if parent_batch_id:
        parent = db.get(Batch, parent_batch_id)
        if parent is None:
            raise NotFound("Parent batch not found")
        if quantity > parent.quantity + 1e-9:
            raise ValidationFailed(
                f"Quantity {quantity} exceeds the parent batch quantity {parent.quantity}")

    batch = Batch(org_id=org_id, batch_code=batch_code, verification_code=verification_code(),
                  product_id=product_id, parent_batch_id=parent_batch_id, seed_lot_id=seed_lot_id,
                  crop_id=crop_id, farm_id=farm_id, gmo_event_id=gmo_event_id,
                  quantity=quantity, initial_quantity=quantity, unit=unit,
                  custodian_org_id=org_id,
                  origin_region=origin_region, origin_country=origin_country,
                  harvested_at=_aware(harvested_at), created_by=actor_id)
    db.add(batch)
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
        _msp_for(db, org_id))
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
    if quantity is not None and quantity > batch.quantity + 1e-9:
        raise ValidationFailed(
            f"Event quantity {quantity} exceeds the batch quantity {batch.quantity} "
            f"(quantity conservation)")

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
        _msp_for(db, org_id))

    if receipt.get("status") == "REJECTED":
        # The contract enforces the lifecycle; surface its reason to the caller.
        db.expunge(event)
        raise ValidationFailed(receipt.get("detail", "Ledger rejected the event"))

    gmo_service._apply_receipt(db, event, receipt, "SupplyChainEvent")

    new_state = BIZ_STEP_TO_STATE.get(biz_step)
    if new_state:
        batch.state = new_state
    if quantity is not None:
        batch.quantity = quantity

    if to_org_id and to_org_id != batch.custodian_org_id:
        transfer_custody(db, batch, org_id, to_org_id, occurred_at)

    db.flush()
    audit.record(db, "supply.record_event", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="SupplyChainEvent", entity_id=event.id,
                 detail={"batch_code": batch.batch_code, "biz_step": biz_step,
                         "anchor_status": event.anchor_status})
    return event


def transfer_custody(db: Session, batch: Batch, from_org_id: str, to_org_id: str,
                     occurred_at: datetime) -> dict[str, Any]:
    receiving = db.get(Organization, to_org_id)
    if receiving is None:
        raise NotFound("Receiving organisation not found")
    receipt = ledger_client.submit(
        "provenance", "TransferCustody",
        {"batch_code": batch.batch_code, "from_org": _msp_for(db, from_org_id),
         "to_org": receiving.msp_id, "occurred_at": _aware(occurred_at).isoformat()},
        _msp_for(db, from_org_id))
    if receipt.get("ok"):
        batch.custodian_org_id = to_org_id
        db.flush()
    return receipt


def chain_of_custody(db: Session, batch: Batch) -> list[SupplyChainEvent]:
    return list(db.execute(
        select(SupplyChainEvent).where(SupplyChainEvent.batch_id == batch.id)
        .order_by(SupplyChainEvent.occurred_at.asc())).scalars())


def lineage(db: Session, batch: Batch, max_depth: int = 12) -> list[Batch]:
    chain, current, depth = [], batch, 0
    while current and depth < max_depth:
        chain.append(current)
        current = db.get(Batch, current.parent_batch_id) if current.parent_batch_id else None
        depth += 1
    return chain


# --------------------------------------------------------------------------- #
# Shipments
# --------------------------------------------------------------------------- #
def create_shipment(db: Session, org_id: str, actor_id: str, actor_role: str, **kwargs) -> Shipment:
    if db.execute(select(Shipment).where(Shipment.sscc == kwargs["sscc"])).scalar_one_or_none():
        raise Conflict(f"Shipment {kwargs['sscc']} already exists")
    batch = db.get(Batch, kwargs["batch_id"])
    if batch is None:
        raise NotFound("Batch not found")
    arrived = _aware(kwargs.get("arrived_at"))
    departed = _aware(kwargs["departed_at"])
    if arrived and arrived < departed:
        raise ValidationFailed("arrived_at must not precede departed_at")
    kwargs["departed_at"] = departed
    kwargs["arrived_at"] = arrived
    shipment = Shipment(org_id=org_id, status="DELIVERED" if arrived else "IN_TRANSIT", **kwargs)
    db.add(shipment)
    db.flush()
    audit.record(db, "supply.create_shipment", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="Shipment", entity_id=shipment.id,
                 detail={"sscc": shipment.sscc, "batch_id": shipment.batch_id})
    return shipment


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
        _msp_for(db, issuer_org_id))
    gmo_service._apply_receipt(db, certification, receipt, "Certification")

    audit.record(db, "cert.issue", actor_id=actor_id, actor_role=actor_role, org_id=issuer_org_id,
                 entity_type="Certification", entity_id=certification.id,
                 detail={"cert_code": cert_code, "cert_type": cert_type,
                         "subject_org_id": subject_org_id})
    return certification


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
        _msp_for(db, certification.issuer_org_id))
    db.flush()
    audit.record(db, "cert.revoke", actor_id=actor_id, actor_role=actor_role,
                 org_id=certification.issuer_org_id, entity_type="Certification",
                 entity_id=certification.id,
                 detail={"reason": reason, "anchored": bool(receipt.get("ok"))})

    for link in db.execute(select(CertificationLink).where(
            CertificationLink.certification_id == certification.id)).scalars():
        batch = db.get(Batch, link.batch_id)
        if batch:
            notifications.raise_alert(
                db, "CERTIFICATION", "HIGH",
                f"Certification {certification.cert_code} revoked; batch {batch.batch_code} affected",
                detail=reason, org_id=batch.org_id, entity_type="Batch", entity_id=batch.id)
    return certification


def link_certification(db: Session, certification: Certification, batch: Batch, actor_id: str,
                       actor_role: str) -> CertificationLink:
    # BOLA fix: a certification may only be claimed on a batch owned by the organisation
    # it was actually issued to. Without this, any organisation holding a batch could
    # attach ANY other organisation's certification id to it, forging an organic/non-GMO/
    # specialty claim they were never issued — the exact failure FR-D2 exists to prevent.
    # Unguessable UUIDs are not an authorisation boundary; this check is.
    if certification.subject_org_id != batch.org_id:
        raise PermissionDenied(
            f"Certification {certification.cert_code} was issued to a different "
            f"organisation and cannot be claimed on this batch")
    if certification.status != "ACTIVE":
        raise ValidationFailed(
            f"Certification {certification.cert_code} is {certification.status}, not ACTIVE, "
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
            "standard": certification.standard, "status": certification.status,
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
    from ai.fraud import evaluate

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

    verdict = evaluate(context, model_dir=str(settings.repo_root / "ai" / "models"),
                       suspect_threshold=settings.fraud_suspect_threshold,
                       fail_threshold=settings.fraud_fail_threshold)

    integrity = {"VERIFIED": "VERIFIED", "SUSPECT": "SUSPECT", "FAILED": "FAILED"}[verdict["level"]]
    batch.integrity_status = integrity
    db.add(FraudAssessment(batch_id=batch.id, org_id=batch.org_id, score=verdict["score"],
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
        notifications.raise_alert(
            db, "FRAUD", "CRITICAL" if integrity == "FAILED" else "HIGH",
            f"Supply-chain integrity {integrity} for batch {batch.batch_code}",
            detail="; ".join(r["detail"] for r in verdict["reasons"][:3]),
            org_id=batch.org_id, entity_type="Batch", entity_id=batch.id,
            reasons=[r["rule"] for r in verdict["reasons"]])

    return {
        "integrity_status": integrity, "fraud_score": verdict["score"],
        "fraud_level": verdict["level"], "ledger_status": ledger_status,
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
