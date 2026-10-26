"""Ledger explorer and verification endpoints (FR-B4)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from sqlalchemy import select

from ..core.deps import DbSession, rate_limit, require_permission
from ..core.errors import NotFound, ValidationFailed
from ..core.permissions import P, has_permission
from ..core.security import content_hash
from ..models import (Batch, Certification, CertificationLink, ComplianceReport, GMOEvent,
                      Product, SupplyChainEvent)
from ..repositories import get_or_404
from ..schemas import VerifyRecordRequest
from ..services import (anchoring, audit, compliance as compliance_service, fabric_bridge,
                        gmo as gmo_service, ledger_client, supplychain as supply_service)

router = APIRouter(prefix="/blockchain", tags=["Blockchain"], dependencies=[Depends(rate_limit)])


@router.get("/stats", summary="Ledger height, transactions and participants")
def stats(principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]) -> dict:
    """Height and transaction count are proof-of-activity and safe for every role. The
    participant list names every organisation on the channel, so it is withheld from roles
    without BLOCKCHAIN_EXPLORE."""
    payload = dict(ledger_client.stats())
    if not has_permission(principal.role, P.BLOCKCHAIN_EXPLORE):
        payload.pop("organizations", None)
        payload.pop("by_function", None)
    return {**payload,
            "marking": "DEMO/SIMULATION: single-node ordering. Cryptography is real "
                       "(ECDSA P-256, SHA-256, Merkle trees)."}


@router.get("/verify", summary="Replay and verify the whole chain")
def verify_chain(principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]
                 ) -> dict:
    return ledger_client.verify_chain()


@router.get("/blocks", summary="Recent blocks")
def blocks(principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_EXPLORE))],
           limit: int = Query(default=20, ge=1, le=100)) -> dict:
    return ledger_client.recent_blocks(limit)


@router.get("/blocks/{number}", summary="Get one block")
def get_block(number: int,
              principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_EXPLORE))]) -> dict:
    block = ledger_client.get_block(number)
    if block is None:
        raise NotFound("Block not found")
    return block


@router.get("/transactions/{tx_id}", summary="Get one transaction")
def get_transaction(tx_id: str,
                    principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_EXPLORE))]
                    ) -> dict:
    record = ledger_client.get_transaction(tx_id)
    if record is None:
        raise NotFound("Transaction not found")
    return record


@router.get("/transactions/{tx_id}/proof", summary="Merkle inclusion proof for a transaction")
def proof(tx_id: str,
          principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]) -> dict:
    result = ledger_client.proof(tx_id)
    if result is None:
        raise NotFound("Transaction not found")
    return result


@router.get("/state/{key:path}", summary="Read a world-state key")
def state(key: str,
          principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_EXPLORE))]) -> dict:
    value = ledger_client.query(key)
    if value is None:
        raise NotFound("State key not found")
    return {"key": key, "value": value}


def _require_visible(principal, org_ids: set[str | None]) -> None:
    """IDOR/BOLA guard: verifying a record is a read of its content hash and anchor
    status, which is enough to confirm existence and tamper status of another
    organisation's data. Only the parties that may read the record, or a platform-wide
    oversight role, may verify it — everyone else gets the same 404 an unknown id
    would give, so existence is not disclosed either."""
    if principal.is_cross_tenant:
        return
    if principal.org_id not in org_ids:
        raise NotFound("Record not found")


def _can_read_batch(db, principal, batch_id: str) -> bool:
    """The read visibility of GET /supply-chain/batches/{id}: owner, custodian, the issuer of
    a certificate claimed on it, or an oversight role."""
    try:
        supply_service.readable_batch(db, batch_id, principal.role, principal.org_id)
    except NotFound:
        return False
    return True


@router.post("/verify-record", summary="Verify a stored record against its ledger anchor")
def verify_record(payload: VerifyRecordRequest, db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]
                  ) -> dict:
    """Recomputes the entity's content hash and compares it with the anchored value.
    MISMATCH means the stored record was altered after it was anchored. Restricted to
    the record's own organisation(s) or a cross-tenant oversight role (T-05/BOLA)."""
    entity_type = payload.entity_type.upper()
    if entity_type == "GMO_EVENT":
        event = db.get(GMOEvent, payload.entity_id)
        if event is None:
            raise NotFound("GMO event not found")
        digest, tx_id, stored = content_hash(gmo_service.event_content(event)), event.tx_id, \
            event.content_hash
        _require_visible(principal, {event.org_id})
        fabric_key = f"gmo:{event.event_code}"
    elif entity_type == "BATCH":
        # The same visibility as reading the batch (owner, custodian, certifier, oversight),
        # not only the creating organisation.
        batch = supply_service.readable_batch(db, payload.entity_id, principal.role,
                                              principal.org_id)
        product = db.get(Product, batch.product_id)
        digest, tx_id, stored = content_hash(supply_service.batch_content(batch, product)), \
            batch.tx_id, batch.content_hash
        fabric_key = f"batch:{batch.batch_code}"
    elif entity_type == "SUPPLY_CHAIN_EVENT":
        event = db.get(SupplyChainEvent, payload.entity_id)
        if event is None:
            raise NotFound("Event not found")
        # Whoever recorded the event, and whoever may read the batch's chain of custody.
        if not (principal.is_cross_tenant or event.org_id == principal.org_id
                or _can_read_batch(db, principal, event.batch_id)):
            raise NotFound("Event not found")
        batch = db.get(Batch, event.batch_id)
        if not (principal.is_cross_tenant or event.org_id == principal.org_id
                or principal.org_id in {batch.org_id, batch.custodian_org_id}):
            # Read through a certificate only (round 6): the events its certified
            # organisation(s) took part in, as the batch's chain of custody shows them.
            from .supplychain import certificate_subjects, event_involves  # noqa: PLC0415

            if not event_involves(event, certificate_subjects(db, principal, batch.id)):
                raise NotFound("Event not found")
        digest, tx_id, stored = content_hash(supply_service.event_content(event, batch)), \
            event.tx_id, event.content_hash
        fabric_key = f"event:{event.id}"
    elif entity_type == "CERTIFICATION":
        certification = db.get(Certification, payload.entity_id)
        if certification is None:
            raise NotFound("Certification not found")
        # As GET /supply-chain/certifications: issuer, subject, and the owner or holder of a
        # batch the certificate is claimed on.
        parties = {certification.issuer_org_id, certification.subject_org_id}
        for batch in db.execute(select(Batch).join(
                CertificationLink, CertificationLink.batch_id == Batch.id).where(
                CertificationLink.certification_id == certification.id)).scalars():
            parties |= {batch.org_id, batch.custodian_org_id}
        _require_visible(principal, parties)
        digest, tx_id, stored = certification.content_hash or "", certification.tx_id, \
            certification.content_hash
        fabric_key = f"cert:{certification.cert_code}"
    elif entity_type == "COMPLIANCE_REPORT":
        # Runner, the batch's owner and custodian, or oversight: the report list's visibility.
        report = get_or_404(db, ComplianceReport, payload.entity_id, principal.role,
                            principal.org_id, name="Report")
        # Exactly what was anchored: the subject's business code, not its id.
        digest = compliance_service.report_digest(db, report)
        tx_id, stored = report.tx_id, report.content_hash
        fabric_key = f"report:{report.id}"
    else:
        raise ValidationFailed(
            "entity_type must be one of GMO_EVENT, BATCH, SUPPLY_CHAIN_EVENT, "
            "CERTIFICATION, COMPLIANCE_REPORT")

    result = ledger_client.verify_content(digest, tx_id)
    response = {**result, "entity_type": entity_type, "entity_id": payload.entity_id,
                "computed_hash": digest, "stored_hash": stored, "tx_id": tx_id}
    if fabric_bridge.enabled():
        # Second, independent opinion from the Fabric network (two organisations' peers).
        response["fabric"] = fabric_bridge.verify(fabric_key, digest)
    return response


@router.get("/fabric", summary="Hyperledger Fabric mirror: connection and recent anchors")
def fabric_status(db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]
                  ) -> dict:
    """Counts come from the ledger_writes journal, so they survive a restart; `recent` is
    this API process's own feed."""
    body = fabric_bridge.status()
    if body.get("enabled"):
        body.update(anchoring.mirror_counts(db))
    return body


@router.get("/anchors", summary="Anchoring journal: writes by anchor status")
def anchor_status(db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_EXPLORE))]
                  ) -> dict:
    return {"anchors": anchoring.anchor_counts(db), "fabric": anchoring.mirror_counts(db)}


@router.post("/anchors/retry", summary="Replay unanchored ledger writes and re-mirror to Fabric")
def retry_anchors(db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.AUDIT_ANCHOR))]
                  ) -> dict:
    """The same sweep scripts/scheduled_tasks.py runs: replays PENDING/FAILED writes in
    order, then mirrors anchored writes whose Fabric copy failed or never happened. Submits
    ledger transactions, hence AUDIT_ANCHOR (ADMIN, SECURITY_ANALYST)."""
    retried = anchoring.retry_pending(db)
    db.commit()
    mirrored = anchoring.remirror(db)
    audit.record(db, "blockchain.anchor_retry", actor_id=principal.id, actor_role=principal.role,
                 org_id=principal.org_id, entity_type="LedgerWrite", entity_id=None,
                 detail={"retry": retried, "fabric": mirrored})
    db.commit()
    return {"retry": retried, "fabric": mirrored, "anchors": anchoring.anchor_counts(db)}


@router.get("/fabric/history", summary="Every Fabric version of one anchored key")
def fabric_history(principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_EXPLORE))],
                   key: str = Query(min_length=3, max_length=140,
                                    pattern=r"^[a-z_]{2,20}:[A-Za-z0-9._:-]{1,120}$")) -> dict:
    return fabric_bridge.history(key)


@router.get("/contracts", summary="Deployed chaincode functions and endorsement policies")
def contracts(principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]) -> dict:
    return ledger_client.contracts()
