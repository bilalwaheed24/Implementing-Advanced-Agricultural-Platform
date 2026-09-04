"""Ledger explorer and verification endpoints (FR-B4)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..core.deps import DbSession, rate_limit, require_permission
from ..core.errors import NotFound, ValidationFailed
from ..core.permissions import P
from ..core.security import content_hash
from ..models import Batch, Certification, ComplianceReport, GMOEvent, Product, SupplyChainEvent
from ..schemas import VerifyRecordRequest
from ..services import gmo as gmo_service, ledger_client, supplychain as supply_service

router = APIRouter(prefix="/blockchain", tags=["Blockchain"], dependencies=[Depends(rate_limit)])


@router.get("/stats", summary="Ledger height, transactions and participants")
def stats(principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]) -> dict:
    return {**ledger_client.stats(),
            "marking": "DEMO/SIMULATION: single-node ordering. Cryptography is real "
                       "(ECDSA P-256, SHA-256, Merkle trees)."}


@router.get("/verify", summary="Replay and verify the whole chain")
def verify_chain(principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]
                 ) -> dict:
    return ledger_client.verify_chain()


@router.get("/blocks", summary="Recent blocks")
def blocks(principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))],
           limit: int = Query(default=20, ge=1, le=100)) -> dict:
    ledger = ledger_client.get_ledger()
    return {"height": ledger.height, "blocks": ledger.recent_blocks(limit)}


@router.get("/blocks/{number}", summary="Get one block")
def get_block(number: int,
              principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]) -> dict:
    block = ledger_client.get_ledger().get_block(number)
    if block is None:
        raise NotFound("Block not found")
    return block


@router.get("/transactions/{tx_id}", summary="Get one transaction")
def get_transaction(tx_id: str,
                    principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]
                    ) -> dict:
    record = ledger_client.get_ledger().get_transaction(tx_id)
    if record is None:
        raise NotFound("Transaction not found")
    return record


@router.get("/transactions/{tx_id}/proof", summary="Merkle inclusion proof for a transaction")
def proof(tx_id: str,
          principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]) -> dict:
    result = ledger_client.get_ledger().proof(tx_id)
    if result is None:
        raise NotFound("Transaction not found")
    return result


@router.get("/state/{key:path}", summary="Read a world-state key")
def state(key: str,
          principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]) -> dict:
    value = ledger_client.query(key)
    if value is None:
        raise NotFound("State key not found")
    return {"key": key, "value": value}


def _require_visible(principal, org_ids: set[str | None]) -> None:
    """IDOR/BOLA guard: verifying a record is a read of its content hash and anchor
    status, which is enough to confirm existence and tamper status of another
    organisation's data. Only that record's own organisation(s), or a platform-wide
    oversight role, may verify it — everyone else gets the same 404 an unknown id
    would give, so existence is not disclosed either."""
    if principal.is_cross_tenant:
        return
    if principal.org_id not in org_ids:
        raise NotFound("Record not found")


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
    elif entity_type == "BATCH":
        batch = db.get(Batch, payload.entity_id)
        if batch is None:
            raise NotFound("Batch not found")
        _require_visible(principal, {batch.org_id})
        product = db.get(Product, batch.product_id)
        digest, tx_id, stored = content_hash(supply_service.batch_content(batch, product)), \
            batch.tx_id, batch.content_hash
    elif entity_type == "SUPPLY_CHAIN_EVENT":
        event = db.get(SupplyChainEvent, payload.entity_id)
        if event is None:
            raise NotFound("Event not found")
        _require_visible(principal, {event.org_id})
        batch = db.get(Batch, event.batch_id)
        digest, tx_id, stored = content_hash(supply_service.event_content(event, batch)), \
            event.tx_id, event.content_hash
    elif entity_type == "CERTIFICATION":
        certification = db.get(Certification, payload.entity_id)
        if certification is None:
            raise NotFound("Certification not found")
        _require_visible(principal, {certification.issuer_org_id, certification.subject_org_id})
        digest, tx_id, stored = certification.content_hash or "", certification.tx_id, \
            certification.content_hash
    elif entity_type == "COMPLIANCE_REPORT":
        report = db.get(ComplianceReport, payload.entity_id)
        if report is None:
            raise NotFound("Report not found")
        _require_visible(principal, {report.org_id})
        digest = content_hash({"subject": report.subject_id, "jurisdiction": report.jurisdiction,
                               "status": report.status, "results": report.results})
        tx_id, stored = report.tx_id, report.content_hash
    else:
        raise ValidationFailed(
            "entity_type must be one of GMO_EVENT, BATCH, SUPPLY_CHAIN_EVENT, "
            "CERTIFICATION, COMPLIANCE_REPORT")

    result = ledger_client.verify_content(digest, tx_id)
    return {**result, "entity_type": entity_type, "entity_id": payload.entity_id,
            "computed_hash": digest, "stored_hash": stored, "tx_id": tx_id}


@router.get("/contracts", summary="Deployed chaincode functions and endorsement policies")
def contracts(principal: Annotated[object, Depends(require_permission(P.BLOCKCHAIN_READ))]) -> dict:
    from ledger.contracts import CONTRACTS, ENDORSEMENT_POLICIES, SUBMIT_RIGHTS

    return {
        "contracts": {name: sorted(functions) for name, functions in CONTRACTS.items()},
        "endorsement_policies": ENDORSEMENT_POLICIES,
        "submit_rights": {k: sorted(v) for k, v in SUBMIT_RIGHTS.items()},
    }
