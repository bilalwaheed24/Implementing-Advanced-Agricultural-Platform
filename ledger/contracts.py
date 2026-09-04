"""Chaincode-style smart contracts (Blockchain-integration.md §5).

Each contract function receives (state, args, submitter_msp) and returns a
(read_set, write_set) pair, or raises ContractError. Contracts are deterministic:
no clocks, no randomness, no external calls.
"""
from __future__ import annotations

from typing import Any, Callable

from .block import sha256_hex


class ContractError(Exception):
    """A contract rejected a transaction. No block is produced."""


# Endorsement policies: which MSPs must endorse a function.
# "AND" = every listed MSP must sign; "OR" = at least one must sign.
ENDORSEMENT_POLICIES: dict[str, dict[str, Any]] = {
    "gmo_registry.RegisterEvent":     {"rule": "AND", "orgs": ["BiotechMSP", "RegulatorMSP"]},
    "gmo_registry.RecordApproval":    {"rule": "AND", "orgs": ["RegulatorMSP"]},
    "gmo_registry.RegisterSeedLot":   {"rule": "OR",  "orgs": ["BiotechMSP"]},
    "provenance.CreateBatch":         {"rule": "OR",  "orgs": ["FarmMSP", "SupplyMSP", "BiotechMSP"]},
    "provenance.RecordEvent":         {"rule": "OR",  "orgs": ["FarmMSP", "SupplyMSP"]},
    "provenance.TransferCustody":     {"rule": "OR",  "orgs": ["FarmMSP", "SupplyMSP"]},
    "certification.Issue":            {"rule": "AND", "orgs": ["RegulatorMSP"]},
    "certification.Revoke":           {"rule": "AND", "orgs": ["RegulatorMSP"]},
    "compliance_anchor.AnchorReport": {"rule": "OR",  "orgs": ["RegulatorMSP", "SupplyMSP"]},
    "compliance_anchor.AnchorAuditHead": {"rule": "OR",
                                          "orgs": ["RegulatorMSP", "SupplyMSP", "FarmMSP", "BiotechMSP"]},
}

# Which MSPs may *submit* each function (authorisation, distinct from endorsement).
SUBMIT_RIGHTS: dict[str, set[str]] = {
    "gmo_registry.RegisterEvent": {"BiotechMSP"},
    "gmo_registry.RecordApproval": {"RegulatorMSP"},
    "gmo_registry.RegisterSeedLot": {"BiotechMSP"},
    "provenance.CreateBatch": {"FarmMSP", "SupplyMSP", "BiotechMSP"},
    "provenance.RecordEvent": {"FarmMSP", "SupplyMSP"},
    "provenance.TransferCustody": {"FarmMSP", "SupplyMSP"},
    "certification.Issue": {"RegulatorMSP"},
    "certification.Revoke": {"RegulatorMSP"},
    "compliance_anchor.AnchorReport": {"RegulatorMSP", "SupplyMSP"},
    "compliance_anchor.AnchorAuditHead": {"RegulatorMSP", "SupplyMSP", "FarmMSP", "BiotechMSP"},
}

# Legal batch state transitions enforced on-chain.
BATCH_TRANSITIONS: dict[str, set[str]] = {
    "CREATED": {"HARVESTED", "PROCESSED", "IN_TRANSIT", "RECALLED"},
    "HARVESTED": {"PROCESSED", "IN_TRANSIT", "STORED", "RECALLED"},
    "PROCESSED": {"PACKAGED", "IN_TRANSIT", "STORED", "RECALLED"},
    "PACKAGED": {"IN_TRANSIT", "STORED", "RECALLED"},
    "IN_TRANSIT": {"RECEIVED", "STORED", "RECALLED"},
    "RECEIVED": {"PROCESSED", "PACKAGED", "IN_TRANSIT", "STORED", "RETAILED", "RECALLED"},
    "STORED": {"IN_TRANSIT", "PROCESSED", "PACKAGED", "RETAILED", "RECALLED"},
    "RETAILED": {"CONSUMED", "RECALLED"},
    "CONSUMED": set(),
    "RECALLED": set(),
}

BIZ_STEP_TO_STATE = {
    "commissioning": "CREATED",
    "harvesting": "HARVESTED",
    "transforming": "PROCESSED",
    "packing": "PACKAGED",
    "shipping": "IN_TRANSIT",
    "receiving": "RECEIVED",
    "storing": "STORED",
    "retail_selling": "RETAILED",
    "recalling": "RECALLED",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _num(value: Any, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"{name} must be numeric") from exc
    _require(result >= 0, f"{name} must not be negative")
    return result


# --------------------------------------------------------------------------- #
# gmo_registry
# --------------------------------------------------------------------------- #
def register_event(state: dict[str, Any], args: dict[str, Any], msp: str):
    key = f"gmo:{args['event_code']}"
    _require(key not in state, f"GMO event {args['event_code']} already registered")
    for required in ("event_code", "crop_type", "trait", "donor_organism", "developer", "screening_hash"):
        _require(bool(args.get(required)), f"{required} is required")
    _require(len(args["screening_hash"]) == 64, "screening_hash must be a SHA-256 hex digest")
    record = {
        "type": "gmo_event", "event_code": args["event_code"], "crop_type": args["crop_type"],
        "trait": args["trait"], "donor_organism": args["donor_organism"],
        "developer": args["developer"], "screening_hash": args["screening_hash"],
        "content_hash": args.get("content_hash", ""), "registered_by": msp,
    }
    return [key], {key: record}


def record_approval(state: dict[str, Any], args: dict[str, Any], msp: str):
    gmo_key = f"gmo:{args['event_code']}"
    _require(gmo_key in state, f"Unknown GMO event {args['event_code']}")
    _require(args.get("status") in {"APPROVED", "PENDING", "REJECTED", "NOT_SUBMITTED"},
             "Invalid approval status")
    key = f"gmoapproval:{args['event_code']}:{args['jurisdiction']}"
    record = {"type": "gmo_approval", "event_code": args["event_code"],
              "jurisdiction": args["jurisdiction"], "status": args["status"],
              "reference": args.get("reference", ""), "recorded_by": msp}
    return [gmo_key, key], {key: record}


def register_seed_lot(state: dict[str, Any], args: dict[str, Any], msp: str):
    key = f"seedlot:{args['lot_code']}"
    _require(key not in state, f"Seed lot {args['lot_code']} already exists")
    quantity = _num(args.get("quantity_kg"), "quantity_kg")
    read_set = [key]
    if args.get("event_code"):
        gmo_key = f"gmo:{args['event_code']}"
        _require(gmo_key in state, f"Unknown GMO event {args['event_code']}")
        read_set.append(gmo_key)
    record = {"type": "seed_lot", "lot_code": args["lot_code"], "event_code": args.get("event_code"),
              "quantity_kg": quantity, "producer": msp, "content_hash": args.get("content_hash", "")}
    return read_set, {key: record}


# --------------------------------------------------------------------------- #
# provenance
# --------------------------------------------------------------------------- #
def create_batch(state: dict[str, Any], args: dict[str, Any], msp: str):
    key = f"batch:{args['batch_code']}"
    _require(key not in state, f"Batch {args['batch_code']} already exists")   # duplicate-code fraud
    quantity = _num(args.get("quantity"), "quantity")
    read_set = [key]
    parents = args.get("parents") or []
    parent_total = 0.0
    for parent_code in parents:
        parent_key = f"batch:{parent_code}"
        _require(parent_key in state, f"Unknown parent batch {parent_code}")
        read_set.append(parent_key)
        parent_total += float(state[parent_key].get("quantity", 0))
    if parents:
        _require(quantity <= parent_total + 1e-9,
                 f"Quantity {quantity} exceeds combined parent quantity {parent_total}")
    record = {"type": "batch", "batch_code": args["batch_code"], "product": args.get("product", ""),
              "quantity": quantity, "unit": args.get("unit", "kg"), "state": "CREATED",
              "custodian": msp, "origin": args.get("origin", ""), "parents": parents,
              "gmo_event": args.get("gmo_event"), "content_hash": args.get("content_hash", "")}
    return read_set, {key: record}


def record_event(state: dict[str, Any], args: dict[str, Any], msp: str):
    batch_key = f"batch:{args['batch_code']}"
    _require(batch_key in state, f"Unknown batch {args['batch_code']}")
    batch = dict(state[batch_key])
    biz_step = args.get("biz_step", "")
    _require(biz_step in BIZ_STEP_TO_STATE, f"Unknown business step {biz_step}")
    new_state = BIZ_STEP_TO_STATE[biz_step]
    current = batch.get("state", "CREATED")
    if new_state != current:
        _require(new_state in BATCH_TRANSITIONS.get(current, set()),
                 f"Illegal transition {current} -> {new_state}; allowed: "
                 f"{sorted(BATCH_TRANSITIONS.get(current, set()))}")
    if args.get("quantity") is not None:
        quantity = _num(args["quantity"], "quantity")
        _require(quantity <= float(batch.get("quantity", 0)) + 1e-9,
                 "Event quantity exceeds the batch quantity (quantity conservation)")
        batch["quantity"] = quantity
    event_key = f"event:{args['event_id']}"
    _require(event_key not in state, "Duplicate supply-chain event id")
    batch["state"] = new_state
    event_record = {"type": "sc_event", "batch_code": args["batch_code"], "biz_step": biz_step,
                    "disposition": args.get("disposition", ""), "location": args.get("location_gln", ""),
                    "quantity": args.get("quantity"), "recorded_by": msp,
                    "content_hash": args.get("content_hash", ""), "occurred_at": args.get("occurred_at", "")}
    return [batch_key, event_key], {event_key: event_record, batch_key: batch}


def transfer_custody(state: dict[str, Any], args: dict[str, Any], msp: str):
    batch_key = f"batch:{args['batch_code']}"
    _require(batch_key in state, f"Unknown batch {args['batch_code']}")
    batch = dict(state[batch_key])
    _require(batch.get("custodian") == args.get("from_org"),
             f"Current custodian is {batch.get('custodian')}, not {args.get('from_org')}")
    _require(msp in {args.get("from_org"), args.get("to_org")},
             "Custody transfer must be submitted by a participating organisation")
    batch["custodian"] = args["to_org"]
    history = list(batch.get("custody_history", []))
    history.append({"from": args["from_org"], "to": args["to_org"], "at": args.get("occurred_at", "")})
    batch["custody_history"] = history
    return [batch_key], {batch_key: batch}


# --------------------------------------------------------------------------- #
# certification
# --------------------------------------------------------------------------- #
def issue_certification(state: dict[str, Any], args: dict[str, Any], msp: str):
    key = f"cert:{args['cert_code']}"
    _require(key not in state, f"Certification {args['cert_code']} already issued")
    _require(args.get("cert_type") in {"ORGANIC", "NON_GMO", "SPECIALTY"}, "Unknown certification type")
    _require(bool(args.get("valid_from")) and bool(args.get("valid_to")), "Validity window is required")
    _require(str(args["valid_to"]) > str(args["valid_from"]), "valid_to must be after valid_from")
    record = {"type": "certification", "cert_code": args["cert_code"], "cert_type": args["cert_type"],
              "standard": args.get("standard", ""), "subject": args.get("subject", ""),
              "valid_from": args["valid_from"], "valid_to": args["valid_to"],
              "status": "ACTIVE", "issuer": msp, "content_hash": args.get("content_hash", "")}
    return [key], {key: record}


def revoke_certification(state: dict[str, Any], args: dict[str, Any], msp: str):
    key = f"cert:{args['cert_code']}"
    _require(key in state, f"Unknown certification {args['cert_code']}")
    record = dict(state[key])
    _require(record.get("issuer") == msp, "Only the issuing organisation may revoke a certification")
    _require(record.get("status") == "ACTIVE", "Certification is not active")
    record["status"] = "REVOKED"
    record["revoke_reason"] = args.get("reason", "")
    return [key], {key: record}


# --------------------------------------------------------------------------- #
# compliance_anchor
# --------------------------------------------------------------------------- #
def anchor_report(state: dict[str, Any], args: dict[str, Any], msp: str):
    key = f"report:{args['report_id']}"
    _require(key not in state, "Report already anchored")
    _require(len(args.get("content_hash", "")) == 64, "content_hash must be a SHA-256 hex digest")
    record = {"type": "compliance_report", "report_id": args["report_id"],
              "subject": args.get("subject", ""), "jurisdiction": args.get("jurisdiction", ""),
              "status": args.get("status", ""), "content_hash": args["content_hash"], "anchored_by": msp}
    return [key], {key: record}


def anchor_audit_head(state: dict[str, Any], args: dict[str, Any], msp: str):
    key = "audithead:latest"
    seq = int(args.get("seq", 0))
    if key in state:
        _require(seq >= int(state[key].get("seq", 0)), "Audit head sequence must not go backwards")
    _require(len(args.get("head_hash", "")) == 64, "head_hash must be a SHA-256 hex digest")
    record = {"type": "audit_head", "seq": seq, "head_hash": args["head_hash"], "anchored_by": msp}
    return [key], {key: record}


CONTRACTS: dict[str, dict[str, Callable]] = {
    "gmo_registry": {
        "RegisterEvent": register_event,
        "RecordApproval": record_approval,
        "RegisterSeedLot": register_seed_lot,
    },
    "provenance": {
        "CreateBatch": create_batch,
        "RecordEvent": record_event,
        "TransferCustody": transfer_custody,
    },
    "certification": {
        "Issue": issue_certification,
        "Revoke": revoke_certification,
    },
    "compliance_anchor": {
        "AnchorReport": anchor_report,
        "AnchorAuditHead": anchor_audit_head,
    },
}


def resolve(contract: str, function: str) -> Callable:
    if contract not in CONTRACTS or function not in CONTRACTS[contract]:
        raise ContractError(f"Unknown chaincode function {contract}.{function}")
    return CONTRACTS[contract][function]


def content_digest(payload: Any) -> str:
    from .block import canonical

    return sha256_hex(canonical(payload))
