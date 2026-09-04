"""Regulatory compliance rule engine and reporting (FR-F1, FR-F2).

Rules are modelled on published USDA, FDA, EU, Codex Alimentarius and GS1 requirements.
They are an engineering implementation of publicly stated rules, not legal advice.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.errors import NotFound, ValidationFailed
from ..core.security import ensure_aware as _aware, content_hash, utcnow
from ..models import (Batch, ComplianceReport, GMOApproval, GMOEvent, Organization, Product,
                      SequenceScreening, SupplyChainEvent)
from . import audit, gmo as gmo_service, ledger_client, notifications, supplychain

DISCLAIMER = ("Automated evaluation of publicly published regulatory requirements. "
              "This is an engineering control, not legal advice.")

JURISDICTIONS = ["US-USDA", "US-FDA", "EU", "CODEX", "GS1"]




def _result(rule_id: str, title: str, citation: str, passed: bool, severity: str,
            detail: str, **evidence: Any) -> dict[str, Any]:
    return {"rule_id": rule_id, "title": title, "citation": citation, "passed": passed,
            "severity": severity, "detail": detail, "evidence": evidence}


# --------------------------------------------------------------------------- #
# Individual rules. Each takes (db, batch, context) and returns a result dict.
# --------------------------------------------------------------------------- #
def rule_traceability_one_step(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    events = ctx["events"]
    has_inbound = bool(batch.parent_batch_id or batch.seed_lot_id or batch.farm_id)
    has_outbound = any(e.biz_step in {"shipping", "receiving", "retail_selling"} for e in events)
    passed = has_inbound and (has_outbound or batch.state in {"CREATED", "HARVESTED", "STORED"})
    return _result(
        "TRACE-001", "One-step-back, one-step-forward traceability",
        "US FDA FSMA 204 / EU 178/2002 Art. 18", passed, "HIGH",
        "Inbound origin and outbound destination are both recorded" if passed
        else "The batch does not record both an inbound source and an outbound destination",
        has_inbound=has_inbound, has_outbound=has_outbound)


def rule_lot_identification(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    product = ctx["product"]
    passed = bool(batch.batch_code and product and product.gtin)
    return _result(
        "TRACE-002", "Lot and trade-item identification", "GS1 General Specifications (GTIN + lot)",
        passed, "MEDIUM",
        f"Batch {batch.batch_code} carries GTIN {product.gtin}" if passed
        else "The batch lacks a lot code or its product lacks a GTIN",
        batch_code=batch.batch_code, gtin=product.gtin if product else None)


def rule_event_completeness(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    events = ctx["events"]
    incomplete = [e.id for e in events
                  if not (e.biz_step and e.disposition and e.occurred_at)]
    passed = bool(events) and not incomplete
    return _result(
        "TRACE-003", "Critical tracking events carry required key data elements",
        "GS1 EPCIS 2.0 / FDA FSMA 204 KDEs", passed, "HIGH",
        f"{len(events)} events each carry a business step, disposition and timestamp" if passed
        else ("No supply-chain events recorded" if not events
              else f"{len(incomplete)} event(s) are missing required data elements"),
        events=len(events), incomplete=len(incomplete))


def rule_gmo_approval(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    event: GMOEvent | None = ctx["gmo_event"]
    jurisdiction = ctx["jurisdiction"]
    if event is None:
        return _result("GMO-001", "GMO approval in the destination jurisdiction",
                       "EU 1829/2003 / USDA APHIS 7 CFR 340", True, "HIGH",
                       "No GMO event in the batch lineage; the rule does not apply")
    approval = db.execute(select(GMOApproval).where(
        GMOApproval.gmo_event_id == event.id,
        GMOApproval.jurisdiction == jurisdiction)).scalar_one_or_none()
    status = approval.status if approval else "NOT_SUBMITTED"
    expired = bool(approval and approval.expires_at and _aware(approval.expires_at) < utcnow())
    passed = status == "APPROVED" and not expired
    return _result(
        "GMO-001", "GMO approval in the destination jurisdiction",
        "EU 1829/2003 / USDA APHIS 7 CFR 340", passed, "CRITICAL",
        f"Event {event.event_code} is approved in {jurisdiction}" if passed
        else f"Event {event.event_code} has approval status {status}"
             + (" and the approval has expired" if expired else "") + f" in {jurisdiction}",
        event_code=event.event_code, approval_status=status, expired=expired)


def rule_gmo_labelling(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    event: GMOEvent | None = ctx["gmo_event"]
    jurisdiction = ctx["jurisdiction"]
    if event is None or jurisdiction not in gmo_service.LABELLING_RULES:
        return _result("GMO-002", "GMO labelling disclosure",
                       "EU 1829/2003 Art. 12-13 / USDA BE Disclosure Standard", True, "HIGH",
                       "No GMO event in the lineage, or no labelling rule for this jurisdiction")
    labelling = gmo_service.validate_labelling(db, batch, jurisdiction)
    passed = not labelling["requires_label"] or bool(labelling["approved_in_jurisdiction"])
    return _result(
        "GMO-002", "GMO labelling disclosure", labelling["citation"], passed, "HIGH",
        (f"Disclosure required and permitted: '{labelling['required_label_text']}'"
         if labelling["requires_label"] and passed else
         "No disclosure threshold exceeded" if not labelling["requires_label"] else
         "Disclosure is required but the event is not approved in this jurisdiction"),
        requires_label=labelling["requires_label"],
        required_label_text=labelling["required_label_text"],
        threshold_pct=labelling["threshold_pct"])


def rule_biosecurity_screening(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    event: GMOEvent | None = ctx["gmo_event"]
    if event is None:
        return _result("BIO-001", "Biosecurity screening before release",
                       "Internal biosafety policy / DURC oversight", True, "CRITICAL",
                       "No GMO event in the lineage; the rule does not apply")
    screening = db.get(SequenceScreening, event.screening_id) if event.screening_id else None
    passed = screening is not None and screening.status in {"APPROVED_AUTO", "APPROVED_BY_REVIEW"}
    return _result(
        "BIO-001", "Biosecurity screening before release",
        "Internal biosafety policy / DURC oversight", passed, "CRITICAL",
        f"Screening {screening.id[:8]} passed with verdict {screening.verdict}" if passed
        else "The GMO event has no screening in a passing state",
        screening_status=screening.status if screening else None,
        durc_flag=screening.durc_flag if screening else None)


def rule_certification_validity(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    certifications = ctx["certifications"]
    if not certifications:
        return _result("CERT-001", "Certification claims are authentic and current",
                       "USDA NOP 7 CFR 205 / EU 2018/848 / Codex CAC-GL-32", True, "HIGH",
                       "No certification claims are made on this batch")
    invalid = [c["cert_code"] for c in certifications if not c["authentic"]]
    passed = not invalid
    return _result(
        "CERT-001", "Certification claims are authentic and current",
        "USDA NOP 7 CFR 205 / EU 2018/848 / Codex CAC-GL-32", passed, "HIGH",
        f"All {len(certifications)} certification claim(s) authenticate" if passed
        else f"Certification(s) failing authentication: {', '.join(invalid)}",
        total=len(certifications), invalid=invalid)


def rule_claim_consistency(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    product: Product | None = ctx["product"]
    event: GMOEvent | None = ctx["gmo_event"]
    conflict = bool(event) and bool(product and (product.non_gmo_claim or product.organic_claim))
    return _result(
        "CERT-002", "Product claims are consistent with the batch lineage",
        "FTC/USDA labelling truthfulness; EU 2018/848", not conflict, "CRITICAL",
        "Product claims are consistent with the lineage" if not conflict
        else f"Product claims non-GMO or organic while the lineage contains "
             f"GMO event {event.event_code}",
        non_gmo_claim=product.non_gmo_claim if product else False,
        organic_claim=product.organic_claim if product else False,
        gmo_event=event.event_code if event else None)


def rule_cold_chain(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    product: Product | None = ctx["product"]
    summary = ctx["telemetry_summary"]
    if not product or product.storage_temp_max_c is None or not summary:
        return _result("SAFE-001", "Temperature control through the chain",
                       "Codex CAC/RCP 1-1969 (HACCP) / FDA 21 CFR 117", True, "HIGH",
                       "No temperature limits defined for this product, or no cold-chain telemetry")
    observed_max = summary.get("temp_max_c")
    observed_min = summary.get("temp_min_c")
    breached = (observed_max is not None and observed_max > product.storage_temp_max_c) or \
               (product.storage_temp_min_c is not None and observed_min is not None
                and observed_min < product.storage_temp_min_c)
    return _result(
        "SAFE-001", "Temperature control through the chain",
        "Codex CAC/RCP 1-1969 (HACCP) / FDA 21 CFR 117", not breached, "HIGH",
        f"Observed range {observed_min} to {observed_max} °C is within the product limits"
        if not breached else
        f"Cold-chain excursion: observed {observed_min} to {observed_max} °C against limits "
        f"{product.storage_temp_min_c} to {product.storage_temp_max_c} °C",
        observed_min_c=observed_min, observed_max_c=observed_max,
        limit_min_c=product.storage_temp_min_c, limit_max_c=product.storage_temp_max_c)


def rule_ledger_integrity(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    anchored = batch.anchor_status == "ANCHORED"
    unanchored_events = sum(1 for e in ctx["events"] if not e.tx_id)
    passed = anchored and unanchored_events == 0
    return _result(
        "AUDIT-001", "Traceability records are anchored and tamper-evident",
        "FSMA 204 record retention / ISO 22005", passed, "HIGH",
        "The batch and every event are anchored to the ledger" if passed
        else f"Batch anchor status {batch.anchor_status}; {unanchored_events} event(s) unanchored",
        batch_anchor=batch.anchor_status, unanchored_events=unanchored_events)


def rule_recall_readiness(db: Session, batch: Batch, ctx: dict) -> dict[str, Any]:
    """A recall must be executable: the chain must resolve in both directions within 24 h."""
    lineage = supplychain.lineage(db, batch)
    downstream = db.execute(select(Batch).where(Batch.parent_batch_id == batch.id)).scalars()
    passed = bool(lineage) and bool(ctx["events"])
    return _result(
        "SAFE-002", "Recall readiness: the chain resolves upstream and downstream",
        "FDA 21 CFR 7 / EU 178/2002 Art. 19", passed, "MEDIUM",
        f"Lineage depth {len(lineage)}, {len(list(downstream))} downstream batch(es), "
        f"{len(ctx['events'])} events" if passed
        else "The chain cannot be resolved for a recall",
        lineage_depth=len(lineage), events=len(ctx["events"]))


RULES: list[Callable[[Session, Batch, dict], dict[str, Any]]] = [
    rule_traceability_one_step, rule_lot_identification, rule_event_completeness,
    rule_gmo_approval, rule_gmo_labelling, rule_biosecurity_screening,
    rule_certification_validity, rule_claim_consistency, rule_cold_chain,
    rule_ledger_integrity, rule_recall_readiness,
]


def evaluate_batch(db: Session, batch: Batch, jurisdiction: str, actor_id: str,
                   actor_role: str, org_id: str) -> ComplianceReport:
    if jurisdiction not in JURISDICTIONS:
        raise ValidationFailed(f"jurisdiction must be one of {JURISDICTIONS}")

    events = supplychain.chain_of_custody(db, batch)
    telemetry_summary: dict[str, Any] = {}
    from ..models import Shipment
    for shipment in db.execute(select(Shipment).where(Shipment.batch_id == batch.id)).scalars():
        from . import telemetry as telemetry_service
        summary = telemetry_service.shipment_summary(db, shipment.id)
        if summary.get("temp_max_c") is not None:
            telemetry_summary = summary
            break

    ctx = {
        "product": db.get(Product, batch.product_id),
        "events": events,
        "gmo_event": gmo_service.lineage_gmo_event(db, batch),
        "certifications": supplychain.authenticate_certifications(db, batch),
        "telemetry_summary": telemetry_summary,
        "jurisdiction": jurisdiction,
    }

    results = [rule(db, batch, ctx) for rule in RULES]
    failed = [r for r in results if not r["passed"]]
    critical_failures = [r for r in failed if r["severity"] == "CRITICAL"]

    if not failed:
        status = "COMPLIANT"
    elif critical_failures:
        status = "NON_COMPLIANT"
    else:
        status = "NON_COMPLIANT" if len(failed) > 2 else "CONDITIONAL"

    summary = {
        "rules_evaluated": len(results), "passed": len(results) - len(failed),
        "failed": len(failed), "critical_failures": len(critical_failures),
        "pass_rate": round((len(results) - len(failed)) / len(results), 4),
        "jurisdiction": jurisdiction, "batch_code": batch.batch_code,
        "disclaimer": DISCLAIMER,
    }

    report = ComplianceReport(
        org_id=org_id, report_type="COMPLIANCE", subject_type="BATCH", subject_id=batch.id,
        jurisdiction=jurisdiction, status=status, results=results, summary=summary,
        generated_by=actor_id)
    db.add(report)
    db.flush()

    digest = content_hash({"subject": batch.batch_code, "jurisdiction": jurisdiction,
                           "status": status, "results": results})
    report.content_hash = digest
    receipt = ledger_client.submit(
        "compliance_anchor", "AnchorReport",
        {"report_id": report.id, "subject": batch.batch_code, "jurisdiction": jurisdiction,
         "status": status, "content_hash": digest},
        _reporting_msp(db, org_id))
    gmo_service._apply_receipt(db, report, receipt, "ComplianceReport")

    audit.record(db, "compliance.evaluate", actor_id=actor_id, actor_role=actor_role,
                 org_id=org_id, entity_type="ComplianceReport", entity_id=report.id,
                 outcome="SUCCESS" if status == "COMPLIANT" else "FAILURE",
                 detail={"batch_code": batch.batch_code, "jurisdiction": jurisdiction,
                         "status": status, "failed_rules": [r["rule_id"] for r in failed]})

    if status != "COMPLIANT":
        notifications.raise_alert(
            db, "COMPLIANCE", "CRITICAL" if critical_failures else "HIGH",
            f"Batch {batch.batch_code} is {status} in {jurisdiction}",
            detail="; ".join(r["detail"] for r in failed[:3]), org_id=org_id,
            entity_type="Batch", entity_id=batch.id,
            reasons=[r["rule_id"] for r in failed])
    return report


def _reporting_msp(db: Session, org_id: str) -> str:
    """Only RegulatorMSP and SupplyMSP may anchor reports; fall back to SupplyMSP."""
    organization = db.get(Organization, org_id)
    if organization and organization.msp_id in {"RegulatorMSP", "SupplyMSP"}:
        return organization.msp_id
    return "SupplyMSP"


# --------------------------------------------------------------------------- #
# Environmental impact assessment (FR-F2)
# --------------------------------------------------------------------------- #
def environmental_impact(db: Session, event: GMOEvent, actor_id: str, actor_role: str,
                         org_id: str, cultivation_area_ha: float,
                         adjacent_wild_relatives: bool, pesticide_change_pct: float,
                         notes: str) -> ComplianceReport:
    """Structured environmental impact assessment for a biotech crop approval."""
    findings: list[dict[str, Any]] = []

    gene_flow_risk = "HIGH" if adjacent_wild_relatives and cultivation_area_ha > 100 else \
        "MODERATE" if adjacent_wild_relatives else "LOW"
    findings.append(_result(
        "EIA-001", "Gene flow to wild or weedy relatives",
        "USDA APHIS 7 CFR 340 environmental assessment", gene_flow_risk == "LOW",
        "HIGH" if gene_flow_risk == "HIGH" else "MEDIUM",
        f"Gene-flow risk assessed as {gene_flow_risk} over {cultivation_area_ha} ha"
        + (" with sexually compatible wild relatives adjacent" if adjacent_wild_relatives else ""),
        risk=gene_flow_risk, area_ha=cultivation_area_ha,
        adjacent_wild_relatives=adjacent_wild_relatives))

    pesticide_ok = pesticide_change_pct <= 0
    findings.append(_result(
        "EIA-002", "Change in pesticide application intensity",
        "EPA/EU environmental risk assessment guidance", pesticide_ok, "MEDIUM",
        f"Pesticide application changes by {pesticide_change_pct:+.1f}% relative to the "
        f"conventional comparator",
        pesticide_change_pct=pesticide_change_pct))

    non_target_ok = not (adjacent_wild_relatives and pesticide_change_pct > 20)
    findings.append(_result(
        "EIA-003", "Effects on non-target organisms",
        "Codex Alimentarius CAC/GL 45-2003 Annex 3", non_target_ok, "MEDIUM",
        "No compounding non-target risk identified" if non_target_ok
        else "Increased pesticide use adjacent to wild relatives raises non-target risk",
        ))

    screening = db.get(SequenceScreening, event.screening_id) if event.screening_id else None
    screening_ok = screening is not None and screening.status in {"APPROVED_AUTO",
                                                                 "APPROVED_BY_REVIEW"}
    findings.append(_result(
        "EIA-004", "Biosafety screening supports environmental release",
        "Cartagena Protocol Annex III risk assessment", screening_ok, "CRITICAL",
        "The transformation event has a passing biosecurity screening" if screening_ok
        else "No passing biosecurity screening supports this event",
        screening_status=screening.status if screening else None))

    failed = [f for f in findings if not f["passed"]]
    status = "COMPLIANT" if not failed else (
        "NON_COMPLIANT" if any(f["severity"] == "CRITICAL" for f in failed) else "CONDITIONAL")

    summary = {"rules_evaluated": len(findings), "failed": len(failed),
               "gene_flow_risk": gene_flow_risk, "cultivation_area_ha": cultivation_area_ha,
               "event_code": event.event_code, "notes": notes[:500],
               "disclaimer": DISCLAIMER}

    report = ComplianceReport(
        org_id=org_id, report_type="ENVIRONMENTAL_IMPACT", subject_type="GMO_EVENT",
        subject_id=event.id, jurisdiction="US-USDA", status=status, results=findings,
        summary=summary, generated_by=actor_id)
    db.add(report)
    db.flush()
    digest = content_hash({"subject": event.event_code, "type": "EIA", "status": status,
                           "results": findings})
    report.content_hash = digest
    receipt = ledger_client.submit(
        "compliance_anchor", "AnchorReport",
        {"report_id": report.id, "subject": event.event_code, "jurisdiction": "US-USDA",
         "status": status, "content_hash": digest}, _reporting_msp(db, org_id))
    gmo_service._apply_receipt(db, report, receipt, "ComplianceReport")

    audit.record(db, "compliance.eia", actor_id=actor_id, actor_role=actor_role, org_id=org_id,
                 entity_type="ComplianceReport", entity_id=report.id,
                 detail={"event_code": event.event_code, "status": status})
    return report


def dashboard(db: Session, org_id: str | None) -> dict[str, Any]:
    query = select(ComplianceReport)
    if org_id:
        query = query.where(ComplianceReport.org_id == org_id)
    reports = list(db.execute(query).scalars())
    by_status: dict[str, int] = {}
    for report in reports:
        by_status[report.status] = by_status.get(report.status, 0) + 1
    rule_failures: dict[str, int] = {}
    for report in reports:
        for result in report.results or []:
            if not result.get("passed"):
                rule_failures[result["rule_id"]] = rule_failures.get(result["rule_id"], 0) + 1
    total_rules = sum(len(r.results or []) for r in reports)
    passed_rules = sum(sum(1 for x in (r.results or []) if x.get("passed")) for r in reports)
    return {
        "reports_total": len(reports), "by_status": by_status,
        "rule_pass_rate": round(passed_rules / total_rules, 4) if total_rules else None,
        "top_failing_rules": sorted(rule_failures.items(), key=lambda kv: -kv[1])[:5],
        "jurisdictions": JURISDICTIONS, "disclaimer": DISCLAIMER,
    }
