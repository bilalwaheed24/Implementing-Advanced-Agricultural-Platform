"""Regulatory compliance evaluation and reporting (FR-F1, FR-F2)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.permissions import P
from ..models import Batch, ComplianceReport, GMOEvent
from ..repositories import get_or_404, paginate, visible
from ..schemas import ComplianceReportOut, ComplianceRequest, EIARequest, Page
from ..services import compliance as service

router = APIRouter(prefix="/compliance", tags=["Compliance"], dependencies=[Depends(rate_limit)])


@router.post("/evaluate", response_model=ComplianceReportOut, status_code=201,
             summary="Evaluate a batch against a jurisdiction's rule set")
def evaluate(payload: ComplianceRequest, db: DbSession,
             principal: Annotated[object, Depends(require_permission(P.COMPLIANCE_RUN))]
             ) -> ComplianceReportOut:
    batch = get_or_404(db, Batch, payload.subject_id, principal.role, principal.org_id,
                       name="Batch")
    report = service.evaluate_batch(db, batch, payload.jurisdiction.upper(), principal.id,
                                    principal.role, principal.org_id)
    db.commit()
    return ComplianceReportOut.model_validate(report)


@router.post("/eia", response_model=ComplianceReportOut, status_code=201,
             summary="Generate an environmental impact assessment for a biotech crop")
def environmental_impact(payload: EIARequest, db: DbSession,
                         principal: Annotated[object, Depends(require_permission(P.COMPLIANCE_RUN))]
                         ) -> ComplianceReportOut:
    event = get_or_404(db, GMOEvent, payload.gmo_event_id, principal.role, principal.org_id,
                       name="GMO event")
    report = service.environmental_impact(
        db, event, principal.id, principal.role, principal.org_id, payload.cultivation_area_ha,
        payload.adjacent_wild_relatives, payload.pesticide_change_pct, payload.notes)
    db.commit()
    return ComplianceReportOut.model_validate(report)


@router.get("/reports", response_model=Page[ComplianceReportOut], summary="List reports")
def list_reports(db: DbSession, paging: PagingDep,
                 principal: Annotated[object, Depends(require_permission(P.COMPLIANCE_READ))],
                 jurisdiction: str | None = Query(default=None),
                 report_type: str | None = Query(default=None)) -> Page[ComplianceReportOut]:
    query = visible(ComplianceReport, principal.role, principal.org_id).order_by(
        ComplianceReport.created_at.desc())
    if jurisdiction:
        query = query.where(ComplianceReport.jurisdiction == jurisdiction.upper())
    if report_type:
        query = query.where(ComplianceReport.report_type == report_type.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[ComplianceReportOut](items=[ComplianceReportOut.model_validate(r) for r in rows],
                                     total=total, page=paging.page, page_size=paging.page_size)


@router.get("/reports/{report_id}", response_model=ComplianceReportOut, summary="Get a report")
def get_report(report_id: str, db: DbSession,
               principal: Annotated[object, Depends(require_permission(P.COMPLIANCE_READ))]
               ) -> ComplianceReportOut:
    return ComplianceReportOut.model_validate(
        get_or_404(db, ComplianceReport, report_id, principal.role, principal.org_id,
                   name="Report"))


@router.get("/dashboard", summary="Compliance dashboard")
def dashboard(db: DbSession,
              principal: Annotated[object, Depends(require_permission(P.COMPLIANCE_READ))]) -> dict:
    org_id = None if principal.is_cross_tenant else principal.org_id
    return service.dashboard(db, org_id)


@router.get("/rules", summary="The implemented rule set and its citations")
def rules(principal: Annotated[object, Depends(require_permission(P.COMPLIANCE_READ))]) -> dict:
    catalogue = []
    for rule in service.RULES:
        doc = (rule.__doc__ or "").strip().splitlines()
        catalogue.append({"function": rule.__name__,
                          "description": doc[0] if doc else rule.__name__})
    return {"jurisdictions": service.JURISDICTIONS, "rules": catalogue,
            "disclaimer": service.DISCLAIMER}
