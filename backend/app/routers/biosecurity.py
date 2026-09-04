"""Sequence screening, CRISPR risk assessment, DURC review (FR-C1..C4)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..core.deps import DbSession, PagingDep, rate_limit, require_permission
from ..core.permissions import P
from ..models import CrisprAssessment, HazardSequence, SequenceScreening
from ..repositories import get_or_404, paginate, visible
from ..schemas import (CrisprCreate, CrisprOut, HazardCreate, HazardOut, Page, ReviewDecision,
                       ScreeningCreate, ScreeningDetail, ScreeningHitOut, ScreeningOut)
from ..services import biosecurity as service

router = APIRouter(prefix="/biosecurity", tags=["Biosecurity"],
                   dependencies=[Depends(rate_limit)])


@router.post("/screenings", response_model=ScreeningDetail, status_code=201,
             summary="Screen a nucleotide sequence against the hazard database")
def submit_screening(payload: ScreeningCreate, db: DbSession,
                     principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_SUBMIT))]
                     ) -> ScreeningDetail:
    """A BLOCK verdict can only be released by a biosafety officer."""
    screening = service.submit_screening(
        db, principal.org_id, principal.id, principal.role, payload.name, payload.sequence,
        payload.intent, payload.organism)
    hits = service.get_hits(db, screening.id)
    db.commit()
    detail = ScreeningDetail.model_validate(screening)
    detail.hits = [ScreeningHitOut.model_validate(h) for h in hits]
    return detail


@router.get("/screenings", response_model=Page[ScreeningOut], summary="List screenings")
def list_screenings(db: DbSession, paging: PagingDep,
                    principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_READ))],
                    verdict: str | None = Query(default=None),
                    status_filter: str | None = Query(default=None, alias="status")
                    ) -> Page[ScreeningOut]:
    query = visible(SequenceScreening, principal.role, principal.org_id).order_by(
        SequenceScreening.created_at.desc())
    if verdict:
        query = query.where(SequenceScreening.verdict == verdict.upper())
    if status_filter:
        query = query.where(SequenceScreening.status == status_filter.upper())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[ScreeningOut](items=[ScreeningOut.model_validate(r) for r in rows], total=total,
                              page=paging.page, page_size=paging.page_size)


@router.get("/screenings/queue", response_model=list[ScreeningOut],
            summary="Biosafety review queue")
def review_queue(db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_REVIEW))]
                 ) -> list[ScreeningOut]:
    return [ScreeningOut.model_validate(s) for s in service.review_queue(db)]


@router.get("/screenings/{screening_id}", response_model=ScreeningDetail,
            summary="Screening detail with alignment evidence")
def get_screening(screening_id: str, db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_READ))]
                  ) -> ScreeningDetail:
    screening = get_or_404(db, SequenceScreening, screening_id, principal.role, principal.org_id,
                           name="Screening")
    detail = ScreeningDetail.model_validate(screening)
    detail.hits = [ScreeningHitOut.model_validate(h) for h in service.get_hits(db, screening.id)]
    return detail


@router.post("/screenings/{screening_id}/review", response_model=ScreeningOut,
             summary="Approve or reject a flagged or blocked screening")
def review_screening(screening_id: str, payload: ReviewDecision, db: DbSession,
                     principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_REVIEW))]
                     ) -> ScreeningOut:
    screening = get_or_404(db, SequenceScreening, screening_id, principal.role, principal.org_id,
                           name="Screening")
    service.review_screening(db, screening, principal.id, principal.role, payload.decision,
                             payload.rationale)
    db.commit()
    return ScreeningOut.model_validate(screening)


@router.post("/crispr", response_model=CrisprOut, status_code=201,
             summary="Assess the risk of a CRISPR gene-edit proposal")
def assess_crispr(payload: CrisprCreate, db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_SUBMIT))]
                  ) -> CrisprOut:
    assessment = service.assess_crispr(
        db, principal.org_id, principal.id, principal.role, payload.target_gene, payload.organism,
        payload.organism_class, payload.guide_rna, payload.pam, payload.edit_type, payload.intent,
        payload.reference_sequence)
    db.commit()
    return CrisprOut.model_validate(assessment)


@router.get("/crispr", response_model=Page[CrisprOut], summary="List CRISPR assessments")
def list_crispr(db: DbSession, paging: PagingDep,
                principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_READ))],
                risk_level: str | None = Query(default=None),
                durc_only: bool = Query(default=False)) -> Page[CrisprOut]:
    query = visible(CrisprAssessment, principal.role, principal.org_id).order_by(
        CrisprAssessment.created_at.desc())
    if risk_level:
        query = query.where(CrisprAssessment.risk_level == risk_level.upper())
    if durc_only:
        query = query.where(CrisprAssessment.durc_flag.is_(True))
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[CrisprOut](items=[CrisprOut.model_validate(r) for r in rows], total=total,
                           page=paging.page, page_size=paging.page_size)


@router.post("/crispr/{assessment_id}/review", response_model=CrisprOut,
             summary="Review a flagged gene-edit proposal")
def review_crispr(assessment_id: str, payload: ReviewDecision, db: DbSession,
                  principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_REVIEW))]
                  ) -> CrisprOut:
    assessment = get_or_404(db, CrisprAssessment, assessment_id, principal.role, principal.org_id,
                            name="Assessment")
    service.review_crispr(db, assessment, principal.id, principal.role, payload.decision,
                          payload.rationale)
    db.commit()
    return CrisprOut.model_validate(assessment)


@router.get("/hazards", response_model=Page[HazardOut], summary="List the hazard database")
def list_hazards(db: DbSession, paging: PagingDep,
                 principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_READ))]
                 ) -> Page[HazardOut]:
    from sqlalchemy import select

    query = select(HazardSequence).order_by(HazardSequence.severity.desc())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[HazardOut](items=[HazardOut.model_validate(r) for r in rows], total=total,
                           page=paging.page, page_size=paging.page_size)


@router.post("/hazards", response_model=HazardOut, status_code=201,
             summary="Add a hazard sequence to the reference database")
def add_hazard(payload: HazardCreate, db: DbSession,
               principal: Annotated[object, Depends(require_permission(P.HAZARD_WRITE))]
               ) -> HazardOut:
    hazard = service.add_hazard(db, principal.id, principal.role, payload.agent_name,
                                payload.hazard_class, payload.severity, payload.description,
                                payload.sequence)
    db.commit()
    return HazardOut.model_validate(hazard)


@router.get("/statistics", summary="Biosecurity dashboard statistics")
def statistics(db: DbSession,
               principal: Annotated[object, Depends(require_permission(P.BIOSECURITY_READ))]) -> dict:
    org_id = None if principal.is_cross_tenant else principal.org_id
    return service.statistics(db, org_id)
