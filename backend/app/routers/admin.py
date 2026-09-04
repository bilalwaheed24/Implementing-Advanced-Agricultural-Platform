"""User and organisation administration (FR-X2, FR-X3)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Depends, Query

from ..core.deps import CurrentUser, DbSession, PagingDep, rate_limit, require_permission
from ..core.errors import NotFound
from ..core.permissions import P, ROLE_PERMISSIONS, Role
from ..models import Organization, User
from ..repositories import paginate, unscoped, visible
from ..core.errors import ValidationFailed
from ..schemas import (OrganizationCreate, OrganizationOut, Page, UserOut,
                      UserUpdate)
from ..services import audit, identity, ledger_client

router = APIRouter(prefix="/admin", tags=["Administration"],
                   dependencies=[Depends(rate_limit)])


@router.get("/users", response_model=Page[UserOut], summary="List users")
def list_users(db: DbSession, paging: PagingDep,
               principal: Annotated[object, Depends(require_permission(P.USER_READ))],
               role: str | None = Query(default=None),
               status_filter: str | None = Query(default=None, alias="status")) -> Page[UserOut]:
    query = visible(User, principal.role, principal.org_id).order_by(User.created_at.desc())
    if role:
        query = query.where(User.role == role)
    if status_filter:
        query = query.where(User.status == status_filter)
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[UserOut](items=[UserOut.model_validate(r) for r in rows], total=total,
                         page=paging.page, page_size=paging.page_size)


@router.post("/users/{user_id}/approve", response_model=UserOut, summary="Approve a pending user")
def approve_user(user_id: str, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.USER_WRITE))]) -> UserOut:
    user = identity.approve_user(db, user_id, principal.id, principal.role)
    db.commit()
    return UserOut.model_validate(user)


@router.post("/users/{user_id}/suspend", response_model=UserOut,
             summary="Suspend a user and revoke their sessions")
def suspend_user(user_id: str, db: DbSession,
                 principal: Annotated[object, Depends(require_permission(P.USER_WRITE))],
                 reason: Annotated[str, Body(embed=True, min_length=3, max_length=500)]) -> UserOut:
    user = identity.suspend_user(db, user_id, principal.id, principal.role, reason)
    db.commit()
    return UserOut.model_validate(user)


@router.get("/organizations", response_model=Page[OrganizationOut], summary="List organisations")
def list_organizations(db: DbSession, paging: PagingDep,
                       principal: Annotated[object, Depends(require_permission(P.ORG_READ))]
                       ) -> Page[OrganizationOut]:
    from sqlalchemy import select

    query = select(Organization).order_by(Organization.name.asc())
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[OrganizationOut](items=[OrganizationOut.model_validate(r) for r in rows],
                                 total=total, page=paging.page, page_size=paging.page_size)


@router.post("/organizations", response_model=OrganizationOut, status_code=201,
             summary="Create an organisation and its ledger identity")
def create_organization(payload: OrganizationCreate, db: DbSession,
                        principal: Annotated[object, Depends(require_permission(P.ORG_WRITE))]
                        ) -> OrganizationOut:
    from sqlalchemy import select

    from ..core.errors import Conflict

    if db.execute(select(Organization).where(
            Organization.msp_id == payload.msp_id)).scalar_one_or_none():
        raise Conflict(f"MSP identifier {payload.msp_id} is already registered")
    organization = Organization(**payload.model_dump())
    db.add(organization)
    db.flush()
    # Ensure the organisation has a ledger signing identity.
    try:
        ledger_client.get_ledger().msp.ensure(organization.msp_id, organization.name)
    except Exception:                                    # noqa: BLE001 - non-fatal
        pass
    audit.record(db, "org.create", actor_id=principal.id, actor_role=principal.role,
                 entity_type="Organization", entity_id=organization.id,
                 detail={"msp_id": organization.msp_id, "org_type": organization.org_type})
    db.commit()
    return OrganizationOut.model_validate(organization)


@router.get("/roles", summary="Role to permission matrix")
def roles(principal: Annotated[object, Depends(require_permission(P.USER_READ))]
          ) -> dict[str, list[str]]:
    return {role.value: sorted(p.value for p in permissions)
            for role, permissions in ROLE_PERMISSIONS.items()}


@router.get("/users/{user_id}", response_model=UserOut, summary="Get one user")
def get_user(user_id: str, db: DbSession,
             principal: Annotated[object, Depends(require_permission(P.USER_READ))]) -> UserOut:
    query = visible(User, principal.role, principal.org_id).where(User.id == user_id)
    user = db.execute(query).scalar_one_or_none()
    if user is None:
        raise NotFound("User not found")
    return UserOut.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserOut,
             summary="Update a user's name or role (status changes use /approve, /suspend)")
def update_user(user_id: str, payload: UserUpdate, db: DbSession,
                principal: Annotated[object, Depends(require_permission(P.USER_WRITE))]
                ) -> UserOut:
    if payload.status is not None:
        raise ValidationFailed(
            "status cannot be changed here; use POST /admin/users/{id}/approve or "
            "/admin/users/{id}/suspend, which apply the account state machine correctly")
    user = identity.update_user(db, user_id, principal.id, principal.role,
                                payload.full_name, payload.role)
    db.commit()
    return UserOut.model_validate(user)
