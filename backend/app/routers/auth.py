"""Authentication routes (FR-X1)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from ..core.deps import CurrentUser, DbSession, auth_rate_limit, client_ip
from ..schemas import (LoginRequest, RefreshRequest, RegisterRequest, TokenResponse, UserOut)
from ..services import identity

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(auth_rate_limit)],
             summary="Register a new account")
def register(payload: RegisterRequest, request: Request, db: DbSession) -> UserOut:
    """Privileged roles are created in PENDING status and require administrator approval."""
    user = identity.register(db, payload.email, payload.full_name, payload.password,
                             payload.role, payload.org_id, ip=client_ip(request))
    db.commit()
    return UserOut.model_validate(user)


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(auth_rate_limit)],
             summary="Exchange credentials for an access and refresh token")
def login(payload: LoginRequest, request: Request, db: DbSession) -> TokenResponse:
    user = identity.authenticate(db, payload.email, payload.password, ip=client_ip(request),
                                 user_agent=request.headers.get("user-agent"))
    tokens = identity.issue_tokens(db, user)
    db.commit()
    return TokenResponse(**tokens)


@router.post("/refresh", response_model=TokenResponse, dependencies=[Depends(auth_rate_limit)],
             summary="Rotate a refresh token")
def refresh(payload: RefreshRequest, request: Request, db: DbSession) -> TokenResponse:
    """Reuse of an already-rotated token invalidates the entire token family."""
    tokens = identity.refresh(db, payload.refresh_token, ip=client_ip(request))
    db.commit()
    return TokenResponse(**tokens)


@router.post("/logout", status_code=status.HTTP_200_OK, summary="Revoke all refresh tokens")
def logout(request: Request, principal: CurrentUser, db: DbSession) -> dict[str, int]:
    revoked = identity.logout(db, principal.id, ip=client_ip(request))
    db.commit()
    return {"tokens_revoked": revoked}


@router.get("/me", summary="Current principal and effective permissions")
def me(principal: CurrentUser) -> dict[str, object]:
    return {"id": principal.id, "email": principal.email, "full_name": principal.full_name,
            "role": principal.role, "org_id": principal.org_id,
            "permissions": principal.permissions()}
