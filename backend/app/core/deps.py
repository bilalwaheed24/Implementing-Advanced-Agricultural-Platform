"""Request-scoped dependencies: authentication, authorisation, rate limiting, paging."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Annotated, Callable

from fastapi import Depends, Header, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import User
from .config import get_settings
from .database import get_db
from .errors import AuthError, PermissionDenied, RateLimited
from .logging_conf import actor_id as actor_ctx, org_id as org_ctx, security_event
from .permissions import CROSS_TENANT_ROLES, P, Role, has_permission, permissions_for
from .ratelimit import TokenBucketLimiter
from .security import decode_token

_settings = get_settings()
api_limiter = TokenBucketLimiter(_settings.rate_limit_per_minute, _settings.rate_limit_per_minute)
public_limiter = TokenBucketLimiter(_settings.public_rate_limit_per_minute,
                                    _settings.public_rate_limit_per_minute)
auth_limiter = TokenBucketLimiter(10, 10)


@dataclass
class Principal:
    id: str
    email: str
    role: str
    org_id: str
    full_name: str = ""

    @property
    def is_cross_tenant(self) -> bool:
        return self.role in {r.value for r in CROSS_TENANT_ROLES}

    def permissions(self) -> list[str]:
        return permissions_for(self.role)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def get_current_principal(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        security_event("missing bearer token", path=request.url.path, ip=client_ip(request))
        raise AuthError("Authentication required")
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_token(token, "access")
    user = db.execute(
        select(User).where(User.id == payload["sub"], User.deleted_at.is_(None))
    ).scalar_one_or_none()
    if user is None or user.status != "ACTIVE":
        security_event("token for inactive or unknown user", user_id=payload.get("sub"),
                       ip=client_ip(request))
        raise AuthError("Account is not active")
    # A role or organisation change invalidates outstanding tokens.
    if payload.get("role") != user.role or payload.get("org") != user.org_id:
        security_event("token claims no longer match the account", user_id=user.id)
        raise AuthError("Token is no longer valid; sign in again")

    principal = Principal(id=user.id, email=user.email, role=user.role, org_id=user.org_id,
                          full_name=user.full_name)
    actor_ctx.set(principal.id)
    org_ctx.set(principal.org_id)
    request.state.principal = principal
    return principal


CurrentUser = Annotated[Principal, Depends(get_current_principal)]
DbSession = Annotated[Session, Depends(get_db)]


def require_permission(permission: P) -> Callable[..., Principal]:
    """Route dependency asserting the caller's role holds `permission`. Deny by default."""

    def dependency(request: Request, principal: CurrentUser) -> Principal:
        if not has_permission(principal.role, permission):
            security_event("authorisation denied", level=logging.WARNING,
                           actor_id=principal.id, role=principal.role,
                           required=permission.value, path=request.url.path,
                           ip=client_ip(request))
            raise PermissionDenied(f"This action requires the '{permission.value}' permission")
        request.state.required_permission = permission.value
        return principal

    dependency.__absp_permission__ = permission.value      # read by the coverage test
    return dependency


def rate_limit(request: Request, principal: CurrentUser) -> None:
    allowed, retry_after = api_limiter.allow(f"user:{principal.id}")
    if not allowed:
        security_event("rate limit exceeded", actor_id=principal.id, path=request.url.path)
        raise RateLimited(f"Rate limit exceeded. Retry in {retry_after} seconds",
                          retry_after=retry_after)


def public_rate_limit(request: Request) -> None:
    allowed, retry_after = public_limiter.allow(f"ip:{client_ip(request)}")
    if not allowed:
        security_event("public rate limit exceeded", ip=client_ip(request), path=request.url.path)
        raise RateLimited(f"Rate limit exceeded. Retry in {retry_after} seconds",
                          retry_after=retry_after)


def auth_rate_limit(request: Request) -> None:
    allowed, retry_after = auth_limiter.allow(f"auth:{client_ip(request)}")
    if not allowed:
        security_event("authentication rate limit exceeded", ip=client_ip(request))
        raise RateLimited(f"Too many authentication attempts. Retry in {retry_after} seconds",
                          retry_after=retry_after)


@dataclass
class Paging:
    page: int
    page_size: int

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def paging(
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 25,
) -> Paging:
    return Paging(page=page, page_size=min(page_size, get_settings().max_page_size))


PagingDep = Annotated[Paging, Depends(paging)]
