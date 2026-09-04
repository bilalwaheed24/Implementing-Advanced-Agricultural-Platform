"""Authentication, registration, lockout and token lifecycle (FR-X1, FR-X2, FR-X3)."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.errors import AccountLocked, AuthError, Conflict, NotFound, ValidationFailed
from ..core.logging_conf import security_event
from ..core.permissions import APPROVAL_REQUIRED_ROLES, Role
from ..core.security import (create_access_token, create_refresh_token, decode_token,
                             ensure_aware, hash_password, new_id, utcnow,
                             validate_password_strength, verify_password)
from ..models import Organization, RefreshToken, User
from . import audit, notifications


def register(db: Session, email: str, full_name: str, password: str, role: str,
             org_id: str, ip: str | None = None) -> User:
    settings = get_settings()
    try:
        role_enum = Role(role.upper())
    except ValueError as exc:
        raise ValidationFailed(f"Unknown role {role}") from exc

    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        # Do not reveal which addresses are registered.
        security_event("registration attempted for an existing address", ip=ip)
        raise Conflict("Registration could not be completed")

    organization = db.execute(
        select(Organization).where(Organization.id == org_id,
                                   Organization.is_active.is_(True))).scalar_one_or_none()
    if organization is None:
        raise ValidationFailed("Unknown or inactive organisation")

    validate_password_strength(password)
    status = "PENDING" if role_enum in APPROVAL_REQUIRED_ROLES else "ACTIVE"
    user = User(email=email, full_name=full_name, password_hash=hash_password(password),
                role=role_enum.value, org_id=org_id, status=status)
    db.add(user)
    db.flush()
    audit.record(db, "user.register", actor_id=user.id, actor_role=user.role, org_id=org_id,
                 entity_type="User", entity_id=user.id, ip=ip,
                 detail={"role": user.role, "status": status})
    _ = settings
    return user


def authenticate(db: Session, email: str, password: str, ip: str | None = None,
                 user_agent: str | None = None) -> User:
    settings = get_settings()
    user = db.execute(
        select(User).where(User.email == email, User.deleted_at.is_(None))).scalar_one_or_none()

    if user is None:
        # Constant work regardless of whether the account exists (timing neutrality).
        verify_password(password, "$2b$12$" + "x" * 53)
        security_event("login failed: unknown account", ip=ip)
        raise AuthError("Invalid email or password")

    now = utcnow()
    if user.locked_until and ensure_aware(user.locked_until) > now:
        security_event("login attempt on a locked account", actor_id=user.id, ip=ip)
        raise AccountLocked("Account is temporarily locked after repeated failed attempts")

    if not verify_password(password, user.password_hash):
        user.failed_attempts += 1
        if user.failed_attempts >= settings.max_failed_logins:
            # Exponential backoff beyond the first lockout.
            multiplier = 2 ** min(4, user.failed_attempts - settings.max_failed_logins)
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes * multiplier)
            security_event("account locked after repeated failures", level=logging.WARNING,
                           actor_id=user.id, failures=user.failed_attempts, ip=ip)
            notifications.raise_alert(
                db, "DATA_THEFT", "HIGH", f"Account locked after {user.failed_attempts} failed logins",
                detail=f"Account {user.email} was locked following repeated authentication failures.",
                org_id=user.org_id, entity_type="User", entity_id=user.id)
        db.flush()
        audit.record(db, "auth.login", actor_id=user.id, actor_role=user.role, org_id=user.org_id,
                     entity_type="User", entity_id=user.id, outcome="FAILURE", ip=ip,
                     user_agent=user_agent, detail={"failed_attempts": user.failed_attempts})
        # The counter MUST be durable before the exception unwinds: the route never
        # commits on an error path, so without this the session is rolled back and
        # brute-force protection silently does nothing at all.
        db.commit()
        security_event("login failed: bad password", actor_id=user.id, ip=ip)
        raise AuthError("Invalid email or password")

    if user.status == "PENDING":
        raise AuthError("Account is awaiting administrator approval")
    if user.status != "ACTIVE":
        raise AuthError("Account is not active")

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    db.flush()
    audit.record(db, "auth.login", actor_id=user.id, actor_role=user.role, org_id=user.org_id,
                 entity_type="User", entity_id=user.id, ip=ip, user_agent=user_agent)
    return user


def issue_tokens(db: Session, user: User, family_id: str | None = None) -> dict[str, object]:
    settings = get_settings()
    family = family_id or new_id()
    access_token, _ = create_access_token(user.id, user.role, user.org_id)
    refresh_token, refresh_payload = create_refresh_token(user.id, family)
    db.add(RefreshToken(
        jti=refresh_payload["jti"], family_id=family, user_id=user.id,
        expires_at=utcnow() + timedelta(days=settings.refresh_token_days)))
    db.flush()
    return {"access_token": access_token, "refresh_token": refresh_token,
            "token_type": "bearer", "expires_in": settings.access_token_minutes * 60}


def refresh(db: Session, token: str, ip: str | None = None) -> dict[str, object]:
    """Rotate a refresh token. Reuse of a rotated token invalidates the whole family (T-04)."""
    payload = decode_token(token, "refresh")
    jti, family_id = payload["jti"], payload.get("fam", "")
    stored = db.execute(select(RefreshToken).where(RefreshToken.jti == jti)).scalar_one_or_none()

    if stored is None:
        security_event("refresh token not recognised", level=logging.WARNING, ip=ip)
        raise AuthError("Invalid refresh token")

    if stored.revoked or stored.used_at is not None:
        # Reuse detection: kill every token in the family and alarm.
        family = db.execute(
            select(RefreshToken).where(RefreshToken.family_id == family_id)).scalars()
        for item in family:
            item.revoked = True
        db.flush()
        security_event("refresh token reuse detected: family invalidated",
                       level=logging.ERROR, actor_id=stored.user_id, family=family_id, ip=ip)
        user = db.get(User, stored.user_id)
        notifications.raise_alert(
            db, "DATA_THEFT", "CRITICAL", "Refresh token reuse detected",
            detail="A refresh token was presented after it had already been rotated. "
                   "Every token in the family has been invalidated.",
            org_id=user.org_id if user else None, entity_type="User", entity_id=stored.user_id)
        audit.record(db, "auth.refresh_reuse", actor_id=stored.user_id,
                     entity_type="RefreshToken", entity_id=stored.id, outcome="FAILURE", ip=ip)
        # Durable before unwinding: the route does not commit on an error path, so
        # without this the family revocation is rolled back and the stolen token keeps
        # working — the exact attack this control exists to stop.
        db.commit()
        raise AuthError("Invalid refresh token")

    if ensure_aware(stored.expires_at) < utcnow():
        raise AuthError("Refresh token has expired")

    user = db.get(User, stored.user_id)
    if user is None or user.status != "ACTIVE" or user.deleted_at is not None:
        raise AuthError("Account is not active")

    stored.used_at = utcnow()
    stored.revoked = True
    db.flush()
    tokens = issue_tokens(db, user, family_id=family_id)
    audit.record(db, "auth.refresh", actor_id=user.id, actor_role=user.role, org_id=user.org_id,
                 entity_type="User", entity_id=user.id, ip=ip)
    return tokens


def logout(db: Session, user_id: str, ip: str | None = None) -> int:
    tokens = list(db.execute(
        select(RefreshToken).where(RefreshToken.user_id == user_id,
                                   RefreshToken.revoked.is_(False))).scalars())
    for token in tokens:
        token.revoked = True
    db.flush()
    audit.record(db, "auth.logout", actor_id=user_id, entity_type="User", entity_id=user_id,
                 ip=ip, detail={"tokens_revoked": len(tokens)})
    return len(tokens)


def approve_user(db: Session, user_id: str, actor_id: str, actor_role: str) -> User:
    user = db.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise NotFound("User not found")
    user.status = "ACTIVE"
    db.flush()
    audit.record(db, "user.approve", actor_id=actor_id, actor_role=actor_role,
                 org_id=user.org_id, entity_type="User", entity_id=user.id)
    return user


def update_user(db: Session, user_id: str, actor_id: str, actor_role: str,
                full_name: str | None, role: str | None) -> User:
    """Admin-only profile/role edit. Status changes are deliberately out of scope here —
    ACTIVE/PENDING/SUSPENDED is a state machine owned exclusively by approve_user() and
    suspend_user(), so this function cannot be used to bypass those transitions."""
    user = db.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise NotFound("User not found")
    changes: dict[str, Any] = {}
    if full_name is not None:
        changes["full_name"] = {"from": user.full_name, "to": full_name}
        user.full_name = full_name
    if role is not None:
        try:
            role_enum = Role(role.upper())
        except ValueError as exc:
            raise ValidationFailed(f"Unknown role {role}") from exc
        changes["role"] = {"from": user.role, "to": role_enum.value}
        user.role = role_enum.value
        # A role change invalidates any outstanding token for this user (deps.py checks
        # that the token's role claim still matches the account), so no separate
        # revocation step is needed here.
    if changes:
        db.flush()
        audit.record(db, "user.update", actor_id=actor_id, actor_role=actor_role,
                     org_id=user.org_id, entity_type="User", entity_id=user.id,
                     detail=changes)
    return user


def suspend_user(db: Session, user_id: str, actor_id: str, actor_role: str,
                 reason: str) -> User:
    user = db.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise NotFound("User not found")
    user.status = "SUSPENDED"
    for token in db.execute(select(RefreshToken).where(
            RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))).scalars():
        token.revoked = True
    db.flush()
    audit.record(db, "user.suspend", actor_id=actor_id, actor_role=actor_role,
                 org_id=user.org_id, entity_type="User", entity_id=user.id,
                 detail={"reason": reason})
    return user
