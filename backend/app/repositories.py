"""Organisation-scoped data access (ADR-015).

The secure path is the convenient path: `scoped()` is the normal way to read, and it
always applies the caller's organisation filter. Reading across tenants requires the
explicit `unscoped()` escape hatch, which is permitted only for ADMIN and REGULATOR
and is always audit-logged by the caller.
"""
from __future__ import annotations

from typing import Any, TypeVar

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from .core.errors import NotFound, PermissionDenied
from .core.permissions import CROSS_TENANT_ROLES, Role

T = TypeVar("T")

# Models that carry no org_id and are therefore platform-wide by design.
GLOBAL_MODELS = {"HazardSequence", "Organization", "BlockchainTx", "SchemaVersion", "AuditLog"}


def _has_column(model: type, name: str) -> bool:
    return hasattr(model, name)


def scoped(model: type[T], org_id: str | None, *, include_deleted: bool = False) -> Select:
    """Base SELECT for a model, filtered to one organisation and excluding soft-deleted rows."""
    query = select(model)
    if org_id is not None and _has_column(model, "org_id"):
        query = query.where(getattr(model, "org_id") == org_id)
    if not include_deleted and _has_column(model, "deleted_at"):
        query = query.where(getattr(model, "deleted_at").is_(None))
    return query


def unscoped(model: type[T], role: str, *, include_deleted: bool = False) -> Select:
    """Cross-tenant read. Callers MUST audit-log the use of this accessor."""
    try:
        if Role(role) not in CROSS_TENANT_ROLES:
            raise PermissionDenied("Cross-organisation access is not permitted for this role")
    except ValueError as exc:
        raise PermissionDenied("Unknown role") from exc
    query = select(model)
    if not include_deleted and _has_column(model, "deleted_at"):
        query = query.where(getattr(model, "deleted_at").is_(None))
    return query


def visible(model: type[T], role: str, org_id: str | None, *,
            include_deleted: bool = False) -> Select:
    """Scoped for ordinary roles, unscoped for cross-tenant roles."""
    try:
        cross = Role(role) in CROSS_TENANT_ROLES
    except ValueError:
        cross = False
    if cross:
        return unscoped(model, role, include_deleted=include_deleted)
    return scoped(model, org_id, include_deleted=include_deleted)


def get_or_404(db: Session, model: type[T], entity_id: str, role: str, org_id: str | None,
               *, name: str | None = None) -> T:
    """Fetch by id within the caller's visibility.

    Returns 404 rather than 403 when a row exists but belongs to another tenant:
    revealing existence would itself leak tenancy information (Development-rules.md §13).
    """
    query = visible(model, role, org_id).where(getattr(model, "id") == entity_id)
    entity = db.execute(query).scalar_one_or_none()
    if entity is None:
        raise NotFound(f"{name or model.__name__} not found")
    return entity


def paginate(db: Session, query: Select, page: int, page_size: int,
             max_page_size: int = 200) -> tuple[list[Any], int]:
    page = max(1, page)
    page_size = max(1, min(page_size, max_page_size))
    count_query = select(func.count()).select_from(query.order_by(None).subquery())
    total = int(db.execute(count_query).scalar_one())
    rows = list(db.execute(query.limit(page_size).offset((page - 1) * page_size)).scalars())
    return rows, total
