"""Organisation-scoped data access (ADR-015).

The secure path is the convenient path: `scoped()` is the normal way to read, and it
always applies the caller's organisation filter. Reading across tenants requires the
explicit `unscoped()` escape hatch, which is permitted only for ADMIN and REGULATOR
and is always audit-logged by the caller.
"""
from __future__ import annotations

from typing import Any, TypeVar

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from .core import request_flags
from .core.errors import NotFound, PermissionDenied
from .core.permissions import CROSS_TENANT_ROLES, Role

T = TypeVar("T")

# Models that carry no org_id and are therefore platform-wide by design.
GLOBAL_MODELS = {"HazardSequence", "Organization", "BlockchainTx", "SchemaVersion", "AuditLog"}

# Columns naming an organisation that is a party to the row and may therefore read it.
# `org_id` is always first; the others apply only to models that carry them.
PARTY_COLUMNS = ("org_id", "custodian_org_id", "owner_org_id")


def _has_column(model: type, name: str) -> bool:
    return hasattr(model, name)


def scoped(model: type[T], org_id: str | None, *, include_deleted: bool = False,
           also: Any = None) -> Select:
    """Base SELECT for a model, filtered to one organisation and excluding soft-deleted rows.

    `also` is an extra SQL condition under which a row is visible to the organisation besides
    the party columns, e.g. a batch carrying a certificate the organisation issued.
    """
    query = select(model)
    if org_id is not None and _has_column(model, "org_id"):
        # A batch handed over in a custody transfer is visible to its current custodian as well
        # as to the organisation that created it; a report about a batch is visible to the
        # batch's owner and custodian as well as to whoever ran it. A model can name its own
        # parties instead (a shipment's sender and receiver) through `__party_columns__`.
        columns = getattr(model, "__party_columns__", None) or PARTY_COLUMNS
        parties = [getattr(model, column) == org_id for column in columns
                   if _has_column(model, column)]
        if also is not None:
            parties.append(also)
        query = query.where(or_(*parties)) if len(parties) > 1 else query.where(parties[0])
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
            include_deleted: bool = False, also: Any = None) -> Select:
    """Scoped for ordinary roles, unscoped for cross-tenant roles (`also`: see `scoped`)."""
    try:
        cross = Role(role) in CROSS_TENANT_ROLES
    except ValueError:
        cross = False
    if cross:
        return unscoped(model, role, include_deleted=include_deleted)
    return scoped(model, org_id, include_deleted=include_deleted, also=also)


def get_or_404(db: Session, model: type[T], entity_id: str, role: str, org_id: str | None,
               *, name: str | None = None, also: Any = None) -> T:
    """Fetch by id within the caller's visibility.

    Returns 404 rather than 403 when a row exists but belongs to another tenant:
    revealing existence would itself leak tenancy information (Development-rules.md §13).
    """
    query = visible(model, role, org_id, also=also).where(getattr(model, "id") == entity_id)
    entity = db.execute(query).scalar_one_or_none()
    if entity is None:
        # The caller still gets a plain 404, but if the row exists in another tenant this
        # was a cross-tenant probe, which the data-theft detector must count.
        if db.execute(select(getattr(model, "id")).where(
                getattr(model, "id") == entity_id).limit(1)).first() is not None:
            request_flags.raise_flag("cross_tenant_probe")
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
