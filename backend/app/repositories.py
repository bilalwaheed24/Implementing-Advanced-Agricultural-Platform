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
from .core.permissions import (CROSS_TENANT_ROLES, OVERSIGHT_ALERT_CATEGORIES, Role,
                               cross_tenant_categories, is_security_oversight)

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


def category_limit_conditions(model: type, role: str, org_id: str | None = None) -> list[Any]:
    """WHERE conditions narrowing a category-limited cross-tenant role (a biosafety officer)
    to alerts and incidents of its oversight categories in any organisation, plus everything
    its own organisation is a party to (round 6). Without `org_id` only the oversight
    categories match. Empty for every other role and model."""
    limited = cross_tenant_categories(role)
    if not limited:
        return []
    from .models import Alert, Incident                          # noqa: PLC0415 (cycle)

    if model not in (Alert, Incident):
        return []
    clauses = [model.category.in_(sorted(limited))]
    if org_id:
        clauses += [model.org_id == org_id, model.custodian_org_id == org_id]
    return [or_(*clauses)]


def oversight_conditions(model: type, role: str, org_id: str | None = None) -> list[Any]:
    """Extra WHERE conditions hiding security-oversight material from every other role.

    A DATA_THEFT alert is filed under the suspect user's own organisation, and tenant roles
    hold alert:read and incident:read, so the suspect (and colleagues) could read "Possible
    data exfiltration by ..." and the analysts' notes on its incident (round 5). Alerts in
    OVERSIGHT_ALERT_CATEGORIES, and incidents of those categories, opened from such an alert
    or carrying one, are visible to SECURITY_OVERSIGHT_ROLES only. Empty for those roles and
    for every other model.

    A category-limited cross-tenant role is further narrowed by `category_limit_conditions`
    (pass the caller's `org_id` so its own organisation's alerts stay visible)."""
    if is_security_oversight(role):
        return []
    from .models import Alert, Incident                          # noqa: PLC0415 (cycle)

    limits = category_limit_conditions(model, role, org_id)
    categories = sorted(OVERSIGHT_ALERT_CATEGORIES)
    if model is Alert:
        return [Alert.category.not_in(categories), *limits]
    if model is Incident:
        oversight_alerts = select(Alert.id).where(Alert.category.in_(categories))
        return [*limits,
            or_(Incident.category.is_(None), Incident.category.not_in(categories)),
            or_(Incident.source_alert_id.is_(None),
                Incident.source_alert_id.not_in(oversight_alerts)),
            ~select(Alert.id).where(Alert.incident_id == Incident.id,
                                    Alert.category.in_(categories)).exists(),
        ]
    return []


def visible(model: type[T], role: str, org_id: str | None, *,
            include_deleted: bool = False, also: Any = None) -> Select:
    """Scoped for ordinary roles, unscoped for cross-tenant roles (`also`: see `scoped`).

    Alerts and incidents are further narrowed by `oversight_conditions`."""
    try:
        cross = Role(role) in CROSS_TENANT_ROLES
    except ValueError:
        cross = False
    if cross:
        query = unscoped(model, role, include_deleted=include_deleted)
    else:
        query = scoped(model, org_id, include_deleted=include_deleted, also=also)
    hidden = oversight_conditions(model, role, org_id)
    return query.where(*hidden) if hidden else query


def audit_conditions(role: str, org_id: str | None, *, cross_tenant: bool) -> list[Any]:
    """WHERE conditions for reading the audit trail. A tenant role reads its own organisation's
    entries. A category-limited cross-tenant role (a biosafety officer) reads its own
    organisation's entries plus biosecurity entries from every organisation (round 6: her trail
    listed every tenant's logins, shipments and device changes). Other cross-tenant roles read
    everything."""
    from .core.permissions import AUDIT_CROSS_TENANT_ACTION_PREFIXES  # noqa: PLC0415
    from .models import AuditLog                                  # noqa: PLC0415 (cycle)

    if not cross_tenant:
        return [AuditLog.org_id == org_id]
    try:
        prefixes = AUDIT_CROSS_TENANT_ACTION_PREFIXES.get(Role(role))
    except ValueError:
        prefixes = None
    if prefixes is None:
        return []
    return [or_(AuditLog.org_id == org_id,
                *[AuditLog.action.startswith(prefix, autoescape=True) for prefix in prefixes])]


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
        # A row hidden by oversight_conditions is not another tenant's, so not a probe.
        if db.execute(select(getattr(model, "id")).where(
                getattr(model, "id") == entity_id, *oversight_conditions(model, role))
                .limit(1)).first() is not None:
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
