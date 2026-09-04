"""Role-aware dashboard aggregation (FR-X5)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from ..core.deps import CurrentUser, DbSession, rate_limit
from ..core.permissions import P, has_permission
from ..models import (Alert, Batch, Device, GMOEvent, Notification, SequenceScreening,
                      SupplyChainEvent, Telemetry)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"], dependencies=[Depends(rate_limit)])


def _count(db, model, org_id: str | None, *conditions) -> int:
    query = select(func.count()).select_from(model)
    if org_id is not None and hasattr(model, "org_id"):
        query = query.where(model.org_id == org_id)
    if hasattr(model, "deleted_at"):
        query = query.where(model.deleted_at.is_(None))
    for condition in conditions:
        query = query.where(condition)
    return int(db.execute(query).scalar_one())


@router.get("", summary="Dashboard tiles filtered to the caller's role and organisation")
def dashboard(db: DbSession, principal: CurrentUser) -> dict:
    org_id = None if principal.is_cross_tenant else principal.org_id
    tiles: dict[str, object] = {"role": principal.role, "organization_id": principal.org_id}

    if has_permission(principal.role, P.DEVICE_READ):
        tiles["devices"] = {
            "total": _count(db, Device, org_id),
            "active": _count(db, Device, org_id, Device.status == "ACTIVE"),
            "quarantined": _count(db, Device, org_id, Device.status == "QUARANTINED"),
        }
    if has_permission(principal.role, P.TELEMETRY_READ):
        tiles["telemetry"] = {
            "readings": _count(db, Telemetry, org_id),
            "suspect": _count(db, Telemetry, org_id, Telemetry.quality != "OK"),
        }
    if has_permission(principal.role, P.ALERT_READ):
        tiles["alerts"] = {
            "open": _count(db, Alert, org_id, Alert.status == "OPEN"),
            "critical_open": _count(db, Alert, org_id, Alert.status == "OPEN",
                                    Alert.severity == "CRITICAL"),
        }
    if has_permission(principal.role, P.BIOSECURITY_READ):
        tiles["biosecurity"] = {
            "screenings": _count(db, SequenceScreening, org_id),
            "pending_review": _count(db, SequenceScreening, org_id,
                                     SequenceScreening.status == "PENDING_REVIEW"),
            "blocked": _count(db, SequenceScreening, org_id,
                              SequenceScreening.status == "BLOCKED"),
        }
    if has_permission(principal.role, P.GMO_READ):
        tiles["gmo"] = {"events": _count(db, GMOEvent, org_id)}
    if has_permission(principal.role, P.SUPPLY_READ):
        tiles["supply_chain"] = {
            "batches": _count(db, Batch, org_id),
            "events": _count(db, SupplyChainEvent, org_id),
            "integrity_failed": _count(db, Batch, org_id, Batch.integrity_status == "FAILED"),
            "integrity_suspect": _count(db, Batch, org_id, Batch.integrity_status == "SUSPECT"),
        }
    if has_permission(principal.role, P.BLOCKCHAIN_READ):
        from ..services import ledger_client

        stats = ledger_client.stats()
        tiles["ledger"] = {"height": stats.get("height", 0),
                           "transactions": stats.get("transactions", 0),
                           "network": stats.get("network", "single-node-demo")}

    tiles["notifications_unread"] = int(db.execute(
        select(func.count()).select_from(Notification).where(
            Notification.user_id == principal.id,
            Notification.read_at.is_(None))).scalar_one())
    return tiles
