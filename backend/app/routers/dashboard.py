"""Role-aware dashboard aggregation.

A tile is returned only when it means something to the caller's role, not merely when the
role holds the read permission behind it: a supply-chain operator may read devices, but its
organisation owns none, so a "Devices 0" tile would only be noise. Each role gets the counts
it works with (a certifier its certificates, a processor the batches it holds).
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select

from ..core.deps import CurrentUser, DbSession, rate_limit
from ..core.permissions import P, Role, has_permission
from ..core.security import utcnow
from ..repositories import oversight_conditions
from ..services import supplychain as supply_service
from ..models import (Alert, Batch, Certification, CertificationLink, Device, GMOEvent,
                      Notification, SeedLot, SequenceScreening, Shipment, SupplyChainEvent,
                      Telemetry)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"], dependencies=[Depends(rate_limit)])

# Roles whose organisations run field equipment. Others may hold device:read for oversight
# or cold-chain lookups, but have no fleet of their own to count.
_FLEET_ROLES = {Role.ADMIN, Role.SECURITY_ANALYST, Role.FARM_OPERATOR, Role.AGRONOMIST,
                Role.REGULATOR}
# Roles that work with the GMO event register itself; growers instead see the GMO material
# they hold.
_GMO_REGISTER_ROLES = {Role.ADMIN, Role.SECURITY_ANALYST, Role.BIOTECH_RESEARCHER,
                       Role.BIOSAFETY_OFFICER, Role.REGULATOR}
_GROWER_ROLES = {Role.FARM_OPERATOR, Role.AGRONOMIST}
# Roles that handle batches. A certifier reads batches only to check a claim.
_BATCH_ROLES = {Role.ADMIN, Role.SECURITY_ANALYST, Role.FARM_OPERATOR, Role.AGRONOMIST,
                Role.SUPPLY_CHAIN_OPERATOR, Role.REGULATOR}

EXPIRY_WINDOW_DAYS = 30
UNRESOLVED_ALERT_STATUSES = ("OPEN", "ACKNOWLEDGED")


def _count(db, model, org_id: str | None, *conditions) -> int:
    query = select(func.count()).select_from(model)
    if org_id is not None and hasattr(model, "org_id"):
        if hasattr(model, "custodian_org_id"):        # a received batch counts for its holder
            query = query.where(or_(model.org_id == org_id, model.custodian_org_id == org_id))
        else:
            query = query.where(model.org_id == org_id)
    if hasattr(model, "deleted_at"):
        query = query.where(model.deleted_at.is_(None))
    for condition in conditions:
        query = query.where(condition)
    return int(db.execute(query).scalar_one())


def _scalar(db, query) -> int:
    return int(db.execute(query).scalar_one())


def _role(value: str) -> Role | None:
    try:
        return Role(value)
    except ValueError:
        return None


def _supply_tiles(db, org_id: str | None) -> dict:
    # "In your custody now": a batch still on the road to the caller is counted once, under
    # awaiting_arrival, not here as well (round 5).
    # The batch list's ?held=true applies the same rule, so the tile and its link agree.
    held = [Batch.state != "IN_TRANSIT"]
    if org_id is not None:
        held.append(Batch.custodian_org_id == org_id)
    # Both ends of a shipment work with it: the sender dispatched it, and the receiver must
    # mark it arrived. The receiver of an internal move (no to_org_id) is the sender itself.
    shipped = [] if org_id is None else [or_(Shipment.org_id == org_id,
                                             Shipment.to_org_id == org_id)]
    receiving = [] if org_id is None else [or_(
        Shipment.to_org_id == org_id,
        (Shipment.to_org_id.is_(None)) & (Shipment.org_id == org_id))]
    return {
        "batches": _count(db, Batch, org_id),
        "held": _scalar(db, select(func.count()).select_from(Batch).where(*held)),
        "events": _count(db, SupplyChainEvent, org_id),
        "integrity_failed": _count(db, Batch, org_id, Batch.integrity_status == "FAILED"),
        "integrity_suspect": _count(db, Batch, org_id, Batch.integrity_status == "SUSPECT"),
        "shipments_in_transit": _scalar(db, select(func.count()).select_from(Shipment).where(
            Shipment.status == "IN_TRANSIT", *shipped)),
        # In transit to the caller, who is the one to mark them arrived.
        "awaiting_arrival": _scalar(db, select(func.count()).select_from(Shipment).where(
            Shipment.status == "IN_TRANSIT", *receiving)),
        # Reached the caller but not booked in. A batch still IN_TRANSIT is counted once,
        # under awaiting_arrival, not here as well (supply_service.awaiting_booking).
        "pending_handovers": _scalar(db, select(func.count()).select_from(Batch).where(
            *supply_service.awaiting_booking(org_id))),
    }


def _certification_tiles(db, org_id: str | None) -> dict:
    now = utcnow()
    issued = [] if org_id is None else [Certification.issuer_org_id == org_id]
    live = [Certification.status == "ACTIVE", Certification.valid_to >= now, *issued]
    return {
        "issued": _scalar(db, select(func.count()).select_from(Certification).where(*issued)),
        "active": _scalar(db, select(func.count()).select_from(Certification).where(*live)),
        "expiring": _scalar(db, select(func.count()).select_from(Certification).where(
            *live, Certification.valid_to <= now + timedelta(days=EXPIRY_WINDOW_DAYS))),
        "expiry_window_days": EXPIRY_WINDOW_DAYS,
        "claimed": _scalar(db, select(func.count()).select_from(CertificationLink).join(
            Certification, Certification.id == CertificationLink.certification_id)
            .where(*issued)),
    }


def _gmo_holdings(db, org_id: str | None) -> dict:
    lots = [] if org_id is None else [or_(SeedLot.org_id == org_id,
                                          SeedLot.custodian_org_id == org_id)]
    return {
        "seed_lots": _scalar(db, select(func.count()).select_from(SeedLot).where(
            SeedLot.gmo_event_id.is_not(None), *lots)),
        # GMO lineage through the batch, its seed lot or a parent, as the batch list's filter.
        "batches": _count(db, Batch, org_id, Batch.id.in_(supply_service.gmo_lineage_ids())),
    }


@router.get("", summary="Dashboard tiles filtered to the caller's role and organisation")
def dashboard(db: DbSession, principal: CurrentUser) -> dict:
    org_id = None if principal.is_cross_tenant else principal.org_id
    role = _role(principal.role)
    tiles: dict[str, object] = {"role": principal.role, "organization_id": principal.org_id}

    if has_permission(principal.role, P.DEVICE_READ) and role in _FLEET_ROLES:
        tiles["devices"] = {
            "total": _count(db, Device, org_id),
            # "active" means active and reporting: a device the health sweep found silent
            # keeps status ACTIVE (so it can come back) but is counted as offline instead.
            "active": _count(db, Device, org_id, Device.status == "ACTIVE",
                             Device.offline_since.is_(None)),
            "offline": _count(db, Device, org_id, Device.status == "ACTIVE",
                              Device.offline_since.is_not(None)),
            "quarantined": _count(db, Device, org_id, Device.status == "QUARANTINED"),
        }
    if has_permission(principal.role, P.TELEMETRY_READ) and role in _FLEET_ROLES:
        tiles["telemetry"] = {
            "readings": _count(db, Telemetry, org_id),
            "suspect": _count(db, Telemetry, org_id, Telemetry.quality != "OK"),
        }
    if has_permission(principal.role, P.ALERT_READ):
        # Unresolved (OPEN or ACKNOWLEDGED): an acknowledged alert still needs attention. The
        # tile, its link (#/alerts?status=UNRESOLVED) and the dashboard's alert card all use
        # this one definition, so their numbers agree.
        # Security-oversight alerts (DATA_THEFT, LEDGER) are not counted for other roles: they
        # cannot open them (repositories.oversight_conditions), and a count that moved when
        # an exfiltration finding about a colleague was raised would itself tip them off.
        unresolved = Alert.status.in_(UNRESOLVED_ALERT_STATUSES)
        hidden = oversight_conditions(Alert, principal.role)
        by_severity = select(Alert.severity, func.count()).where(unresolved, *hidden)
        if org_id is not None:
            # The same parties as _count (owner or custodian side) and the alert list.
            by_severity = by_severity.where(or_(Alert.org_id == org_id,
                                                Alert.custodian_org_id == org_id))
        tiles["alerts"] = {
            "open": _count(db, Alert, org_id, unresolved, *hidden),
            "critical_open": _count(db, Alert, org_id, unresolved, *hidden,
                                    Alert.severity == "CRITICAL"),
            "by_severity": {severity: int(count) for severity, count in db.execute(
                by_severity.group_by(Alert.severity)).all()},
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
        if role in _GMO_REGISTER_ROLES:
            tiles["gmo"] = {"events": _count(db, GMOEvent, org_id)}
        elif role in _GROWER_ROLES:
            tiles["gmo_holdings"] = _gmo_holdings(db, org_id)
    if has_permission(principal.role, P.SUPPLY_READ) and role in _BATCH_ROLES:
        tiles["supply_chain"] = _supply_tiles(db, org_id)
    if has_permission(principal.role, P.CERT_READ) and (
            has_permission(principal.role, P.CERT_ISSUE) or role == Role.REGULATOR):
        tiles["certifications"] = _certification_tiles(db, org_id)
    # Ledger internals are an oversight concern. Every role keeps blockchain:read for proof
    # checks on its own records, but only the explorer roles get the chain-height tile.
    if has_permission(principal.role, P.BLOCKCHAIN_EXPLORE):
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
