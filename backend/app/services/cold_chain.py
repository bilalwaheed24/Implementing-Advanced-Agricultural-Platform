"""Cold-chain binding between a shipment and its sensor (FR-D1).

A shipment names the cold-chain sensor travelling with it (`Shipment.cold_chain_device_id`).
That binding, not a shipment id the device puts in its own message, decides which shipment a
reading belongs to: a device could otherwise tag any organisation's shipment, and a sensor
that never sends a shipment id would leave its shipment with no evidence at all.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.logging_conf import security_event
from ..core.security import ensure_aware as _aware
from ..models import Batch, Device, Product, Shipment, Telemetry
from . import notifications


def _covers(shipment: Shipment, recorded_at: datetime) -> bool:
    """Whether a reading taken at `recorded_at` falls inside the shipment's journey."""
    when = _aware(recorded_at)
    if when < _aware(shipment.departed_at):
        return False
    return shipment.arrived_at is None or when <= _aware(shipment.arrived_at)


def bind_shipment(db: Session, device: Device, claimed_id: str | None,
                  recorded_at: datetime) -> Shipment | None:
    """The shipment a reading from this device belongs to, or None.

    A shipment id the device sends is accepted only when that shipment is bound to this very
    device and the reading falls inside its journey (a backfilled reading from a delivered
    shipment, say). Anything else is ignored and logged, and the reading is attached to the
    device's open shipment instead, if it has one.
    """
    if claimed_id:
        claimed = db.get(Shipment, claimed_id)
        if (claimed is not None and claimed.cold_chain_device_id == device.id
                and _covers(claimed, recorded_at)):
            return claimed
        security_event("telemetry shipment tag ignored: shipment is not bound to this device",
                       level=logging.WARNING, device_id=device.id, shipment_id=claimed_id)
    return db.execute(
        select(Shipment).where(Shipment.cold_chain_device_id == device.id,
                               Shipment.status == "IN_TRANSIT")
        .order_by(Shipment.departed_at.desc()).limit(1)).scalar_one_or_none()


def storage_limits(db: Session, shipment: Shipment) -> tuple[float | None, float | None]:
    batch = db.get(Batch, shipment.batch_id)
    product = db.get(Product, batch.product_id) if batch else None
    if product is None:
        return None, None
    return product.storage_temp_min_c, product.storage_temp_max_c


def outside(value: float | None, low: float | None, high: float | None) -> bool:
    if value is None:
        return False
    return (low is not None and value < low) or (high is not None and value > high)


def record_reading(db: Session, shipment: Shipment, record: Telemetry) -> None:
    """Fold one bound reading into the shipment and raise an excursion alert if needed."""
    temperature = (record.summary or {}).get("temp_c")
    if not isinstance(temperature, (int, float)) or isinstance(temperature, bool):
        return
    shipment.temp_min_c = (temperature if shipment.temp_min_c is None
                           else min(shipment.temp_min_c, temperature))
    shipment.temp_max_c = (temperature if shipment.temp_max_c is None
                           else max(shipment.temp_max_c, temperature))
    low, high = storage_limits(db, shipment)
    if not outside(temperature, low, high):
        return
    if notifications.has_open_alert(db, "COMPLIANCE", shipment.id, kind=EXCURSION_KIND):
        return                                   # one open excursion alert per shipment
    batch = db.get(Batch, shipment.batch_id)
    batch_code = batch.batch_code if batch else shipment.batch_id
    limits = _limits_text(low, high)
    when = _aware(record.recorded_at)
    title = f"Cold-chain excursion on shipment {shipment.sscc} (batch {batch_code})"
    detail = (f"Sensor {record.device_id[:8]} read {temperature:g} °C on "
              f"{notifications.human_date(when)} at {when:%H:%M} UTC. The product must stay "
              f"{limits}.")
    receiver = shipment.to_org_id if shipment.to_org_id != shipment.org_id else None
    notifications.raise_alert(db, "COMPLIANCE", "HIGH", title, detail=detail,
                              org_id=shipment.org_id, entity_type="Shipment",
                              entity_id=shipment.id, reasons=["Temperature out of range"],
                              notify=False, kind=EXCURSION_KIND, party_org_id=receiver)
    # Both ends of the leg are told, whatever their roles: the sender (often a farm, whose
    # users hold none of the COMPLIANCE roles the category fan-out reaches) is responsible for
    # the goods in transit, and the receiver is about to take them and has to know before it
    # accepts them. Platform oversight roles for the category are told as well.
    notifications.notify_parties(db, [shipment.org_id, receiver], "COMPLIANCE", title, detail,
                                 "Shipment", shipment.id, severity="HIGH",
                                 include_oversight=True)


EXCURSION_KIND = "cold_chain_excursion"


def _limits_text(low: float | None, high: float | None) -> str:
    if low is not None and high is not None:
        return f"between {low:g} and {high:g} °C"
    if low is not None:
        return f"at or above {low:g} °C"
    return f"at or below {high:g} °C"


def summary(db: Session, shipment: Shipment, telemetry_summary: dict[str, Any]) -> dict[str, Any]:
    """Storage range and excursion count to go with telemetry.shipment_summary()."""
    low, high = storage_limits(db, shipment)
    excursions = 0
    if low is not None or high is not None:
        for (reading,) in db.execute(select(Telemetry.summary).where(
                Telemetry.shipment_id == shipment.id)):
            value = (reading or {}).get("temp_c")
            if isinstance(value, (int, float)) and outside(value, low, high):
                excursions += 1
    return {"storage_temp_min_c": low, "storage_temp_max_c": high, "excursions": excursions,
            "within_limits": (None if not telemetry_summary.get("readings")
                              or (low is None and high is None) else excursions == 0)}
