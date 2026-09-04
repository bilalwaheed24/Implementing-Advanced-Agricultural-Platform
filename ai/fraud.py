"""Food fraud detection and supply-chain integrity verification (FR-D3).

Rules-first (ADR-012): each rule produces a citable reason a regulator or a trading
partner can challenge. An Isolation Forest over event features adds a novelty
component when a model has been trained.
"""
from __future__ import annotations

import math
import pickle
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

MODEL_VERSION = "fraud-1.0.0"

# Rule weights. Configuration, not constants buried in branches.
RULE_WEIGHTS: dict[str, float] = {
    "quantity_mismatch": 0.35,
    "custody_gap": 0.30,
    "timeline_inconsistency": 0.30,
    "impossible_transit": 0.35,
    "expired_certification": 0.40,
    "revoked_certification": 0.55,
    "claim_conflict": 0.60,
    "cold_chain_break": 0.35,
    "ledger_mismatch": 0.80,
    "unanchored_events": 0.15,
    "duplicate_batch_code": 0.70,
}

# Stages that should appear between two recorded steps for a complete chain.
EXPECTED_ORDER = ["commissioning", "harvesting", "transforming", "packing",
                  "shipping", "receiving", "retail_selling"]

MAX_PLAUSIBLE_SPEED_KMH = 900.0     # air freight upper bound
EARTH_RADIUS_KM = 6371.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


class _ModelCache:
    def __init__(self) -> None:
        self._model: Any = None
        self._checked = False
        self._lock = threading.Lock()

    def get(self, model_dir: str) -> Any | None:
        with self._lock:
            if self._checked:
                return self._model
            self._checked = True
            path = Path(model_dir) / "fraud_if.joblib"
            if path.is_file():
                try:
                    with path.open("rb") as handle:
                        self._model = pickle.load(handle)   # noqa: S301 - our own artefact
                except Exception:                            # noqa: BLE001
                    self._model = None
            return self._model

    def clear(self) -> None:
        with self._lock:
            self._model, self._checked = None, False


_cache = _ModelCache()


def evaluate(context: dict[str, Any], model_dir: str = "./ai/models",
             suspect_threshold: float = 0.30, fail_threshold: float = 0.70) -> dict[str, Any]:
    """Score a batch for fraud.

    `context` carries: batch, events[], certifications[], telemetry_summary,
    shipments[], product, ledger_status, duplicate_codes.
    """
    reasons: list[dict[str, Any]] = []
    triggered: set[str] = set()

    batch = context.get("batch", {})
    events: list[dict[str, Any]] = sorted(
        context.get("events", []), key=lambda e: str(e.get("occurred_at", "")))
    certifications: list[dict[str, Any]] = context.get("certifications", [])
    shipments: list[dict[str, Any]] = context.get("shipments", [])
    product: dict[str, Any] = context.get("product", {})

    def add(rule: str, detail: str, **evidence: Any) -> None:
        if rule not in triggered:
            triggered.add(rule)
        reasons.append({"rule": rule, "detail": detail, "weight": RULE_WEIGHTS.get(rule, 0.2),
                        "evidence": evidence})

    # --- quantity conservation ------------------------------------------
    # The baseline is the quantity the batch was created with, not its current value:
    # quantity falls legitimately through processing loss, so comparing events against
    # the current value would flag every normal chain.
    declared = float(batch.get("initial_quantity") or batch.get("quantity") or 0)
    quantities = [float(e["quantity"]) for e in events if e.get("quantity") is not None]
    if quantities:
        if max(quantities) > declared * 1.001 and declared > 0:
            add("quantity_mismatch",
                f"An event declares {max(quantities)} against a batch created with {declared}",
                max_event_quantity=max(quantities), initial_quantity=declared)
        # Quantity must never increase between consecutive events: mass is not created
        # in a supply chain, and an increase is the signature of dilution or substitution.
        for earlier, later in zip(quantities, quantities[1:]):
            if later > earlier * 1.001:
                add("quantity_mismatch",
                    f"Quantity increased from {earlier} to {later} between consecutive "
                    f"events, which is not physically possible without an added input",
                    from_quantity=earlier, to_quantity=later)
                break
        if len(quantities) >= 2 and quantities[0]:
            loss = (quantities[0] - quantities[-1]) / quantities[0]
            if loss > 0.10:
                add("quantity_mismatch",
                    f"Unexplained loss of {loss:.0%} across the chain "
                    f"({quantities[0]} to {quantities[-1]})", loss_fraction=round(loss, 4))

    # --- custody gaps ----------------------------------------------------
    steps = [e.get("biz_step") for e in events if e.get("biz_step") in EXPECTED_ORDER]
    if len(steps) >= 2:
        first, last = EXPECTED_ORDER.index(steps[0]), EXPECTED_ORDER.index(steps[-1])
        missing = [s for s in EXPECTED_ORDER[first:last + 1] if s not in steps]
        # 'transforming' and 'packing' are legitimately absent for unprocessed produce.
        missing = [m for m in missing if m not in {"transforming", "packing"}]
        if missing:
            add("custody_gap", f"Missing chain stage(s): {', '.join(missing)}", missing=missing)

    # --- timeline --------------------------------------------------------
    times = [_as_datetime(e.get("occurred_at")) for e in events]
    times = [t for t in times if t]
    for earlier, later in zip(times, times[1:]):
        if later < earlier:
            add("timeline_inconsistency",
                f"Event recorded at {later.isoformat()} precedes the previous event "
                f"at {earlier.isoformat()}")
            break

    # --- transit plausibility -------------------------------------------
    for shipment in shipments:
        departed, arrived = _as_datetime(shipment.get("departed_at")), _as_datetime(shipment.get("arrived_at"))
        if not (departed and arrived) or arrived <= departed:
            continue
        try:
            distance = haversine_km(float(shipment["origin_lat"]), float(shipment["origin_lon"]),
                                    float(shipment["destination_lat"]), float(shipment["destination_lon"]))
        except (KeyError, TypeError, ValueError):
            continue
        hours = (arrived - departed).total_seconds() / 3600
        speed = distance / hours if hours > 0 else float("inf")
        if speed > MAX_PLAUSIBLE_SPEED_KMH:
            add("impossible_transit",
                f"Shipment covers {distance:.0f} km in {hours:.1f} h "
                f"({speed:.0f} km/h), above the plausible maximum",
                distance_km=round(distance, 1), hours=round(hours, 2), speed_kmh=round(speed, 1))

    # --- certifications ---------------------------------------------------
    now = _as_datetime(context.get("as_of")) or datetime.now(timezone.utc)
    for cert in certifications:
        valid_from, valid_to = _as_datetime(cert.get("valid_from")), _as_datetime(cert.get("valid_to"))
        if cert.get("status") == "REVOKED":
            add("revoked_certification",
                f"Certification {cert.get('cert_code')} ({cert.get('cert_type')}) has been revoked",
                cert_code=cert.get("cert_code"))
        elif valid_to and valid_to < now:
            add("expired_certification",
                f"Certification {cert.get('cert_code')} expired on {valid_to.date()}",
                cert_code=cert.get("cert_code"))
        elif valid_from and valid_from > now:
            add("expired_certification",
                f"Certification {cert.get('cert_code')} is not yet valid (from {valid_from.date()})",
                cert_code=cert.get("cert_code"))

    # --- claim conflicts --------------------------------------------------
    has_gmo_lineage = bool(batch.get("gmo_event_id") or batch.get("gmo_event_code"))
    if has_gmo_lineage:
        for cert in certifications:
            if cert.get("cert_type") in {"NON_GMO", "ORGANIC"} and cert.get("status") == "ACTIVE":
                add("claim_conflict",
                    f"{cert.get('cert_type')} certification claimed on a batch whose lineage "
                    f"contains GMO event {batch.get('gmo_event_code') or batch.get('gmo_event_id')}",
                    cert_code=cert.get("cert_code"))
        if product.get("non_gmo_claim") or product.get("organic_claim"):
            add("claim_conflict",
                "Product carries a non-GMO or organic claim but the batch lineage contains a GMO event")

    # --- cold chain -------------------------------------------------------
    telemetry = context.get("telemetry_summary") or {}
    low, high = product.get("storage_temp_min_c"), product.get("storage_temp_max_c")
    observed_min, observed_max = telemetry.get("temp_min_c"), telemetry.get("temp_max_c")
    if observed_max is not None and high is not None and float(observed_max) > float(high):
        add("cold_chain_break",
            f"Cold-chain excursion: observed {observed_max} °C exceeds the product maximum {high} °C",
            observed_max_c=observed_max, limit_c=high)
    if observed_min is not None and low is not None and float(observed_min) < float(low):
        add("cold_chain_break",
            f"Cold-chain excursion: observed {observed_min} °C is below the product minimum {low} °C",
            observed_min_c=observed_min, limit_c=low)

    # --- ledger integrity --------------------------------------------------
    ledger_status = context.get("ledger_status", "UNKNOWN")
    if ledger_status == "MISMATCH":
        add("ledger_mismatch",
            "A stored record's content hash does not match its blockchain anchor — "
            "the record has been altered after anchoring")
    unanchored = int(context.get("unanchored_events") or 0)
    if unanchored:
        add("unanchored_events", f"{unanchored} supply-chain event(s) are not anchored to the ledger",
            count=unanchored)

    if context.get("duplicate_batch_code"):
        add("duplicate_batch_code", "The same batch code appears in more than one custody chain")

    # --- aggregate ---------------------------------------------------------
    rule_score = 0.0
    for rule in triggered:
        weight = RULE_WEIGHTS.get(rule, 0.2)
        rule_score = rule_score + weight - rule_score * weight   # probabilistic OR

    model = _cache.get(model_dir)
    degraded = model is None
    final = rule_score
    if model is not None:
        try:
            vector = np.array([[
                len(events), declared, len(certifications), len(shipments),
                float(len(triggered)), float(unanchored),
                float(telemetry.get("temp_max_c") or 0), float(telemetry.get("temp_min_c") or 0),
            ]], dtype=float)
            raw = float(model.decision_function(vector)[0])
            novelty = float(np.clip(0.5 - raw, 0.0, 1.0))
            final = max(rule_score, round(0.75 * rule_score + 0.25 * novelty, 4))
            if novelty > 0.6 and not reasons:
                reasons.append({"rule": "statistical_novelty", "weight": 0.25,
                                "detail": "Event profile is statistically unusual for this product class",
                                "evidence": {}})
        except Exception:                          # noqa: BLE001
            degraded = True

    final = float(min(1.0, round(final, 4)))
    if final >= fail_threshold:
        level = "FAILED"
    elif final >= suspect_threshold:
        level = "SUSPECT"
    else:
        level = "VERIFIED"

    if not reasons:
        reasons.append({"rule": "none", "weight": 0.0,
                        "detail": "No fraud indicator triggered; chain of custody is complete and consistent",
                        "evidence": {}})

    return {"score": final, "level": level, "reasons": reasons, "degraded": degraded,
            "model_version": MODEL_VERSION + ("+rules-only" if degraded else ""),
            "rules_triggered": sorted(triggered)}
