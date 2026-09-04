"""Telemetry anomaly detection for device compromise and sensor failure (FR-A5).

Isolation Forest per device class (unsupervised: no labelled attack data exists for
farm telemetry). Falls back to a deterministic range/delta rule when no model is
available, so ingestion never fails because a model file is missing (NFR-5).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import numpy as np

MODEL_VERSION = "anomaly-if-1.0.0"

# Calibration knob. IsolationForest.decision_function is positive for inliers and
# negative for outliers; the magnitude depends on the trained forest, so the scale
# below maps "how negative" onto 0..1 and is measured, not assumed. Re-measure with
# scripts/calibrate_anomaly.py after retraining on different data.
IF_OUTLIER_SCALE = 0.15

# Ordered feature vector per device class. Order is part of the model contract.
FEATURES: dict[str, list[str]] = {
    "SOIL_SENSOR": ["soil_moisture_pct", "soil_temp_c", "ph", "nitrogen_ppm",
                    "phosphorus_ppm", "potassium_ppm", "ec_ds_m"],
    "WEATHER_STATION": ["air_temp_c", "humidity_pct", "rainfall_mm", "wind_speed_ms", "solar_w_m2"],
    "DRONE": ["altitude_m", "battery_pct", "images_captured", "speed_ms"],
    "YIELD_MONITOR": ["yield_t_ha", "moisture_pct", "speed_kmh", "swath_m"],
    "IRRIGATION_CONTROLLER": ["flow_l_min", "pressure_bar", "duration_s"],
    "COLD_CHAIN_SENSOR": ["temp_c", "humidity_pct", "shock_g"],
}

# Physically plausible ranges — validation, and the rule-based fallback detector.
RANGES: dict[str, tuple[float, float]] = {
    "soil_moisture_pct": (0, 100), "soil_temp_c": (-60, 80), "ph": (0, 14),
    "nitrogen_ppm": (0, 500), "phosphorus_ppm": (0, 300), "potassium_ppm": (0, 800),
    "ec_ds_m": (0, 20), "air_temp_c": (-60, 80), "humidity_pct": (0, 100),
    "rainfall_mm": (0, 500), "wind_speed_ms": (0, 120), "solar_w_m2": (0, 1500),
    "altitude_m": (0, 3000), "battery_pct": (0, 100), "images_captured": (0, 100000),
    "speed_ms": (0, 60), "yield_t_ha": (0, 50), "moisture_pct": (0, 100),
    "speed_kmh": (0, 60), "swath_m": (0, 20), "flow_l_min": (0, 2000),
    "pressure_bar": (0, 20), "duration_s": (0, 86400), "temp_c": (-40, 60),
    "shock_g": (0, 50),
}

# Typical operating band per channel; a reading outside it is suspicious but legal.
TYPICAL: dict[str, tuple[float, float]] = {
    "soil_moisture_pct": (8, 60), "soil_temp_c": (-5, 45), "ph": (4.5, 8.5),
    "nitrogen_ppm": (5, 120), "phosphorus_ppm": (3, 80), "potassium_ppm": (20, 300),
    "ec_ds_m": (0.1, 4), "air_temp_c": (-15, 45), "humidity_pct": (10, 100),
    "rainfall_mm": (0, 80), "wind_speed_ms": (0, 25), "solar_w_m2": (0, 1100),
    "altitude_m": (0, 400), "battery_pct": (10, 100), "speed_ms": (0, 25),
    "yield_t_ha": (0.5, 20), "moisture_pct": (8, 35), "speed_kmh": (0, 20),
    "swath_m": (1, 12), "flow_l_min": (0, 900), "pressure_bar": (0.5, 8),
    "temp_c": (-25, 25), "shock_g": (0, 5),
}


class _ModelCache:
    def __init__(self) -> None:
        self._models: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._missing: set[str] = set()

    def get(self, device_type: str, model_dir: str) -> Any | None:
        # The cache key includes the model directory: keying on device type alone made a
        # caller pointing at an empty directory silently receive a previously loaded model.
        key = f"{model_dir}::{device_type}"
        with self._lock:
            if key in self._models:
                return self._models[key]
            if key in self._missing:
                return None
            path = Path(model_dir) / f"anomaly_{device_type.lower()}.joblib"
            if not path.is_file():
                self._missing.add(key)
                return None
            try:
                import pickle

                with path.open("rb") as handle:
                    model = pickle.load(handle)   # noqa: S301 - our own artefact, integrity-checked
            except Exception:                     # noqa: BLE001 - degrade, never fail ingestion
                self._missing.add(key)
                return None
            self._models[key] = model
            return model

    def clear(self) -> None:
        with self._lock:
            self._models.clear()
            self._missing.clear()


_cache = _ModelCache()


def validate_readings(device_type: str, readings: dict[str, Any]) -> list[str]:
    """Return a list of violations. Empty means the payload is physically plausible."""
    problems: list[str] = []
    known = set(FEATURES.get(device_type, []))
    for channel, value in readings.items():
        if channel in ("sequence", "flight_mode", "valve_state", "door_open", "gps_lat", "gps_lon"):
            continue
        if channel not in known:
            problems.append(f"Unknown channel '{channel}' for device type {device_type}")
            continue
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            problems.append(f"Channel '{channel}' must be numeric")
            continue
        low, high = RANGES.get(channel, (float("-inf"), float("inf")))
        if not low <= float(value) <= high:
            problems.append(f"Channel '{channel}' value {value} is outside the physical range "
                            f"[{low}, {high}]")
    return problems


def extract_features(device_type: str, readings: dict[str, Any],
                     previous: dict[str, Any] | None = None,
                     seconds_since_previous: float | None = None,
                     hour: int = 12) -> list[float]:
    channels = FEATURES.get(device_type, [])
    vector: list[float] = []
    for channel in channels:
        value = readings.get(channel)
        vector.append(float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0)
    for channel in channels:
        current = readings.get(channel)
        prior = (previous or {}).get(channel)
        if isinstance(current, (int, float)) and isinstance(prior, (int, float)):
            vector.append(float(current) - float(prior))
        else:
            vector.append(0.0)
    vector.append(float(seconds_since_previous if seconds_since_previous is not None else 0.0))
    vector.append(float(hour))
    return vector


def _rule_score(device_type: str, readings: dict[str, Any],
                previous: dict[str, Any] | None) -> tuple[float, list[str]]:
    """Deterministic fallback detector. Also supplies human-readable reasons."""
    reasons: list[str] = []
    score = 0.0

    # Stuck-sensor signature: every numeric channel reporting exactly the same value
    # (classically all zeros) is not a plausible simultaneous physical state. This is
    # detectable from a single message, without needing a previous reading.
    channels = FEATURES.get(device_type, [])
    numeric = [float(readings[c]) for c in channels
               if isinstance(readings.get(c), (int, float)) and not isinstance(readings.get(c), bool)]
    if len(numeric) >= 3 and len(set(numeric)) == 1:
        score += 0.7
        reasons.append(
            f"All {len(numeric)} numeric channels report the identical value {numeric[0]}, "
            f"which indicates a stuck or spoofed sensor rather than a physical state")
    for channel in FEATURES.get(device_type, []):
        value = readings.get(channel)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        value = float(value)
        low, high = RANGES.get(channel, (float("-inf"), float("inf")))
        if not low <= value <= high:
            score += 0.5
            reasons.append(f"{channel}={value} is outside the physical range [{low}, {high}]")
            continue
        t_low, t_high = TYPICAL.get(channel, (low, high))
        span = max(t_high - t_low, 1e-6)
        if value < t_low:
            deviation = (t_low - value) / span
            if deviation > 0.15:
                score += min(0.45, deviation * 0.5)
                reasons.append(f"{channel}={value} is below the typical band [{t_low}, {t_high}]")
        elif value > t_high:
            deviation = (value - t_high) / span
            if deviation > 0.15:
                score += min(0.45, deviation * 0.5)
                reasons.append(f"{channel}={value} is above the typical band [{t_low}, {t_high}]")
        prior = (previous or {}).get(channel)
        if isinstance(prior, (int, float)) and not isinstance(prior, bool):
            jump = abs(value - float(prior))
            if jump > span * 0.8:
                score += 0.3
                reasons.append(f"{channel} jumped by {jump:.2f} since the previous reading")
    return min(1.0, score), reasons


def score(device_type: str, readings: dict[str, Any], previous: dict[str, Any] | None = None,
          seconds_since_previous: float | None = None, hour: int = 12,
          model_dir: str = "./ai/models") -> dict[str, Any]:
    """Return {score, level, reasons, degraded, model_version}. Never raises."""
    rule_score, reasons = _rule_score(device_type, readings, previous)
    model = _cache.get(device_type, model_dir)
    degraded = model is None
    final = rule_score

    if model is not None:
        try:
            vector = np.array([extract_features(device_type, readings, previous,
                                                seconds_since_previous, hour)], dtype=float)
            raw = float(model.decision_function(vector)[0])
            # Positive = inlier (score 0); increasingly negative = increasingly anomalous.
            model_score = float(np.clip(-raw / IF_OUTLIER_SCALE, 0.0, 1.0))
            final = max(rule_score, round(0.6 * model_score + 0.4 * rule_score, 4))
            if model_score > 0.6 and not reasons:
                reasons.append("Reading is statistically inconsistent with this device class's "
                               "learned behaviour")
        except Exception:                          # noqa: BLE001 - degrade to the rule score
            degraded = True

    final = float(min(1.0, round(final, 4)))
    if final >= 0.8:
        level = "CRITICAL"
    elif final >= 0.65:
        level = "HIGH"
    elif final >= 0.4:
        level = "WARNING"
    else:
        level = "INFO"

    if not reasons:
        reasons.append("Reading is consistent with the expected operating envelope")

    return {"score": final, "level": level, "reasons": reasons[:8], "degraded": degraded,
            "model_version": MODEL_VERSION + ("+rules-only" if degraded else "")}


def model_card(model_dir: str = "./ai/models") -> dict[str, Any]:
    path = Path(model_dir) / "anomaly_model_card.json"
    if path.is_file():
        return json.loads(path.read_text())
    return {"status": "not_trained", "note": "Run scripts/train_models.py"}
