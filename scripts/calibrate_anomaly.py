#!/usr/bin/env python3
"""Measure the IsolationForest decision-function separation and report the scale to use.

The physical world needs tuning a fixed constant cannot see: after retraining on
different data, run this and set IF_OUTLIER_SCALE in ai/anomaly.py accordingly.
"""
from __future__ import annotations

import datetime
import pickle
import random
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai.anomaly import FEATURES, extract_features                    # noqa: E402
from ai.data.generate import anomalous_reading, telemetry_reading    # noqa: E402


def main() -> int:
    model_dir = ROOT / "ai" / "models"
    now = datetime.datetime.now(datetime.timezone.utc)
    print(f"{'device class':24s} {'normal med':>11s} {'attack med':>11s} {'suggested scale':>16s}")
    for device_type in FEATURES:
        path = model_dir / f"anomaly_{device_type.lower()}.joblib"
        if not path.is_file():
            print(f"{device_type:24s} (no artefact — run scripts/train_models.py)")
            continue
        with path.open("rb") as handle:
            model = pickle.load(handle)   # noqa: S301 - our own artefact
        rng = random.Random(5)
        previous = telemetry_reading(device_type, now, rng)
        normal = [model.decision_function(
            [extract_features(device_type, telemetry_reading(device_type, now, rng),
                              previous, 900.0, 12)])[0] for _ in range(40)]
        attack = []
        for mode in ("spoof", "drift", "stuck"):
            attack += [model.decision_function(
                [extract_features(device_type, anomalous_reading(device_type, seed=i, mode=mode),
                                  previous, 900.0, 12)])[0] for i in range(15)]
        normal_median, attack_median = statistics.median(normal), statistics.median(attack)
        suggested = round(abs(attack_median), 2) if attack_median < 0 else 0.15
        print(f"{device_type:24s} {normal_median:+11.4f} {attack_median:+11.4f} {suggested:16.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
