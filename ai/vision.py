"""Crop condition classification from leaf imagery (TensorFlow/Keras CNN).

The specification names TensorFlow and computer vision for crop monitoring.
REAL IMPLEMENTATION (model + training loop). DEMO data: procedurally generated
leaf patches (ai/data/generate.py), so reported accuracy describes the synthetic
task only and does not predict field performance.

TensorFlow is imported lazily: importing it costs seconds, and the API must start
quickly and must keep working when no model artefact is present (NFR-5).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import numpy as np

from .data.generate import CROP_CLASSES

MODEL_VERSION = "cropvision-cnn-1.0.0"
IMAGE_SIZE = 48

ADVICE = {
    "HEALTHY": "No action required. Continue the routine monitoring schedule.",
    "LEAF_BLIGHT": "Necrotic lesions consistent with blight. Inspect the affected zone, "
                   "consider a targeted fungicide programme and review irrigation timing.",
    "RUST": "Pustule pattern consistent with rust. Scout neighbouring fields and consider a "
            "resistant variety for the next cycle.",
    "NUTRIENT_DEFICIENCY": "Interveinal chlorosis consistent with a nutrient deficiency. "
                           "Confirm against soil sensor nitrogen readings before applying.",
}

_lock = threading.Lock()
_model: Any = None
_checked = False


def _model_path(model_dir: str) -> Path:
    return Path(model_dir) / "crop_vision.keras"


def load_model(model_dir: str = "./ai/models") -> Any | None:
    global _model, _checked
    with _lock:
        if _checked:
            return _model
        _checked = True
        path = _model_path(model_dir)
        if not path.is_file():
            return None
        try:
            import tensorflow as tf                     # noqa: PLC0415 - deliberate lazy import

            _model = tf.keras.models.load_model(path)
        except Exception:                               # noqa: BLE001 - degrade, never crash
            _model = None
        return _model


def reset_cache() -> None:
    global _model, _checked
    with _lock:
        _model, _checked = None, False


def build_model(num_classes: int = len(CROP_CLASSES)) -> Any:
    import tensorflow as tf                             # noqa: PLC0415

    layers = tf.keras.layers
    return tf.keras.Sequential([
        layers.Input(shape=(IMAGE_SIZE, IMAGE_SIZE, 3)),
        layers.Conv2D(16, 3, activation="relu", padding="same"),
        layers.MaxPooling2D(),
        layers.Conv2D(32, 3, activation="relu", padding="same"),
        layers.MaxPooling2D(),
        layers.Conv2D(64, 3, activation="relu", padding="same"),
        layers.GlobalAveragePooling2D(),
        layers.Dropout(0.25),
        layers.Dense(64, activation="relu"),
        layers.Dense(num_classes, activation="softmax"),
    ], name="crop_vision")


def _fallback_classify(image: np.ndarray) -> dict[str, Any]:
    """Deterministic colour-statistic classifier used when no CNN artefact exists.

    Not a pretend model: it is an explicit, documented degraded mode.
    """
    red, green, blue = (float(image[..., i].mean()) for i in range(3))
    greenness = green - (red + blue) / 2
    if red > 0.45 and green < 0.45:
        label, confidence = "RUST", 0.55
    elif red > 0.38 and green > 0.45:
        label, confidence = "NUTRIENT_DEFICIENCY", 0.55
    elif greenness < 0.18:
        label, confidence = "LEAF_BLIGHT", 0.50
    else:
        label, confidence = "HEALTHY", 0.60
    return {
        "label": label, "confidence": confidence,
        "probabilities": {c: (confidence if c == label else
                              round((1 - confidence) / (len(CROP_CLASSES) - 1), 4))
                          for c in CROP_CLASSES},
        "degraded": True, "model_version": MODEL_VERSION + "+colour-fallback",
        "advice": ADVICE[label],
    }


def classify(image: np.ndarray, model_dir: str = "./ai/models") -> dict[str, Any]:
    """Classify one HxWx3 float image in [0,1]. Never raises on model problems."""
    if image.ndim != 3 or image.shape[2] != 3:
        raise ValueError("Image must have shape (height, width, 3)")
    if image.shape[0] != IMAGE_SIZE or image.shape[1] != IMAGE_SIZE:
        image = _resize(image, IMAGE_SIZE)

    model = load_model(model_dir)
    if model is None:
        return _fallback_classify(image)
    try:
        probabilities = model.predict(image[None, ...], verbose=0)[0]
    except Exception:                                   # noqa: BLE001
        return _fallback_classify(image)
    index = int(np.argmax(probabilities))
    label = CROP_CLASSES[index]
    return {
        "label": label,
        "confidence": round(float(probabilities[index]), 4),
        "probabilities": {c: round(float(p), 4) for c, p in zip(CROP_CLASSES, probabilities)},
        "degraded": False,
        "model_version": MODEL_VERSION,
        "advice": ADVICE[label],
    }


def _resize(image: np.ndarray, size: int) -> np.ndarray:
    """Nearest-neighbour resize (stdlib/NumPy only — no image library required)."""
    height, width = image.shape[:2]
    rows = (np.arange(size) * height // size).clip(0, height - 1)
    cols = (np.arange(size) * width // size).clip(0, width - 1)
    return image[rows][:, cols]


def model_card(model_dir: str = "./ai/models") -> dict[str, Any]:
    path = Path(model_dir) / "crop_vision_model_card.json"
    if path.is_file():
        return json.loads(path.read_text())
    return {"status": "not_trained", "note": "Run scripts/train_models.py"}
