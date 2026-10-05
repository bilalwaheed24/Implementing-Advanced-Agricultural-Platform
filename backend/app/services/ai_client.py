"""Backend-facing client for the AI service (ADR-016).

With AI_SERVICE_URL set, every call goes over HTTP to the `ai` container. Without it,
the same handler functions in `ai/service.py` run in-process — that is the path the test
suite and `run_local.sh` use — so both modes return byte-for-byte the same shapes.

Input the models reject surfaces as AIInputError (callers turn it into a 422);
an unreachable service surfaces as service_http.ServiceUnavailable.
"""
from __future__ import annotations

from functools import lru_cache
from types import SimpleNamespace
from typing import Any

from ..core.config import get_settings
from . import service_http


class AIInputError(ValueError):
    """The AI service rejected caller-supplied input."""


# path -> (handler name in ai.service, request model name or None, HTTP method)
_ROUTES: dict[str, tuple[str, str | None, str]] = {
    "/v1/meta": ("meta", None, "GET"),
    "/v1/sequence/validate": ("validate_sequence", "ValidateSequenceRequest", "POST"),
    "/v1/sequence/screen": ("screen", "ScreenRequest", "POST"),
    "/v1/crispr/assess": ("crispr_assess", "CrisprRequest", "POST"),
    "/v1/anomaly/validate": ("anomaly_validate", "ReadingsRequest", "POST"),
    "/v1/anomaly/score": ("anomaly_score", "AnomalyScoreRequest", "POST"),
    "/v1/fraud/evaluate": ("fraud_evaluate", "FraudRequest", "POST"),
    "/v1/vision/classify": ("vision_classify", "VisionRequest", "POST"),
    "/v1/model-cards": ("model_cards", None, "GET"),
}


def _invoke(path: str, payload: dict[str, Any] | None = None) -> Any:
    handler_name, model_name, method = _ROUTES[path]
    settings = get_settings()
    if settings.ai_service_url:
        status, body = service_http.call(settings.ai_service_url, method, path, payload)
        if status == 422:
            detail = body.get("detail") if isinstance(body, dict) else body
            raise AIInputError(detail if isinstance(detail, str) else "invalid input")
        if status != 200:
            raise service_http.unavailable(settings.ai_service_url, path, f"status {status}")
        return body

    from pydantic import ValidationError

    from ai import service                                     # noqa: PLC0415

    handler = getattr(service, handler_name)
    try:
        if model_name is None:
            return handler()
        return handler(getattr(service, model_name)(**(payload or {})))
    except service.InputError as exc:
        raise AIInputError(str(exc)) from exc
    except ValidationError as exc:
        raise AIInputError(str(exc)) from exc


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def meta() -> dict[str, Any]:
    """Static per deployment (engine version, image size, classes), so cached."""
    return _invoke("/v1/meta")


def validate_sequence(sequence: str, max_length: int) -> str:
    return _invoke("/v1/sequence/validate",
                   {"sequence": sequence, "max_length": max_length})["sequence"]


def screen(sequence: str, hazards: list[dict[str, Any]], max_length: int) -> SimpleNamespace:
    """Result exposes verdict, max_identity, hits[], hazard_classes, reasons,
    engine_version and normalized (the cleaned query sequence)."""
    result = _invoke("/v1/sequence/screen", {"sequence": sequence, "hazards": hazards,
                                             "max_length": max_length})
    return SimpleNamespace(**{**result, "hits": [SimpleNamespace(**h) for h in result["hits"]]})


def assess_crispr(target_gene: str, organism: str, organism_class: str, guide_rna: str,
                  pam: str, edit_type: str, intent: str, reference: str = "") -> SimpleNamespace:
    return SimpleNamespace(**_invoke("/v1/crispr/assess", {
        "target_gene": target_gene, "organism": organism, "organism_class": organism_class,
        "guide_rna": guide_rna, "pam": pam, "edit_type": edit_type, "intent": intent,
        "reference": reference}))


def validate_readings(device_type: str, readings: dict[str, Any]) -> list[str]:
    return _invoke("/v1/anomaly/validate",
                   {"device_type": device_type, "readings": readings})["problems"]


def anomaly_score(device_type: str, readings: dict[str, Any],
                  previous: dict[str, Any] | None = None,
                  seconds_since_previous: float | None = None, hour: int = 12) -> dict[str, Any]:
    return _invoke("/v1/anomaly/score", {
        "device_type": device_type, "readings": readings, "previous": previous,
        "seconds_since_previous": seconds_since_previous, "hour": hour})


def evaluate_fraud(context: dict[str, Any], suspect_threshold: float,
                   fail_threshold: float) -> dict[str, Any]:
    return _invoke("/v1/fraud/evaluate", {"context": context,
                                          "suspect_threshold": suspect_threshold,
                                          "fail_threshold": fail_threshold})


def classify_image(pixels: list[float], size: int) -> dict[str, Any]:
    return _invoke("/v1/vision/classify", {"pixels": pixels, "size": size})


def model_cards() -> dict[str, Any]:
    return _invoke("/v1/model-cards")
