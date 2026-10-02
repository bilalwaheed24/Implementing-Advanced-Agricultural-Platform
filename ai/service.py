"""AI inference service (ADR-016): the `ai` container's HTTP surface.

The backend calls this through `backend/app/services/ai_client.py`. Every endpoint is a
thin wrapper over a function in this package, so the in-process path (used by the test
suite and `run_local.sh`) and the container path run exactly the same code.

Internal only: the compose network does not publish this port, and when SERVICE_TOKEN is
set every call except /health must present it in `X-Service-Token`.

    uvicorn ai.service:app --host 0.0.0.0 --port 8100
"""
from __future__ import annotations

import dataclasses
import hmac
import os
from pathlib import Path
from typing import Any

import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import anomaly, crispr_risk, fraud, sequence_screening, vision
from .data.generate import CROP_CLASSES

MODEL_DIR = os.environ.get("AI_MODEL_DIR") or str(Path(__file__).resolve().parent / "models")
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")


class InputError(Exception):
    """Caller-supplied input was rejected by the model's own validation."""


def require_token(x_service_token: str = Header(default="")) -> None:
    """Fail closed.

    This used to allow every request when SERVICE_TOKEN was unset, so a misconfigured
    deployment silently exposed the whole internal API unauthenticated (audit P2). An absent
    token is now a refusal, not a bypass: the service is useless without configuration rather
    than open. Compose supplies the token via ${SERVICE_TOKEN:?}.
    """
    if not SERVICE_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="service is not configured: SERVICE_TOKEN is unset")
    if not hmac.compare_digest(x_service_token, SERVICE_TOKEN):
        raise HTTPException(status_code=401, detail="invalid service token")


app = FastAPI(title="ABSP AI service", version="1.0.0", docs_url=None, redoc_url=None,
              openapi_url=None)


@app.exception_handler(InputError)
async def _input_error(_request, exc: InputError) -> JSONResponse:      # noqa: ANN001
    return JSONResponse(status_code=422, content={"error": "invalid_input", "detail": str(exc)})


# --------------------------------------------------------------------------- #
# Request bodies
# --------------------------------------------------------------------------- #
class HazardIn(BaseModel):
    id: str
    agent_name: str
    hazard_class: str
    severity: int
    sequence: str


class ScreenRequest(BaseModel):
    sequence: str
    hazards: list[HazardIn]
    max_length: int = 100_000


class ValidateSequenceRequest(BaseModel):
    sequence: str
    max_length: int = 100_000


class CrisprRequest(BaseModel):
    target_gene: str
    organism: str
    organism_class: str
    guide_rna: str
    pam: str
    edit_type: str
    intent: str
    reference: str = ""


class ReadingsRequest(BaseModel):
    device_type: str
    readings: dict[str, Any]


class AnomalyScoreRequest(ReadingsRequest):
    previous: dict[str, Any] | None = None
    seconds_since_previous: float | None = None
    hour: int = 12


class FraudRequest(BaseModel):
    context: dict[str, Any]
    suspect_threshold: float = 0.30
    fail_threshold: float = 0.70


class VisionRequest(BaseModel):
    pixels: list[float] = Field(min_length=3)
    size: int = Field(ge=1, le=512)


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "ai",
            "models": {"anomaly": anomaly.model_card(MODEL_DIR).get("status", "trained"),
                       "crop_vision": vision.model_card(MODEL_DIR).get("status", "trained")}}


@app.get("/v1/meta", dependencies=[Depends(require_token)])
def meta() -> dict:
    return {"screening_engine_version": sequence_screening.ENGINE_VERSION,
            "image_size": vision.IMAGE_SIZE, "crop_classes": CROP_CLASSES}


@app.post("/v1/sequence/validate", dependencies=[Depends(require_token)])
def validate_sequence(payload: ValidateSequenceRequest) -> dict:
    try:
        return {"sequence": sequence_screening.validate(payload.sequence, payload.max_length)}
    except sequence_screening.SequenceError as exc:
        raise InputError(str(exc)) from exc


@app.post("/v1/sequence/screen", dependencies=[Depends(require_token)])
def screen(payload: ScreenRequest) -> dict:
    hazards = [sequence_screening.HazardRecord(**h.model_dump()) for h in payload.hazards]
    try:
        result = sequence_screening.screen(payload.sequence, hazards, payload.max_length)
    except sequence_screening.SequenceError as exc:
        raise InputError(str(exc)) from exc
    # Unrounded values: the backend stores these, and must store exactly what the
    # in-process engine produced (as_dict() rounds for display).
    return {**result.as_dict(), "max_identity": result.max_identity,
            "hits": [dataclasses.asdict(hit) for hit in result.hits],
            "normalized": sequence_screening.normalize(payload.sequence)}


@app.post("/v1/crispr/assess", dependencies=[Depends(require_token)])
def crispr_assess(payload: CrisprRequest) -> dict:
    try:
        result = crispr_risk.assess(**payload.model_dump())
    except crispr_risk.CrisprInputError as exc:
        raise InputError(str(exc)) from exc
    return {**result.as_dict(), "risk_score": result.risk_score}


@app.post("/v1/anomaly/validate", dependencies=[Depends(require_token)])
def anomaly_validate(payload: ReadingsRequest) -> dict:
    return {"problems": anomaly.validate_readings(payload.device_type, payload.readings)}


@app.post("/v1/anomaly/score", dependencies=[Depends(require_token)])
def anomaly_score(payload: AnomalyScoreRequest) -> dict:
    return anomaly.score(payload.device_type, payload.readings, payload.previous,
                         seconds_since_previous=payload.seconds_since_previous,
                         hour=payload.hour, model_dir=MODEL_DIR)


@app.post("/v1/fraud/evaluate", dependencies=[Depends(require_token)])
def fraud_evaluate(payload: FraudRequest) -> dict:
    return fraud.evaluate(payload.context, model_dir=MODEL_DIR,
                          suspect_threshold=payload.suspect_threshold,
                          fail_threshold=payload.fail_threshold)


@app.post("/v1/vision/classify", dependencies=[Depends(require_token)])
def vision_classify(payload: VisionRequest) -> dict:
    if len(payload.pixels) != payload.size * payload.size * 3:
        raise InputError(f"pixels must contain exactly {payload.size * payload.size * 3} "
                         f"values for size {payload.size}")
    image = np.array(payload.pixels, dtype=np.float32).reshape(
        payload.size, payload.size, 3).clip(0.0, 1.0)
    return vision.classify(image, model_dir=MODEL_DIR)


@app.get("/v1/model-cards", dependencies=[Depends(require_token)])
def model_cards() -> dict:
    import json

    fraud_path = Path(MODEL_DIR) / "fraud_model_card.json"
    fraud_card = json.loads(fraud_path.read_text()) if fraud_path.is_file() else {
        "status": "not_trained"}
    return {"anomaly": anomaly.model_card(MODEL_DIR), "crop_vision": vision.model_card(MODEL_DIR),
            "fraud": fraud_card}
