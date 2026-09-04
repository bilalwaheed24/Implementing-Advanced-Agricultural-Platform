"""Public consumer verification (FR-D4).

Unauthenticated and rate-limited. Exposes only non-sensitive provenance: never farmer
identity, exact coordinates, or commercial terms.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Response

from ..core.deps import DbSession, public_rate_limit
from ..qrcode import qr_svg
from ..schemas import PublicVerification
from ..services import supplychain as service

router = APIRouter(prefix="/verify", tags=["Public Verification"],
                   dependencies=[Depends(public_rate_limit)])

CODE_PATTERN = r"^[A-Z2-7\-]{16,40}$"


@router.get("/{code}", response_model=PublicVerification,
            summary="Verify a product by its QR verification code")
def verify(code: str = Path(pattern=CODE_PATTERN), db: DbSession = None) -> PublicVerification:
    return PublicVerification(**service.public_verification(db, code.upper()))


@router.get("/{code}/qr", summary="QR code for the public verification page (SVG)")
def qr(code: str = Path(pattern=CODE_PATTERN), db: DbSession = None) -> Response:
    """Generated locally with the standard library: no external service, no dependency."""
    service.public_verification(db, code.upper())      # 404 for unknown codes
    svg = qr_svg(f"/verify.html?code={code.upper()}")
    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=3600"})
