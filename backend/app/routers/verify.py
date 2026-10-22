"""Public consumer verification (FR-D4).

Unauthenticated and rate-limited. Exposes only non-sensitive provenance: never farmer
identity, exact coordinates, or commercial terms.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Request, Response

from ..core.config import get_settings
from ..core.deps import DbSession, public_rate_limit
from ..core.errors import ValidationFailed
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
def qr(request: Request, code: str = Path(pattern=CODE_PATTERN),
       db: DbSession = None) -> Response:
    """Generated locally with the standard library: no external service, no dependency.

    The payload is an absolute URL, because a phone camera cannot open a relative path:
    PUBLIC_BASE_URL when configured, otherwise the host the request arrived on (nginx passes
    `Host` through, port included).
    """
    service.public_verification(db, code.upper())      # 404 for unknown codes
    configured = get_settings().public_base_url
    base = configured or str(request.base_url).rstrip("/")
    try:
        svg = qr_svg(f"{base}/verify.html?code={code.upper()}")
    except ValueError as exc:                     # an over-long host cannot fit a QR payload
        raise ValidationFailed("The verification address is too long to fit in a QR code; "
                               "set a shorter PUBLIC_BASE_URL") from exc
    # Built from the request Host unless PUBLIC_BASE_URL is set, so a shared cache must not
    # serve one client's QR to another.
    cache = "public, max-age=3600" if configured else "private, max-age=3600"
    return Response(content=svg, media_type="image/svg+xml", headers={"Cache-Control": cache})
