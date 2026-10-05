"""Minimal JSON-over-HTTP client for the internal `ai` and `ledger` services (ADR-016).

Standard library only (Development-rules.md §10). Every call carries the shared
service token and the current correlation id, so one request can be followed across
the api, ai and ledger logs.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import date, datetime
from typing import Any

from ..core.config import get_settings
from ..core.errors import IntegrationError
from ..core.logging_conf import app_log, correlation_id, log_event


def _encode(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


class ServiceUnavailable(IntegrationError):
    """The internal service could not be reached or answered with a server error.

    An IntegrationError, so an unhandled one becomes a 503 problem response. The detail
    shown to API callers is generic; the internal URL and cause go to the log only."""


def unavailable(base_url: str, path: str, cause: str) -> ServiceUnavailable:
    log_event(app_log, logging.ERROR, "internal service call failed", url=f"{base_url}{path}",
              error=cause[:500])
    return ServiceUnavailable("A dependent internal service is unavailable")


def call(base_url: str, method: str, path: str,
         body: dict[str, Any] | None = None) -> tuple[int, Any]:
    """Return (status, decoded JSON body). 4xx is returned to the caller to interpret;
    connection failures and 5xx raise ServiceUnavailable."""
    settings = get_settings()
    # Internal services are plain HTTP(S) only: refuse file:// and other urllib schemes.
    if not base_url.startswith(("http://", "https://")):
        raise unavailable(base_url, path, "service URL must be http:// or https://")
    data = json.dumps(body, default=_encode).encode() if body is not None else None
    request = urllib.request.Request(f"{base_url}{path}", data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if settings.service_token:
        request.add_header("X-Service-Token", settings.service_token)
    request.add_header("X-Request-ID", correlation_id.get() or "-")
    try:
        with urllib.request.urlopen(request, timeout=settings.service_timeout_seconds) as resp:  # nosec B310 - scheme checked above
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        try:
            decoded = json.loads(payload or b"null")
        except ValueError:
            decoded = {"detail": payload.decode(errors="replace")[:500]}
        if exc.code >= 500:
            detail = decoded.get("detail") if isinstance(decoded, dict) else decoded
            raise unavailable(base_url, path, f"{exc.code}: {detail}") from exc
        return exc.code, decoded
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise unavailable(base_url, path, f"unreachable: {exc}") from exc
