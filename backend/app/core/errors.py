"""Domain exception hierarchy and RFC-7807 style HTTP mapping."""
from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from .logging_conf import app_log, correlation_id, log_event
import logging


class AppError(Exception):
    """Base class for every expected error in the application."""

    status_code = 500
    error_type = "internal_error"
    title = "Internal server error"

    def __init__(self, detail: str = "", **context: Any) -> None:
        super().__init__(detail or self.title)
        self.detail = detail or self.title
        self.context = context


class ValidationFailed(AppError):
    status_code = 422
    error_type = "validation_failed"
    title = "Validation failed"


class BadRequest(AppError):
    status_code = 400
    error_type = "bad_request"
    title = "Bad request"


class AuthError(AppError):
    status_code = 401
    error_type = "authentication_failed"
    title = "Authentication failed"


class AccountLocked(AppError):
    status_code = 423
    error_type = "account_locked"
    title = "Account locked"


class PermissionDenied(AppError):
    status_code = 403
    error_type = "permission_denied"
    title = "Permission denied"


class NotFound(AppError):
    status_code = 404
    error_type = "not_found"
    title = "Resource not found"


class Conflict(AppError):
    status_code = 409
    error_type = "conflict"
    title = "Conflict"


class RateLimited(AppError):
    status_code = 429
    error_type = "rate_limited"
    title = "Too many requests"


class IntegrationError(AppError):
    """A downstream component (ledger, AI) failed. Callers degrade rather than fail."""

    status_code = 503
    error_type = "integration_unavailable"
    title = "Dependent service unavailable"


def problem(status: int, error_type: str, title: str, detail: str, **extra: Any) -> JSONResponse:
    body = {
        "type": f"https://absp.local/errors/{error_type}",
        "title": title,
        "status": status,
        "detail": detail,
        "correlation_id": correlation_id.get(),
    }
    body.update(extra)
    return JSONResponse(status_code=status, content=body)


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    # 5xx is unexpected: log with stack. 4xx is normal control flow: log at info.
    if exc.status_code >= 500:
        log_event(app_log, logging.ERROR, "application error",
                  path=request.url.path, error=exc.error_type, detail=exc.detail)
    else:
        log_event(app_log, logging.INFO, "client error",
                  path=request.url.path, error=exc.error_type)
    return problem(exc.status_code, exc.error_type, exc.title, exc.detail, **exc.context)


async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    """Never leak internals (Security.md T-18): log the trace, return a generic body."""
    app_log.exception("unhandled exception at %s", request.url.path)
    return problem(
        500,
        "internal_error",
        "Internal server error",
        "An unexpected error occurred. Quote the correlation id when reporting this.",
    )
