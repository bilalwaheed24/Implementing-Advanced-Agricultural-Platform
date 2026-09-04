"""Structured JSON logging with correlation ids and secret redaction.

Three streams (Security.md §19): application, security, audit.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import datetime, timezone

correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")
actor_id: ContextVar[str] = ContextVar("actor_id", default="-")
org_id: ContextVar[str] = ContextVar("org_id", default="-")

# Keys whose values must never reach a log sink.
_SECRET_KEY = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization|hmac|signature|sequence)",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"


def redact(value: object, _depth: int = 0) -> object:
    """Recursively redact secret-shaped keys from a structure."""
    if _depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            k: (_REDACTED if _SECRET_KEY.search(str(k)) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value][:50]
    if isinstance(value, str) and len(value) > 512:
        return value[:512] + "…[TRUNCATED]"
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id.get(),
        }
        if actor_id.get() != "-":
            payload["actor_id"] = actor_id.get()
        if org_id.get() != "-":
            payload["org_id"] = org_id.get()
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(redact(extra))  # type: ignore[arg-type]
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)[-2000:]
        return json.dumps(payload, default=str)


class RedactionFilter(logging.Filter):
    """Last-resort guard: strip obvious secret material from free-text messages."""

    _PATTERNS = [
        (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+"), r"\1[REDACTED]"),
        (re.compile(r"(eyJ[A-Za-z0-9._\-]{20,})"), _REDACTED),
        (re.compile(r"((?:password|secret|token)\"?\s*[:=]\s*\"?)([^\s,\"}]+)", re.I), r"\1[REDACTED]"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, repl in self._PATTERNS:
                record.msg = pattern.sub(repl, record.msg)
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    for noisy in ("uvicorn.access", "uvicorn.error"):
        logging.getLogger(noisy).handlers.clear()
        logging.getLogger(noisy).propagate = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


app_log = get_logger("absp.app")
security_log = get_logger("absp.security")
audit_log = get_logger("absp.audit")


def log_event(logger: logging.Logger, level: int, message: str, **fields: object) -> None:
    logger.log(level, message, extra={"extra_fields": fields})


def security_event(message: str, level: int = logging.WARNING, **fields: object) -> None:
    """Record a security-relevant event (authn/authz outcomes, rate limits, device auth)."""
    log_event(security_log, level, message, **fields)
