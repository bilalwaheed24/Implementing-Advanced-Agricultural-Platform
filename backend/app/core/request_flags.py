"""Per-request flags that deep code can raise and the access recorder can read.

The data-theft detector needs to know when a request probed another tenant's record.
That request deliberately gets a plain 404 (revealing existence would leak tenancy), so
the status code alone cannot tell the recorder. The repository raises this flag instead.
A mutable dict is stored in the context variable so a flag set inside the threadpool that
runs a sync endpoint is visible to the middleware that created it.
"""
from __future__ import annotations

from contextvars import ContextVar

_flags: ContextVar[dict[str, bool] | None] = ContextVar("absp_request_flags", default=None)


def begin() -> dict[str, bool]:
    flags: dict[str, bool] = {}
    _flags.set(flags)
    return flags


def raise_flag(name: str) -> None:
    flags = _flags.get()
    if flags is not None:
        flags[name] = True
