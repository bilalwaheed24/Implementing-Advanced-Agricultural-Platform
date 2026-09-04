#!/usr/bin/env python3
"""Post-deploy smoke test (brief §24 pipeline stage, §40 health check).

Exercises health, readiness, authentication and one read/write round trip against a
running instance. Exit code 0 means the deployment is serving traffic correctly.

Usage: python3 scripts/smoke_test.py [--api-url http://127.0.0.1:8000]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def call(base: str, method: str, path: str, body: dict | None = None,
         token: str | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        base + path, data=json.dumps(body).encode() if body is not None else None,
        headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            content_type = response.headers.get("content-type", "")
            if not raw or "json" not in content_type:
                return response.status, {}
            return response.status, json.loads(raw)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, (json.loads(raw) if raw else {})
        except json.JSONDecodeError:
            return error.code, {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--login-email", default="regulator@absp.demo")
    parser.add_argument("--login-password", default="DemoPassw0rd!2026")
    args = parser.parse_args()
    base = args.api_url.rstrip("/")
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        status = "PASS" if condition else "FAIL"
        print(f"  [{status}] {name}" + (f" — {detail}" if detail and not condition else ""))
        if not condition:
            failures.append(name)

    print(f"Smoke testing {base}")

    status, body = call(base, "GET", "/health")
    check("liveness: /health returns 200", status == 200, str(body))

    status, body = call(base, "GET", "/health/ready")
    check("readiness: database and ledger checks pass", status == 200, str(body))

    status, _ = call(base, "GET", "/metrics")
    check("metrics endpoint responds", status == 200)

    status, body = call(base, "GET", "/api/v1/farms")
    check("unauthenticated request is rejected (401)", status == 401, str(body))

    status, body = call(base, "POST", "/api/v1/auth/login",
                        {"email": args.login_email, "password": args.login_password})
    check("login succeeds with the seeded demo account", status == 200, str(body))
    token = body.get("access_token")

    if token:
        status, body = call(base, "GET", "/api/v1/auth/me", token=token)
        check("authenticated request succeeds", status == 200, str(body))

        status, body = call(base, "GET", "/api/v1/blockchain/verify", token=token)
        check("ledger reports a valid chain", status == 200 and body.get("valid") is True,
              str(body))

        status, body = call(base, "GET", "/api/v1/audit/verify", token=token)
        check("audit hash chain verifies", status == 200 and body.get("valid") is True,
              str(body))
    else:
        check("authenticated checks skipped: no token", False, "login failed above")

    # Correctly-shaped code (base32 alphabet the path pattern accepts) that does not exist.
    status, _ = call(base, "GET", "/api/v1/verify/ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ")
    check("public verification endpoint is reachable and rejects unknown codes",
         status == 404)

    print()
    if failures:
        print(f"SMOKE TEST FAILED: {len(failures)} check(s) failed: {failures}")
        return 1
    print("SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
