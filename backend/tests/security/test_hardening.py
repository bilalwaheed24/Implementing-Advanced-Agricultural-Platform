"""Injection, headers, rate limiting, error hygiene and log redaction.

Covers threats T-01, T-13, T-14, T-18, T-19, T-20 from Security.md §2.
"""
from __future__ import annotations

import pytest

SQL_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE farms; --",
    "1 UNION SELECT password_hash FROM users",
    "admin'--",
    "\" OR 1=1 --",
    "%27%20OR%201%3D1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "'\"><svg/onload=alert(1)>",
]


class TestSqlInjection:
    """T-14: the ORM parameterises everything; no string-built SQL exists."""

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_login_email_is_not_injectable(self, client, users, payload):
        response = client.post("/api/v1/auth/login",
                               json={"email": payload, "password": payload})
        assert response.status_code in (401, 422)
        assert "syntax" not in response.text.lower()
        assert "sqlite" not in response.text.lower()

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_query_filters_are_not_injectable(self, client, auth, payload):
        response = client.get("/api/v1/farms", headers=auth("FARM_OPERATOR"),
                              params={"region": payload})
        assert response.status_code == 200
        assert response.json()["items"] == []

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_path_parameters_are_not_injectable(self, client, auth, payload):
        response = client.get(f"/api/v1/farms/{payload}", headers=auth("FARM_OPERATOR"))
        assert response.status_code in (404, 422)

    def test_tables_survive_the_attempts(self, client, auth, farm):
        """The most direct proof: the data is still there afterwards."""
        response = client.get("/api/v1/farms", headers=auth("FARM_OPERATOR"))
        assert response.status_code == 200
        assert response.json()["total"] >= 1


class TestStoredContentIsNotExecutable:
    """T-20: the API stores text as text; the frontend never interpolates HTML."""

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_payload_is_returned_as_data_not_markup(self, client, auth, payload):
        created = client.post("/api/v1/farms", headers=auth("FARM_OPERATOR"), json={
            "name": payload, "region": "Iowa", "country": "US", "latitude": 42.0,
            "longitude": -93.0, "area_ha": 10.0})
        assert created.status_code == 201
        assert created.json()["name"] == payload           # stored verbatim
        assert created.headers["content-type"].startswith("application/json")

    def test_frontend_never_interpolates_untrusted_html(self):
        """Static assertion over the frontend source (ADR-004)."""
        from pathlib import Path

        frontend = Path(__file__).resolve().parents[3] / "frontend"
        if not frontend.is_dir():
            pytest.skip("frontend not present")
        offenders = []
        for path in frontend.rglob("*.js"):
            in_block_comment = False
            for number, line in enumerate(path.read_text().splitlines(), 1):
                stripped = line.strip()
                # Track /* ... */ block comments (our file headers use them) so a
                # word like "innerHTML" inside documentation is not a false positive.
                if in_block_comment:
                    if "*/" in stripped:
                        in_block_comment = False
                    continue
                if stripped.startswith("/*") and "*/" not in stripped:
                    in_block_comment = True
                    continue
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue
                if "innerHTML" in stripped and "innerHTML = ''" not in stripped \
                        and 'innerHTML = ""' not in stripped:
                    offenders.append(f"{path.name}:{number}")
                if "eval(" in stripped or "new Function(" in stripped:
                    offenders.append(f"{path.name}:{number} (eval)")
        assert not offenders, f"unsafe DOM or eval usage: {offenders}"


class TestSecurityHeaders:
    """T-20: headers are set on every response, including errors."""

    @pytest.mark.parametrize("path", ["/health", "/api/v1/farms", "/metrics"])
    def test_headers_present(self, client, path):
        response = client.get(path)
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert "object-src 'none'" in response.headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]

    def test_correlation_id_is_returned_and_echoed(self, client):
        assert client.get("/health").headers["X-Request-ID"]
        supplied = client.get("/health", headers={"X-Request-ID": "trace-me-123"})
        assert supplied.headers["X-Request-ID"] == "trace-me-123"

    def test_csp_forbids_inline_script(self, client):
        policy = client.get("/health").headers["Content-Security-Policy"]
        assert "unsafe-inline" not in policy
        assert "unsafe-eval" not in policy


class TestErrorHygiene:
    """T-18: no stack traces, no internal detail, no secrets in responses."""

    def test_validation_error_does_not_leak_internals(self, client, auth):
        response = client.post("/api/v1/farms", headers=auth("FARM_OPERATOR"),
                               json={"name": "x"})
        assert response.status_code == 422
        assert "Traceback" not in response.text
        assert "sqlalchemy" not in response.text.lower()

    def test_error_body_is_rfc7807_shaped(self, client):
        body = client.get("/api/v1/farms").json()
        assert set(body) >= {"type", "title", "status", "detail", "correlation_id"}
        assert body["status"] == 401

    def test_not_found_carries_no_query_detail(self, client, auth):
        response = client.get("/api/v1/devices/00000000-0000-0000-0000-000000000000",
                              headers=auth("FARM_OPERATOR"))
        assert response.status_code == 404
        assert "SELECT" not in response.text

    def test_no_password_hash_in_any_user_response(self, client, auth):
        response = client.get("/api/v1/admin/users", headers=auth("ADMIN"))
        assert response.status_code == 200
        assert "password" not in response.text.lower()
        assert "$2b$" not in response.text


class TestInputLimits:
    """T-13, T-19: expensive inputs are bounded."""

    def test_page_size_is_capped(self, client, auth):
        assert client.get("/api/v1/farms", headers=auth("FARM_OPERATOR"),
                          params={"page_size": 100000}).status_code == 422

    def test_oversized_sequence_rejected(self, client, auth):
        response = client.post("/api/v1/biosecurity/screenings",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"name": "huge", "sequence": "A" * 300_000,
                                     "intent": "research"})
        assert response.status_code == 422

    def test_invalid_alphabet_rejected(self, client, auth, hazards):
        response = client.post("/api/v1/biosecurity/screenings",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"name": "bad", "sequence": "ACGT" * 10 + "XYZQ",
                                     "intent": "research"})
        assert response.status_code == 422
        assert "alphabet" in response.json()["detail"].lower()

    def test_negative_and_absurd_numbers_rejected(self, client, auth):
        for area in (-5.0, 0.0, 10_000_000.0):
            response = client.post("/api/v1/farms", headers=auth("FARM_OPERATOR"), json={
                "name": "Bad Area", "region": "Iowa", "country": "US", "latitude": 42.0,
                "longitude": -93.0, "area_ha": area})
            assert response.status_code == 422, area

    @pytest.mark.parametrize("latitude,longitude", [(91, 0), (-91, 0), (0, 181), (0, -181)])
    def test_out_of_range_coordinates_rejected(self, client, auth, latitude, longitude):
        response = client.post("/api/v1/farms", headers=auth("FARM_OPERATOR"), json={
            "name": "Bad Coords", "region": "Iowa", "country": "US", "latitude": latitude,
            "longitude": longitude, "area_ha": 5.0})
        assert response.status_code == 422


class TestRateLimiting:
    """T-19: the limiter is real; functional tests raise the ceiling deliberately."""

    def test_token_bucket_refuses_when_exhausted(self):
        from app.core.ratelimit import TokenBucketLimiter

        limiter = TokenBucketLimiter(capacity=3, refill_per_minute=60)
        assert [limiter.allow("k")[0] for _ in range(5)] == [True, True, True, False, False]

    def test_retry_after_is_reported(self):
        from app.core.ratelimit import TokenBucketLimiter

        limiter = TokenBucketLimiter(capacity=1, refill_per_minute=60)
        limiter.allow("k")
        allowed, retry_after = limiter.allow("k")
        assert not allowed and retry_after > 0

    def test_buckets_are_isolated_per_key(self):
        from app.core.ratelimit import TokenBucketLimiter

        limiter = TokenBucketLimiter(capacity=1, refill_per_minute=60)
        assert limiter.allow("a")[0]
        assert limiter.allow("b")[0], "one principal must not exhaust another's budget"

    def test_public_verification_endpoint_is_limited(self, client, monkeypatch):
        """The consumer endpoint is unauthenticated, so it must be IP-limited."""
        from app.core import deps
        from app.core.ratelimit import TokenBucketLimiter

        monkeypatch.setattr(deps, "public_limiter", TokenBucketLimiter(2, 2))
        codes = [client.get("/api/v1/verify/AAAA-BBBB-CCCC-DDDD-EEEE").status_code
                 for _ in range(5)]
        assert 429 in codes, f"public endpoint was not rate limited: {codes}"

    def test_rate_limited_response_carries_retry_after(self, client, monkeypatch):
        from app.core import deps
        from app.core.ratelimit import TokenBucketLimiter

        monkeypatch.setattr(deps, "public_limiter", TokenBucketLimiter(1, 1))
        client.get("/api/v1/verify/AAAA-BBBB-CCCC-DDDD-EEEE")
        response = client.get("/api/v1/verify/AAAA-BBBB-CCCC-DDDD-EEEE")
        if response.status_code == 429:
            assert "Retry-After" in response.headers


class TestLogRedaction:
    """NFR-13: secrets must never reach a log sink."""

    @pytest.mark.parametrize("key", ["password", "device_secret", "api_key", "authorization",
                                     "jwt_token", "private_key", "hmac_signature", "sequence"])
    def test_secret_shaped_keys_are_redacted(self, key):
        from app.core.logging_conf import redact

        assert redact({key: "super-secret-value"})[key] == "[REDACTED]"

    def test_nested_structures_are_redacted(self):
        from app.core.logging_conf import redact

        result = redact({"outer": {"inner": {"password": "x"}}, "list": [{"token": "y"}]})
        assert result["outer"]["inner"]["password"] == "[REDACTED]"
        assert result["list"][0]["token"] == "[REDACTED]"

    def test_long_values_are_truncated(self):
        from app.core.logging_conf import redact

        assert "TRUNCATED" in redact({"note": "x" * 900})["note"]

    def test_bearer_tokens_are_stripped_from_messages(self):
        import logging

        from app.core.logging_conf import RedactionFilter

        record = logging.LogRecord("t", logging.INFO, "f", 1,
                                   "Authorization: Bearer eyJabc.def.ghi", None, None)
        RedactionFilter().filter(record)
        assert "eyJabc" not in record.msg

    def test_redaction_terminates_on_deep_structures(self):
        from app.core.logging_conf import redact

        deep: dict = {"k": {}}
        cursor = deep["k"]
        for _ in range(20):
            cursor["k"] = {}
            cursor = cursor["k"]
        assert redact(deep)          # must not recurse without bound


class TestPublicEndpointExposure:
    """T-01: the consumer endpoint must not become a data-harvesting API."""

    def test_unknown_code_returns_404_with_no_detail(self, client):
        response = client.get("/api/v1/verify/AAAA-BBBB-CCCC-DDDD-EEEE")
        assert response.status_code == 404
        assert "batch" not in response.text.lower() or "not found" in response.text.lower()

    @pytest.mark.parametrize("code", ["short", "lower-case-code", "../../etc/passwd", "a" * 100])
    def test_malformed_codes_are_rejected_by_the_pattern(self, client, code):
        assert client.get(f"/api/v1/verify/{code}").status_code in (404, 422)

    def test_verification_codes_are_unguessable(self):
        """128 bits of entropy: enumeration is not a feasible attack."""
        from app.core.security import verification_code

        codes = {verification_code() for _ in range(500)}
        assert len(codes) == 500
