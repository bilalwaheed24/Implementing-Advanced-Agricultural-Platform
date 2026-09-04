"""Unit tests for the cryptographic and identity primitives (Security.md §5, §9)."""
from __future__ import annotations

import base64

import pytest

from app.core.errors import AuthError, ValidationFailed
from app.core.security import (canonical_json, content_hash, create_access_token,
                               decode_token, decrypt_at_rest, device_signature,
                               encrypt_at_rest, generate_device_secret, hash_password,
                               timestamp_within_window, utcnow, validate_password_strength,
                               verification_code, verify_device_signature, verify_password)


class TestPasswords:
    def test_hash_is_salted_and_verifies(self):
        first, second = hash_password("Str0ng-Passw0rd!"), hash_password("Str0ng-Passw0rd!")
        assert first != second, "bcrypt must salt each hash"
        assert verify_password("Str0ng-Passw0rd!", first)
        assert verify_password("Str0ng-Passw0rd!", second)

    def test_wrong_password_rejected(self):
        assert not verify_password("wrong", hash_password("Str0ng-Passw0rd!"))

    def test_malformed_hash_returns_false_rather_than_raising(self):
        assert not verify_password("anything", "not-a-bcrypt-hash")

    def test_bcrypt_cost_is_at_least_12(self):
        assert int(hash_password("Str0ng-Passw0rd!").split("$")[2]) >= 12

    @pytest.mark.parametrize("password", [
        "short", "alllowercaseonly", "password123", "PASSWORD1234",
    ])
    def test_weak_passwords_rejected(self, password):
        with pytest.raises(ValidationFailed):
            validate_password_strength(password)

    def test_strong_password_accepted(self):
        validate_password_strength("Corr3ct-Horse-Battery!")


class TestJwt:
    def test_round_trip(self):
        token, payload = create_access_token("user-1", "ADMIN", "org-1")
        decoded = decode_token(token, "access")
        assert decoded["sub"] == "user-1"
        assert decoded["role"] == "ADMIN"
        assert decoded["org"] == "org-1"
        assert decoded["jti"] == payload["jti"]

    def test_token_type_is_enforced(self):
        token, _ = create_access_token("user-1", "ADMIN", "org-1")
        with pytest.raises(AuthError):
            decode_token(token, "refresh")

    def test_tampered_signature_rejected(self):
        token, _ = create_access_token("user-1", "ADMIN", "org-1")
        header, body, signature = token.split(".")
        with pytest.raises(AuthError):
            decode_token(f"{header}.{body}.{signature[:-4]}AAAA", "access")

    def test_alg_none_downgrade_rejected(self):
        """T-03: an unsigned token forged with alg:none must never verify."""
        import json

        def b64(data: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

        forged = (b64({"alg": "none", "typ": "JWT"}) + "." +
                  b64({"sub": "attacker", "typ": "access", "jti": "x",
                       "iat": 0, "exp": 9999999999, "iss": "absp", "aud": "absp-api"}) + ".")
        with pytest.raises(AuthError):
            decode_token(forged, "access")

    def test_expired_token_rejected(self):
        import jwt as pyjwt

        from app.core.config import get_settings

        settings = get_settings()
        expired = pyjwt.encode(
            {"sub": "u", "typ": "access", "jti": "j", "iat": 0, "exp": 1,
             "iss": settings.jwt_issuer, "aud": settings.jwt_audience},
            settings.jwt_secret, algorithm=settings.jwt_algorithm)
        with pytest.raises(AuthError):
            decode_token(expired, "access")


class TestDeviceHmac:
    def test_valid_signature_accepted(self):
        secret = generate_device_secret()
        readings = {"soil_moisture_pct": 31.2, "ph": 6.4}
        signature = device_signature(secret, "dev-1", "2026-01-01T00:00:00+00:00", "n1", readings)
        assert verify_device_signature(secret, "dev-1", "2026-01-01T00:00:00+00:00", "n1",
                                       readings, signature)

    def test_secret_is_256_bits(self):
        assert len(bytes.fromhex(generate_device_secret())) == 32

    @pytest.mark.parametrize("mutation", ["device", "timestamp", "nonce", "readings", "secret"])
    def test_any_mutation_invalidates_the_signature(self, mutation):
        secret = generate_device_secret()
        readings = {"soil_moisture_pct": 31.2}
        args = ["dev-1", "2026-01-01T00:00:00+00:00", "n1", readings]
        signature = device_signature(secret, *args)
        if mutation == "device":
            args[0] = "dev-2"
        elif mutation == "timestamp":
            args[1] = "2026-01-01T00:05:00+00:00"
        elif mutation == "nonce":
            args[2] = "n2"
        elif mutation == "readings":
            args[3] = {"soil_moisture_pct": 31.3}
        else:
            secret = generate_device_secret()
        assert not verify_device_signature(secret, *args, signature)

    def test_signature_is_independent_of_key_order(self):
        """Canonical JSON means a re-ordered payload still verifies."""
        secret = generate_device_secret()
        signature = device_signature(secret, "d", "t", "n", {"a": 1, "b": 2})
        assert verify_device_signature(secret, "d", "t", "n", {"b": 2, "a": 1}, signature)

    def test_timestamp_window(self):
        assert timestamp_within_window(utcnow().isoformat(), 300)
        assert not timestamp_within_window("2020-01-01T00:00:00+00:00", 300)
        assert not timestamp_within_window("not-a-timestamp", 300)


class TestEncryptionAtRest:
    def test_round_trip_with_associated_data(self):
        blob = encrypt_at_rest("sensitive payload", "record-1")
        assert "sensitive payload" not in blob
        assert decrypt_at_rest(blob, "record-1") == "sensitive payload"

    def test_ciphertext_is_not_reused(self):
        assert encrypt_at_rest("same", "r1") != encrypt_at_rest("same", "r1")

    def test_wrong_associated_data_fails(self):
        """A ciphertext cannot be moved to a different record."""
        blob = encrypt_at_rest("payload", "record-1")
        with pytest.raises(Exception):
            decrypt_at_rest(blob, "record-2")

    def test_tampered_ciphertext_fails(self):
        blob = encrypt_at_rest("payload", "r")
        raw = bytearray(base64.b64decode(blob))
        raw[-1] ^= 0x01
        with pytest.raises(Exception):
            decrypt_at_rest(base64.b64encode(bytes(raw)).decode(), "r")


class TestHashing:
    def test_canonical_json_is_order_independent(self):
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

    def test_content_hash_is_stable_and_sensitive(self):
        assert content_hash({"a": 1}) == content_hash({"a": 1})
        assert content_hash({"a": 1}) != content_hash({"a": 2})
        assert len(content_hash({"a": 1})) == 64


class TestVerificationCode:
    def test_shape_and_uniqueness(self):
        codes = {verification_code() for _ in range(200)}
        assert len(codes) == 200, "codes must be unguessable and unique"
        sample = codes.pop()
        assert len(sample.replace("-", "")) == 20
        assert all(part.isalnum() for part in sample.split("-"))
