"""Cryptographic and identity primitives.

REAL IMPLEMENTATION: bcrypt password hashing, JWT issue/verify with an explicit
algorithm allow-list, HMAC-SHA256 device authentication with replay protection,
AES-256-GCM encryption at rest, canonical hashing.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import get_settings
from .errors import AuthError

# --------------------------------------------------------------------------- #
# Canonical hashing — the single definition used for entity hashes, transaction
# ids and audit-chain entries so any party can reproduce a hash independently.
# --------------------------------------------------------------------------- #

def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def content_hash(payload: Any) -> str:
    return sha256_hex(canonical_json(payload))


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime | None) -> datetime | None:
    """Attach UTC to a naive datetime.

    SQLite has no native timestamp type, so SQLAlchemy hands back naive datetimes even
    for columns declared `DateTime(timezone=True)`. Comparing one of those with an aware
    `utcnow()` raises TypeError, which is how a 500 reached the refresh endpoint. Every
    comparison against a persisted datetime goes through this function.
    """
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #

# Deliberately small list; the production control is a full breached-password
# corpus check.  ponytail: inline list, swap for a HIBP range API in production.
COMMON_PASSWORDS = {
    "password", "password123", "123456789012", "qwertyuiop12", "letmein12345",
    "administrator", "welcome12345", "iloveyou1234", "changeme1234", "agriculture1",
}


def validate_password_strength(password: str) -> None:
    from .errors import ValidationFailed

    settings = get_settings()
    if len(password) < settings.password_min_length:
        raise ValidationFailed(f"Password must be at least {settings.password_min_length} characters")
    if password.lower() in COMMON_PASSWORDS:
        raise ValidationFailed("Password appears in the common-password list")
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    if classes < 3:
        raise ValidationFailed("Password must combine at least three of: lower, upper, digit, symbol")


def hash_password(password: str) -> str:
    rounds = get_settings().bcrypt_rounds
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt(rounds)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:72], hashed.encode())
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #

def _claims(subject: str, token_type: str, minutes: float, extra: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    now = utcnow()
    payload = {
        "sub": subject,
        "typ": token_type,
        "jti": secrets.token_urlsafe(16),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    payload.update(extra)
    return payload


def create_access_token(user_id: str, role: str, organization_id: str | None) -> tuple[str, dict[str, Any]]:
    settings = get_settings()
    payload = _claims(user_id, "access", settings.access_token_minutes,
                      {"role": role, "org": organization_id})
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm,
                       headers={"kid": settings.jwt_key_id})
    return token, payload


def create_refresh_token(user_id: str, family_id: str) -> tuple[str, dict[str, Any]]:
    settings = get_settings()
    payload = _claims(user_id, "refresh", settings.refresh_token_days * 24 * 60, {"fam": family_id})
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm,
                       headers={"kid": settings.jwt_key_id})
    return token, payload


def decode_token(token: str, expected_type: str) -> dict[str, Any]:
    """Verify a JWT. Algorithm allow-list defeats the `alg:none` downgrade (T-03)."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],   # allow-list, never from the header
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid token") from exc
    if payload.get("typ") != expected_type:
        raise AuthError("Incorrect token type")
    return payload


# --------------------------------------------------------------------------- #
# Device authentication (IoT-Devices.md §4)
# --------------------------------------------------------------------------- #

def generate_device_secret() -> str:
    return secrets.token_hex(32)          # 256 bits


def device_canonical_string(device_id: str, timestamp: str, nonce: str, readings: Any) -> str:
    return "\n".join([device_id, timestamp, nonce, sha256_hex(canonical_json(readings))])


def device_signature(secret: str, device_id: str, timestamp: str, nonce: str, readings: Any) -> str:
    canonical = device_canonical_string(device_id, timestamp, nonce, readings)
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def verify_device_signature(secret: str, device_id: str, timestamp: str, nonce: str,
                            readings: Any, signature: str) -> bool:
    expected = device_signature(secret, device_id, timestamp, nonce, readings)
    return hmac.compare_digest(expected, (signature or "").strip().lower())


def timestamp_within_window(timestamp: str, window_seconds: int) -> bool:
    try:
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return abs((utcnow() - ts).total_seconds()) <= window_seconds


class NonceCache:
    """In-memory replay cache. ponytail: process-local; use Redis when multi-node."""

    def __init__(self, ttl_seconds: int = 600) -> None:
        self._ttl = ttl_seconds
        self._seen: dict[str, float] = {}

    def check_and_add(self, key: str) -> bool:
        """Return True if the nonce is new; False if it is a replay."""
        now = time.monotonic()
        if len(self._seen) > 100_000:
            self._purge(now)
        if key in self._seen and now - self._seen[key] < self._ttl:
            return False
        self._seen[key] = now
        return True

    def _purge(self, now: float) -> None:
        self._seen = {k: v for k, v in self._seen.items() if now - v < self._ttl}


nonce_cache = NonceCache()


# --------------------------------------------------------------------------- #
# Encryption at rest (AES-256-GCM)
# --------------------------------------------------------------------------- #

def encrypt_at_rest(plaintext: str, associated_data: str = "") -> str:
    """Return base64(nonce || ciphertext). AAD binds the record to its own id."""
    key = get_settings().encryption_key
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), associated_data.encode() or None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_at_rest(blob: str, associated_data: str = "") -> str:
    key = get_settings().encryption_key
    raw = base64.b64decode(blob)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, associated_data.encode() or None).decode("utf-8")


# --------------------------------------------------------------------------- #
# Misc token helpers
# --------------------------------------------------------------------------- #

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def verification_code() -> str:
    """Unguessable public code for consumer verification (128 bits, grouped base32)."""
    raw = secrets.token_bytes(16)
    encoded = base64.b32encode(raw).decode().rstrip("=")
    return "-".join(encoded[i:i + 4] for i in range(0, 20, 4))
