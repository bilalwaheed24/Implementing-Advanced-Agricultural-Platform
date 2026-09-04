"""Typed application settings loaded from the environment.

Rule (Development-rules.md §11): no module outside this one reads os.environ.
Production refuses to start with development defaults for any secret.
"""
from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

_DEV_JWT_DEFAULT = "dev-only-insecure-jwt-secret-change-me"
_PLACEHOLDERS = {
    "CHANGE_ME_generate_a_48_byte_url_safe_random_string",
    "CHANGE_ME_base64_encoded_32_byte_key",
    _DEV_JWT_DEFAULT,
    "",
}


def _load_dotenv() -> None:
    """Minimal .env loader (stdlib only). Real environment always wins."""
    path = REPO_ROOT / ".env"
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.split(" #")[0].strip().strip("'\"")
        os.environ.setdefault(key, value)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


class ConfigurationError(RuntimeError):
    """Raised when the process is configured unsafely for its environment."""


@dataclass(frozen=True)
class Settings:
    env: str = "development"
    app_name: str = "Agricultural Biotechnology Security Platform"
    api_prefix: str = "/api/v1"
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    demo_mode: bool = True

    database_url: str = "sqlite:///./absp.db"

    jwt_secret: str = _DEV_JWT_DEFAULT
    jwt_algorithm: str = "HS256"
    jwt_key_id: str = "k1"
    jwt_issuer: str = "absp"
    jwt_audience: str = "absp-api"
    access_token_minutes: int = 30
    refresh_token_days: int = 7
    bcrypt_rounds: int = 12
    password_min_length: int = 12
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    encryption_key_b64: str = ""

    device_timestamp_window_seconds: int = 300
    device_backfill_window_seconds: int = 86400
    device_max_batch: int = 500
    # Inline AI scoring costs ~10 ms per message (sklearn per-call overhead dominates
    # the ingestion path). True gives the caller an immediate anomaly verdict, which is
    # what the demonstration wants. False defers scoring to a background task and raises
    # single-node throughput by roughly an order of magnitude. See PRD.md NFR-2.
    telemetry_inline_scoring: bool = True

    rate_limit_per_minute: int = 120
    public_rate_limit_per_minute: int = 30
    max_body_bytes: int = 2 * 1024 * 1024
    max_page_size: int = 200

    cors_origins: tuple[str, ...] = ("http://127.0.0.1:8000", "http://localhost:8000")

    ledger_data_dir: str = "./ledger_data"
    ledger_channel: str = "agri-channel"

    ai_model_dir: str = "./ai/models"
    # Where the demo device-secret file and any other writable demo artefacts go.
    # Separated from repo_root because a container's application directory is read-only
    # (docker-compose.yml sets read_only: true) — only this path needs to be a volume.
    data_dir: str = "."
    anomaly_alert_threshold: float = 0.65
    fraud_suspect_threshold: float = 0.30
    fraud_fail_threshold: float = 0.70
    max_sequence_length: int = 100_000

    repo_root: Path = field(default=REPO_ROOT)

    # -- derived ----------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    @property
    def is_test(self) -> bool:
        return self.env.lower() == "test"

    @property
    def encryption_key(self) -> bytes:
        """32-byte AES-GCM key. Derived deterministically outside production."""
        raw = self.encryption_key_b64
        if raw and raw not in _PLACEHOLDERS:
            try:
                key = base64.b64decode(raw)
                if len(key) == 32:
                    return key
            except Exception:  # noqa: BLE001 - fall through to the error below
                pass
            raise ConfigurationError("ENCRYPTION_KEY must be base64 of exactly 32 bytes")
        if self.is_production:
            raise ConfigurationError("ENCRYPTION_KEY must be set in production")
        # Development/test: stable key derived from the JWT secret so restarts can
        # still decrypt locally-stored demo data.  Never used in production.
        import hashlib

        return hashlib.sha256(("dev-key::" + self.jwt_secret).encode()).digest()

    def validate(self) -> None:
        if self.is_production:
            if self.jwt_secret in _PLACEHOLDERS or len(self.jwt_secret) < 32:
                raise ConfigurationError("JWT_SECRET must be set to a strong value in production")
            if not self.encryption_key_b64 or self.encryption_key_b64 in _PLACEHOLDERS:
                raise ConfigurationError("ENCRYPTION_KEY must be set in production")
            if self.database_url.startswith("sqlite"):
                raise ConfigurationError("SQLite is not supported in production; use PostgreSQL")
            if any(o.strip() == "*" for o in self.cors_origins):
                raise ConfigurationError("Wildcard CORS origin is not permitted in production")
        if self.bcrypt_rounds < 12:
            raise ConfigurationError("BCRYPT_ROUNDS must be at least 12")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    _load_dotenv()
    env_name = _env("ENV", "development")
    jwt_secret = _env("JWT_SECRET", "")
    if jwt_secret in _PLACEHOLDERS:
        # Development convenience only. In production, jwt_secret is left as "" (a
        # value validate() below recognises and refuses to start on) rather than being
        # silently replaced by a fresh random secret — a missing JWT_SECRET must be a
        # startup failure, not an invisible per-restart key that invalidates every
        # outstanding token and gives no operator any signal that anything is wrong.
        jwt_secret = _DEV_JWT_DEFAULT if env_name != "production" else ""
    origins = tuple(
        o.strip() for o in _env("CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",") if o.strip()
    )
    settings = Settings(
        env=_env("ENV", "development"),
        app_name=_env("APP_NAME", "Agricultural Biotechnology Security Platform"),
        api_prefix=_env("API_PREFIX", "/api/v1"),
        host=_env("HOST", "127.0.0.1"),
        port=_env_int("PORT", 8000),
        log_level=_env("LOG_LEVEL", "INFO"),
        demo_mode=_env_bool("DEMO_MODE", True),
        database_url=_env("DATABASE_URL", "sqlite:///./absp.db"),
        # Auto-generate only outside production (e.g. a bare `pytest` run with no .env).
        # In production an empty jwt_secret is deliberately preserved so validate() below
        # rejects the startup instead of masking a missing JWT_SECRET.
        jwt_secret=(jwt_secret or secrets.token_urlsafe(48)) if env_name != "production"
        else jwt_secret,
        jwt_algorithm=_env("JWT_ALGORITHM", "HS256"),
        jwt_key_id=_env("JWT_KEY_ID", "k1"),
        access_token_minutes=_env_int("ACCESS_TOKEN_MINUTES", 30),
        refresh_token_days=_env_int("REFRESH_TOKEN_DAYS", 7),
        bcrypt_rounds=_env_int("BCRYPT_ROUNDS", 12),
        password_min_length=_env_int("PASSWORD_MIN_LENGTH", 12),
        max_failed_logins=_env_int("MAX_FAILED_LOGINS", 5),
        lockout_minutes=_env_int("LOCKOUT_MINUTES", 15),
        encryption_key_b64=_env("ENCRYPTION_KEY", ""),
        device_timestamp_window_seconds=_env_int("DEVICE_TIMESTAMP_WINDOW_SECONDS", 300),
        device_backfill_window_seconds=_env_int("DEVICE_BACKFILL_WINDOW_SECONDS", 86400),
        device_max_batch=_env_int("DEVICE_MAX_BATCH", 500),
        telemetry_inline_scoring=_env_bool("TELEMETRY_INLINE_SCORING", True),
        rate_limit_per_minute=_env_int("RATE_LIMIT_PER_MINUTE", 120),
        public_rate_limit_per_minute=_env_int("PUBLIC_RATE_LIMIT_PER_MINUTE", 30),
        max_body_bytes=_env_int("MAX_BODY_BYTES", 2 * 1024 * 1024),
        max_page_size=_env_int("MAX_PAGE_SIZE", 200),
        cors_origins=origins,
        ledger_data_dir=_env("LEDGER_DATA_DIR", "./ledger_data"),
        ledger_channel=_env("LEDGER_CHANNEL", "agri-channel"),
        ai_model_dir=_env("AI_MODEL_DIR", "./ai/models"),
        anomaly_alert_threshold=_env_float("ANOMALY_ALERT_THRESHOLD", 0.65),
        fraud_suspect_threshold=_env_float("FRAUD_SUSPECT_THRESHOLD", 0.30),
        fraud_fail_threshold=_env_float("FRAUD_FAIL_THRESHOLD", 0.70),
        max_sequence_length=_env_int("MAX_SEQUENCE_LENGTH", 100_000),
        data_dir=_env("DATA_DIR", "."),
    )
    settings.validate()
    return settings
