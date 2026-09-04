"""Production configuration safety (Security.md §5, PRD.md NFR-6).

Regression coverage for a real defect (see SECURITY-ASSESSMENT.md): `get_settings()` used to
backfill a missing `JWT_SECRET` with a fresh random value in every environment, including
production, before `validate()` ran — so a deployment that simply forgot to set the
variable booted successfully instead of refusing to start. These tests exercise the
variable being *absent*, not merely set to a placeholder, which is exactly the case the
original test fixtures (all of which set a real secret) never covered.
"""
from __future__ import annotations

import base64
import importlib
import os
import secrets
import sys
from pathlib import Path

import pytest

# These tests manipulate process-wide module state (env vars, an lru_cache, and the
# repo-root .env file lookup), so they run against a copy of the config module reloaded
# under a controlled environment rather than the shared `app.core.config` used elsewhere.
REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def clean_config(monkeypatch, tmp_path):
    """Reload app.core.config with no repo .env file visible and a clean env.

    Order matters: `importlib.reload()` re-executes the module's top-level code, which
    would reassign module-level `REPO_ROOT` back to the real repo path — undoing a patch
    applied *before* the reload. So REPO_ROOT is patched *after* reloading, once the
    fresh module object exists to patch.
    """
    for var in ("JWT_SECRET", "ENCRYPTION_KEY", "DATABASE_URL", "ENV"):
        monkeypatch.delenv(var, raising=False)
    module = importlib.reload(importlib.import_module("app.core.config"))
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path, raising=False)
    module.get_settings.cache_clear()
    yield module
    module.get_settings.cache_clear()
    importlib.reload(module)  # restore the real REPO_ROOT for the rest of the suite


class TestProductionRefusesAnAbsentSecret:
    def test_missing_jwt_secret_refuses_to_start(self, clean_config, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host/db")
        monkeypatch.setenv("ENCRYPTION_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
        with pytest.raises(clean_config.ConfigurationError, match="JWT_SECRET"):
            clean_config.get_settings()

    def test_missing_encryption_key_refuses_to_start(self, clean_config, monkeypatch):
        """validate() catches this eagerly at get_settings() time — stricter than the
        JWT_SECRET case, which is caught eagerly too; both fail fast rather than only
        failing lazily the first time something needs the value."""
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host/db")
        monkeypatch.setenv("JWT_SECRET", secrets.token_urlsafe(48))
        with pytest.raises(clean_config.ConfigurationError, match="ENCRYPTION_KEY"):
            clean_config.get_settings()

    def test_placeholder_jwt_secret_refuses_to_start(self, clean_config, monkeypatch):
        """The explicit placeholder string must be rejected exactly like an absent value."""
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host/db")
        monkeypatch.setenv("JWT_SECRET",
                           "CHANGE_ME_generate_a_48_byte_url_safe_random_string")
        monkeypatch.setenv("ENCRYPTION_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
        with pytest.raises(clean_config.ConfigurationError, match="JWT_SECRET"):
            clean_config.get_settings()

    def test_sqlite_refused_in_production(self, clean_config, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("JWT_SECRET", secrets.token_urlsafe(48))
        monkeypatch.setenv("ENCRYPTION_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
        with pytest.raises(clean_config.ConfigurationError, match="SQLite"):
            clean_config.get_settings()

    def test_valid_production_configuration_starts(self, clean_config, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host/db")
        monkeypatch.setenv("JWT_SECRET", secrets.token_urlsafe(48))
        monkeypatch.setenv("ENCRYPTION_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
        settings = clean_config.get_settings()
        assert settings.is_production
        assert len(settings.encryption_key) == 32


class TestDevelopmentConvenience:
    """Outside production, a missing secret should still let the app start locally."""

    def test_missing_jwt_secret_is_backfilled_in_development(self, clean_config, monkeypatch):
        monkeypatch.setenv("ENV", "development")
        settings = clean_config.get_settings()
        assert settings.jwt_secret and len(settings.jwt_secret) >= 32

    def test_missing_encryption_key_is_derived_in_development(self, clean_config, monkeypatch):
        monkeypatch.setenv("ENV", "development")
        settings = clean_config.get_settings()
        assert len(settings.encryption_key) == 32

    def test_test_environment_is_not_production(self, clean_config, monkeypatch):
        monkeypatch.setenv("ENV", "test")
        settings = clean_config.get_settings()
        assert not settings.is_production
