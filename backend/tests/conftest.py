"""Test configuration.

Environment variables are set BEFORE any application module is imported, because the
engine and settings are built at import time. Tests never touch the developer's
database or ledger, and never require network access.
"""
from __future__ import annotations

import base64
import os
import secrets
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST_DIR = Path(tempfile.mkdtemp(prefix="absp-tests-"))

os.environ["ENV"] = "test"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DIR / 'test.db'}"
os.environ["LEDGER_DATA_DIR"] = str(TEST_DIR / "ledger")
os.environ["JWT_SECRET"] = secrets.token_urlsafe(48)
os.environ["ENCRYPTION_KEY"] = base64.b64encode(secrets.token_bytes(32)).decode()
os.environ["DEMO_MODE"] = "true"
os.environ["BCRYPT_ROUNDS"] = "12"
# Generous limits so functional tests are not throttled; the limiter itself is
# tested explicitly in tests/security/test_rate_limiting.py.
os.environ["RATE_LIMIT_PER_MINUTE"] = "100000"
os.environ["PUBLIC_RATE_LIMIT_PER_MINUTE"] = "100000"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

import pytest                                                        # noqa: E402
from fastapi.testclient import TestClient                            # noqa: E402

from app.core.database import SessionLocal, create_all               # noqa: E402
from app.core.security import (encrypt_at_rest, generate_device_secret,   # noqa: E402
                               hash_password, utcnow)
from app.main import app                                             # noqa: E402
from app.models import (Certification, Device, Farm, Field, HazardSequence,   # noqa: E402
                        Organization, Product, User)

PASSWORD = "TestPassw0rd!2026"


@pytest.fixture(scope="session", autouse=True)
def _schema() -> None:
    create_all()


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="session")
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture(autouse=True)
def _reset_limiters():
    """Rate limiters are process-global; clear them so tests cannot starve each other."""
    from app.core.deps import api_limiter, auth_limiter, public_limiter

    for limiter in (api_limiter, auth_limiter, public_limiter):
        limiter.reset()
    yield


@pytest.fixture(scope="session")
def orgs(db) -> dict[str, Organization]:
    """The four consortium organisations, matching the ledger's MSP identities."""
    definitions = [
        ("Test Biotech", "BIOTECH", "BiotechMSP", []),
        ("Test Farm Co-op", "FARM", "FarmMSP", []),
        ("Test Processor", "SUPPLY", "SupplyMSP", []),
        ("Test Regulator", "REGULATOR", "RegulatorMSP", ["ORGANIC", "NON_GMO", "SPECIALTY"]),
    ]
    created: dict[str, Organization] = {}
    for name, org_type, msp_id, trusted in definitions:
        existing = db.query(Organization).filter(Organization.msp_id == msp_id).one_or_none()
        if existing is None:
            existing = Organization(name=name, org_type=org_type, msp_id=msp_id,
                                    country="US", trusted_issuer_types=trusted)
            db.add(existing)
            db.flush()
        created[org_type] = existing
    db.commit()
    return created


@pytest.fixture(scope="session")
def users(db, orgs) -> dict[str, User]:
    """One active user per role, mapped onto the appropriate organisation."""
    mapping = [
        ("ADMIN", "REGULATOR"), ("SECURITY_ANALYST", "REGULATOR"),
        ("FARM_OPERATOR", "FARM"), ("AGRONOMIST", "FARM"),
        ("BIOTECH_RESEARCHER", "BIOTECH"), ("BIOSAFETY_OFFICER", "BIOTECH"),
        ("SUPPLY_CHAIN_OPERATOR", "SUPPLY"), ("CERTIFIER", "REGULATOR"),
        ("REGULATOR", "REGULATOR"),
    ]
    password_hash = hash_password(PASSWORD)
    created: dict[str, User] = {}
    for role, org_type in mapping:
        email = f"{role.lower()}@test.absp"
        user = db.query(User).filter(User.email == email).one_or_none()
        if user is None:
            user = User(email=email, full_name=f"Test {role.title()}",
                        password_hash=password_hash, role=role,
                        org_id=orgs[org_type].id, status="ACTIVE")
            db.add(user)
            db.flush()
        created[role] = user
    db.commit()
    return created


@pytest.fixture(scope="session")
def second_farm_org(db) -> Organization:
    """A second farm organisation, used to prove cross-tenant isolation."""
    existing = db.query(Organization).filter(Organization.msp_id == "FarmMSP-B").one_or_none()
    if existing is None:
        existing = Organization(name="Rival Farm Co-op", org_type="FARM", msp_id="FarmMSP-B",
                                country="US", trusted_issuer_types=[])
        db.add(existing)
        db.flush()
        db.add(User(email="rival@test.absp", full_name="Rival Operator",
                    password_hash=hash_password(PASSWORD), role="FARM_OPERATOR",
                    org_id=existing.id, status="ACTIVE"))
        db.commit()
    return existing


def _token(client: TestClient, email: str) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture
def auth(client, users):
    """auth('FARM_OPERATOR') -> {'Authorization': 'Bearer ...'} for that role."""
    cache: dict[str, str] = {}

    def _headers(role: str) -> dict[str, str]:
        if role not in cache:
            cache[role] = _token(client, f"{role.lower()}@test.absp")
        return {"Authorization": f"Bearer {cache[role]}"}

    return _headers


@pytest.fixture
def rival_auth(client, second_farm_org):
    return {"Authorization": f"Bearer {_token(client, 'rival@test.absp')}"}


@pytest.fixture(scope="session")
def hazards(db) -> list[HazardSequence]:
    from ai.data.generate import hazard_database

    if db.query(HazardSequence).count() == 0:
        for record in hazard_database():
            db.add(HazardSequence(agent_name=record["agent_name"],
                                  hazard_class=record["hazard_class"],
                                  severity=record["severity"],
                                  description=record["description"],
                                  sequence=record["sequence"], is_synthetic=True))
        db.commit()
    return db.query(HazardSequence).all()


@pytest.fixture(scope="session")
def farm(db, orgs, users) -> Farm:
    existing = db.query(Farm).filter(Farm.name == "Test Farm").one_or_none()
    if existing is None:
        existing = Farm(org_id=orgs["FARM"].id, name="Test Farm", region="Iowa", country="US",
                        latitude=42.0, longitude=-93.6, area_ha=100.0,
                        created_by=users["FARM_OPERATOR"].id)
        db.add(existing)
        db.flush()
        db.add(Field(farm_id=existing.id, org_id=orgs["FARM"].id, name="Field 1",
                     area_ha=25.0, soil_type="Loam"))
        db.commit()
    return existing


@pytest.fixture(scope="session")
def field(db, farm) -> Field:
    return db.query(Field).filter(Field.farm_id == farm.id).first()


@pytest.fixture
def provisioned_device(client, auth, farm, field):
    """A device registered and activated through the API, with its real secret."""
    response = client.post("/api/v1/devices", headers=auth("FARM_OPERATOR"), json={
        "device_type": "SOIL_SENSOR", "model": "TestProbe", "firmware_version": "1.0.0",
        "farm_id": farm.id, "field_id": field.id, "interval_seconds": 900})
    assert response.status_code == 201, response.text
    payload = response.json()
    device_id = payload["device"]["id"]
    activate = client.post(f"/api/v1/devices/{device_id}/activate", headers=auth("FARM_OPERATOR"))
    assert activate.status_code == 200, activate.text
    return {"id": device_id, "secret": payload["device_secret"]}


@pytest.fixture(scope="session")
def product(db, orgs) -> Product:
    existing = db.query(Product).filter(Product.gtin == "09999900000017").one_or_none()
    if existing is None:
        existing = Product(org_id=orgs["SUPPLY"].id, gtin="09999900000017",
                           name="Test Sweetcorn", category="Chilled vegetables",
                           storage_temp_min_c=0.0, storage_temp_max_c=4.0)
        db.add(existing)
        db.commit()
    return existing


def unique(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4).upper()}"
