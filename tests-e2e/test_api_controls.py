"""Live API-level verification of the access-control decisions, against the running stack.

This is the regression form of the original audit's findings: each test asserts that a
control now holds. It complements the in-process suite by exercising the real containers
(nginx -> api -> ai/ledger/db) rather than a TestClient.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid

import pytest

from conftest import ACCOUNTS, BASE, PASSWORD

API = BASE + "/api/v1"


def call(method, path, token=None, body=None):
    req = urllib.request.Request(API + path, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=30) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"null")
        except ValueError:
            return e.code, {"detail": raw[:200].decode(errors="replace")}


def call_auth(method, path, body):
    """Call a rate-limited auth endpoint, honouring the limiter's Retry-After.

    The limiter is itself a control (asserted in tests/security/test_rate_limiting.py), so a
    429 here is expected traffic shaping rather than a failure.
    """
    import re
    import time

    for _ in range(6):
        status, payload = call(method, path, body=body)
        if status != 429:
            return status, payload
        wait = re.search(r"([\d.]+) seconds", str(payload.get("detail", "")))
        time.sleep(float(wait.group(1)) + 0.5 if wait else 3.0)
    return status, payload


@pytest.fixture(scope="module")
def tokens():
    """Sign every role in, respecting the authentication rate limit.

    Nine logins back-to-back legitimately trip the limiter (that control is asserted in
    tests/security/test_rate_limiting.py), so the retry here honours its Retry-After rather
    than treating a 429 as a failure.
    """
    out = {}
    for role, email in ACCOUNTS.items():
        status, body = call_auth("POST", "/auth/login",
                                 {"email": email, "password": PASSWORD})
        assert status == 200, (role, status, body)
        out[role] = body["access_token"]
    return out



@pytest.fixture
def foreign_batch(tokens):
    """A batch owned by the farm organisation, created through the API by that tenant.

    Borrowing one from a listing does not work: the supply operator cannot see another
    tenant's batches, which is the very control under test. So one is created as the farm
    operator (which holds supply:write for its own organisation) and then used as the
    attacker-supplied id.
    """
    status, products = call("GET", "/supply-chain/products", tokens["FARM_OPERATOR"])
    assert status == 200, products
    items = products.get("items") or []
    if not items:
        # The farm tenant owns no product in the seed; create one so the batch has a parent
        # product inside that organisation.
        digits = uuid.uuid4().int % 10**13
        status, product = call("POST", "/supply-chain/products", tokens["FARM_OPERATOR"], {
            "gtin": f"{digits:013d}", "name": f"PW Farm Product {digits % 1000}",
            "category": "Grain"})
        assert status == 201, product
        items = [product]
    status, created = call("POST", "/supply-chain/batches", tokens["FARM_OPERATOR"], {
        "batch_code": f"PW-FGN-{uuid.uuid4().hex[:6]}",
        "product_id": items[0]["id"], "quantity": 100.0, "unit": "kg"})
    assert status == 201, created

    # Precondition: it really is invisible to the other tenant.
    seen, _ = call("GET", f"/supply-chain/batches/{created['id']}",
                   tokens["SUPPLY_CHAIN_OPERATOR"])
    assert seen == 404, f"the batch is not foreign to the supply operator (HTTP {seen})"
    return created


# --------------------------------------------------------------------------- #
# P0-1 registration and the organisation directory
# --------------------------------------------------------------------------- #
class TestRegistrationCannotTakeOverATenant:
    def test_a_normal_role_sees_only_its_own_organisation(self, tokens):
        status, body = call("GET", "/admin/organizations", tokens["AGRONOMIST"])
        rows = body.get("items", body) if isinstance(body, dict) else body
        assert status == 200
        assert len(rows) == 1, f"directory exposed {len(rows)} organisations"

    def test_self_registration_is_pending_and_least_privileged(self, tokens):
        _, body = call("GET", "/admin/organizations", tokens["AGRONOMIST"])
        rows = body.get("items", body) if isinstance(body, dict) else body
        target = rows[0]["id"]
        email = f"pw-{uuid.uuid4().hex[:8]}@test.invalid"
        status, created = call_auth("POST", "/auth/register", {
            "email": email, "full_name": "Playwright Probe",
            "password": "Str0ng-Passw0rd!x", "org_id": target,
            "requested_role": "SUPPLY_CHAIN_OPERATOR"})
        assert status == 201, created
        assert created["status"] == "PENDING"
        assert created["role"] != "SUPPLY_CHAIN_OPERATOR", "a requested role was granted"

        # ...and the account it created is inert.
        status, _ = call_auth("POST", "/auth/login",
                              {"email": email, "password": "Str0ng-Passw0rd!x"})
        assert status == 401, "a pending account was able to sign in"


# --------------------------------------------------------------------------- #
# P0-2 / P0-3 four-eyes and self-certification
# --------------------------------------------------------------------------- #
class TestFourEyesAndSelfCertification:
    def test_a_biosafety_officer_cannot_review_its_own_screening(self, tokens):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from ai.data.generate import hazard_database, hazard_derived_sequence

        # A benign sequence is auto-approved and the already-resolved guard would fire first,
        # so this derives from a seeded hazard to land the record in review.
        hazard = next(h for h in hazard_database() if h["severity"] == 3)
        status, created = call("POST", "/biosecurity/screenings",
                               tokens["BIOSAFETY_OFFICER"], {
                                   "name": f"pw-{uuid.uuid4().hex[:6]}",
                                   "sequence": hazard_derived_sequence(hazard["sequence"],
                                                                      0.04, 7),
                                   "organism": "Probe", "intent": "Four-eyes regression"})
        assert status == 201, created
        assert created["status"] in ("PENDING_REVIEW", "BLOCKED"), created["status"]
        sid = created["id"]
        status, body = call("POST", f"/biosecurity/screenings/{sid}/review",
                            tokens["BIOSAFETY_OFFICER"],
                            {"decision": "APPROVE",
                             "rationale": "Attempting to clear my own submission."})
        assert status == 409, body
        assert "own submission" in body["detail"].lower()

        _, after = call("GET", f"/biosecurity/screenings/{sid}",
                        tokens["BIOSAFETY_OFFICER"])
        assert not after.get("reviewed_by"), "the record was reviewed anyway"

    def test_a_certifier_cannot_certify_its_own_organisation(self, tokens):
        _, me = call("GET", "/auth/me", tokens["CERTIFIER"])
        status, body = call("POST", "/supply-chain/certifications", tokens["CERTIFIER"], {
            "cert_code": f"PW-SELF-{uuid.uuid4().hex[:6]}", "cert_type": "ORGANIC",
            "standard": "EU 2018/848", "subject_org_id": me["org_id"],
            "scope": "self-issued", "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": "2027-01-01T00:00:00Z"})
        assert status == 422, body
        assert "itself" in body["detail"].lower()

    def test_the_eligible_subject_list_excludes_the_issuer(self, tokens):
        _, me = call("GET", "/auth/me", tokens["CERTIFIER"])
        status, rows = call("GET", "/supply-chain/certifications/eligible-subjects",
                            tokens["CERTIFIER"])
        assert status == 200
        assert rows, "a certifier needs someone to certify"
        assert all(r["id"] != me["org_id"] for r in rows)


# --------------------------------------------------------------------------- #
# P1 ledger visibility
# --------------------------------------------------------------------------- #
class TestLedgerExplorerIsScoped:
    @pytest.mark.parametrize("path", ["/blockchain/blocks",
                                      "/blockchain/blocks/1",
                                      "/blockchain/state/batch~PW",
                                      "/blockchain/transactions/deadbeef"])
    def test_denied_to_a_business_role(self, tokens, path):
        status, _ = call("GET", path, tokens["FARM_OPERATOR"])
        assert status == 403, f"{path} returned {status}"

    def test_a_merkle_proof_stays_available_to_a_business_role(self, tokens):
        """Deliberate: an inclusion proof is the evidence a business role needs to verify its
        own record, and carries no other party's data. An unknown id is a plain 404."""
        status, _ = call("GET", "/blockchain/transactions/deadbeef/proof",
                         tokens["FARM_OPERATOR"])
        assert status == 404, f"expected a plain not-found, got {status}"

    def test_allowed_for_a_regulator(self, tokens):
        status, _ = call("GET", "/blockchain/blocks", tokens["REGULATOR"])
        assert status == 200

    def test_stats_stay_proof_level_for_a_business_role(self, tokens):
        """`marking` is the DEMO/SIMULATION honesty label and carries no ledger data; the
        participant list and per-function breakdown are what must be withheld."""
        status, body = call("GET", "/blockchain/stats", tokens["FARM_OPERATOR"])
        assert status == 200
        assert "organizations" not in body, "the channel participant list leaked"
        assert "by_function" not in body, "the per-contract breakdown leaked"
        assert set(body) <= {"channel", "height", "network", "state_keys", "transactions",
                             "marking"}, f"unexpected keys: {sorted(set(body))}"

    def test_a_regulator_does_receive_the_participant_detail(self, tokens):
        status, body = call("GET", "/blockchain/stats", tokens["REGULATOR"])
        assert status == 200
        assert "organizations" in body, "an oversight role should see the participants"


# --------------------------------------------------------------------------- #
# P1 object-level authorisation across tenants
# --------------------------------------------------------------------------- #
class TestTenantIsolation:
    def test_a_foreign_batch_is_an_indistinguishable_404(self, tokens):
        _, mine = call("GET", "/supply-chain/batches", tokens["SUPPLY_CHAIN_OPERATOR"])
        owned = {b["id"] for b in mine.get("items", [])}
        _, theirs = call("GET", "/supply-chain/batches", tokens["FARM_OPERATOR"])
        foreign = [b["id"] for b in theirs.get("items", []) if b["id"] not in owned]

        unknown, _ = call("GET", f"/supply-chain/batches/{uuid.uuid4()}",
                          tokens["SUPPLY_CHAIN_OPERATOR"])
        assert unknown == 404
        if foreign:
            status, _ = call("GET", f"/supply-chain/batches/{foreign[0]}",
                             tokens["SUPPLY_CHAIN_OPERATOR"])
            assert status == unknown, "a foreign id is distinguishable from an unknown one"

    def test_a_foreign_parent_batch_cannot_be_used_on_create(self, tokens, foreign_batch):
        _, products = call("GET", "/supply-chain/products", tokens["SUPPLY_CHAIN_OPERATOR"])
        status, body = call("POST", "/supply-chain/batches",
                            tokens["SUPPLY_CHAIN_OPERATOR"], {
                                "batch_code": f"PW-BOLA-{uuid.uuid4().hex[:6]}",
                                "product_id": products["items"][0]["id"],
                                "parent_batch_id": foreign_batch["id"],
                                "quantity": 10, "unit": "kg"})
        assert status == 404, body
        assert "parent" in str(body.get("detail", "")).lower()

    def test_a_foreign_shipment_batch_is_refused(self, tokens, foreign_batch):
        status, body = call("POST", "/supply-chain/shipments",
                            tokens["SUPPLY_CHAIN_OPERATOR"], {
                                "sscc": f"{uuid.uuid4().int % 10**18:018d}",
                                "batch_id": foreign_batch["id"], "carrier": "Probe",
                                "origin_name": "Origin depot", "origin_lat": 42.0,
                                "origin_lon": -93.0,
                                "destination_name": "Destination depot",
                                "destination_lat": 41.0,
                                "destination_lon": -92.0,
                                "departed_at": "2026-01-01T00:00:00Z"})
        assert status == 404, body

    def test_the_foreign_batch_is_absent_from_the_other_tenants_listing(self, tokens,
                                                                       foreign_batch):
        _, mine = call("GET", "/supply-chain/batches?page=1&page_size=100",
                       tokens["SUPPLY_CHAIN_OPERATOR"])
        assert foreign_batch["id"] not in {b["id"] for b in mine.get("items", [])}


# --------------------------------------------------------------------------- #
# P1 writes must require a write permission
# --------------------------------------------------------------------------- #
class TestReadPermissionCannotWrite:
    def test_a_regulator_cannot_run_a_batch_verify(self, tokens):
        _, batches = call("GET", "/supply-chain/batches", tokens["SUPPLY_CHAIN_OPERATOR"])
        batch = batches["items"][0]["id"]
        status, _ = call("POST", f"/supply-chain/batches/{batch}/verify", tokens["REGULATOR"])
        assert status == 403

    def test_a_regulator_cannot_anchor_the_audit_head(self, tokens):
        status, _ = call("POST", "/audit/anchor", tokens["REGULATOR"])
        assert status == 403

    def test_a_security_analyst_can_anchor_the_audit_head(self, tokens):
        status, _ = call("POST", "/audit/anchor", tokens["SECURITY_ANALYST"])
        assert status == 200


# --------------------------------------------------------------------------- #
# Separation of duties across all nine roles
# --------------------------------------------------------------------------- #
REGULATED = {
    "cert_issue": ("POST", "/supply-chain/certifications", {"CERTIFIER"}),
    "gmo_approve": ("POST", "/gmo/events/{gmo}/approvals", {"REGULATOR"}),
    "hazard_write": ("POST", "/biosecurity/hazards", {"BIOSAFETY_OFFICER"}),
}


class TestNineRoleMatrix:
    """Every role is asked to perform each regulated act; only the owning role may be
    anything other than 403. ADMIN is included deliberately: it must now be refused."""

    def test_only_the_owning_role_reaches_a_regulated_write(self, tokens):
        _, events = call("GET", "/gmo/events", tokens["REGULATOR"])
        gmo = (events.get("items") or [{}])[0].get("id", str(uuid.uuid4()))
        failures = []
        for name, (method, path, owners) in REGULATED.items():
            for role in ACCOUNTS:
                status, _ = call(method, path.format(gmo=gmo), tokens[role], {})
                denied = status == 403
                if role in owners and denied:
                    failures.append(f"{name}: owner {role} was denied")
                if role not in owners and not denied:
                    failures.append(f"{name}: {role} was not denied (HTTP {status})")
        assert not failures, failures

    def test_every_role_is_refused_without_a_token(self):
        for path in ("/farms", "/devices", "/supply-chain/batches", "/gmo/events",
                     "/security/alerts", "/audit/logs", "/blockchain/blocks"):
            status, _ = call("GET", path)
            assert status == 401, f"{path} answered {status} unauthenticated"

    def test_a_sweep_is_scoped_for_a_tenant_role_and_broad_for_oversight(self, tokens):
        status, tenant = call("POST", "/security/data-theft/sweep", tokens["FARM_OPERATOR"])
        assert status == 200, tenant
        status, oversight = call("POST", "/security/data-theft/sweep",
                                 tokens["SECURITY_ANALYST"])
        assert status == 200, oversight
        assert oversight["count"] >= tenant["count"], \
            "a tenant sweep returned more than the platform-wide one"
