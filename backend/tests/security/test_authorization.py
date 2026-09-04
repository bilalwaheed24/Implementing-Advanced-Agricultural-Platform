"""RBAC, tenancy isolation and authorisation coverage (FR-X2, FR-X3, T-05, T-06)."""
from __future__ import annotations

import pytest

from app.core.permissions import (APPROVAL_REQUIRED_ROLES, CROSS_TENANT_ROLES, P,
                                  ROLE_PERMISSIONS, Role, has_permission, is_write_permission)

# Routes that are public by design (Security.md §3).
PUBLIC_PATHS = {"/health", "/health/live", "/health/ready", "/metrics", "/", "/verify.html",
                "/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"}
PUBLIC_PREFIXES = ("/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/refresh",
                   "/api/v1/verify/", "/static")
# Telemetry ingestion authenticates with a device credential, not a user token.
DEVICE_AUTH_PATHS = {"/api/v1/telemetry/ingest", "/api/v1/telemetry/batch"}


class TestRolePermissionMatrix:
    def test_every_role_has_permissions(self):
        for role in Role:
            assert ROLE_PERMISSIONS[role], f"{role} has no permissions"

    def test_admin_has_every_permission(self):
        assert ROLE_PERMISSIONS[Role.ADMIN] == frozenset(set(P))

    def test_regulator_cannot_mutate_operational_data(self):
        """A regulator holds exactly two non-read permissions, and neither one touches
        another party's operational data: `compliance:run` computes a report, and
        `gmo:approve` records a regulatory decision that is the regulator's own to make."""
        writes = {p for p in ROLE_PERMISSIONS[Role.REGULATOR] if is_write_permission(p)}
        assert writes == {P.COMPLIANCE_RUN, P.GMO_APPROVE}
        for forbidden in (P.FARM_WRITE, P.DEVICE_WRITE, P.DEVICE_CONTAIN, P.SUPPLY_WRITE,
                          P.GMO_WRITE, P.CERT_ISSUE, P.CERT_REVOKE, P.USER_WRITE,
                          P.BIOSECURITY_SUBMIT, P.BIOSECURITY_REVIEW, P.HAZARD_WRITE):
            assert forbidden not in ROLE_PERMISSIONS[Role.REGULATOR], forbidden

    def test_agronomist_is_read_only_on_devices(self):
        assert has_permission("AGRONOMIST", P.DEVICE_READ)
        assert not has_permission("AGRONOMIST", P.DEVICE_WRITE)
        assert not has_permission("AGRONOMIST", P.DEVICE_CONTAIN)

    def test_farm_operator_cannot_touch_biosecurity_or_certification(self):
        for permission in (P.BIOSECURITY_SUBMIT, P.BIOSECURITY_REVIEW, P.CERT_ISSUE,
                           P.CERT_REVOKE, P.HAZARD_WRITE, P.GMO_APPROVE):
            assert not has_permission("FARM_OPERATOR", permission), permission

    def test_researcher_cannot_review_their_own_submissions(self):
        assert has_permission("BIOTECH_RESEARCHER", P.BIOSECURITY_SUBMIT)
        assert not has_permission("BIOTECH_RESEARCHER", P.BIOSECURITY_REVIEW)

    def test_only_certifier_and_admin_may_issue_certifications(self):
        allowed = {role for role in Role if has_permission(role.value, P.CERT_ISSUE)}
        assert allowed == {Role.CERTIFIER, Role.ADMIN}

    def test_only_biosafety_and_admin_may_review_biosecurity(self):
        allowed = {role for role in Role if has_permission(role.value, P.BIOSECURITY_REVIEW)}
        assert allowed == {Role.BIOSAFETY_OFFICER, Role.ADMIN}

    def test_unknown_role_has_nothing(self):
        assert not has_permission("SUPERUSER", P.FARM_READ)
        assert not has_permission("", P.FARM_READ)

    def test_privileged_roles_require_approval(self):
        assert Role.ADMIN in APPROVAL_REQUIRED_ROLES
        assert Role.CERTIFIER in APPROVAL_REQUIRED_ROLES
        assert Role.FARM_OPERATOR not in APPROVAL_REQUIRED_ROLES

    def test_cross_tenant_roles_are_the_oversight_roles(self):
        assert CROSS_TENANT_ROLES == {Role.ADMIN, Role.REGULATOR, Role.SECURITY_ANALYST,
                                      Role.BIOSAFETY_OFFICER}


class TestAuthorizationCoverage:
    """Mechanical guarantee that no route was left unprotected (Development-rules.md §7)."""

    def _api_routes(self):
        from app.main import app

        results = []
        for entry in app.routes:
            original = getattr(entry, "original_router", None)
            if original is None:
                if hasattr(entry, "methods"):
                    results.append(("", entry))
                continue
            prefix = getattr(getattr(entry, "include_context", None), "prefix", "")
            for route in original.routes:
                if hasattr(route, "methods"):
                    results.append((prefix, route))
        return results

    def test_every_route_is_reachable_for_inspection(self):
        assert len(self._api_routes()) > 90, "route inspection failed to find the API"

    def test_every_mutating_route_declares_authentication(self):
        """Every POST/PATCH/PUT/DELETE must depend on a principal or a device credential."""
        unprotected = []
        for prefix, route in self._api_routes():
            path = prefix + route.path
            methods = route.methods - {"GET", "HEAD", "OPTIONS"}
            if not methods:
                continue
            if path in PUBLIC_PATHS or path in DEVICE_AUTH_PATHS:
                continue
            if any(path.startswith(p) for p in PUBLIC_PREFIXES):
                continue
            source = str(getattr(route, "dependant", None).__dict__ if
                         getattr(route, "dependant", None) else "")
            names = source + " ".join(
                getattr(d.call, "__name__", "") for d in
                getattr(getattr(route, "dependant", None), "dependencies", []) or [])
            if "principal" not in names and "permission" not in names \
                    and "current" not in names.lower():
                unprotected.append(f"{sorted(methods)} {path}")
        assert not unprotected, f"routes without an authorisation dependency: {unprotected}"

    def test_device_ingestion_paths_are_explicitly_allowlisted(self):
        """Ingestion is unauthenticated at the user layer by design; assert the list is tiny."""
        assert len(DEVICE_AUTH_PATHS) == 2


class TestHttpAuthorization:
    """End-to-end: the server, not the UI, enforces the matrix."""

    @pytest.mark.parametrize("method,path,body", [
        ("POST", "/api/v1/farms", {"name": "X", "region": "Y", "country": "US",
                                   "latitude": 0, "longitude": 0, "area_ha": 1}),
        ("GET", "/api/v1/devices", None),
        ("GET", "/api/v1/biosecurity/screenings", None),
        ("GET", "/api/v1/audit/logs", None),
        ("POST", "/api/v1/compliance/evaluate", {"subject_id": "x"}),
        ("GET", "/api/v1/blockchain/verify", None),
    ])
    def test_unauthenticated_requests_are_rejected(self, client, method, path, body):
        response = client.request(method, path, json=body)
        assert response.status_code == 401, f"{method} {path} returned {response.status_code}"

    def test_agronomist_cannot_create_a_device(self, client, auth, farm):
        response = client.post("/api/v1/devices", headers=auth("AGRONOMIST"), json={
            "device_type": "SOIL_SENSOR", "model": "X", "firmware_version": "1",
            "farm_id": farm.id})
        assert response.status_code == 403
        assert "device:write" in response.json()["detail"]

    def test_farm_operator_cannot_issue_a_certification(self, client, auth, orgs):
        response = client.post("/api/v1/supply-chain/certifications",
                               headers=auth("FARM_OPERATOR"), json={
            "cert_code": "X-1", "cert_type": "ORGANIC", "standard": "USDA-NOP",
            "subject_org_id": orgs["SUPPLY"].id, "scope": "s",
            "valid_from": "2026-01-01T00:00:00Z", "valid_to": "2027-01-01T00:00:00Z"})
        assert response.status_code == 403

    def test_researcher_cannot_review_a_screening(self, client, auth):
        response = client.post("/api/v1/biosecurity/screenings/any-id/review",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"decision": "APPROVE", "rationale": "please let me"})
        assert response.status_code == 403

    def test_regulator_cannot_create_a_farm(self, client, auth):
        response = client.post("/api/v1/farms", headers=auth("REGULATOR"), json={
            "name": "Regulator Farm", "region": "R", "country": "US", "latitude": 1,
            "longitude": 1, "area_ha": 5})
        assert response.status_code == 403

    def test_regulator_cannot_quarantine_a_device(self, client, auth, provisioned_device):
        response = client.post(f"/api/v1/devices/{provisioned_device['id']}/quarantine",
                               headers=auth("REGULATOR"), json={"reason": "testing"})
        assert response.status_code == 403

    def test_operator_cannot_read_the_audit_log(self, client, auth):
        assert client.get("/api/v1/audit/logs",
                          headers=auth("FARM_OPERATOR")).status_code == 403

    def test_analyst_can_read_the_audit_log(self, client, auth):
        assert client.get("/api/v1/audit/logs",
                          headers=auth("SECURITY_ANALYST")).status_code == 200

    def test_permissions_endpoint_matches_the_matrix(self, client, auth):
        body = client.get("/api/v1/auth/me", headers=auth("CERTIFIER")).json()
        assert set(body["permissions"]) == {p.value for p in ROLE_PERMISSIONS[Role.CERTIFIER]}


class TestTenancyIsolation:
    """T-05: one farm co-operative must never see a competitor's agronomic data."""

    def test_rival_cannot_list_another_organisations_farms(self, client, auth, rival_auth, farm):
        mine = client.get("/api/v1/farms", headers=auth("FARM_OPERATOR")).json()
        theirs = client.get("/api/v1/farms", headers=rival_auth).json()
        assert any(item["id"] == farm.id for item in mine["items"])
        assert all(item["id"] != farm.id for item in theirs["items"])

    def test_rival_gets_404_not_403_for_a_foreign_farm(self, client, rival_auth, farm):
        """404 rather than 403: revealing existence would itself leak tenancy."""
        response = client.get(f"/api/v1/farms/{farm.id}", headers=rival_auth)
        assert response.status_code == 404

    def test_rival_cannot_read_a_foreign_device(self, client, rival_auth, provisioned_device):
        assert client.get(f"/api/v1/devices/{provisioned_device['id']}",
                          headers=rival_auth).status_code == 404

    def test_rival_cannot_quarantine_a_foreign_device(self, client, rival_auth,
                                                      provisioned_device):
        response = client.post(f"/api/v1/devices/{provisioned_device['id']}/quarantine",
                               headers=rival_auth, json={"reason": "sabotage attempt"})
        assert response.status_code == 404

    def test_rival_cannot_attach_a_field_to_a_foreign_farm(self, client, rival_auth, farm):
        response = client.post("/api/v1/fields", headers=rival_auth,
                               json={"farm_id": farm.id, "name": "Injected", "area_ha": 1.0})
        assert response.status_code == 404

    def test_oversight_role_can_read_across_tenants(self, client, auth, farm):
        response = client.get("/api/v1/farms", headers=auth("REGULATOR"))
        assert response.status_code == 200
        assert any(item["id"] == farm.id for item in response.json()["items"])

    def test_repository_blocks_unscoped_reads_for_ordinary_roles(self):
        from app.core.errors import PermissionDenied
        from app.models import Farm
        from app.repositories import unscoped

        with pytest.raises(PermissionDenied):
            unscoped(Farm, "FARM_OPERATOR")
        unscoped(Farm, "REGULATOR")       # permitted
