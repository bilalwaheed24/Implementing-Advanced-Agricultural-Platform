"""Integration tests for authentication and the token lifecycle (FR-X1, flow.md §2)."""
from __future__ import annotations

import pytest

from .conftest import PASSWORD, unique


class TestRegistration:
    def test_ordinary_role_is_active_immediately(self, client, orgs):
        email = f"{unique('newop').lower()}@test.absp"
        response = client.post("/api/v1/auth/register", json={
            "email": email, "full_name": "New Operator", "password": "Str0ng-Passw0rd!x",
            "role": "FARM_OPERATOR", "org_id": orgs["FARM"].id})
        assert response.status_code == 201, response.text
        assert response.json()["status"] == "ACTIVE"

    def test_privileged_role_requires_approval(self, client, orgs):
        email = f"{unique('newcert').lower()}@test.absp"
        response = client.post("/api/v1/auth/register", json={
            "email": email, "full_name": "New Certifier", "password": "Str0ng-Passw0rd!x",
            "role": "CERTIFIER", "org_id": orgs["REGULATOR"].id})
        assert response.status_code == 201
        assert response.json()["status"] == "PENDING"
        login = client.post("/api/v1/auth/login",
                            json={"email": email, "password": "Str0ng-Passw0rd!x"})
        assert login.status_code == 401
        assert "approval" in login.json()["detail"].lower()

    def test_weak_password_rejected(self, client, orgs):
        response = client.post("/api/v1/auth/register", json={
            "email": f"{unique('weak').lower()}@test.absp", "full_name": "Weak User",
            "password": "password1234", "role": "FARM_OPERATOR", "org_id": orgs["FARM"].id})
        assert response.status_code == 422

    def test_duplicate_email_does_not_confirm_existence(self, client, orgs, users):
        response = client.post("/api/v1/auth/register", json={
            "email": "farm_operator@test.absp", "full_name": "Impostor",
            "password": "Str0ng-Passw0rd!x", "role": "FARM_OPERATOR",
            "org_id": orgs["FARM"].id})
        assert response.status_code == 409
        assert "farm_operator@test.absp" not in response.text
        assert "already" not in response.json()["detail"].lower()

    def test_unknown_organisation_rejected(self, client):
        response = client.post("/api/v1/auth/register", json={
            "email": f"{unique('x').lower()}@test.absp", "full_name": "No Org",
            "password": "Str0ng-Passw0rd!x", "role": "FARM_OPERATOR",
            "org_id": "00000000-0000-0000-0000-000000000000"})
        assert response.status_code == 422

    @pytest.mark.parametrize("email", ["not-an-email", "a@b", "@nope.com", "spaces in@x.com"])
    def test_invalid_email_rejected(self, client, orgs, email):
        response = client.post("/api/v1/auth/register", json={
            "email": email, "full_name": "Bad Email", "password": "Str0ng-Passw0rd!x",
            "role": "FARM_OPERATOR", "org_id": orgs["FARM"].id})
        assert response.status_code == 422

    def test_unknown_role_rejected(self, client, orgs):
        response = client.post("/api/v1/auth/register", json={
            "email": f"{unique('y').lower()}@test.absp", "full_name": "Bad Role",
            "password": "Str0ng-Passw0rd!x", "role": "SUPERUSER", "org_id": orgs["FARM"].id})
        assert response.status_code == 422


class TestLogin:
    def test_successful_login_returns_a_token_pair(self, client, users):
        response = client.post("/api/v1/auth/login",
                               json={"email": "farm_operator@test.absp", "password": PASSWORD})
        assert response.status_code == 200
        body = response.json()
        assert body["access_token"] and body["refresh_token"]
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == 1800

    def test_wrong_password_rejected_with_a_generic_message(self, client, users):
        response = client.post("/api/v1/auth/login",
                               json={"email": "agronomist@test.absp", "password": "wrong-one"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password"

    def test_unknown_account_gives_the_same_message(self, client):
        response = client.post("/api/v1/auth/login",
                               json={"email": "nobody@test.absp", "password": "whatever"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password"

    def test_response_never_contains_the_password_hash(self, client, users):
        response = client.post("/api/v1/auth/login",
                               json={"email": "farm_operator@test.absp", "password": PASSWORD})
        assert "$2b$" not in response.text

    def test_lockout_after_repeated_failures(self, client, db, orgs):
        """T-02: brute force must lock the account."""
        from app.core.security import hash_password
        from app.models import User

        email = f"{unique('lock').lower()}@test.absp"
        db.add(User(email=email, full_name="Lock Me", password_hash=hash_password(PASSWORD),
                    role="FARM_OPERATOR", org_id=orgs["FARM"].id, status="ACTIVE"))
        db.commit()
        for _ in range(5):
            assert client.post("/api/v1/auth/login",
                               json={"email": email, "password": "bad"}).status_code == 401
        locked = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert locked.status_code == 423
        assert "locked" in locked.json()["detail"].lower()


class TestTokenLifecycle:
    def test_access_token_grants_access(self, client, auth):
        response = client.get("/api/v1/auth/me", headers=auth("FARM_OPERATOR"))
        assert response.status_code == 200
        assert response.json()["role"] == "FARM_OPERATOR"
        assert "device:write" in response.json()["permissions"]

    def test_no_token_rejected(self, client):
        assert client.get("/api/v1/auth/me").status_code == 401

    @pytest.mark.parametrize("header", [
        "Bearer not-a-token", "Basic abc", "bearer", "Bearer ", "",
    ])
    def test_malformed_authorization_rejected(self, client, header):
        assert client.get("/api/v1/auth/me",
                          headers={"Authorization": header}).status_code == 401

    def test_refresh_rotates_the_token(self, client, users):
        login = client.post("/api/v1/auth/login",
                            json={"email": "agronomist@test.absp", "password": PASSWORD}).json()
        refreshed = client.post("/api/v1/auth/refresh",
                                json={"refresh_token": login["refresh_token"]})
        assert refreshed.status_code == 200
        assert refreshed.json()["refresh_token"] != login["refresh_token"]

    def test_refresh_reuse_invalidates_the_whole_family(self, client, users):
        """T-04: a rotated refresh token must never work again, and its family dies."""
        login = client.post("/api/v1/auth/login",
                            json={"email": "supply_chain_operator@test.absp",
                                  "password": PASSWORD}).json()
        first = client.post("/api/v1/auth/refresh",
                            json={"refresh_token": login["refresh_token"]})
        assert first.status_code == 200
        replayed = client.post("/api/v1/auth/refresh",
                               json={"refresh_token": login["refresh_token"]})
        assert replayed.status_code == 401
        # The family is now revoked, so the token issued by the legitimate rotation dies too.
        after = client.post("/api/v1/auth/refresh",
                            json={"refresh_token": first.json()["refresh_token"]})
        assert after.status_code == 401

    def test_access_token_cannot_be_used_as_a_refresh_token(self, client, users):
        login = client.post("/api/v1/auth/login",
                            json={"email": "certifier@test.absp", "password": PASSWORD}).json()
        response = client.post("/api/v1/auth/refresh",
                               json={"refresh_token": login["access_token"]})
        assert response.status_code == 401

    def test_logout_revokes_refresh_tokens(self, client, users):
        login = client.post("/api/v1/auth/login",
                            json={"email": "biosafety_officer@test.absp",
                                  "password": PASSWORD}).json()
        headers = {"Authorization": f"Bearer {login['access_token']}"}
        assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
        assert client.post("/api/v1/auth/refresh",
                           json={"refresh_token": login["refresh_token"]}).status_code == 401

    def test_suspended_account_loses_access(self, client, db, orgs, auth):
        from app.core.security import hash_password
        from app.models import User

        email = f"{unique('susp').lower()}@test.absp"
        user = User(email=email, full_name="To Suspend", password_hash=hash_password(PASSWORD),
                    role="FARM_OPERATOR", org_id=orgs["FARM"].id, status="ACTIVE")
        db.add(user)
        db.commit()
        token = client.post("/api/v1/auth/login",
                            json={"email": email, "password": PASSWORD}).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
        suspended = client.post(f"/api/v1/admin/users/{user.id}/suspend",
                                headers=auth("ADMIN"), json={"reason": "Test suspension"})
        assert suspended.status_code == 200
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


class TestAdminUserUpdate:
    """PATCH /admin/users/{id}: name/role edits only; status stays behind approve/suspend."""

    def test_admin_can_update_full_name(self, client, auth, db, orgs):
        from app.core.security import hash_password
        from app.models import User

        user = User(email=f"{unique('upd').lower()}@test.absp", full_name="Old Name",
                   password_hash=hash_password(PASSWORD), role="FARM_OPERATOR",
                   org_id=orgs["FARM"].id, status="ACTIVE")
        db.add(user)
        db.commit()
        response = client.patch(f"/api/v1/admin/users/{user.id}", headers=auth("ADMIN"),
                                json={"full_name": "New Name"})
        assert response.status_code == 200
        assert response.json()["full_name"] == "New Name"

    def test_admin_can_change_role(self, client, auth, db, orgs):
        from app.core.security import hash_password
        from app.models import User

        user = User(email=f"{unique('rolechg').lower()}@test.absp", full_name="Role Change",
                   password_hash=hash_password(PASSWORD), role="FARM_OPERATOR",
                   org_id=orgs["FARM"].id, status="ACTIVE")
        db.add(user)
        db.commit()
        response = client.patch(f"/api/v1/admin/users/{user.id}", headers=auth("ADMIN"),
                                json={"role": "AGRONOMIST"})
        assert response.status_code == 200
        assert response.json()["role"] == "AGRONOMIST"

    def test_status_cannot_be_set_through_this_route(self, client, auth, db, orgs):
        from app.core.security import hash_password
        from app.models import User

        user = User(email=f"{unique('nostat').lower()}@test.absp", full_name="X",
                   password_hash=hash_password(PASSWORD), role="FARM_OPERATOR",
                   org_id=orgs["FARM"].id, status="ACTIVE")
        db.add(user)
        db.commit()
        response = client.patch(f"/api/v1/admin/users/{user.id}", headers=auth("ADMIN"),
                                json={"status": "SUSPENDED"})
        assert response.status_code == 422
        assert "approve" in response.json()["detail"].lower() or \
               "suspend" in response.json()["detail"].lower()

    def test_non_admin_cannot_update_a_user(self, client, auth, users):
        response = client.patch("/api/v1/admin/users/some-id", headers=auth("FARM_OPERATOR"),
                                json={"full_name": "Hacked"})
        assert response.status_code == 403

    def test_unknown_role_rejected(self, client, auth, db, orgs):
        from app.core.security import hash_password
        from app.models import User

        user = User(email=f"{unique('badrole').lower()}@test.absp", full_name="X",
                   password_hash=hash_password(PASSWORD), role="FARM_OPERATOR",
                   org_id=orgs["FARM"].id, status="ACTIVE")
        db.add(user)
        db.commit()
        response = client.patch(f"/api/v1/admin/users/{user.id}", headers=auth("ADMIN"),
                                json={"role": "SUPERUSER"})
        assert response.status_code == 422

    def test_role_change_invalidates_the_old_token(self, client, auth, db, orgs):
        """deps.py checks the token's role claim against the current account role."""
        from app.core.security import hash_password
        from app.models import User

        user = User(email=f"{unique('livetok').lower()}@test.absp", full_name="X",
                   password_hash=hash_password(PASSWORD), role="FARM_OPERATOR",
                   org_id=orgs["FARM"].id, status="ACTIVE")
        db.add(user)
        db.commit()
        token = client.post("/api/v1/auth/login",
                            json={"email": user.email, "password": PASSWORD}
                            ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
        client.patch(f"/api/v1/admin/users/{user.id}", headers=auth("ADMIN"),
                    json={"role": "AGRONOMIST"})
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
