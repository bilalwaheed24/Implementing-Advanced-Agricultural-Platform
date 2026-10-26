"""A regulator and a biosafety officer read DATA_THEFT and LEDGER alerts but cannot work them.

Both halves are pinned here, because the value of the change is the gap between them: the
platform's oversight roles audit insider findings and ledger-integrity alerts in every
organisation (permissions.OVERSIGHT_ALERT_READER_ROLES), while acknowledging, resolving,
assigning and closing stay with security operations (SECURITY_OVERSIGHT_ROLES). A tenant role
still sees none of it, and neither new reader is added to the notification fan-out.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.security import utcnow
from app.models import Alert, Incident, Notification, User
from app.services import notifications
from .conftest import unique

API = "/api/v1"

# Read these alerts for oversight; neither holds the authority to clear one. Both read them
# across tenants, and neither sits in the organisation the fixtures file the alerts under.
READER_ROLES = ("REGULATOR", "BIOSAFETY_OFFICER")


def _foreign_alert(db, category, org) -> Alert:
    """An oversight-category alert raised in an organisation neither reader belongs to."""
    alert = notifications.raise_alert(
        db, category, "HIGH", f"Oversight read {category} {unique('A')}", org_id=org.id,
        entity_type="User", entity_id=str(uuid.uuid4()), notify=False,
        kind=f"oversight_read_{category.lower()}")
    db.commit()
    return alert


@pytest.fixture
def theft(db, orgs) -> Alert:
    """An exfiltration finding filed under the farm co-op, with its own incident."""
    return _foreign_alert(db, "DATA_THEFT", orgs["FARM"])


@pytest.fixture
def ledger(db, orgs) -> Alert:
    """A ledger-integrity alert filed under the processor, with its own incident."""
    return _foreign_alert(db, "LEDGER", orgs["SUPPLY"])


def _listed(client, headers, path) -> set[str]:
    response = client.get(f"{API}/security/{path}", headers=headers,
                          params={"page_size": 200})
    assert response.status_code == 200, response.text
    return {row["id"] for row in response.json()["items"]}


# --------------------------------------------------------------------------- #
# 1. They read them, in another organisation
# --------------------------------------------------------------------------- #
class TestOversightRolesRead:
    @pytest.mark.parametrize("role", READER_ROLES)
    def test_both_alerts_are_listed(self, client, auth, role, theft, ledger):
        listed = _listed(client, auth(role), "alerts")
        assert theft.id in listed, f"{role} cannot read a foreign data-theft alert"
        assert ledger.id in listed, f"{role} cannot read a foreign ledger alert"

    @pytest.mark.parametrize("role", READER_ROLES)
    @pytest.mark.parametrize("category", ["DATA_THEFT", "LEDGER"])
    def test_the_category_filter_works_for_them(self, client, auth, role, category,
                                                theft, ledger):
        wanted = theft if category == "DATA_THEFT" else ledger
        response = client.get(f"{API}/security/alerts", headers=auth(role),
                              params={"category": category, "page_size": 200})
        assert response.status_code == 200, response.text
        assert wanted.id in {row["id"] for row in response.json()["items"]}

    @pytest.mark.parametrize("role", READER_ROLES)
    def test_the_incidents_open_with_the_analysts_notes(self, client, auth, role, theft):
        noted = client.patch(f"{API}/security/incidents/{theft.incident_id}",
                             headers=auth("SECURITY_ANALYST"),
                             json={"note": unique("containment note")})
        assert noted.status_code == 200, noted.text
        headers = auth(role)
        assert theft.incident_id in _listed(client, headers, "incidents")
        detail = client.get(f"{API}/security/incidents/{theft.incident_id}", headers=headers)
        assert detail.status_code == 200, detail.text
        assert any(e["action"] == "NOTE" for e in detail.json()["timeline"])
        # The page must not offer an edit it would then refuse.
        assert detail.json()["can_update"] is False

    @pytest.mark.parametrize("role", READER_ROLES)
    def test_the_security_board_counts_them(self, client, auth, db, orgs, role):
        def board():
            response = client.get(f"{API}/security/dashboard", headers=auth(role))
            assert response.status_code == 200, response.text
            return response.json()

        before = board()
        _foreign_alert(db, "DATA_THEFT", orgs["SUPPLY"])
        after = board()
        assert after["alerts_open"] == before["alerts_open"] + 1
        assert after["open_by_category"].get("DATA_THEFT", 0) == \
            before["open_by_category"].get("DATA_THEFT", 0) + 1

    @pytest.mark.parametrize("role", READER_ROLES)
    def test_the_dashboard_tile_counts_them(self, client, auth, db, orgs, role):
        def open_alerts():
            response = client.get(f"{API}/dashboard", headers=auth(role))
            assert response.status_code == 200, response.text
            return response.json()["alerts"]["open"]

        before = open_alerts()
        _foreign_alert(db, "LEDGER", orgs["FARM"])
        assert open_alerts() == before + 1


# --------------------------------------------------------------------------- #
# 2. Reading is not working: no acknowledge, resolve, assign or close
# --------------------------------------------------------------------------- #
class TestOversightRolesCannotActOnThem:
    @pytest.mark.parametrize("role", READER_ROLES)
    @pytest.mark.parametrize("action", ["acknowledge", "resolve"])
    def test_the_alert_cannot_be_acknowledged_or_resolved(self, client, auth, db, role,
                                                          action, theft, ledger):
        for alert in (theft, ledger):
            response = client.post(f"{API}/security/alerts/{alert.id}/{action}",
                                   headers=auth(role))
            # 403, not 404: they can see the row, so hiding it would be a lie. A regulator
            # holds no alert:write at all; a biosafety officer does, and is turned away by
            # security_ops._require_alert_authority.
            assert response.status_code == 403, response.text
        db.expire_all()
        assert db.get(Alert, theft.id).status == "OPEN"
        assert db.get(Alert, ledger.id).status == "OPEN"
        assert db.get(Incident, theft.incident_id).status == "OPEN"

    @pytest.mark.parametrize("role", READER_ROLES)
    def test_the_incident_cannot_be_updated_or_closed(self, client, auth, db, role, theft):
        for payload in ({"status": "TRIAGED"}, {"note": "clearing this"},
                        {"root_cause": "false positive"}):
            response = client.patch(f"{API}/security/incidents/{theft.incident_id}",
                                    headers=auth(role), json=payload)
            assert response.status_code == 403, response.text
        db.expire_all()
        assert db.get(Incident, theft.incident_id).status == "OPEN"

    @pytest.mark.parametrize("role", READER_ROLES)
    def test_the_incident_cannot_be_assigned_to_them(self, client, auth, db, users, role,
                                                     theft):
        response = client.patch(f"{API}/security/incidents/{theft.incident_id}",
                                headers=auth("SECURITY_ANALYST"),
                                json={"assignee_id": users[role].id})
        assert response.status_code == 422, response.text
        db.expire_all()
        assert db.get(Incident, theft.incident_id).assignee_id is None

    @pytest.mark.parametrize("role", READER_ROLES)
    def test_security_operations_still_resolve_it(self, client, auth, db, role, theft):
        assert client.post(f"{API}/security/alerts/{theft.id}/resolve",
                           headers=auth(role)).status_code == 403
        response = client.post(f"{API}/security/alerts/{theft.id}/resolve",
                               headers=auth("SECURITY_ANALYST"))
        assert response.status_code == 200, response.text
        db.expire_all()
        assert db.get(Incident, theft.incident_id).status == "RESOLVED"


# --------------------------------------------------------------------------- #
# 3. What the widening must not touch
# --------------------------------------------------------------------------- #
class TestTheRestOfTheRuleHolds:
    @pytest.mark.parametrize("role", ["SUPPLY_CHAIN_OPERATOR", "FARM_OPERATOR", "AGRONOMIST",
                                      "CERTIFIER", "BIOTECH_RESEARCHER"])
    def test_a_tenant_role_still_reads_neither(self, client, auth, role, theft, ledger):
        listed = _listed(client, auth(role), "alerts")
        assert theft.id not in listed and ledger.id not in listed
        refused = client.get(f"{API}/security/incidents/{theft.incident_id}",
                             headers=auth(role))
        # 404 for a role that reads incidents at all — the row is hidden, and a 403 would
        # confirm it exists; a plain 403 for one that holds no incident:read to begin with.
        assert refused.status_code in (403, 404), refused.text

    def test_a_biosafety_officer_reads_no_other_foreign_category(self, client, auth, db,
                                                                 orgs):
        """The round-6 narrowing stands outside the oversight categories: only her own
        organisation's device and certificate alerts, as before."""
        device = _foreign_alert(db, "DEVICE_HEALTH", orgs["FARM"])
        cert = _foreign_alert(db, "CERTIFICATION", orgs["SUPPLY"])
        listed = _listed(client, auth("BIOSAFETY_OFFICER"), "alerts")
        assert device.id not in listed and cert.id not in listed

    def test_neither_reader_is_notified_of_a_new_one(self, db, users, orgs):
        """Read-only visibility, not a push. An alert about one user's access pattern is
        looked up when a case is being overseen; it is not posted to a regulator's inbox."""
        start = utcnow() - timedelta(seconds=1)
        title = unique("Possible data exfiltration by a probe")
        notifications.fan_out(db, "DATA_THEFT", "HIGH", title, "", orgs["FARM"].id,
                              "User", users["FARM_OPERATOR"].id)
        notifications.notify_parties(db, [orgs["FARM"].id], "LEDGER", title, "", "Batch",
                                     None, include_oversight=True)
        db.commit()
        roles = {db.get(User, n.user_id).role for n in db.execute(select(Notification).where(
            Notification.title == title, Notification.created_at >= start)).scalars()}
        assert roles and roles <= {"SECURITY_ANALYST", "ADMIN"}, roles
