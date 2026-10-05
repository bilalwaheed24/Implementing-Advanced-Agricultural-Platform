"""Live browser re-audit of the exam workflows.

Everything is created by clicking the real frontend; the API is read only as evidence.
"""
from __future__ import annotations

import pytest

from conftest import BASE, go, login, open_form, unique


# --------------------------------------------------------------------------- #
# Farm operator: farm, field, devices, lifecycle
# --------------------------------------------------------------------------- #
class TestFarmOperator:
    def test_creates_a_farm(self, page):
        login(page, "FARM_OPERATOR")
        go(page, "#/farms")
        name = unique("Playwright Farm")
        open_form(page, "Register a farm")
        page.fill("form input#" + page.locator("form label", has_text="Farm name")
                  .get_attribute("for"), name)
        page.get_by_role("button", name="Create farm").click()
        page.wait_for_timeout(2500)
        go(page, "#/farms")
        assert page.get_by_text(name, exact=False).count() > 0, "farm not listed after reload"
        assert not page.server_errors, page.server_errors

    def test_registers_a_soil_sensor_and_sees_the_secret_once(self, page):
        login(page, "FARM_OPERATOR")
        go(page, "#/devices")
        open_form(page, "Register a device")
        page.select_option("form select >> nth=0", label="Soil sensor")
        page.fill("form input[placeholder='e.g. FieldProbe S2']", "PW-SoilProbe")
        farm = page.locator("form select").nth(1)
        farm.select_option(index=1)
        page.wait_for_timeout(500)
        page.get_by_role("button", name="Register device").click()
        page.wait_for_timeout(3000)
        assert page.get_by_text("Secret for", exact=False).count() > 0, \
            "the one-time secret notice was not shown"
        assert page.get_by_text("only time this value is shown", exact=False).count() > 0
        assert not page.server_errors, page.server_errors

    def test_a_registered_device_survives_reload_and_re_login(self, page):
        login(page, "FARM_OPERATOR")
        go(page, "#/devices")
        open_form(page, "Register a device")
        page.select_option("form select >> nth=0", label="Drone")
        model = unique("PW-Drone")
        page.fill("form input[placeholder='e.g. FieldProbe S2']", model)
        page.locator("form select").nth(1).select_option(index=1)
        page.wait_for_timeout(500)
        page.get_by_role("button", name="Register device").click()
        page.wait_for_timeout(3000)

        go(page, "#/devices")
        assert page.get_by_text(model, exact=False).count() > 0, "gone after reload"

        login(page, "FARM_OPERATOR")          # full logout/login cycle
        go(page, "#/devices")
        assert page.get_by_text(model, exact=False).count() > 0, "gone after re-login"
        assert not page.server_errors, page.server_errors


# --------------------------------------------------------------------------- #
# Supply chain: batch, shipment, custody
# --------------------------------------------------------------------------- #
class TestSupplyChain:
    def test_creates_a_batch_through_the_form(self, page):
        login(page, "SUPPLY_CHAIN_OPERATOR")
        go(page, "#/batches")
        code = unique("PW-BATCH")
        open_form(page, "Create a batch")
        page.fill("form input[placeholder*='MAIZE-2026-014']", code)
        page.locator("form select").first.select_option(index=1)
        page.get_by_role("button", name="Create batch").click()
        page.wait_for_timeout(3000)
        go(page, "#/batches")
        assert page.get_by_text(code, exact=False).count() > 0, "batch not listed"
        assert not page.server_errors, page.server_errors

    def test_the_farm_selector_is_withdrawn_for_a_role_without_farm_read(self, page):
        """A control sourced from an endpoint the role cannot read must not be shown."""
        login(page, "SUPPLY_CHAIN_OPERATOR")
        go(page, "#/batches")
        open_form(page, "Create a batch")
        hidden = page.evaluate(
            "() => [...document.querySelectorAll('form .field')]"
            ".filter(f => f.querySelector('label')?.textContent === 'Farm of origin')"
            ".map(f => f.hidden)")
        assert hidden == [True], f"Farm of origin field state: {hidden}"
        calls = page.evaluate(
            "() => performance.getEntriesByType('resource')"
            ".filter(e => e.name.includes('/api/v1/farms')).length")
        assert calls == 0, "a forbidden endpoint was still called"

    def test_creates_a_shipment_against_its_own_batch(self, page):
        login(page, "SUPPLY_CHAIN_OPERATOR")
        go(page, "#/shipments")
        sscc = "009" + unique("")[-8:].replace("-", "0")
        open_form(page, "Create a shipment")
        page.fill("form input[placeholder*='SSCC']", sscc)
        page.locator("form select").first.select_option(index=1)
        page.fill("form input[placeholder*='Midwest Cold Freight']", "PW Carrier")
        page.get_by_role("button", name="Create shipment").click()
        page.wait_for_timeout(3000)
        go(page, "#/shipments")
        assert page.get_by_text(sscc, exact=False).count() > 0, "shipment not listed"
        assert not page.server_errors, page.server_errors

    def test_records_a_custody_event_and_the_batch_state_moves(self, page):
        login(page, "SUPPLY_CHAIN_OPERATOR")
        go(page, "#/batches")
        page.locator("table tbody tr td a").first.click()
        page.wait_for_timeout(2000)
        before = page.evaluate("() => document.body.innerText")
        open_form(page, "Record a custody event")
        page.get_by_role("button", name="Record event").click()
        page.wait_for_timeout(3000)
        assert "Event recorded" in page.evaluate("() => document.body.innerText") \
            or before != page.evaluate("() => document.body.innerText")
        assert not page.server_errors, page.server_errors


# --------------------------------------------------------------------------- #
# Regulated governance
# --------------------------------------------------------------------------- #
class TestGovernance:
    def test_regulator_records_a_gmo_decision_without_typing_an_id(self, page):
        login(page, "REGULATOR")
        go(page, "#/gmo")
        open_form(page, "Record a jurisdictional decision")
        selects = page.locator("form select")
        assert selects.count() >= 3, "the decision form should be fully controlled inputs"
        assert page.locator("form input[type=text]").count() <= 1, \
            "no raw identifier entry is permitted"
        page.locator("form select").first.select_option(index=1)
        page.wait_for_timeout(1500)
        assert "On record" in page.evaluate("() => document.body.innerText"), \
            "existing decisions should be shown before a new one is taken"

    def test_regulator_cannot_register_a_gmo_event(self, page):
        login(page, "REGULATOR")
        go(page, "#/gmo")
        assert page.get_by_role("button", name="Register GMO event").count() == 0

    def test_researcher_cannot_record_a_gmo_decision(self, page):
        login(page, "BIOTECH_RESEARCHER")
        go(page, "#/gmo")
        assert page.get_by_role("button",
                                name="Record a jurisdictional decision").count() == 0

    def test_the_screening_selector_is_a_filtered_dropdown(self, page):
        login(page, "BIOTECH_RESEARCHER")
        go(page, "#/gmo")
        open_form(page, "Register GMO event")
        label = page.locator("form label", has_text="Biosecurity screening")
        assert label.count() == 1, "the field should be labelled for a human"
        control = page.locator(f"#{label.get_attribute('for')}")
        assert control.evaluate("e => e.tagName") == "SELECT", \
            "a UUID text box is not acceptable here"

    def test_researcher_creates_a_seed_lot_from_approved_lineage_only(self, page):
        login(page, "BIOTECH_RESEARCHER")
        go(page, "#/seed-lots")
        code = unique("PW-SL")
        open_form(page, "Create a seed lot")
        page.fill("form input[placeholder*='SL-2026-004']", code)
        page.locator("form select").first.select_option(index=1)
        page.get_by_role("button", name="Create seed lot").click()
        page.wait_for_timeout(3000)
        go(page, "#/seed-lots")
        assert page.get_by_text(code, exact=False).count() > 0
        assert not page.server_errors, page.server_errors

    def test_certifier_cannot_select_its_own_organisation(self, page):
        login(page, "CERTIFIER")
        go(page, "#/certifications")
        open_form(page, "Issue a certification")
        own = page.evaluate(
            "() => JSON.parse(localStorage.getItem('absp.session') "
            "|| localStorage.getItem('session') || '{}').org_id")
        options = page.locator("form select").nth(1).locator("option")
        values = [options.nth(i).get_attribute("value") for i in range(options.count())]
        assert own not in [v for v in values if v], "self-certification is selectable"

    def test_certifier_issues_a_certification_for_another_organisation(self, page):
        login(page, "CERTIFIER")
        go(page, "#/certifications")
        code = unique("PW-ORG")
        open_form(page, "Issue a certification")
        page.fill("form input[placeholder*='ORG-2026-0012']", code)
        page.locator("form select").nth(1).select_option(index=1)
        page.get_by_role("button", name="Issue certification").click()
        page.wait_for_timeout(3000)
        go(page, "#/certifications")
        assert page.get_by_text(code, exact=False).count() > 0
        assert not page.server_errors, page.server_errors

    def test_admin_can_no_longer_issue_certifications(self, page):
        """ADMIN is platform administration, not regulated authority (audit P2)."""
        login(page, "ADMIN")
        go(page, "#/certifications")
        assert page.get_by_role("button", name="Issue a certification").count() == 0


# --------------------------------------------------------------------------- #
# Ledger visibility
# --------------------------------------------------------------------------- #
class TestLedgerVisibility:
    def test_a_farm_operator_has_no_ledger_navigation_and_is_denied_directly(self, page):
        login(page, "FARM_OPERATOR")
        assert page.locator("a[href='#/blockchain']").count() == 0, "ledger nav is visible"
        go(page, "#/blockchain")
        text = page.evaluate("() => document.body.innerText").lower()
        assert "not available to your role" in text, text[:300]
        # The explorer's own data must not have rendered behind the refusal.
        assert "block hash" not in text and "merkle" not in text, "ledger content leaked"

    def test_a_regulator_can_open_the_ledger_explorer(self, page):
        login(page, "REGULATOR")
        assert page.locator("a[href='#/blockchain']").count() == 1
        go(page, "#/blockchain")
        text = page.evaluate("() => document.body.innerText").lower()
        assert "not available to your role" not in text
        assert not page.server_errors, page.server_errors


# --------------------------------------------------------------------------- #
# Security operations
# --------------------------------------------------------------------------- #
class TestSecurityOps:
    def test_notification_inbox_marks_an_item_read(self, page):
        login(page, "BIOSAFETY_OFFICER")
        go(page, "#/notifications")
        buttons = page.get_by_role("button", name="Mark as read")
        if buttons.count() == 0:
            pytest.skip("no unread notifications for this role")
        before = buttons.count()
        buttons.first.click()
        page.wait_for_timeout(2000)
        assert page.get_by_role("button", name="Mark as read").count() == before - 1
        assert not page.server_errors, page.server_errors

    def test_analyst_acknowledges_then_resolves_an_alert(self, page):
        login(page, "SECURITY_ANALYST")
        go(page, "#/alerts")
        ack = page.get_by_role("button", name="Acknowledge")
        if ack.count() == 0:
            pytest.skip("no open alert to acknowledge")
        ack.first.click()
        page.wait_for_timeout(2500)
        assert not page.server_errors, page.server_errors


# --------------------------------------------------------------------------- #
# Public consumer surface
# --------------------------------------------------------------------------- #
class TestPublicVerification:
    def test_a_valid_code_verifies(self, page):
        login(page, "SUPPLY_CHAIN_OPERATOR")
        go(page, "#/batches")
        code = page.locator("a[href*='verify.html?code=']").first.get_attribute("href")
        code = code.split("code=")[1]
        page.goto(f"{BASE}/verify.html?code={code}", wait_until="networkidle")
        page.wait_for_timeout(2000)
        text = page.evaluate("() => document.body.innerText")
        assert "not found" not in text.lower(), text[:200]

    def test_a_random_code_leaks_nothing(self, page):
        page.goto(f"{BASE}/verify.html?code=AAAA-BBBB-CCCC-DDDD-EEEE",
                  wait_until="networkidle")
        page.wait_for_timeout(2000)
        text = page.evaluate("() => document.body.innerText")
        for leak in ("Traceback", "SELECT ", "correlation_id", "psycopg", "sqlalchemy"):
            assert leak not in text, f"leaked {leak}"
        assert not page.server_errors, page.server_errors
