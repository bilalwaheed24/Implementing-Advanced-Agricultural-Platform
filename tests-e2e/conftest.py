"""Shared Playwright fixtures for the live browser re-audit.

Runs headed by default so the run can be watched; set ABSP_HEADLESS=1 for CI.
Targets the disposable stack on :8083 and never the main exam database.
"""
from __future__ import annotations

import os
import uuid

import pytest
from playwright.sync_api import sync_playwright

BASE = os.environ.get("ABSP_BASE_URL", "http://127.0.0.1:8083")
PASSWORD = "DemoPassw0rd!2026"
HEADLESS = os.environ.get("ABSP_HEADLESS", "0") == "1"
SLOW_MO = int(os.environ.get("ABSP_SLOWMO", "220"))

ACCOUNTS = {
    "ADMIN": "admin@absp.demo",
    "SECURITY_ANALYST": "analyst@absp.demo",
    "FARM_OPERATOR": "farmer@absp.demo",
    "AGRONOMIST": "agronomist@absp.demo",
    "BIOTECH_RESEARCHER": "researcher@absp.demo",
    "BIOSAFETY_OFFICER": "biosafety@absp.demo",
    "SUPPLY_CHAIN_OPERATOR": "supply@absp.demo",
    "CERTIFIER": "certifier@absp.demo",
    "REGULATOR": "regulator@absp.demo",
}


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6].upper()}"


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch(headless=HEADLESS, slow_mo=SLOW_MO,
                              args=["--window-size=1440,900"])
        yield b
        b.close()


@pytest.fixture
def page(browser):
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    pg = context.new_page()
    pg.console_errors = []
    pg.server_errors = []
    pg.on("console", lambda m: pg.console_errors.append(m.text)
          if m.type == "error" else None)
    pg.on("response", lambda r: pg.server_errors.append(f"{r.status} {r.url}")
          if r.status >= 500 else None)
    yield pg
    context.close()


def login(page, role: str) -> None:
    """Sign in through the real form, not by injecting a token."""
    page.goto(BASE, wait_until="networkidle")
    page.evaluate("localStorage.clear()")
    page.goto(BASE + "/#/login", wait_until="networkidle")
    page.fill("input[type=email]", ACCOUNTS[role])
    page.fill("input[type=password]", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_function("() => !location.hash.includes('login')", timeout=20000)
    page.wait_for_load_state("networkidle")


def go(page, hash_route: str) -> None:
    page.goto(BASE + "/" + hash_route, wait_until="networkidle")
    page.wait_for_timeout(600)


def open_form(page, toggle_text: str):
    page.get_by_role("button", name=toggle_text, exact=True).first.click()
    page.wait_for_timeout(900)
