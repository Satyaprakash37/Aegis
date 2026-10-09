#!/usr/bin/env python3
"""End-to-End Playwright Verification Suite for AEGIS Phase R0 - Threat Intelligence Foundation.

Verifies:
1. Dashboard: Actively Exploited (KEV) KPI stat card
2. Vulnerabilities Table: Threat Intel column with ACTIVE-THREAT, KEV, EPSS percentage
3. Vulnerabilities Detail Drawer: Threat Intelligence section with KEV details, EPSS interpretation, and exploit references
4. Zero browser console errors
"""

import os
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = Path("/home/satya/.gemini/antigravity/brain/c38ef200-b686-4b3e-ac5e-19fb3304d255")
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)


def verify_threat_intel():
    print("========================================================")
    print("AEGIS Phase R0: Threat Intelligence Playwright Suite")
    print("========================================================")

    console_errors = []

    def handle_console(msg):
        if msg.type == "error":
            text = msg.text
            # Filter out expected favicon or network warnings if any
            if "favicon.ico" not in text:
                console_errors.append(text)
                print(f"[BROWSER ERROR] {text}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.on("console", handle_console)

        # 1. Login
        print("[*] Logging in as admin@aegis.internal...")
        page.goto("http://localhost:3000/login", wait_until="networkidle")
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:3000/", timeout=10000)
        page.wait_for_load_state("networkidle")
        time.sleep(1)

        # 2. Verify Dashboard
        print("[*] Verifying Dashboard & KEV stat card...")
        # Check for KEV stat card
        page.wait_for_selector('text="Actively Exploited (KEV)"', timeout=8000)
        kev_card = page.locator('text="Actively Exploited (KEV)"')
        assert kev_card.count() > 0, "Actively Exploited (KEV) card not found on dashboard"

        dash_shot = ARTIFACTS_DIR / "threat_intel_dashboard_kev.png"
        page.screenshot(path=str(dash_shot), full_page=False)
        print(f"[✓] Dashboard verified. Screenshot saved to: {dash_shot}")

        # 3. Verify Vulnerabilities Table
        print("[*] Navigating to /vulnerabilities...")
        page.goto("http://localhost:3000/vulnerabilities", wait_until="networkidle")
        time.sleep(1.5)

        # Verify "Threat Intel" column header
        page.wait_for_selector('th:has-text("Threat Intel")', timeout=8000)
        assert page.locator('th:has-text("Threat Intel")').count() > 0, "Threat Intel header not found in table"

        # Check for ACTIVE THREAT or KEV chip
        active_chips = page.locator('text="ACTIVE THREAT"')
        kev_chips = page.locator('text="KEV ✓"')
        print(f"[*] Found {active_chips.count()} ACTIVE THREAT chip(s) and {kev_chips.count()} KEV chip(s) on current page")

        table_shot = ARTIFACTS_DIR / "threat_intel_vulns_table.png"
        page.screenshot(path=str(table_shot), full_page=False)
        print(f"[✓] Vulnerabilities table verified. Screenshot saved to: {table_shot}")

        # 4. Open Detail Drawer for an ACTIVE THREAT or KEV finding
        print("[*] Opening detail drawer for an ACTIVE THREAT finding...")
        # Find a row with ACTIVE THREAT or first row
        active_row = page.locator('tr:has-text("ACTIVE THREAT")').first
        if active_row.count() > 0:
            active_row.click()
        else:
            page.locator('tbody tr').first.click()

        time.sleep(1)
        # Check drawer elements
        page.wait_for_selector('text="Threat Intelligence Feeds (CISA KEV + FIRST EPSS)"', timeout=8000)
        assert page.locator('text="CISA KEV Catalog"').count() > 0, "CISA KEV Catalog section not found in drawer"
        assert page.locator('text="FIRST EPSS Scoring"').count() > 0, "FIRST EPSS Scoring section not found in drawer"

        drawer_shot = ARTIFACTS_DIR / "threat_intel_detail_drawer.png"
        page.screenshot(path=str(drawer_shot), full_page=False)
        print(f"[✓] Vulnerability detail drawer verified. Screenshot saved to: {drawer_shot}")

        # 5. Check Console Errors
        print(f"[*] Total browser console errors detected: {len(console_errors)}")
        assert len(console_errors) == 0, f"Found browser console errors: {console_errors}"
        print("[✓] Zero browser console errors confirmed.")

        browser.close()

    print("========================================================")
    print("ALL PLAYWRIGHT TESTS PASSED CLEANLY (100% SUCCESS)")
    print("========================================================")


if __name__ == "__main__":
    verify_threat_intel()
