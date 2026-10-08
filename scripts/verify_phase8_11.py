"""
Phase 8.11 Verification Script - Origin Direct & VHost Routing Telemetry
Verifies:
1. Origin Infrastructure Map in Scans Dossier modal with confirmed routing
2. Origin-Direct badges on findings in Vulnerabilities table and modal
3. Evidence payload transparency with [ORIGIN CONFIG AUDIT] markers
4. 0 browser console errors
"""
import os
import sys
import time
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = "/home/satya/.gemini/antigravity/brain/c38ef200-b686-4b3e-ac5e-19fb3304d255"

def run_verification():
    console_errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 960})
        page = context.new_page()

        def handle_console(msg):
            if msg.type == "error":
                print(f"[BROWSER ERROR] {msg.text}")
                console_errors.append(msg.text)

        page.on("console", handle_console)

        print("\n--- STEP 1: Log in as Security Administrator ---")
        page.goto("http://localhost:3000/login", wait_until="networkidle")
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:3000/", timeout=10000)
        page.wait_for_load_state("networkidle")
        time.sleep(1)

        print("\n--- STEP 2: Navigate to /scans and Inspect Dossier #68 ---")
        page.goto("http://localhost:3000/scans", wait_until="networkidle")
        time.sleep(1)

        # Click on scan 68 Summary button
        summary_btn = page.locator("tr:has-text('cutm.ac.in') button:has-text('Summary')").first
        assert summary_btn.count() > 0, "Scan #68 Summary button not found"
        summary_btn.click()
        page.wait_for_selector("h3:has-text('Scan Execution Dossier')", timeout=8000)
        # Wait for scan details API to resolve and render recon section
        page.wait_for_selector("h4:has-text('Reconnaissance Summary')", timeout=10000)
        time.sleep(1)

        # Verify Origin Infrastructure Map renders
        dossier_text = page.inner_text("div.fixed")
        assert "origin infrastructure map" in dossier_text.lower(), "Expected 'Origin Infrastructure Map' in dossier"
        assert "115.241.211.179" in dossier_text, "Expected origin IP 115.241.211.179 in dossier"
        assert "CONFIRMED ✓" in dossier_text or "CONFIRMED" in dossier_text, "Expected CONFIRMED status in dossier"
        print("✓ Origin Infrastructure Map rendered with confirmed routing to 115.241.211.x")

        # Scroll down to ensure Origin Infrastructure Map is in view for screenshot
        origin_section = page.locator("text=Origin Infrastructure Map").first
        origin_section.scroll_into_view_if_needed()
        time.sleep(1)

        # Save screenshot
        screenshot_map = os.path.join(ARTIFACTS_DIR, "origin_infrastructure_map.png")
        page.screenshot(path=screenshot_map)
        print(f"✓ Saved screenshot: {screenshot_map}")

        # Close dossier
        page.keyboard.press("Escape")
        time.sleep(0.5)

        print("\n--- STEP 3: Navigate to /vulnerabilities and verify Origin-Direct Badge ---")
        page.goto("http://localhost:3000/vulnerabilities?scan_id=68", wait_until="networkidle")
        time.sleep(1.5)

        vulns_text = page.inner_text("body")
        assert "Origin-Direct" in vulns_text, "Expected 'Origin-Direct' chip on findings"
        assert "CVE-ACTIVE-ORIGIN-DIRECT-EXPOSURE" in vulns_text, "Expected CVE-ACTIVE-ORIGIN-DIRECT-EXPOSURE in list"
        print("✓ Origin-Direct badge verified in vulnerability findings table")

        # Click on the origin exposure finding to open modal
        origin_vuln_row = page.locator("tr:has-text('CVE-ACTIVE-ORIGIN-DIRECT-EXPOSURE')")
        assert origin_vuln_row.count() > 0, "Origin vuln row not found"
        origin_vuln_row.click()
        time.sleep(1)

        modal_text = page.inner_text("div.fixed")
        assert "Origin-Direct" in modal_text, "Expected Origin-Direct badge inside detail modal"
        assert "[ORIGIN CONFIG AUDIT]" in modal_text, "Expected [ORIGIN CONFIG AUDIT] in evidence payload"
        print("✓ Origin-Direct finding detail modal verified with full evidence transparency")

        screenshot_findings = os.path.join(ARTIFACTS_DIR, "origin_direct_findings.png")
        page.screenshot(path=screenshot_findings)
        print(f"✓ Saved screenshot: {screenshot_findings}")

        browser.close()

    print(f"\nSevere Console Errors: {len(console_errors)}")
    if console_errors:
        for err in console_errors:
            print(f"  - {err}")
        return False

    print("\n✅ ALL PHASE 8.11 VERIFICATION TESTS PASSED WITH 0 CONSOLE ERRORS!")
    return True

if __name__ == "__main__":
    success = run_verification()
    if not success:
        sys.exit(1)
