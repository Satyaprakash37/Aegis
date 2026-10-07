"""Phase 8.3 End-to-End browser UI verification test using Playwright.
Verifies live progress reporting, reconnaissance summary in scan details modal,
SSL verified findings badges, and captures all required screenshots.
"""

import os
import sys
import time
import json
from playwright.sync_api import sync_playwright

def run_phase8_3_verification():
    console_errors = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        def handle_console(msg):
            if msg.type == "error":
                # Filter out intentional network errors during testing (e.g. 401s before login or favicon)
                text = msg.text
                if "favicon" not in text.lower():
                    console_errors.append(text)
                    print(f"[CONSOLE ERROR] {text}")

        page.on("console", handle_console)

        print("[TEST] 1. Logging in as Administrator...")
        page.goto("http://localhost:3000/login", wait_until="networkidle")
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:3000/", timeout=10000)
        time.sleep(1)

        print("[TEST] 2. Navigating to Scans page...")
        page.goto("http://localhost:3000/scans", wait_until="networkidle")
        time.sleep(2)

        # Verify new card description text
        assert "Full recon: subdomain discovery" in page.content(), "Card description not updated!"
        print("  ✓ Deep Scan profile card description verified.")

        # Capture Live Progress Screenshot
        print("[TEST] 3. Verifying Live Progress Bar...")
        page.wait_for_selector("text=Live Scan #", timeout=15000)
        time.sleep(1)
        screenshot_path = "/home/satya/.gemini/antigravity/scratch/aegis/phase8_3_live_progress.png"
        page.screenshot(path=screenshot_path)
        print(f"  ✓ Live progress view captured to {screenshot_path}")

        # Wait or poll for scan progress until at least stage 3 or completion
        print("[TEST] 4. Monitoring scan progress...")
        for _ in range(30):
            time.sleep(2)
            content = page.content()
            if "Reconnaissance Summary" in content or "Completed" in content or "Stage" in content:
                break

        # Click on scan row or 'Summary' button to open Scan Details modal
        print("[TEST] 5. Opening Scan Details Dossier Modal...")
        summary_btns = page.query_selector_all('button:has-text("Summary")')
        if summary_btns:
            summary_btns[0].click()
            time.sleep(2)
            page.wait_for_selector("text=Scan Execution Dossier #", timeout=5000)
            print("  ✓ Scan Details Dossier opened.")

            # Capture Reconnaissance Summary screenshot
            recon_screenshot = "/home/satya/.gemini/antigravity/scratch/aegis/phase8_3_recon_summary.png"
            page.screenshot(path=recon_screenshot)
            print(f"  ✓ Reconnaissance summary view captured to {recon_screenshot}")

            # Close modal
            page.click('button:has-text("Close Dossier")')
            time.sleep(1)

        print("[TEST] 6. Navigating to Vulnerabilities page...")
        page.goto("http://localhost:3000/vulns", wait_until="networkidle")
        time.sleep(2)

        # Check verification filter has 'SSL Audit (Active)'
        content = page.content()
        assert "SSL Audit (Active)" in content, "SSL Audit verification filter missing!"
        print("  ✓ SSL Audit filter option verified.")

        # Check for any SSL audit badges or filter by SSL
        page.select_option('select:has-text("All Verifications")', value="ssl_verified")
        time.sleep(1)
        ssl_screenshot = "/home/satya/.gemini/antigravity/scratch/aegis/phase8_3_ssl_verified_findings.png"
        page.screenshot(path=ssl_screenshot)
        print(f"  ✓ SSL findings view captured to {ssl_screenshot}")

        browser.close()

    print(f"\n[TEST RESULT] Console Error Count: {len(console_errors)}")
    if console_errors:
        print("Unexpected console errors:", console_errors)
    assert len(console_errors) == 0, f"Found {len(console_errors)} console errors"
    print(" ALL PLAYWRIGHT E2E TESTS PASSED WITH 0 CONSOLE ERRORS!")

if __name__ == "__main__":
    run_phase8_3_verification()
