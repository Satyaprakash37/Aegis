"""Capture fresh screenshots of Recon Summary Modal and SSL Verified Findings.
"""

import time
from playwright.sync_api import sync_playwright

def capture_screenshots():
    console_errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" and "favicon" not in msg.text.lower() else None)

        print("1. Logging in...")
        page.goto("http://localhost:3000/login", wait_until="networkidle")
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:3000/", timeout=10000)
        time.sleep(1)

        print("2. Scans page...")
        page.goto("http://localhost:3000/scans", wait_until="networkidle")
        time.sleep(2)

        # Click summary on scan #35 (first row or scanme.nmap.org)
        print("3. Opening Recon Summary for scanme.nmap.org...")
        row = page.locator('tr:has-text("scanme.nmap.org")').first
        if row:
            summary_btn = row.locator('button:has-text("Summary")')
            summary_btn.click()
            time.sleep(2)
            page.wait_for_selector("text=Reconnaissance Summary", timeout=10000)
            page.screenshot(path="/home/satya/.gemini/antigravity/scratch/aegis/phase8_3_recon_summary.png")
            print("  ✓ Captured phase8_3_recon_summary.png")
            page.click('button:has-text("Close Dossier")')
            time.sleep(1)

        print("4. Vulnerabilities page...")
        page.goto("http://localhost:3000/vulns", wait_until="networkidle")
        time.sleep(2)

        # Filter by ssl_verified
        page.select_option('select:has-text("All Verifications")', value="ssl_verified")
        time.sleep(2)
        page.screenshot(path="/home/satya/.gemini/antigravity/scratch/aegis/phase8_3_ssl_verified_findings.png")
        print("  ✓ Captured phase8_3_ssl_verified_findings.png")

        # Click on one of the SSL findings to show its details drawer with SSL Audit badge
        row_vuln = page.locator('tr:has-text("SSL-")').first
        if row_vuln:
            row_vuln.click()
            time.sleep(2)
            page.screenshot(path="/home/satya/.gemini/antigravity/scratch/aegis/phase8_3_ssl_drawer.png")
            print("  ✓ Captured phase8_3_ssl_drawer.png")

        browser.close()

    print(f"Console errors: {len(console_errors)}")
    assert len(console_errors) == 0, f"Errors: {console_errors}"
    print("ALL SCREENSHOTS CAPTURED WITH 0 CONSOLE ERRORS!")

if __name__ == "__main__":
    capture_screenshots()
