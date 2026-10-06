"""End-to-End browser UI regression test using Playwright for AEGIS v1.0.0.
"""

import sys
import time
from playwright.sync_api import sync_playwright

def run_e2e_test():
    console_errors = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        def handle_console(msg):
            if msg.type == "error":
                # Filter out intentional network errors during testing
                if "favicon" not in msg.text.lower():
                    console_errors.append(msg.text)
                    print(f"[CONSOLE ERROR] {msg.text}")

        page.on("console", handle_console)

        print("[E2E] 1. Visiting Login Page...")
        page.goto("http://localhost:3000/login", wait_until="networkidle")
        time.sleep(1)
        assert "Authentication Portal" in page.title() or "AEGIS" in page.title()
        page.screenshot(path="e2e_login.png")
        print("  -> Login page title:", page.title())

        print("[E2E] 2. Logging in as Administrator...")
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:3000/", timeout=10000)
        page.wait_for_selector("text=Cybersecurity Command Center", timeout=10000)
        time.sleep(2)
        print("  -> Dashboard title:", page.title())
        assert "Dashboard" in page.title()
        page.screenshot(path="e2e_dashboard.png")

        print("[E2E] 3. Verifying Assets Table...")
        page.click('button:has-text("Assets")')
        page.wait_for_url("http://localhost:3000/assets", timeout=10000)
        time.sleep(2)
        print("  -> Assets title:", page.title())
        assert "Asset" in page.title()
        page.wait_for_selector("text=mail-relay-edge", timeout=10000)
        page.screenshot(path="e2e_assets.png")

        print("[E2E] 4. Verifying Vulnerabilities Page & Risk Scores...")
        page.click('button:has-text("Vulnerabilities")')
        page.wait_for_url("http://localhost:3000/vulns", timeout=10000)
        time.sleep(2)
        print("  -> Vulnerabilities title:", page.title())
        assert "Vulnerability" in page.title()
        page.screenshot(path="e2e_vulns.png")
        print("  -> Vulns text sample:", page.inner_text("body")[:300])

        print("[E2E] 5. Verifying Reports Page...")
        page.click('button:has-text("Reports")')
        page.wait_for_url("http://localhost:3000/reports", timeout=10000)
        time.sleep(2)
        print("  -> Reports title:", page.title())
        assert "Reports" in page.title()
        page.wait_for_selector("text=Security Reports & Compliance Export", timeout=10000)
        page.screenshot(path="e2e_reports.png")

        print("[E2E] 6. Verifying 404 Route...")
        page.goto("http://localhost:3000/some-invalid-security-route", wait_until="networkidle")
        time.sleep(1)
        print("  -> 404 title:", page.title())
        assert "404" in page.title()
        page.wait_for_selector("text=Sector Not Found", timeout=10000)
        page.screenshot(path="e2e_notfound.png")

        # Test Return to Base button
        page.click("text=Return to Base")
        page.wait_for_url("http://localhost:3000/", timeout=10000)
        time.sleep(1)
        print("  -> Successfully returned to Dashboard from 404!")

        browser.close()

    print("\n[E2E] Console Error Count:", len(console_errors))
    assert len(console_errors) == 0, f"Found unexpected console errors: {console_errors}"
    print("\n ALL E2E BROWSER PLAYWRIGHT TESTS PASSED WITH ZERO CONSOLE ERRORS!")

if __name__ == "__main__":
    run_e2e_test()
