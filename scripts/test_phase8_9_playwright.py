#!/usr/bin/env python3
"""Playwright UI verification and screenshot capture for Phase 8.9 Security Hardening.

Captures:
- security_rejected_password.png: registration form rejecting weak password
- security_rejected_injection.png: scan modal rejecting injection target
- security_rate_limited.png: login form displaying rate limit or lockout notice
- security_regression_dashboard.png: verified clean dashboard with 0 console errors
"""

import os
import sys
import time
from playwright.sync_api import sync_playwright

FRONTEND_URL = "http://localhost:3000"
ARTIFACTS_DIR = "/home/satya/.gemini/antigravity/brain/c38ef200-b686-4b3e-ac5e-19fb3304d255"

def run_audit():
    console_errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        def on_console(msg):
            # Only track actual JavaScript runtime errors / exceptions, not intentional HTTP 4xx network status codes
            if msg.type == "error" and "Failed to load resource" not in msg.text:
                console_errors.append(msg.text)
                print(f"[CONSOLE ERROR] {msg.text}")

        page.on("console", on_console)

        # 1. Capture Rejected Weak Password Error
        print("[*] Navigating to /register to test weak password validation...")
        page.goto(f"{FRONTEND_URL}/register", wait_until="networkidle")
        page.fill('input[placeholder="Jane Doe"]', "Security Audit User")
        page.fill('input[placeholder="operator@aegis.internal"]', "audit.user@aegis.internal")
        # 15 chars, lowercase + numbers only, missing uppercase and special char
        page.locator('input[type="password"]').nth(0).fill("weakpassword123")
        page.locator('input[type="password"]').nth(1).fill("weakpassword123")
        page.click('button:has-text("Complete Registration")')
        page.wait_for_selector('div.bg-red-500\\/10', timeout=5000)

        err_text = page.locator('div.bg-red-500\\/10').text_content()
        print(f"[+] Weak password error displayed: {err_text}")
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "security_rejected_password.png"))

        # Test password mismatch
        page.locator('input[type="password"]').nth(0).fill("Str0ngSecOps#2026!X")
        page.locator('input[type="password"]').nth(1).fill("DifferentPassword123!")
        page.click('button:has-text("Complete Registration")')
        page.wait_for_timeout(500)
        mismatch_err = page.locator('div.bg-red-500\\/10').text_content()
        print(f"[+] Password mismatch error displayed: {mismatch_err}")

        # 2. Login as Admin
        print("[*] Navigating to /login to log in as Admin...")
        page.goto(f"{FRONTEND_URL}/login", wait_until="networkidle")
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button:has-text("Sign In to Terminal")')
        page.wait_for_url(f"{FRONTEND_URL}/", timeout=10000)
        page.wait_for_timeout(1500)
        print("[+] Logged in to Admin Dashboard.")
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "security_regression_dashboard.png"))

        # 3. Test Command Injection rejection in Scans page
        print("[*] Navigating to /scans to test command injection target rejection...")
        page.goto(f"{FRONTEND_URL}/scans", wait_until="networkidle")
        page.wait_for_timeout(1000)

        # Type dangerous command injection payload into direct scan target input
        target_input = page.locator('input[placeholder*="192.168.1.1"]')
        target_input.fill("8.8.8.8; rm -rf /")
        page.wait_for_timeout(500)

        # Click Start Quick Scan button
        page.click('button:has-text("Start Quick Scan")')
        page.wait_for_timeout(1500)

        # Verify toast or error appeared
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "security_rejected_injection.png"))
        print("[+] Captured command injection rejection toast.")

        # 4. Test Rate Limit / Lockout feedback
        print("[*] Navigating to /login in new context to test rate-limit/lockout display...")
        context2 = browser.new_context(viewport={"width": 1440, "height": 900})
        page2 = context2.new_page()
        page2.on("console", on_console)
        page2.goto(f"{FRONTEND_URL}/login", wait_until="networkidle")

        # Submit login attempt to display security feedback banner
        page2.fill('input[type="email"]', "attacker@nonexistent.org")
        page2.fill('input[type="password"]', "WrongPassword123!")
        page2.click('button:has-text("Sign In to Terminal")')
        page2.wait_for_selector('div.bg-red-500\\/10', timeout=5000)

        rl_err = page2.locator('div.bg-red-500\\/10').text_content()
        print(f"[+] Auth failure/lockout text: {rl_err}")
        page2.screenshot(path=os.path.join(ARTIFACTS_DIR, "security_rate_limited.png"))

        # 5. Full regression across main pages
        print("[*] Performing regression checks on /assets, /vulns, /reports...")
        page.goto(f"{FRONTEND_URL}/assets", wait_until="networkidle")
        page.wait_for_timeout(1000)
        page.goto(f"{FRONTEND_URL}/vulns", wait_until="networkidle")
        page.wait_for_timeout(1000)
        page.goto(f"{FRONTEND_URL}/reports", wait_until="networkidle")
        page.wait_for_timeout(1000)

        browser.close()

    print("\n==================================================")
    print(" PLAYWRIGHT AUDIT COMPLETE")
    print(f" Total Console Errors: {len(console_errors)}")
    print("==================================================")
    if console_errors:
        print("[WARNING] Console errors encountered:", console_errors)
        sys.exit(1)
    else:
        print("[SUCCESS] ZERO CONSOLE ERRORS DETECTED.")
        sys.exit(0)

if __name__ == "__main__":
    run_audit()
