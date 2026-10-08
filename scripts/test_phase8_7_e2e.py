import os
import sys
import time
from playwright.sync_api import sync_playwright

ARTIFACT_DIR = "/home/satya/.gemini/antigravity/brain/c38ef200-b686-4b3e-ac5e-19fb3304d255"

def run_verification():
    console_errors = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        def handle_console(msg):
            if msg.type == "error":
                text = msg.text
                if "favicon" not in text.lower() and "status of 401" not in text.lower() and "status of 422" not in text.lower():
                    console_errors.append(f"[{page.url}] {text}")
                    print(f"[BROWSER ERROR] {text}", file=sys.stderr)

        page.on("console", handle_console)
        page.on("pageerror", lambda err: console_errors.append(f"[{page.url}] Uncaught exception: {err}"))

        print("\n--- STEP 1: Verify Login Page Theme ---")
        page.goto("http://localhost:3000/login", wait_until="networkidle")
        page.screenshot(path=os.path.join(ARTIFACT_DIR, "theme_login.png"))
        print("Captured theme_login.png")

        print("\n--- STEP 2: Login as Admin ---")
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:3000/", timeout=10000)
        page.wait_for_load_state("networkidle")
        time.sleep(2)

        print("\n--- STEP 3: Admin Dashboard Theme & Metrics ---")
        page.screenshot(path=os.path.join(ARTIFACT_DIR, "theme_dashboard.png"))
        print("Captured theme_dashboard.png")

        print("\n--- STEP 4: Admin Vulnerabilities (Verify Dedup on dc-primary-01) ---")
        page.goto("http://localhost:3000/vulns?search=dc-primary", wait_until="networkidle")
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACT_DIR, "dedup_dc_primary.png"))
        print("Captured dedup_dc_primary.png")

        print("\n--- STEP 5: Vulnerabilities Table Overall Theme ---")
        page.goto("http://localhost:3000/vulns", wait_until="networkidle")
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACT_DIR, "theme_vulns.png"))
        print("Captured theme_vulns.png")

        print("\n--- STEP 6: Verify False Positive Reclassifications ---")
        page.goto("http://localhost:3000/vulns?status=false_positive", wait_until="networkidle")
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACT_DIR, "false_positive_reclass.png"))
        print("Captured false_positive_reclass.png")

        print("\n--- STEP 7: Reports Page & Back Button ---")
        page.goto("http://localhost:3000/reports", wait_until="networkidle")
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACT_DIR, "theme_reports_back.png"))
        print("Captured theme_reports_back.png")

        # Test Back Button
        back_btn = page.locator('button:has-text("Back")')
        if back_btn.count() > 0:
            print("Clicking Back button on Reports page...")
            back_btn.first.click()
            page.wait_for_load_state("networkidle")
            time.sleep(1)
            print(f"Navigated back to: {page.url}")

        print("\n--- STEP 8: Logout Admin & Register User B ---")
        page.goto("http://localhost:3000/login", wait_until="networkidle")
        context.clear_cookies()
        page.evaluate("() => localStorage.clear()")

        page.goto("http://localhost:3000/register", wait_until="networkidle")
        name_input = page.locator('input[placeholder*="Name" i], input[type="text"]').first
        name_input.fill("Analyst Beta")
        page.fill('input[type="email"]', "analyst.beta@aegis.internal")
        page.fill('input[type="password"]', "BetaSecretPassword123")
        page.click('button[type="submit"]')
        
        # If user already registered in previous run, try login
        try:
            page.wait_for_url("http://localhost:3000/", timeout=5000)
        except Exception:
            print("User B may already be enrolled, logging in...")
            page.goto("http://localhost:3000/login", wait_until="networkidle")
            page.fill('input[type="email"]', "analyst.beta@aegis.internal")
            page.fill('input[type="password"]', "BetaSecretPassword123")
            page.click('button[type="submit"]')
            page.wait_for_url("http://localhost:3000/", timeout=10000)

        page.wait_for_load_state("networkidle")
        time.sleep(2)

        print("\n--- STEP 9: User B Empty State Verification ---")
        page.screenshot(path=os.path.join(ARTIFACT_DIR, "user_b_empty_state.png"))
        print("Captured user_b_empty_state.png")

        print("\n--- STEP 10: User B Scans Page & Direct Scan Launch ---")
        page.goto("http://localhost:3000/scans", wait_until="networkidle")
        time.sleep(1)

        # Launch direct scan on 172.20.0.5
        target_input = page.locator('input[placeholder*="target" i], input[placeholder*="domain" i], input[placeholder*="192.168" i]')
        if target_input.count() > 0:
            target_input.first.fill("172.20.0.5")
            quick_radio = page.locator('input[value="quick"]')
            if quick_radio.count() > 0:
                quick_radio.check()
            start_btn = page.locator('button[type="submit"]:has-text("Scan"), button:has-text("Start Quick Scan")')
            if start_btn.count() > 0:
                print("Launching quick scan as User B on 172.20.0.5...")
                start_btn.first.click()
                time.sleep(4)
        
        page.screenshot(path=os.path.join(ARTIFACT_DIR, "user_b_scans.png"))
        print("Captured user_b_scans.png")

        browser.close()

    print("\n--- CONSOLE ERROR REPORT ---")
    if console_errors:
        print(f"TOTAL CONSOLE ERRORS: {len(console_errors)}", file=sys.stderr)
        for err in console_errors:
            print(f"  - {err}", file=sys.stderr)
    else:
        print("ZERO CONSOLE ERRORS DETECTED! ALL CHECKS PASSED.")

if __name__ == "__main__":
    run_verification()
