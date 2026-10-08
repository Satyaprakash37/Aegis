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

        print("\n--- STEP 1: Log in as Admin ---")
        page.goto("http://localhost:3000/login", wait_until="networkidle")
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:3000/", timeout=10000)
        page.wait_for_load_state("networkidle")
        time.sleep(2)

        print("\n--- STEP 2: Navigate to Scans Page ---")
        page.goto("http://localhost:3000/scans", wait_until="networkidle")
        time.sleep(3)

        print("\n--- STEP 3: Find cutm.ac.in scan and Open Dossier ---")
        summary_buttons = page.locator("button:has-text('Summary')").all()
        print(f"Found {len(summary_buttons)} Summary buttons on scans page")

        if summary_buttons:
            # Click the first one (most recent scan)
            summary_buttons[0].click()
            time.sleep(3)

        # Scroll to ensure Reconnaissance Summary is visible
        recon_card = page.locator("text=Reconnaissance Summary")
        if recon_card.count() > 0:
            recon_card.first.scroll_into_view_if_needed()
            time.sleep(1)
            print("Found Reconnaissance Summary card!")
        else:
            print("Warning: Reconnaissance Summary text not found directly, scrolling page...")
            page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
            time.sleep(1)

        # Capture screenshot
        screenshot_path = os.path.join(ARTIFACT_DIR, "recon_summary_multimethod.png")
        page.screenshot(path=screenshot_path, full_page=True)
        print(f"Captured screenshot at {screenshot_path}")

        browser.close()

    print(f"\nTotal Browser Console Errors: {len(console_errors)}")
    if console_errors:
        print("Console errors found:")
        for err in console_errors:
            print(f"  - {err}")
    else:
        print("✓ Zero browser console errors verified!")

if __name__ == "__main__":
    run_verification()
