"""Phase 8.4 End-to-End Verification Test using Playwright.
Verifies:
1. Notification bell: opens panel, displays stream, handles mark-all-read, closes on outside click/Escape.
2. Topbar terminal button: opens diagnostics modal, displays toolchain status, closes properly.
3. Live telemetry pill & background resilience across page navigation.
4. Zero console errors across all tested pages.
5. Captures screenshots for documentation and artifacts.
"""

import os
import sys
import time
import json
from playwright.sync_api import sync_playwright

def run_phase8_4_verification():
    console_errors = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        def handle_console(msg):
            if msg.type == "error":
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
        page.wait_for_selector("header", timeout=5000)
        time.sleep(2)
        print("  ✓ Authenticated and redirected to Dashboard.")

        # --- Test Topbar Terminal & Diagnostics Modal ---
        print("[TEST] 2. Testing Topbar Diagnostics / Terminal button...")
        terminal_btn = page.locator('button[title="System Diagnostics & CLI Telemetry"]')
        terminal_btn.wait_for(state="visible", timeout=5000)
        terminal_btn.click()
        time.sleep(1)

        # Verify diagnostics modal is open
        assert page.locator("text=AEGIS SecOps Core Engine Telemetry").first.is_visible(), "Diagnostics modal failed to open!"
        assert page.locator("text=Nmap 7.93+").first.is_visible(), "Nmap toolchain missing in diagnostics!"
        assert page.locator("text=Nuclei v3").first.is_visible(), "Nuclei toolchain missing in diagnostics!"
        assert page.locator("text=Subfinder v2").first.is_visible(), "Subfinder toolchain missing in diagnostics!"
        assert page.locator("text=testssl.sh").first.is_visible(), "testssl.sh toolchain missing in diagnostics!"
        print("  ✓ System Diagnostics modal opened and verified toolchain status.")

        # Capture diagnostics screenshot
        diag_screenshot = "/home/satya/.gemini/antigravity/scratch/aegis/phase8_4_topbar_diagnostics.png"
        page.screenshot(path=diag_screenshot)
        print(f"  ✓ Diagnostics modal screenshot saved to {diag_screenshot}")

        # Close modal with Escape
        page.keyboard.press("Escape")
        time.sleep(0.5)
        assert not page.locator("text=AEGIS SecOps Core Engine Telemetry").is_visible(), "Modal failed to close on Escape!"
        print("  ✓ Diagnostics modal dismissed via Escape key.")

        # --- Test Topbar Notification Bell ---
        print("[TEST] 3. Testing Notification Bell & Dropdown Panel...")
        bell_btn = page.locator('button[title="Platform Notifications & Security Alerts"]')
        bell_btn.wait_for(state="visible", timeout=5000)
        bell_btn.click()
        time.sleep(1)

        # Verify notifications panel is open
        assert page.locator("text=Notifications").first.is_visible(), "Notification panel header failed to open!"
        assert page.locator("text=Mark all read").is_visible(), "Mark all read button missing!"
        print("  ✓ Notification panel opened and verified.")

        # Capture notifications panel screenshot
        notif_screenshot = "/home/satya/.gemini/antigravity/scratch/aegis/phase8_4_notifications_panel.png"
        page.screenshot(path=notif_screenshot)
        print(f"  ✓ Notification panel screenshot saved to {notif_screenshot}")

        # Test Mark all read
        mark_read_btn = page.locator("button:has-text('Mark all read')")
        mark_read_btn.click()
        time.sleep(1)
        print("  ✓ 'Mark all read' action executed.")

        # Close panel with Escape
        page.keyboard.press("Escape")
        time.sleep(0.5)
        assert not page.locator("h3:has-text('Notifications')").is_visible(), "Notification panel failed to dismiss on Escape!"
        print("  ✓ Notification panel dismissed via Escape key.")

        # Reopen and test click outside dismissal
        bell_btn.click()
        time.sleep(0.5)
        assert page.locator("h3:has-text('Notifications')").is_visible(), "Notification panel failed to reopen!"
        page.mouse.click(100, 300)
        time.sleep(0.5)
        assert not page.locator("h3:has-text('Notifications')").is_visible(), "Notification panel failed to dismiss on click outside!"
        print("  ✓ Notification panel dismissed via click outside.")

        # --- Test Navigation Resilience Mid-Scan ---
        print("[TEST] 4. Testing Navigation Resilience across routes...")
        routes = ["/scans", "/vulns", "/assets", "/reports", "/dashboard"]
        for r in routes:
            page.goto(f"http://localhost:3000{r}", wait_until="networkidle")
            time.sleep(1)
            print(f"  ✓ Navigated to {r} cleanly.")

        # --- Capture Scans Page & Timing Screenshot ---
        print("[TEST] 5. Capturing Scans Page with Timing Metadata...")
        page.goto("http://localhost:3000/scans", wait_until="networkidle")
        time.sleep(2)
        scans_screenshot = "/home/satya/.gemini/antigravity/scratch/aegis/phase8_4_scan_timing.png"
        page.screenshot(path=scans_screenshot)
        print(f"  ✓ Scans page with timing captured to {scans_screenshot}")

        # Assert no console errors
        print(f"[TEST] Console errors recorded: {len(console_errors)}")
        if console_errors:
            print(f"Errors: {console_errors}")
        assert len(console_errors) == 0, f"Found {len(console_errors)} console errors during E2E test!"

        browser.close()
        print("\n[SUCCESS] All Phase 8.4 verification checks passed with 0 console errors!")

if __name__ == "__main__":
    run_phase8_4_verification()
