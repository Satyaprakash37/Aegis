import time
import os
from pathlib import Path
from playwright.sync_api import sync_playwright

FRONTEND_URL = "http://localhost:3000"
BACKEND_URL = "http://localhost:8000"
OUTPUT_DIR = Path("/home/satya/.gemini/antigravity/scratch/aegis/video_assets")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def capture_scenes():
    print("[*] Starting Playwright 1080p Screenshot Capture Pipeline...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # Exactly 1920x1080 for crisp Full HD video rendering
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            device_scale_factor=1.0,
        )
        page = context.new_page()

        # -------------------------------------------------------------
        # 1. Login Page
        # -------------------------------------------------------------
        print("[1/8] Capturing Login Page...")
        page.goto(f"{FRONTEND_URL}/login")
        page.wait_for_selector('input[type="email"]', timeout=15000)
        time.sleep(1.0)
        page.screenshot(path=str(OUTPUT_DIR / "01_login_page.png"))
        print("[✓] Saved 01_login_page.png")

        # Perform Login
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{FRONTEND_URL}/")
        time.sleep(2.0)

        # -------------------------------------------------------------
        # 2. Dashboard with live data
        # -------------------------------------------------------------
        print("[2/8] Capturing Dashboard with live data...")
        page.wait_for_selector("text=Cybersecurity Command Center", timeout=15000)
        time.sleep(2.0)
        page.screenshot(path=str(OUTPUT_DIR / "02_dashboard.png"))
        print("[✓] Saved 02_dashboard.png")

        # -------------------------------------------------------------
        # 3. Scan initiation - typing target
        # -------------------------------------------------------------
        print("[3/8] Capturing Scan Initiation (typing target)...")
        page.click("text=Scans")
        page.wait_for_selector("text=Initiate Vulnerability Scan", timeout=15000)
        scan_input = page.locator('input[placeholder*="Enter IP, domain or URL"]')
        scan_input.click()
        # Type target cleanly with realistic speed
        scan_input.type("target-corp.internal", delay=80)
        time.sleep(1.0)
        page.screenshot(path=str(OUTPUT_DIR / "03_scan_initiation.png"))
        print("[✓] Saved 03_scan_initiation.png")

        # -------------------------------------------------------------
        # 4. Live scan progress / execution history
        # -------------------------------------------------------------
        print("[4/8] Capturing Live Scan Execution & History...")
        page.mouse.wheel(0, 420)
        time.sleep(1.2)
        page.screenshot(path=str(OUTPUT_DIR / "04_scan_progress.png"))
        print("[✓] Saved 04_scan_progress.png")

        # -------------------------------------------------------------
        # 5. Vulnerabilities table with verified badges
        # -------------------------------------------------------------
        print("[5/8] Capturing Vulnerabilities table...")
        page.click("text=Vulnerabilities")
        page.wait_for_selector("text=Identified Vulnerabilities", timeout=15000)
        time.sleep(2.0)
        page.screenshot(path=str(OUTPUT_DIR / "05_vulns_table.png"))
        print("[✓] Saved 05_vulns_table.png")

        # -------------------------------------------------------------
        # 6. Evidence drawer open (finding with real verified evidence)
        # -------------------------------------------------------------
        print("[6/8] Capturing Evidence Drawer open...")
        # Search for a verified finding or click finding with evidence
        search_box = page.locator('input[placeholder*="Search by CVE"]')
        search_box.fill("CVE-2019-11043")
        time.sleep(1.5)
        row = page.locator("tr:has-text('CVE-2019-11043')").first
        row.click()
        page.wait_for_selector("text=Active Verification Evidence & Raw Output", timeout=10000)
        time.sleep(1.5)
        page.screenshot(path=str(OUTPUT_DIR / "06_evidence_drawer.png"))
        print("[✓] Saved 06_evidence_drawer.png")

        # Close drawer
        page.click('button:has-text("Close")')
        time.sleep(1.0)

        # -------------------------------------------------------------
        # 7. Origin Infrastructure Map
        # -------------------------------------------------------------
        print("[7/8] Capturing Origin Infrastructure Map (Scan #68 dossier)...")
        page.click("text=Scans")
        page.wait_for_selector("text=Initiate Vulnerability Scan", timeout=15000)
        # Open scan #68 dossier (has origin infrastructure map with cutm.ac.in)
        scan_68_row = page.locator("tr:has-text('cutm.ac.in')").first
        scan_68_row.click()
        page.wait_for_selector("text=Origin Infrastructure Map (VHost Routing & WAF Bypass)", timeout=15000)
        # Scroll to Origin Infrastructure Map table
        origin_section = page.locator("text=Origin Infrastructure Map (VHost Routing & WAF Bypass)")
        origin_section.scroll_into_view_if_needed()
        time.sleep(1.5)
        page.screenshot(path=str(OUTPUT_DIR / "07_origin_infrastructure_map.png"))
        print("[✓] Saved 07_origin_infrastructure_map.png")

        # Close dossier
        page.click('button:has-text("Close")')
        time.sleep(1.0)

        # -------------------------------------------------------------
        # 8. PDF Report Open / Preview
        # -------------------------------------------------------------
        print("[8/8] Capturing PDF Report Open / Preview...")
        # Navigate to Reports page
        page.click("text=Reports")
        page.wait_for_selector("text=Security Reports & Compliance Export", timeout=15000)
        time.sleep(2.0)
        page.screenshot(path=str(OUTPUT_DIR / "08_pdf_report_view.png"))
        print("[✓] Saved 08_pdf_report_view.png")

        browser.close()

    print("\n[✓] All 8 real AEGIS screenshots captured successfully in 1920x1080!")

if __name__ == "__main__":
    capture_scenes()
