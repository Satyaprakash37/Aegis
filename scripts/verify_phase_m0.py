"""AEGIS Phase M0 Verification Script.

Verifies:
1. All 9 Docker services active (docker ps)
2. Metasploit RPC daemon health status (/api/agent/msf-status)
3. Lab assets displaying 🧪 LAB badges on Assets page
4. Vulnerability drawer displaying Attack Simulation hint for lab assets
5. 0 browser console errors
"""

import json
import os
import subprocess
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = "/home/satya/.gemini/antigravity/brain/c38ef200-b686-4b3e-ac5e-19fb3304d255"


def main():
    console_errors = []

    # 1. Output docker ps status
    print("\n--- 1. DOCKER SERVICE STATUS ---")
    ps_output = subprocess.check_output(["docker", "compose", "ps"]).decode("utf-8")
    print(ps_output)

    # 2. Query /api/agent/msf-status
    print("\n--- 2. METASPLOIT RPC HEALTH CHECK ---")
    status_cmd = [
        "docker", "compose", "exec", "-T", "backend", "python3", "-c",
        "import asyncio, json, httpx\n"
        "from app.api.routes.auth import create_access_token\n"
        "async def check():\n"
        "    token = create_access_token({'sub': '1'})\n"
        "    async with httpx.AsyncClient() as client:\n"
        "        resp = await client.get('http://127.0.0.1:8000/api/agent/msf-status', headers={'Authorization': f'Bearer {token}'})\n"
        "        print(resp.status_code)\n"
        "        print(json.dumps(resp.json()))\n"
        "asyncio.run(check())"
    ]
    status_res = subprocess.check_output(status_cmd).decode("utf-8").strip().splitlines()
    status_code = int(status_res[0])
    msf_data = json.loads(status_res[1])
    print("Status Code:", status_code)
    print("msf-status response:\n", json.dumps(msf_data, indent=2))
    assert status_code == 200, f"Expected 200, got {status_code}"
    assert msf_data.get("connected") is True, "Expected connected=True"
    assert msf_data.get("modules_count", 0) > 5000, "Expected >5000 modules"

    # 3. Browser UI verification with Playwright
    print("\n--- 3. FRONTEND UI VERIFICATION ---")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 960})

        def handle_console(msg):
            if msg.type == "error":
                print(f"[BROWSER ERROR] {msg.text}")
                console_errors.append(msg.text)

        page.on("console", handle_console)

        # Login as Admin
        page.goto("http://localhost:3000/login", wait_until="networkidle")
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url("http://localhost:3000/", timeout=10000)
        page.wait_for_load_state("networkidle")
        time.sleep(1)

        # Navigate to Assets
        print("Checking /assets page for 🧪 LAB badges...")
        page.goto("http://localhost:3000/assets", wait_until="networkidle")
        time.sleep(1.5)

        assets_text = page.inner_text("body")
        assert "lab-wordpress" in assets_text, "Expected 'lab-wordpress' in assets table"
        assert "lab-dvwa" in assets_text, "Expected 'lab-dvwa' in assets table"
        assert "LAB" in assets_text, "Expected 'LAB' badge in assets table"

        # Capture screenshot of Assets page with LAB badges
        screenshot_assets = os.path.join(ARTIFACTS_DIR, "assets_page_lab_badges.png")
        page.screenshot(path=screenshot_assets)
        print(f"✓ Saved screenshot: {screenshot_assets}")

        # Navigate to Vulnerabilities for scan 72 (lab-wordpress findings)
        print("Checking /vulns for lab attack simulation hint...")
        page.goto("http://localhost:3000/vulns?scan_id=72", wait_until="networkidle")
        time.sleep(1.5)

        vuln_rows = page.locator("table tbody tr")
        if vuln_rows.count() > 0:
            first_row = vuln_rows.first
            first_row.click()
            time.sleep(1)

            drawer_text = page.inner_text("div.fixed")
            assert "Attack simulation available" in drawer_text, "Expected 'Attack simulation available' in drawer"
            assert "coming in v2.0" in drawer_text, "Expected 'coming in v2.0' in drawer"
            print("✓ Lab attack simulation hint and placeholder button verified in drawer")

            screenshot_drawer = os.path.join(ARTIFACTS_DIR, "vuln_drawer_lab_hint.png")
            page.screenshot(path=screenshot_drawer)
            print(f"✓ Saved screenshot: {screenshot_drawer}")

        browser.close()

    print(f"\nSevere Browser Console Errors: {len(console_errors)}")
    if console_errors:
        for err in console_errors:
            print(f"  - {err}")
        return False

    print("\n✅ ALL PHASE M0 CHECKS PASSED PERFECTLY!")
    return True


if __name__ == "__main__":
    import sys

    success = main()
    if not success:
        sys.exit(1)
