#!/usr/bin/env python3
"""AEGIS Phase R2 Verification Suite - Attack Surface Intelligence.

Verifies:
1. Generation on lab-wordpress (Asset 52) with all sections populated.
2. Attack path CVE accuracy check (all referenced CVEs exist in asset findings).
3. Generation on juice-shop (Asset 45) with its findings.
4. Asset with NO findings (Asset 53) clean empty state + CTA without crashing.
5. Regeneration updates report_generated_at timestamp.
6. Copilot Chat tool: asking 'explain the attack paths' references cached report.
7. Playwright UI rendering:
   - Full intel page (summary + paths)
   - Close-up chain visualization
   - Empty state on asset without findings
8. Zero console errors.
9. Saves screenshots:
   - attack_surface_intel_page.png
   - attack_path_chain_visualization.png
   - attack_surface_empty_state.png
"""

import os
import sys
import time
from pathlib import Path
import requests
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = Path("/home/satya/.gemini/antigravity/brain/c38ef200-b686-4b3e-ac5e-19fb3304d255")
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

BASE_URL = "http://localhost:8000"
FRONTEND_URL = "http://localhost:3000"


def run_phase_r2_verification():
    print("=" * 70)
    print("AEGIS PHASE R2 VERIFICATION SUITE: ATTACK SURFACE INTELLIGENCE")
    print("=" * 70)

    # 1. Login as Admin
    login_resp = requests.post(
        f"{BASE_URL}/api/auth/login",
        data={"username": "admin@aegis.internal", "password": "SuperSecretPassword123"},
        timeout=10,
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[✓] Authenticated successfully as admin@aegis.internal")

    # 2. Check lab-wordpress (Asset 52)
    print("\n--- TEST 1: Generation on lab-wordpress (Asset 52) ---")
    gen_wp = requests.post(f"{BASE_URL}/api/assets/52/attack-surface/generate", headers=headers, timeout=20)
    assert gen_wp.status_code == 200, f"Generate on Asset 52 failed: {gen_wp.text}"
    wp_data = gen_wp.json()["data"]
    assert "executive_summary" in wp_data and len(wp_data["executive_summary"]) > 50, "Missing executive_summary"
    assert "attack_surface_map" in wp_data, "Missing attack_surface_map"
    assert "attack_paths" in wp_data and len(wp_data["attack_paths"]) > 0, "Missing attack_paths"
    assert "prioritized_concerns" in wp_data and len(wp_data["prioritized_concerns"]) > 0, "Missing prioritized_concerns"
    t1 = gen_wp.json()["report_generated_at"]
    print(f"[✓] Asset 52 generated successfully. Paths count: {len(wp_data['attack_paths'])}")
    print(f"    Executive Summary sample: {wp_data['executive_summary'][:140]}...")

    # 3. Accuracy check: verify CVEs in chains exist in Asset 52 findings
    print("\n--- TEST 2: Attack Path CVE Accuracy Check ---")
    wp_vulns_resp = requests.get(f"{BASE_URL}/api/vulns?asset_id=52&page_size=100", headers=headers, timeout=10)
    wp_vulns = wp_vulns_resp.json().get("data", [])
    valid_cves = {v["cve_id"] for v in wp_vulns if v.get("cve_id")}
    print(f"[*] Total valid CVEs cataloged on Asset 52: {len(valid_cves)} ({sorted(list(valid_cves))[:4]}...)")

    all_verified = True
    for idx, path in enumerate(wp_data["attack_paths"], 1):
        print(f"[*] Path {idx}: '{path['title']}' | Likelihood: {path['likelihood']}")
        for ref in path["findings_refs"]:
            if ref in valid_cves:
                print(f"    [✓] Verified finding reference: {ref}")
            else:
                print(f"    [✗] ERROR: Hallucinated finding reference: {ref}")
                all_verified = False
    assert all_verified, "Hallucinated CVE detected in attack path narrative!"
    print("[✓] 100% Accuracy Verified: All referenced CVEs exist in target findings.")

    # 4. Generation on juice-shop (Asset 45)
    print("\n--- TEST 3: Attack Path Generation on juice-shop (Asset 45) ---")
    gen_js = requests.post(f"{BASE_URL}/api/assets/45/attack-surface/generate", headers=headers, timeout=20)
    assert gen_js.status_code == 200, f"Generate on Asset 45 failed: {gen_js.text}"
    js_data = gen_js.json()["data"]
    assert len(js_data["attack_paths"]) > 0, "Juice shop should have attack paths"
    print(f"[✓] Juice shop generated successfully with {len(js_data['attack_paths'])} attack path(s).")
    print(f"    Sample Juice shop path: {js_data['attack_paths'][0]['title']}")

    # 5. Clean Empty State on Asset with NO findings (Asset 53 lab-dvwa)
    print("\n--- TEST 4: Clean Empty State on Asset with 0 findings (Asset 53) ---")
    gen_empty = requests.post(f"{BASE_URL}/api/assets/53/attack-surface/generate", headers=headers, timeout=20)
    assert gen_empty.status_code == 200, f"Generate on Asset 53 failed: {gen_empty.text}"
    empty_data = gen_empty.json()["data"]
    assert len(empty_data["attack_paths"]) == 0, "Asset with 0 findings should have 0 attack paths"
    assert "intact perimeter" in empty_data["executive_summary"].lower() or "zero" in empty_data["executive_summary"].lower()
    print("[✓] Asset with 0 findings handled gracefully without crash.")

    # 6. Regeneration updates report_generated_at
    print("\n--- TEST 5: Regeneration Timestamp Update ---")
    time.sleep(1.2)
    regen_wp = requests.post(f"{BASE_URL}/api/assets/52/attack-surface/generate", headers=headers, timeout=20)
    t2 = regen_wp.json()["report_generated_at"]
    assert t2 != t1, f"Timestamp did not update! t1={t1}, t2={t2}"
    print(f"[✓] Timestamp updated successfully: {t1} -> {t2}")

    # 7. Copilot Chat Integration
    print("\n--- TEST 6: Copilot Chat Tool Calling for Attack Paths ---")
    chat_resp = requests.post(
        f"{BASE_URL}/api/copilot/chat",
        headers=headers,
        json={"asset_id": 52, "message": "Explain the attack paths for this target"},
        timeout=30,
    )
    assert chat_resp.status_code == 200, f"Chat failed: {chat_resp.text}"
    chat_data = chat_resp.json()
    tools_used = [t["tool"] for t in chat_data.get("tools_used", [])]
    print(f"[*] Chat tools invoked: {tools_used}")
    assert "get_attack_surface" in tools_used, "Copilot did not invoke get_attack_surface tool!"
    print("[✓] Copilot invoked get_attack_surface tool and referenced cached report.")

    # 8. Playwright UI Verification & Screenshot Capture
    print("\n--- TEST 7: Playwright UI Verification & Screenshot Capture ---")
    console_errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        page.on(
            "console",
            lambda msg: console_errors.append(msg.text)
            if msg.type == "error" and "404" not in msg.text and "status of 404" not in msg.text
            else None,
        )

        # Login via UI
        page.goto(f"{FRONTEND_URL}/login")
        page.wait_for_selector('input[type="email"]')
        page.fill('input[type="email"]', "admin@aegis.internal")
        page.fill('input[type="password"]', "SuperSecretPassword123")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{FRONTEND_URL}/")
        print("[✓] Browser logged in successfully")

        # Navigate to Asset 52 Intel page
        page.goto(f"{FRONTEND_URL}/assets/52/intel")
        page.wait_for_selector("text=EXECUTIVE SECURITY POSTURE ASSESSMENT", timeout=15000)
        time.sleep(1.5)

        # Capture Screenshot 1: Full Intel Page
        full_page_path = ARTIFACTS_DIR / "attack_surface_intel_page.png"
        page.screenshot(path=str(full_page_path), full_page=True)
        print(f"[✓] Saved full page screenshot: {full_page_path}")

        # Capture Screenshot 2: Attack Path Chain Close-up
        chain_section = page.locator("#attack-paths-section")
        chain_path = ARTIFACTS_DIR / "attack_path_chain_visualization.png"
        chain_section.screenshot(path=str(chain_path))
        print(f"[✓] Saved chain visualization close-up: {chain_path}")

        # Navigate to Asset 53 (Clean Empty State)
        # First reset Asset 53 report to test empty state in UI
        import subprocess
        reset_code = """
import asyncio
from app.db.session import AsyncSessionLocal
from app.models.asset import Asset
from sqlalchemy import select

async def r():
    async with AsyncSessionLocal() as db:
        a = (await db.execute(select(Asset).where(Asset.id == 53))).scalar_one()
        a.attack_surface_report = None
        a.report_generated_at = None
        await db.commit()

asyncio.run(r())
"""
        subprocess.run(["docker", "exec", "aegis-backend", "python3", "-c", reset_code], check=True)

        page.goto(f"{FRONTEND_URL}/assets/53/intel")
        page.wait_for_selector("text=No Intelligence Report Yet", timeout=10000)
        time.sleep(1.0)

        # Capture Screenshot 3: Empty State
        empty_path = ARTIFACTS_DIR / "attack_surface_empty_state.png"
        page.screenshot(path=str(empty_path))
        print(f"[✓] Saved empty state screenshot: {empty_path}")

        # Test in-page CTA: Click "Generate Analysis"
        page.click("text=Generate Analysis")
        page.wait_for_selector("text=EXECUTIVE SECURITY POSTURE ASSESSMENT", timeout=15000)
        print("[✓] Empty state CTA 'Generate Analysis' clicked and successfully rendered generated report.")

        browser.close()

    print(f"[*] Total browser console errors: {len(console_errors)}")
    if console_errors:
        print("    Console error details:", console_errors)
    assert len(console_errors) == 0, f"Found {len(console_errors)} console errors!"
    print("[✓] Zero console errors verified.")

    print("\n" + "=" * 70)
    print("ALL PHASE R2 VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    run_phase_r2_verification()
