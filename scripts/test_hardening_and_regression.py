"""Verification test script for AEGIS Phase 7 Security Hardening & Regression.
"""

import sys
import requests

BASE_URL = "http://localhost:8000"

def test_security_headers():
    print("[TEST] Verifying Security Headers...")
    r = requests.get(f"{BASE_URL}/docs")
    headers = r.headers
    assert "X-Content-Type-Options" in headers, "Missing X-Content-Type-Options"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "X-Frame-Options" in headers, "Missing X-Frame-Options"
    assert headers["X-Frame-Options"] == "DENY"
    assert "X-XSS-Protection" in headers, "Missing X-XSS-Protection"
    assert "Referrer-Policy" in headers, "Missing Referrer-Policy"
    print("  -> PASS: All security headers verified (nosniff, DENY, XSS-Protection, Referrer-Policy)")

def test_account_lockout():
    import time
    print("[TEST] Verifying Account Lockout Policy (5 failed attempts -> lockout)...")
    email = f"lockout_test_{int(time.time())}@aegis.internal"
    
    # 1. Register test user
    requests.post(f"{BASE_URL}/api/auth/register", json={
        "email": email,
        "password": "ValidPassword123!",
        "full_name": "Lockout Target"
    })
    
    # 2. Attempt 4 wrong passwords (should return 401)
    for i in range(1, 5):
        resp = requests.post(f"{BASE_URL}/api/auth/login", data={"username": email, "password": f"wrong_{i}"})
        assert resp.status_code == 401, f"Attempt {i} expected 401, got {resp.status_code}"
    print("  -> 4 failed attempts returned 401 as expected.")
    
    # 3. 5th wrong password should return 403 (Account temporarily locked)
    resp5 = requests.post(f"{BASE_URL}/api/auth/login", data={"username": email, "password": "wrong_5"})
    assert resp5.status_code == 403, f"5th attempt expected 403, got {resp5.status_code}"
    assert "Account temporarily locked" in resp5.text or "locked" in resp5.text.lower()
    print("  -> PASS: Account locked on 5th failure with HTTP 403.")

def test_rate_limiting():
    print("[TEST] Verifying Rate Limiting on Auth Endpoints...")
    # Make rapid requests to /api/auth/login
    limit_hit = False
    for i in range(120):
        resp = requests.post(f"{BASE_URL}/api/auth/login", data={"username": "rl@aegis.internal", "password": "p"})
        if resp.status_code == 429:
            limit_hit = True
            print(f"  -> PASS: Rate limiter intercepted flood at request #{i+1} with HTTP 429.")
            break
    assert limit_hit, "Rate limit of 100/min on /api/auth/login was not triggered after 120 calls"

def test_seeded_data_and_summary():
    print("[TEST] Verifying Seeded Telemetry & Dashboard Analytics...")
    # Login as admin
    login_resp = requests.post(f"{BASE_URL}/api/auth/login", data={
        "username": "admin@aegis.internal",
        "password": "SuperSecretPassword123"
    })
    assert login_resp.status_code == 200, f"Admin login failed: {login_resp.text}"
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Dashboard summary
    dash_resp = requests.get(f"{BASE_URL}/api/dashboard/summary", headers=headers)
    assert dash_resp.status_code == 200, f"Dashboard summary failed: {dash_resp.text}"
    summary = dash_resp.json().get("data", {})
    print(f"  -> Total Assets: {summary.get('total_assets')}")
    print(f"  -> Total Vulns: {summary.get('total_vulnerabilities')}")
    print(f"  -> Critical/High Count: {summary.get('critical_high_count')}")
    print(f"  -> Open Vulns: {summary.get('open_vulns')}")
    print(f"  -> Mitigated Vulns: {summary.get('mitigated_vulns')}")
    assert summary.get("total_assets") >= 8, "Expected at least 8 assets"
    assert summary.get("total_vulnerabilities") >= 16, "Expected at least 16 vulnerabilities"
    
    # Vulns list
    vulns_resp = requests.get(f"{BASE_URL}/api/vulns?page=1&page_size=50", headers=headers)
    assert vulns_resp.status_code == 200
    vulns_data = vulns_resp.json()
    print(f"  -> Retrieved {len(vulns_data.get('data', []))} vulnerabilities with risk scores.")
    assert len(vulns_data.get("data", [])) >= 16
    print("  -> PASS: Telemetry and dashboard metrics match seed expectations.")

if __name__ == "__main__":
    try:
        test_security_headers()
        test_account_lockout()
        test_seeded_data_and_summary()
        test_rate_limiting()
        print("\n ALL HARDENING & BACKEND REGRESSION TESTS PASSED SUCCESSFULLY!")
    except Exception as e:
        print(f"\n[FAIL] Test failed: {e}")
        sys.exit(1)
