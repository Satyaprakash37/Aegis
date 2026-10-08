#!/usr/bin/env python3
"""Phase 8.9 Comprehensive Security Hardening Audit Verification Suite.

Tests 8 critical security controls:
1. SQL injection attempt on search/sort parameter -> HTTP 422
2. Command injection attempt via scan target -> HTTP 400/422
3. Weak password rejected at registration -> HTTP 422
4. Disposable email domain rejected at registration -> HTTP 422
5. IDOR: User B attempting to access User A's private asset -> HTTP 404
6. Oversized request payload (> 1MB) -> HTTP 413
7. Tightened rate limiting: 11th login attempt within 1 min -> HTTP 429
8. Path traversal on report download -> HTTP 404
"""

import sys
import time
import requests

BASE_URL = "http://localhost:8000"
FRONTEND_URL = "http://localhost:3000"

results = []

def record(test_num, name, passed, detail):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] Test {test_num}: {name} - {detail}")
    results.append({"test": test_num, "name": name, "passed": passed, "detail": detail})

def main():
    print("==================================================")
    print(" AEGIS PHASE 8.9 SECURITY HARDENING AUDIT SUITE   ")
    print("==================================================")

    # 0. Authenticate Admin and Analyst accounts
    print("\n[*] Authenticating test users...")
    admin_login = requests.post(f"{BASE_URL}/api/auth/login", data={
        "username": "admin@aegis.internal",
        "password": "SuperSecretPassword123"
    })
    if admin_login.status_code != 200:
        print(f"[-] Admin login failed ({admin_login.status_code}): {admin_login.text}")
        sys.exit(1)
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print("[+] Admin authenticated successfully.")

    # 1. SQL Injection Attempt on search / sort params
    print("\n[*] Testing Case 1: SQL Injection attempt on sort_by / order...")
    sqli_payloads = [
        "name; DROP TABLE assets;--",
        "criticality UNION SELECT null, null, null--",
        "' OR '1'='1",
        "SLEEP(5)"
    ]
    all_sqli_blocked = True
    sqli_details = []
    for payload in sqli_payloads:
        r = requests.get(
            f"{BASE_URL}/api/assets",
            params={"sort_by": payload, "order": "asc"},
            headers=admin_headers
        )
        if r.status_code == 422:
            sqli_details.append(f"'{payload}' -> 422 Unprocessable Entity (Whitelisted)")
        else:
            all_sqli_blocked = False
            sqli_details.append(f"'{payload}' -> {r.status_code} (FAILED)")

    record(1, "SQL Injection on Sort/Filter Parameters", all_sqli_blocked, "; ".join(sqli_details))

    # 2. Command Injection via Scan Target
    print("\n[*] Testing Case 2: Command injection attempt via scan target...")
    cmd_payloads = [
        "8.8.8.8; rm -rf /",
        "127.0.0.1 && cat /etc/passwd",
        "`id`",
        "$(whoami).com",
        "169.254.169.254"  # SSRF cloud metadata
    ]
    all_cmd_blocked = True
    cmd_details = []
    for target in cmd_payloads:
        r = requests.post(
            f"{BASE_URL}/api/scans/direct",
            json={"target": target, "scan_type": "quick"},
            headers=admin_headers
        )
        # Should be rejected with 400 Bad Request or 422 Unprocessable Entity
        if r.status_code in [400, 422]:
            err_msg = r.json().get("detail", "")
            cmd_details.append(f"'{target}' -> {r.status_code} ({err_msg})")
        else:
            all_cmd_blocked = False
            cmd_details.append(f"'{target}' -> {r.status_code} (FAILED)")

    record(2, "Command Injection & SSRF Target Protection", all_cmd_blocked, "; ".join(cmd_details))

    # 3. Weak Password Rejection at Registration
    print("\n[*] Testing Case 3: Weak password policy enforcement...")
    weak_passwords = [
        "short",  # <12 chars
        "password123456",  # no uppercase, no symbol, dictionary pattern
        "ALLUPPERCASE123!",  # no lowercase
        "alllowercase123!",  # no uppercase
        "NoDigitsHere!!!!",  # no digits
        "NoSpecialChar1234"   # no special char
    ]
    all_weak_blocked = True
    weak_details = []
    for wp in weak_passwords:
        r = requests.post(
            f"{BASE_URL}/api/auth/register",
            json={
                "email": f"test_weak_{time.time()}@aegis-secops.org",
                "password": wp,
                "full_name": "Weak Test User"
            }
        )
        if r.status_code == 422:
            weak_details.append(f"'{wp}' -> 422 Rejected")
        else:
            all_weak_blocked = False
            weak_details.append(f"'{wp}' -> {r.status_code} (FAILED)")

    record(3, "Weak Password Policy Enforcement", all_weak_blocked, "; ".join(weak_details))

    # 4. Disposable Email Domain Rejection at Registration
    print("\n[*] Testing Case 4: Disposable email domain rejection...")
    disposable_emails = [
        "auditor@tempmail.com",
        "auditor@10minutemail.com",
        "auditor@guerrillamail.com",
        "auditor@mailinator.com"
    ]
    all_disp_blocked = True
    disp_details = []
    for de in disposable_emails:
        r = requests.post(
            f"{BASE_URL}/api/auth/register",
            json={
                "email": de,
                "password": "Str0ngSecOps#2026!X",
                "full_name": "Disposable Email Tester"
            }
        )
        if r.status_code in [400, 422]:
            disp_details.append(f"'{de}' -> {r.status_code} Rejected")
        else:
            all_disp_blocked = False
            disp_details.append(f"'{de}' -> {r.status_code} (FAILED)")

    record(4, "Disposable Email Blocklist Enforcement", all_disp_blocked, "; ".join(disp_details))

    # 5. IDOR Protection: User B accessing User A's private asset
    print("\n[*] Testing Case 5: IDOR Protection across tenants...")
    # Admin creates a private asset
    asset_res = requests.post(
        f"{BASE_URL}/api/assets",
        json={
            "name": f"Admin-Private-Vault-{int(time.time())}",
            "ip_address": f"10.0.99.{int(time.time()) % 200 + 10}",
            "asset_type": "server",
            "environment": "production",
            "criticality": 5,
            "owner": "Admin"
        },
        headers=admin_headers
    )
    if asset_res.status_code != 201:
        print(f"[-] Failed to create test asset for IDOR: {asset_res.text}")
        sys.exit(1)
    admin_asset_id = asset_res.json()["id"]

    # Register/Login Analyst User B
    b_email = f"user_b_idor_{int(time.time())}@aegis-corp.net"
    reg_b = requests.post(f"{BASE_URL}/api/auth/register", json={
        "email": b_email,
        "password": "Str0ngSecOps#2026!X",
        "full_name": "User B Analyst"
    })
    login_b = requests.post(f"{BASE_URL}/api/auth/login", data={
        "username": b_email,
        "password": "Str0ngSecOps#2026!X"
    })
    if login_b.status_code != 200:
        print(f"[-] User B login failed: {login_b.status_code} {login_b.text}")
        sys.exit(1)
    b_token = login_b.json()["access_token"]
    b_headers = {"Authorization": f"Bearer {b_token}"}

    # User B attempts to access Admin's asset
    idor_get = requests.get(f"{BASE_URL}/api/assets/{admin_asset_id}", headers=b_headers)
    idor_put = requests.put(f"{BASE_URL}/api/assets/{admin_asset_id}", json={"name": "Hacked Asset"}, headers=b_headers)
    idor_del = requests.delete(f"{BASE_URL}/api/assets/{admin_asset_id}", headers=b_headers)

    idor_passed = (idor_get.status_code == 404 and idor_put.status_code == 404 and idor_del.status_code == 404)
    record(
        5,
        "Insecure Direct Object Reference (IDOR) Isolation",
        idor_passed,
        f"GET -> {idor_get.status_code}, PUT -> {idor_put.status_code}, DELETE -> {idor_del.status_code} (All 404 Not Found)"
    )

    # 6. Oversized Payload Rejection (> 1MB)
    print("\n[*] Testing Case 6: Payload size limit middleware (max 1MB)...")
    large_payload = {"name": "A" * (1024 * 1024 + 100), "ip_address": "10.0.0.1", "asset_type": "server", "environment": "production", "criticality": 1}
    r_large = requests.post(f"{BASE_URL}/api/assets", json=large_payload, headers=admin_headers)
    payload_passed = (r_large.status_code == 413)
    record(6, "Request Body Size Limit (Max 1MB)", payload_passed, f"Oversized body -> HTTP {r_large.status_code} ({r_large.json() if r_large.headers.get('content-type') == 'application/json' else r_large.text[:100]})")

    # 7. Rate Limit Tightening: 11th login attempt within 1 min -> 429
    print("\n[*] Testing Case 7: Rate limiting on authentication (10/min)...")
    rate_limited = False
    status_codes = []
    # Rapid login attempts
    for i in range(12):
        r_rl = requests.post(f"{BASE_URL}/api/auth/login", data={
            "username": f"attacker_{i}@nonexistent.org",
            "password": "InvalidPassword123!"
        })
        status_codes.append(r_rl.status_code)
        if r_rl.status_code == 429:
            rate_limited = True
            break
        time.sleep(0.05)

    record(7, "Strict Login Rate Limiting (10/min)", rate_limited, f"StatusCodes: {status_codes}")

    # 8. Path Traversal on Report Download -> 404
    print("\n[*] Testing Case 8: Path traversal protection on report download...")
    traversal_paths = [
        f"{BASE_URL}/api/reports/../../etc/passwd/download",
        f"{BASE_URL}/api/reports/99999999/download",
        f"{BASE_URL}/api/reports/-1/download"
    ]
    all_traversal_blocked = True
    traversal_details = []
    for url in traversal_paths:
        r_trav = requests.get(url, headers=admin_headers)
        if r_trav.status_code in [404, 422]:
            traversal_details.append(f"{url.split('reports/')[1]} -> {r_trav.status_code} Blocked")
        else:
            all_traversal_blocked = False
            traversal_details.append(f"{url} -> {r_trav.status_code} (FAILED)")

    record(8, "Path Traversal & Arbitrary File Access Defense", all_traversal_blocked, "; ".join(traversal_details))

    # Summary
    print("\n==================================================")
    print("                 AUDIT SUMMARY                    ")
    print("==================================================")
    all_passed = all(r["passed"] for r in results)
    for r in results:
        sym = "✓" if r["passed"] else "✗"
        print(f"[{sym}] Test {r['test']}: {r['name']}")

    if all_passed:
        print("\n[SUCCESS] ALL 8 SECURITY AUDIT CONTROLS PASSED RIGOROUSLY!")
        sys.exit(0)
    else:
        print("\n[FAIL] ONE OR MORE SECURITY CONTROLS FAILED AUDIT.")
        sys.exit(1)

if __name__ == "__main__":
    main()
