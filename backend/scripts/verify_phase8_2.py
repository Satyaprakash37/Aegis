import asyncio
import json
import time
import urllib.parse
import urllib.request
import urllib.error

BASE_URL = "http://localhost:8000"

def get_token():
    data = urllib.parse.urlencode({
        "username": "admin@aegis.internal",
        "password": "SuperSecretPassword123"
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/api/auth/login",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode())
        return res["access_token"]

def api_request(method, endpoint, token, data=None):
    url = f"{BASE_URL}{endpoint}"
    req_data = json.dumps(data).encode("utf-8") if data is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"detail": body}

def run_tests():
    print("=== STARTING PHASE 8.2 VERIFICATION SUITE ===")
    token = get_token()
    print("✓ Auth Token obtained")

    # TEST 4: Invalid domain
    print("\n--- Test 4: Invalid Domain Resolution (notarealdomain.fake) ---")
    st4, res4 = api_request("POST", "/api/scans/direct", token, {"target": "notarealdomain.fake", "scan_type": "quick"})
    print(f"Status: {st4}, Detail: {res4.get('detail')}")
    assert st4 == 422, f"Expected 422, got {st4}"
    assert "DNS" in str(res4.get("detail")) or "resolve" in str(res4.get("detail")), "Expected DNS resolution error message"
    print("✓ Test 4 Passed: 422 error on invalid domain with clear message")

    # TEST 5: Invalid IP address
    print("\n--- Test 5: Invalid IP Format (999.999.1.1) ---")
    st5, res5 = api_request("POST", "/api/scans/direct", token, {"target": "999.999.1.1", "scan_type": "quick"})
    print(f"Status: {st5}, Detail: {res5.get('detail')}")
    assert st5 == 422, f"Expected 422, got {st5}"
    print("✓ Test 5 Passed: 422 error on invalid IP")

    # TEST 8: Clear Demo Data (deletes seed assets like owasp-juice-shop)
    print("\n--- Test 8: Clear Demo Data (DELETE /api/assets/seed) ---")
    st_del, res_del = api_request("DELETE", "/api/assets/seed", token)
    print(f"Status: {st_del}, Response: {res_del}")
    assert st_del == 200, f"Expected 200, got {st_del}"
    print(f"Deleted {res_del.get('deleted_count')} seed assets")

    # Verify seed assets are gone
    st_list_after, res_list_after = api_request("GET", "/api/assets?page_size=100", token)
    remaining_seed = [a["name"] for a in res_list_after["data"] if a.get("is_seed")]
    assert len(remaining_seed) == 0, f"Expected 0 seed assets, found {remaining_seed}"
    print("✓ Test 8 Passed: Successfully cleared demo seed data")

    # Clean up any existing 172.20.0.5 asset so Test 1 tests fresh auto-creation
    for a in res_list_after["data"]:
        if a["ip_address"] == "172.20.0.5":
            api_request("DELETE", f"/api/assets/{a['id']}", token)

    # TEST 1: Direct scan on real container 172.20.0.5 (Now not in DB -> Auto Creates Asset!)
    print("\n--- Test 1: Direct Scan on 172.20.0.5 (Unregistered Target) ---")
    st1, res1 = api_request("POST", "/api/scans/direct", token, {"target": "172.20.0.5", "scan_type": "quick"})
    print(f"Status: {st1}, Response: {res1}")
    assert st1 in (200, 201), f"Expected 200/201, got {st1}"
    assert res1["auto_created"] is True, f"Expected auto_created=True, got {res1['auto_created']}"
    scan_id_1 = res1["scan_id"]
    asset_id_1 = res1["asset_id"]
    print(f"Auto-created Asset ID: {asset_id_1}, Dispatched Scan ID: {scan_id_1}")

    # Wait for Scan 1 to complete
    print("Waiting for quick scan on 172.20.0.5 to complete...")
    for _ in range(35):
        time.sleep(2)
        st_s, res_s = api_request("GET", f"/api/scans/{scan_id_1}", token)
        status = res_s.get("status")
        print(f"Scan status: {status}")
        if status in ("completed", "failed"):
            break

    assert status == "completed", f"Scan did not complete successfully, status: {status}"
    raw_out = res_s.get("raw_output") or {}
    open_ports = [f"{p['port']}/{p['service']}" for p in raw_out.get("ports", [])]
    print(f"Scan completed! Discovered open ports: {open_ports}")
    assert len(open_ports) > 0, "Expected open ports to be found on 172.20.0.5"
    print("✓ Test 1 Passed: Auto-created asset, completed quick scan, ports discovered")

    # TEST 2: Same target again -> Reuses Asset
    print("\n--- Test 2: Repeat Direct Scan on Same Target (172.20.0.5) ---")
    st2, res2 = api_request("POST", "/api/scans/direct", token, {"target": "172.20.0.5", "scan_type": "quick"})
    print(f"Status: {st2}, Response: {res2}")
    assert st2 in (200, 201), f"Expected 200/201, got {st2}"
    assert res2["asset_id"] == asset_id_1, f"Expected asset reuse ({asset_id_1}), got {res2['asset_id']}"
    assert res2["auto_created"] is False, "Expected auto_created=False on reused existing asset"
    print(f"✓ Test 2 Passed: Successfully reused asset {asset_id_1} without duplication")

    # TEST 9: Smart Asset Type Detection on 172.20.0.5
    print("\n--- Test 9: Smart Asset Type Detection ---")
    st_a, res_a = api_request("GET", f"/api/assets/{asset_id_1}", token)
    print(f"Asset 172.20.0.5 details: Name: {res_a['name']}, Type: {res_a['asset_type']}, AutoCreated: {res_a['auto_created']}")
    assert res_a["auto_created"] is True, "Expected auto_created=True"
    assert res_a["asset_type"] == "web", f"Expected asset_type='web' due to port 3000, got {res_a['asset_type']}"
    print("✓ Test 9 Passed: Smart asset type classified as 'web'")

    # TEST 3: Domain target
    print("\n--- Test 3: Domain Target Direct Scan (google.com) ---")
    st3, res3 = api_request("POST", "/api/scans/direct", token, {"target": "google.com", "scan_type": "quick"})
    print(f"Status: {st3}, Response: {res3}")
    assert st3 in (200, 201), f"Expected 200/201, got {st3}"
    assert res3["target_type"] == "domain", f"Expected domain target type, got {res3['target_type']}"
    print(f"✓ Test 3 Passed: Successfully resolved and launched scan for google.com (Asset ID {res3['asset_id']})")

    print("\n==========================================")
    print("ALL TEST CASES PASSED SUCCESSFULLY!")
    print("==========================================")

if __name__ == "__main__":
    run_tests()
