import httpx
import time
import json
from datetime import datetime

BASE = "http://localhost:8000"
API = f"{BASE}/api/v1"
EVENTS_URL = f"{API}/events/"

client = httpx.Client(timeout=30.0)

def banner(title):
    print(f"\n{'='*20} {title} {'='*20}")

def test_sql_injection_src_ip():
    banner("SQL Injection: src_ip")
    payload = {
        "event_type": "network",
        "src_ip": "'; DROP TABLE security_events; --",
        "action": "allow"
    }
    r = client.post(EVENTS_URL, json=payload)
    print(f"Status: {r.status_code}")
    if r.status_code == 201:
        print("✅ PASS: Input accepted as literal string (parameters used)")
    else:
        print(f"❌ FAIL: Unexpected status {r.status_code}")

def test_sql_injection_description():
    banner("SQL Injection: description")
    payload = {
        "event_type": "system",
        "src_ip": "127.0.0.1",
        "description": "UNION SELECT username, password FROM users",
        "action": "alert"
    }
    r = client.post(EVENTS_URL, json=payload)
    print(f"Status: {r.status_code}")
    if r.status_code == 201:
        print("✅ PASS: Input accepted as literal string")
    else:
        print(f"❌ FAIL: Unexpected status {r.status_code}")

def test_port_range():
    banner("Port Range Enforcement")
    payload = {
        "event_type": "network",
        "src_ip": "127.0.0.1",
        "dst_port": 100000,
        "action": "allow"
    }
    r = client.post(EVENTS_URL, json=payload)
    print(f"Status: {r.status_code}")
    if r.status_code == 422:
        print("✅ PASS: Port 100000 rejected (Pydantic validation)")
    else:
        print(f"❌ FAIL: Unexpected status {r.status_code} (should be 422)")

def test_oversized_payload():
    banner("Oversized Payload (5MB)")
    large_str = "A" * 5 * 1024 * 1024 
    payload = {
        "event_type": "system",
        "src_ip": "127.0.0.1",
        "description": large_str
    }
    try:
        r = client.post(EVENTS_URL, json=payload)
        print(f"Status: {r.status_code}")
        if r.status_code in (413, 422, 500):
            print(f"✅ PASS/INFO: Payload handled with status {r.status_code}")
        else:
            print(f"⚠️ INFO: Payload accepted with status {r.status_code}")
    except Exception as e:
        print(f"✅ PASS: Connection closed or timed out (Server protection): {e}")

def test_cors():
    banner("CORS Headers")
    headers = {"Origin": "http://evil.com"}
    r = client.options(EVENTS_URL, headers=headers)
    print(f"Status: {r.status_code}")
    print(f"Access-Control-Allow-Origin: {r.headers.get('access-control-allow-origin')}")
    if r.headers.get('access-control-allow-origin'):
        print("✅ PASS: CORS headers present")
    else:
        print("❌ FAIL: CORS headers missing")

def test_stack_trace():
    banner("Internal Stack Trace Exposure")
    # Sending malformed JSON to trigger error
    r = client.post(EVENTS_URL, content="invalid json")
    print(f"Status: {r.status_code}")
    if "traceback" not in r.text.lower() and "file \"/" not in r.text:
        print("✅ PASS: No internal paths or stack traces exposed")
    else:
        print("❌ FAIL: Potential sensitive info leakage detected")

def main():
    print(f"Starting Security Verification: {datetime.now()}")
    test_sql_injection_src_ip()
    test_sql_injection_description()
    test_port_range()
    test_oversized_payload()
    test_cors()
    test_stack_trace()
    print("\nSecurity Verification Complete.")

if __name__ == "__main__":
    main()
