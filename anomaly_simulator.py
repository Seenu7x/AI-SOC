"""
AI-SOC Attack / Anomaly Simulator
====================================
PURPOSE: Simulate security attacks at each severity level (LOW → CRITICAL)
         one-by-one to demonstrate real-time anomaly detection on the dashboard.

Run AFTER normal_data_generator.py has trained the model.

Usage:
    python anomaly_simulator.py              # full demo sequence: all 6 attacks
    python anomaly_simulator.py --step 3    # run only step 3 (MEDIUM)
    python anomaly_simulator.py --pause 5   # wait 5s between attacks (default: 8)
    python anomaly_simulator.py --list      # list all attack steps
"""

import requests
import random
import time
import argparse
from datetime import datetime

BASE_URL = "http://localhost:8000/api/v1"

# ─────────────────────────────────────────────────────────────────
# Attack Scenarios — ordered LOW → CRITICAL
# Each entry describes one attack that the model should flag.
# Feature values are intentionally "extreme" to score outside the
# normal distribution learned during baseline training.
# ─────────────────────────────────────────────────────────────────

ATTACK_SCENARIOS = [

    # ── STEP 1 ── LOW ─────────────────────────────────────────────
    # Very small, atypical packet shape — micro-probe to an unusual port.
    # bytes_sent=0 + packet_count=1 + duration≈0 is a shape the normal model
    # never sees (all normal profiles have bytes_sent >= 40).
    {
        "step":        1,
        "name":        "Suspicious Port Probe",
        "severity":    "🟢 LOW",
        "description": "Single SYN packet to an unusual high port — early reconnaissance.",
        "event": {
            "event_type":     "network",
            "src_ip":         "45.33.49.119",
            "dst_ip":         "192.168.1.10",
            "src_port":       54321,
            "dst_port":       8443,
            "protocol":       "TCP",
            "bytes_sent":     0,
            "bytes_received": 0,
            "duration":       0.001,
            "packet_count":   1,
            "action":         "deny",
            # Behavioral features — must be present for ML scoring
            "request_rate":   1.0,
            "deny_rate":      1.0,
            "inter_arrival":  0.001,
            "description":    "Port probe: SYN to non-standard port 8443 from external IP",
        },
    },

    # ── STEP 2 ── LOW / MEDIUM ────────────────────────────────────
    # Root login attempt — atypical username=root, deny action, external src.
    # inter_arrival very small (rapid), deny_rate=1.0 (all denied).
    {
        "step":        2,
        "name":        "Off-Hours Root Login Attempt",
        "severity":    "🟢 LOW / 🟡 MEDIUM",
        "description": "Single failed SSH login as root from external IP at 00:00.",
        "event": {
            "event_type":     "login",
            "src_ip":         "203.0.113.42",
            "dst_ip":         "192.168.1.1",
            "src_port":       41234,
            "dst_port":       22,
            "protocol":       "TCP",
            "bytes_sent":     64,
            "bytes_received": 64,
            "duration":       0.05,
            "packet_count":   2,
            "action":         "deny",
            "username":       "root",
            # Behavioral features
            "request_rate":   2.0,
            "deny_rate":      1.0,
            "inter_arrival":  0.05,
            "description":    "Failed SSH login: root from 203.0.113.42 — off-hours",
        },
    },

    # ── STEP 3 ── MEDIUM ──────────────────────────────────────────
    # 40 rapid micro-events with deny_rate=1.0 and tiny inter_arrival.
    # The burst of 40 events in quick succession spikes request_rate
    # and deny_rate far above what the normal model ever saw.
    {
        "step":        3,
        "name":        "Port Scan / Network Reconnaissance",
        "severity":    "🟡 MEDIUM",
        "description": "Rapid sweep of 40 ports — classic nmap/masscan behavior.",
        "events_count": 40,
        "base_event": {
            "event_type":     "network",
            "src_ip":         "198.51.100.77",
            "dst_ip":         "192.168.1.10",
            "protocol":       "TCP",
            "bytes_sent":     44,
            "bytes_received": 0,
            "duration":       0.002,
            "packet_count":   1,
            "action":         "deny",
            "request_rate":   40.0,   # 40 req/min — extreme burst
            "deny_rate":      1.0,    # every single one blocked
            "inter_arrival":  0.002,  # sub-millisecond between packets
            "description":    "Port scan: rapid connection sweep from 198.51.100.77",
        },
    },

    # ── STEP 4 ── HIGH ────────────────────────────────────────────
    # 20 rapid SSH failures with extreme request_rate/deny_rate.
    # packet_count=20, bytes=512 each → cumulative anomaly score
    # should push well past -0.6 threshold.
    {
        "step":        4,
        "name":        "SSH Brute-Force Attack",
        "severity":    "🟠 HIGH",
        "description": "20 rapid SSH failures from same IP — credential stuffing.",
        "events_count": 20,
        "base_event": {
            "event_type":     "login",
            "src_ip":         "185.220.101.5",
            "dst_ip":         "192.168.1.1",
            "src_port":       0,
            "dst_port":       22,
            "protocol":       "TCP",
            "bytes_sent":     256,
            "bytes_received": 128,
            "duration":       0.08,
            "packet_count":   4,
            "action":         "deny",
            "username":       "admin",
            # Extreme behavioral features — these 3 drive the anomaly score
            "request_rate":   60.0,   # 60 login attempts per minute
            "deny_rate":      1.0,    # 100% failure rate
            "inter_arrival":  0.08,   # sub-second between each attempt
            "description":    "SSH brute-force: rapid failed logins from 185.220.101.5",
        },
    },

    # ── STEP 5 ── HIGH / CRITICAL ─────────────────────────────────
    # Large bytes + long duration + high packet count for a login event.
    # Normal SSH sessions never have packet_count=500 or bytes_sent=50000.
    {
        "step":        5,
        "name":        "Privilege Escalation Attempt",
        "severity":    "🟠 HIGH / 🔴 CRITICAL",
        "description": "sudo /bin/bash executed by www-data after suspicious login.",
        "event": {
            "event_type":     "login",
            "src_ip":         "10.0.0.99",
            "dst_ip":         "192.168.1.1",
            "src_port":       52000,
            "dst_port":       22,
            "protocol":       "TCP",
            "bytes_sent":     50_000,
            "bytes_received": 25_000,
            "duration":       180.0,
            "packet_count":   500,
            "action":         "allow",
            "username":       "www-data",
            "request_rate":   30.0,
            "deny_rate":      0.0,
            "inter_arrival":  0.1,
            "description":    "Privilege escalation: sudo /bin/bash by www-data",
        },
    },

    # ── STEP 6 ── CRITICAL ────────────────────────────────────────
    # 10MB outbound, 10 minutes, 15000 packets.
    # bytes_sent is 100–200x higher than any normal profile.
    # request_rate=0 (sustained, not bursty) makes the SHAPE unique.
    {
        "step":        6,
        "name":        "Data Exfiltration",
        "severity":    "🔴 CRITICAL",
        "description": "10MB sent to external IP over 10 minutes — data theft.",
        "event": {
            "event_type":     "network",
            "src_ip":         "192.168.1.50",
            "dst_ip":         "91.108.4.200",
            "src_port":       443,
            "dst_port":       443,
            "protocol":       "TCP",
            "bytes_sent":     10_000_000,   # 10 MB — 100–200x normal max
            "bytes_received": 200,
            "duration":       600.0,        # 10 minutes sustained
            "packet_count":   15_000,
            "action":         "allow",
            "request_rate":   1.5,
            "deny_rate":      0.0,
            "inter_arrival":  0.04,
            "description":    "DATA EXFILTRATION: 10MB → 91.108.4.200 over 10 minutes",
        },
    },
]


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def generate_ip():
    return f"{random.randint(1, 223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def score_to_severity(score: float, is_anomaly: bool) -> str:
    """Mirror the backend threshold logic — aligned with anomaly_detection.py."""
    if not is_anomaly:
        return "⚪ NORMAL"
    if score < -0.10:
        return "🔴 CRITICAL"
    if score < -0.07:
        return "🟠 HIGH"
    if score < -0.04:
        return "🟡 MEDIUM"
    return "🟢 LOW"


def post_event(event):
    try:
        r = requests.post(f"{BASE_URL}/events", json=event, timeout=8)
        # Return body on both success and failure for better error visibility
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:200]}
        return r.status_code == 201, body
    except Exception as e:
        return False, {"error": str(e)}


def post_bulk(events):
    try:
        r = requests.post(f"{BASE_URL}/events/bulk", json={"events": events}, timeout=30)
        if r.status_code == 200:
            res = r.json()
            return res.get("successful", 0), res.get("anomalies_detected", 0)
        print(f"  ⚠️  Bulk endpoint returned {r.status_code}: {r.text[:200]}")
        return 0, 0
    except Exception as e:
        print(f"  ⚠️  Bulk API error: {e}")
        return 0, 0


def check_api():
    # Use direct health URL — /../ does not resolve correctly via requests
    health_url = BASE_URL.replace("/api/v1", "") + "/health"
    try:
        r = requests.get(health_url, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def check_model():
    """Returns True if a model is trained and ready."""
    try:
        r = requests.get(f"{BASE_URL}/models/status", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data.get("is_loaded", False) or data.get("model_version") is not None
        # Try alternate endpoint
        r2 = requests.get(f"{BASE_URL}/models/info", timeout=5)
        return r2.status_code == 200
    except Exception:
        return True  # Assume ready if endpoint doesn't exist


def get_latest_alerts(limit=3):
    """Fetch the most recent alerts from the API."""
    try:
        r = requests.get(f"{BASE_URL}/alerts?limit={limit}", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []


def print_separator(char="─", width=60):
    print(char * width)


def print_alert_summary():
    """Print the most recently generated alerts."""
    alerts = get_latest_alerts(5)
    if not alerts:
        print("  (No alerts returned from API yet — refresh your dashboard)")
        return

    print("  📋 Latest Alerts on Dashboard:")
    for a in alerts[:5]:
        severity = a.get("severity", "?").upper()
        title    = a.get("title", "Unknown")
        score    = a.get("anomaly_score", 0)
        icons    = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon     = icons.get(severity, "⚪")
        print(f"    {icon} [{severity:8s}]  {title}  (score: {score:.3f})")


# ─────────────────────────────────────────────────────────────────
# Attack execution
# ─────────────────────────────────────────────────────────────────

def run_scenario(scenario, pause_seconds):
    step = scenario["step"]
    name = scenario["name"]
    sev  = scenario["severity"]
    desc = scenario["description"]

    print_separator()
    print(f"  STEP {step}  |  {sev}")
    print(f"  Attack  : {name}")
    print(f"  What    : {desc}")
    print_separator("─")

    anomalies_detected = 0

    # ── Multi-event attack (port scan, brute force) ────────────
    if "events_count" in scenario:
        count = scenario["events_count"]
        print(f"  Sending {count} rapid events to simulate burst behavior...")

        bulk = []
        base = scenario["base_event"].copy()
        for i in range(count):
            ev = base.copy()
            if scenario["step"] == 3:
                # Port scan — vary destination port
                ev["dst_port"] = random.randint(1, 65535)
                ev["src_ip"]   = "198.51.100.77"
            elif scenario["step"] == 4:
                # Brute force — keep same source, vary packet timing
                ev["src_port"] = random.randint(40000, 65000)
            bulk.append(ev)

        sent, anomalies = post_bulk(bulk)
        anomalies_detected = anomalies
        print(f"  ✅ Sent {sent}/{count} events  |  🚨 Anomalies detected: {anomalies}")

    # ── Single-event attack ────────────────────────────────────
    else:
        event = scenario["event"].copy()
        print(f"  Sending targeted attack event...")
        ok, result = post_event(event)
        if ok:
            is_anomaly = result.get("is_anomaly", False)
            score      = result.get("anomaly_score", 0.0)
            sev_label  = score_to_severity(score, is_anomaly)
            anomalies_detected = 1 if is_anomaly else 0
            status = "🚨 ANOMALY DETECTED" if is_anomaly else "⚪ Not flagged"
            print(f"  ✅ Event sent  |  {status}")
            print(f"     Score    : {score:.4f}")
            print(f"     Severity : {sev_label}")
        else:
            print(f"  ❌ Failed to send event: {result}")

    print()
    print("  ⏳ Waiting for dashboard to update...")
    time.sleep(2)
    print_alert_summary()

    print(f"\n  👉 CHECK YOUR DASHBOARD NOW — look for the new {sev} alert!")
    print(f"  ⏸️  Pausing {pause_seconds}s before next attack...")
    print()

    for remaining in range(pause_seconds, 0, -1):
        print(f"     Next attack in {remaining}s...  (press Ctrl+C to stop)", end="\r")
        time.sleep(1)
    print()

    return anomalies_detected


# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────

def list_scenarios():
    print("\nAvailable attack scenarios:")
    print_separator()
    for s in ATTACK_SCENARIOS:
        events = s.get("events_count", 1)
        # Note: no :30s padding on severity — emojis are multi-byte and break fixed-width alignment
        print(f"  Step {s['step']}  {s['severity']}  |  {s['name']}  ({events} event{'s' if events > 1 else ''})")
    print_separator()


def main():
    parser = argparse.ArgumentParser(description="AI-SOC Attack / Anomaly Simulator")
    parser.add_argument("--step",  type=int, default=0,  help="Run only a specific step (1–6). Default: all")
    parser.add_argument("--pause", type=int, default=8,  help="Seconds to pause between attacks (default: 8)")
    parser.add_argument("--list",  action="store_true",  help="List all attack scenarios and exit")
    args = parser.parse_args()

    if args.list:
        list_scenarios()
        return

    print("=" * 60)
    print("  AI-SOC  —  Attack / Anomaly Simulator")
    print(f"  Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Pause : {args.pause}s between attacks")
    print("=" * 60)

    # ── Pre-flight checks ──────────────────────────────────────
    print("\n🔌 Checking API connection...")
    if not check_api():
        print("  ❌ Cannot reach API at http://localhost:8000")
        print("     Start the backend first, then re-run this script.")
        return
    print("  ✅ API reachable\n")

    print("🤖 Checking if ML model is trained...")
    if not check_model():
        print("  ⚠️  No trained model found!")
        print("     Run: python normal_data_generator.py")
        print("     Then re-run this script.")
        return
    print("  ✅ Model ready\n")

    # ── Select scenarios ───────────────────────────────────────
    scenarios = ATTACK_SCENARIOS
    if args.step:
        scenarios = [s for s in ATTACK_SCENARIOS if s["step"] == args.step]
        if not scenarios:
            print(f"❌ No scenario found for step {args.step}. Use --list to see options.")
            return

    print("🎯 Attack sequence:")
    for s in scenarios:
        print(f"   Step {s['step']}  →  {s['severity']:30s}  {s['name']}")

    print(f"\n🟢 Starting in 5 seconds... Open your dashboard now!")
    print(f"   Dashboard: http://localhost:3000  or  http://localhost:8080")
    for i in range(5, 0, -1):
        print(f"   Starting in {i}...", end="\r")
        time.sleep(1)
    print()

    # ── Run scenarios ──────────────────────────────────────────
    total_anomalies = 0
    for scenario in scenarios:
        try:
            detected = run_scenario(scenario, args.pause)
            total_anomalies += detected
        except KeyboardInterrupt:
            print("\n\n⏹️  Demo stopped by user.")
            break

    # ── Summary ────────────────────────────────────────────────
    print_separator("═")
    print("  DEMO COMPLETE")
    print_separator("═")
    print(f"  Attack steps run     : {len(scenarios)}")
    print(f"  Anomalies detected   : {total_anomalies}")
    print(f"  Dashboard URL        : http://localhost:3000")
    print(f"  API Alerts endpoint  : {BASE_URL}/alerts")
    print()
    print("  Ask your mentor to check:")
    print("  1. 🔴 CRITICAL  — Data Exfiltration alert (highest score)")
    print("  2. 🟠 HIGH      — Brute Force / Privilege Escalation")
    print("  3. 🟡 MEDIUM    — Port Scan alert")
    print("  4. 🟢 LOW       — Suspicious port probe / single failed login")
    print_separator("═")


if __name__ == "__main__":
    main()
