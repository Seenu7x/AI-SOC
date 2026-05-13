"""
AI-SOC Normal Data Generator
==============================
PURPOSE: Generate realistic NORMAL (baseline) events and train the ML model.
Run this FIRST before any attack simulation.

Usage:
    python normal_data_generator.py              # generates 500 events + trains model
    python normal_data_generator.py --count 300  # custom count
    python normal_data_generator.py --no-train   # generate only, skip training
"""

import requests
import random
import time
import argparse
from datetime import datetime

BASE_URL = "http://localhost:8000/api/v1"

# ─────────────────────────────────────────────────────────────────
# Normal traffic profiles — these define what "baseline" looks like
# to the Isolation Forest model. Keep these realistic and varied.
# ─────────────────────────────────────────────────────────────────

NORMAL_PROFILES = {

    "web_browsing": {
        "event_type": "network",
        "bytes_sent":     (100, 5_000),
        "bytes_received": (1_000, 50_000),
        "duration":       (0.1, 10.0),
        "packet_count":   (5, 100),
        "dst_port":       443,
        "protocol":       "TCP",
        "action":         "allow",
        "description":    "Normal HTTPS web browsing",
    },

    "http_api_call": {
        "event_type": "network",
        "bytes_sent":     (200, 3_000),
        "bytes_received": (500, 20_000),
        "duration":       (0.05, 3.0),
        "packet_count":   (3, 60),
        "dst_port":       80,
        "protocol":       "TCP",
        "action":         "allow",
        "description":    "Normal HTTP API request",
    },

    "ssh_session": {
        "event_type": "login",
        "bytes_sent":     (500, 3_000),
        "bytes_received": (500, 3_000),
        "duration":       (1.0, 60.0),
        "packet_count":   (10, 80),
        "dst_port":       22,
        "protocol":       "TCP",
        "action":         "allow",
        "description":    "Normal SSH session",
        "username":       "admin",
    },

    "file_transfer": {
        "event_type": "network",
        "bytes_sent":     (1_000, 20_000),   # tightened: was 100K
        "bytes_received": (1_000, 20_000),   # tightened: was 100K
        "duration":       (5.0, 60.0),        # tightened: was 120s
        "packet_count":   (50, 200),          # tightened: was 1000
        "dst_port":       22,
        "protocol":       "TCP",
        "action":         "allow",
        "description":    "Normal file transfer (SCP/SFTP)",
    },

    "email": {
        "event_type": "network",
        "bytes_sent":     (500, 10_000),
        "bytes_received": (500, 10_000),
        "duration":       (0.5, 5.0),
        "packet_count":   (10, 100),
        "dst_port":       587,
        "protocol":       "TCP",
        "action":         "allow",
        "description":    "Normal email (SMTP)",
    },

    "database_query": {
        "event_type": "network",
        "bytes_sent":     (200, 2_000),
        "bytes_received": (500, 50_000),
        "duration":       (0.01, 5.0),
        "packet_count":   (5, 100),
        "dst_port":       5432,
        "protocol":       "TCP",
        "action":         "allow",
        "description":    "Normal PostgreSQL query",
    },

    "dns_lookup": {
        "event_type": "network",
        "bytes_sent":     (40, 200),
        "bytes_received": (40, 512),
        "duration":       (0.001, 0.5),
        "packet_count":   (1, 4),
        "dst_port":       53,
        "protocol":       "UDP",
        "action":         "allow",
        "description":    "Normal DNS lookup",
    },

    "single_ssh_fail": {
        # One occasional failed login is normal — users mistype passwords
        "event_type": "login",
        "bytes_sent":     (100, 500),
        "bytes_received": (100, 500),
        "duration":       (0.05, 1.0),
        "packet_count":   (3, 15),
        "dst_port":       22,
        "protocol":       "TCP",
        "action":         "deny",
        "description":    "Occasional failed SSH login (normal user error)",
        "username":       "admin",
    },
}


def generate_ip(internal=False):
    """Generate a random IP. internal=True → 192.168.x.x"""
    if internal:
        return f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def build_event(profile_name):
    """Build a single event dict from a named profile."""
    p = NORMAL_PROFILES[profile_name]

    # Normal behavioral rate ranges — model must see these during training
    # so it can distinguish burst attacks (request_rate=60, deny_rate=1.0)
    # from normal traffic (request_rate=0.5–5, deny_rate=0–0.1).
    is_fail = p.get("action") == "deny"
    event = {
        "event_type":     p["event_type"],
        "src_ip":         generate_ip(internal=True),
        "dst_ip":         generate_ip(),
        "src_port":       random.randint(1024, 65535),
        "dst_port":       p["dst_port"],
        "protocol":       p.get("protocol", "TCP"),
        "bytes_sent":     random.randint(*p["bytes_sent"]),
        "bytes_received": random.randint(*p["bytes_received"]),
        "duration":       round(random.uniform(*p["duration"]), 3),
        "packet_count":   random.randint(*p["packet_count"]),
        "action":         p.get("action", "allow"),
        "description":    p["description"],
        # Behavioral features — varied so model learns normal rate distribution
        "request_rate":   round(random.uniform(0.5, 5.0), 3),
        "deny_rate":      round(random.uniform(0.1, 0.3) if is_fail else random.uniform(0.0, 0.05), 3),
        "inter_arrival":  round(random.uniform(5.0, 60.0), 3),
    }
    if "username" in p:
        event["username"] = p["username"]
    return event


def post_event(event):
    """POST a single event to the API."""
    try:
        r = requests.post(f"{BASE_URL}/events", json=event, timeout=5)
        return r.status_code == 201
    except Exception as e:
        print(f"  ⚠️  API error: {e}")
        return False


def post_bulk(events):
    """POST a batch of events via the bulk endpoint."""
    try:
        r = requests.post(f"{BASE_URL}/events/bulk", json={"events": events}, timeout=30)
        if r.status_code == 200:
            result = r.json()
            return result.get("successful", len(events))
        return 0
    except Exception as e:
        print(f"  ⚠️  Bulk API error: {e}")
        return 0


def train_model():
    """Trigger model training via the API."""
    print("\n🤖 Training ML model on the normal baseline...")
    try:
        r = requests.post(
            f"{BASE_URL}/models/train",
            json={
                "model_type":        "isolation_forest",
                "contamination_rate": 0.05,   # 5% — more sensitive to outliers
                "n_estimators":       100,
            },
            timeout=120,
        )
        if r.status_code == 200:
            res = r.json()
            print(f"  ✅ Model trained!")
            print(f"     Version          : {res.get('model_version','?')}")
            print(f"     Training samples : {res.get('training_samples','?')}")
            print(f"     Training time    : {res.get('training_time_seconds', 0):.2f}s")
            print(f"     Message          : {res.get('message','')}")
            return True
        else:
            print(f"  ❌ Training failed [{r.status_code}]: {r.text[:200]}")
            return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False


def check_api():
    """Verify the API is reachable."""
    # Use direct health URL — /../ does not resolve correctly via requests
    health_url = BASE_URL.replace("/api/v1", "") + "/health"
    try:
        r = requests.get(health_url, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def generate_normal_events(count=500, batch_size=50, delay=0.1):
    """
    Generate `count` normal events split across all profiles.
    Sends them in batches for speed, with a small delay between batches.
    """
    profiles = list(NORMAL_PROFILES.keys())
    # Weight single_ssh_fail lower so it stays a rare normal event
    weights = [3, 3, 2, 2, 2, 3, 2, 1]

    print(f"\n📊 Generating {count} normal baseline events...")
    print(f"   Profiles : {', '.join(profiles)}")
    print(f"   Batch size: {batch_size} | Delay: {delay}s between batches\n")

    total_sent = 0
    batch = []

    for i in range(count):
        profile = random.choices(profiles, weights=weights, k=1)[0]
        event = build_event(profile)
        batch.append(event)

        if len(batch) >= batch_size:
            sent = post_bulk(batch)
            total_sent += sent
            print(f"  📤 Batch sent: {total_sent}/{count} events  [{profile}]")
            batch = []
            time.sleep(delay)

    # Send any remaining
    if batch:
        sent = post_bulk(batch)
        total_sent += sent
        print(f"  📤 Final batch sent: {total_sent}/{count} events")

    print(f"\n✅ Done — {total_sent} normal events ingested into the database.")
    return total_sent


def main():
    parser = argparse.ArgumentParser(description="AI-SOC Normal Data Generator")
    parser.add_argument("--count",    type=int, default=500,  help="Number of normal events to generate (default: 500)")
    parser.add_argument("--no-train", action="store_true",    help="Skip model training after generation")
    parser.add_argument("--batch",    type=int, default=50,   help="Batch size (default: 50)")
    parser.add_argument("--delay",    type=float, default=0.1, help="Delay in seconds between batches (default: 0.1)")
    args = parser.parse_args()

    print("=" * 60)
    print("  AI-SOC  —  Normal Baseline Data Generator")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # ── Step 1: Check API ──────────────────────────────────────
    print("\n🔌 Checking API connection...")
    if not check_api():
        print("  ❌ Cannot reach API at http://localhost:8000")
        print("     Make sure the AI-SOC backend is running:")
        print("     docker compose up  OR  uvicorn main:app --reload")
        return

    print("  ✅ API is reachable\n")

    # ── Step 2: Generate normal events ────────────────────────
    total = generate_normal_events(
        count=args.count,
        batch_size=args.batch,
        delay=args.delay,
    )

    if total < 50:
        print("⚠️  Too few events ingested. Check the API logs for errors.")
        return

    # ── Step 3: Train model ────────────────────────────────────
    if not args.no_train:
        success = train_model()
        if success:
            print("\n🎉 Baseline training complete!")
            print("   The model now knows what NORMAL looks like.")
            print("   You can now run: python anomaly_simulator.py")
        else:
            print("\n⚠️  Training failed. Try manually:")
            print(f"   curl -X POST {BASE_URL}/models/train \\")
            print("        -H 'Content-Type: application/json' \\")
            print("        -d '{\"model_type\":\"isolation_forest\",\"contamination_rate\":0.01}'")
    else:
        print("\nℹ️  Skipped training (--no-train flag set).")
        print(f"   Run training manually: POST {BASE_URL}/models/train")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
