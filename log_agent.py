#!/usr/bin/env python3
"""
AI-SOC Real-Time Host Log Ingestion Agent  (Cross-Platform)
=============================================================
Auto-detects the host OS and reads native security logs:

  Linux   → /var/log/auth.log, syslog, ufw.log, Docker container logs
  Windows → Windows Event Log (Security/System) via wevtutil.exe
  macOS   → Unified log via `log stream` + /var/log/system.log

All platforms POST events to the same AI-SOC API endpoint.
"""
import platform
CURRENT_OS = platform.system()   # "Linux" | "Windows" | "Darwin"

import os
import re
import time
import json
import random
import hashlib
import logging
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List

try:
    import httpx
    HTTP = httpx
except ImportError:
    import urllib.request as urllib_req
    HTTP = None

# ─── Config ────────────────────────────────────────────────────────────────────
API_BASE          = os.getenv("API_BASE", "http://localhost:8000/api/v1")
POLL_INTERVAL     = float(os.getenv("POLL_INTERVAL", "2"))   # seconds between batches
BATCH_SIZE        = int(os.getenv("BATCH_SIZE", "20"))        # events per POST
API_KEY           = os.getenv("API_KEY", "")                  # shared secret → X-API-Key header
HOSTNAME         = platform.node()
DOCKER_LOG_ROOT  = os.getenv("DOCKER_LOG_ROOT", "/var/lib/docker/containers")
DOCKER_SCAN_INTERVAL = int(os.getenv("DOCKER_SCAN_INTERVAL", "30"))  # re-scan for new containers

# ─── Noise-control toggles (set to "false" in docker-compose env to silence) ─
ENABLE_KERN_LOG   = os.getenv("ENABLE_KERN_LOG",  "true").lower() == "true"
ENABLE_SYSLOG     = os.getenv("ENABLE_SYSLOG",    "true").lower() == "true"
ENABLE_AUTH_LOG   = os.getenv("ENABLE_AUTH_LOG",  "true").lower() == "true"
ENABLE_UFW_LOG    = os.getenv("ENABLE_UFW_LOG",   "true").lower() == "true"
ENABLE_DOCKER_MON = os.getenv("ENABLE_DOCKER_MON","true").lower() == "true"

# ─── Deduplication: suppress repeated identical events within this window ─────
DEDUP_WINDOW      = int(os.getenv("DEDUP_WINDOW", "30"))   # seconds
DEDUP_MAX_CACHE   = int(os.getenv("DEDUP_MAX_CACHE", "500"))  # max unique fingerprints

LOG_FILES = {
    "/var/log/auth.log":           "login",
    "/var/log/syslog":             "system",
    "/var/log/kern.log":           "system",
    "/var/log/ufw.log":            "network",
    "/var/log/nginx/access.log":   "network",
    "/var/log/apache2/access.log": "network",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [LOG-AGENT] %(levelname)s %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("log_agent")

# ─── Parsers ───────────────────────────────────────────────────────────────────

# SSH / auth patterns
_SSH_ACCEPT  = re.compile(r"Accepted (\w+) for (\S+) from ([\d\.]+) port (\d+)")
_SSH_FAIL    = re.compile(r"Failed (\w+) for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)")
_SSH_INVAL   = re.compile(r"Invalid user (\S+) from ([\d\.]+) port (\d+)")
_SUDO        = re.compile(r"sudo:\s+(\S+) : .* COMMAND=(.*)")
_PAM_FAIL    = re.compile(r"pam_unix.*authentication failure.*user=(\S+)")

# UFW patterns
_UFW_BLOCK   = re.compile(r"\[UFW (BLOCK|ALLOW)\].*SRC=([\d\.]+) DST=([\d\.]+).*SPT=(\d+) DPT=(\d+).*PROTO=(\w+)")

# Nginx/Apache combined log
_HTTP_LOG    = re.compile(r'([\d\.]+) .* "(\w+) (\S+) HTTP/[\d\.]+" (\d+) (\d+)')

# Kernel network (iptables / nf)
_KERN_NET    = re.compile(r"IN=(\S*) OUT=(\S*) SRC=([\d\.]+) DST=([\d\.]+).*SPT=(\d+) DPT=(\d+)")

# Syslog OOM / segfault
_KERN_OOM    = re.compile(r"Out of memory: Killed process")
_SEGFAULT    = re.compile(r"segfault at")


def _ip(v: str) -> str:
    return v if v else "0.0.0.0"


def parse_auth_line(line: str) -> Optional[Dict]:
    m = _SSH_ACCEPT.search(line)
    if m:
        _, user, src_ip, port = m.groups()
        return {
            "event_type": "login", "src_ip": _ip(src_ip), "dst_ip": HOSTNAME,
            "src_port": int(port), "dst_port": 22, "protocol": "TCP",
            "bytes_sent": random.randint(500, 3000),
            "bytes_received": random.randint(500, 3000),
            "duration": round(random.uniform(0.1, 5.0), 3),
            "packet_count": random.randint(10, 80),
            "username": user, "action": "allow",
            "description": f"SSH login accepted: {user} from {src_ip}:{port}",
            "raw_log": line.strip(),
        }
    m = _SSH_FAIL.search(line)
    if m:
        _, user, src_ip, port = m.groups()
        return {
            "event_type": "login", "src_ip": _ip(src_ip), "dst_ip": HOSTNAME,
            "src_port": int(port), "dst_port": 22, "protocol": "TCP",
            "bytes_sent": random.randint(100, 800),
            "bytes_received": random.randint(100, 800),
            "duration": round(random.uniform(0.05, 1.0), 3),
            "packet_count": random.randint(3, 20),
            "username": user, "action": "deny",
            "description": f"SSH login FAILED: {user} from {src_ip}:{port}",
            "raw_log": line.strip(),
        }
    m = _SSH_INVAL.search(line)
    if m:
        user, src_ip, port = m.groups()
        return {
            "event_type": "login", "src_ip": _ip(src_ip), "dst_ip": HOSTNAME,
            "src_port": int(port), "dst_port": 22, "protocol": "TCP",
            "bytes_sent": 64, "bytes_received": 64,
            "duration": round(random.uniform(0.01, 0.3), 3),
            "packet_count": random.randint(2, 8),
            "username": user, "action": "deny",
            "description": f"SSH invalid user: {user} from {src_ip}:{port}",
            "raw_log": line.strip(),
        }
    m = _SUDO.search(line)
    if m:
        user, command = m.groups()
        return {
            "event_type": "system", "src_ip": "127.0.0.1", "dst_ip": HOSTNAME,
            "bytes_sent": 0, "bytes_received": 0,
            "duration": 0.0, "packet_count": 0,
            "username": user, "action": "allow",
            "resource": command.strip(),
            "description": f"sudo: {user} ran {command.strip()}",
            "raw_log": line.strip(),
        }
    m = _PAM_FAIL.search(line)
    if m:
        user = m.group(1)
        return {
            "event_type": "login", "src_ip": "127.0.0.1", "dst_ip": HOSTNAME,
            "bytes_sent": 0, "bytes_received": 0,
            "duration": 0.0, "packet_count": 0,
            "username": user, "action": "deny",
            "description": f"PAM auth failure: {user}",
            "raw_log": line.strip(),
        }
    return None


def parse_ufw_line(line: str) -> Optional[Dict]:
    m = _UFW_BLOCK.search(line)
    if m:
        verdict, src, dst, spt, dpt, proto = m.groups()
        return {
            "event_type": "network",
            "src_ip": _ip(src), "dst_ip": _ip(dst),
            "src_port": int(spt), "dst_port": int(dpt),
            "protocol": proto,
            "bytes_sent": random.randint(40, 500),
            "bytes_received": 0,
            "duration": 0.0,
            "packet_count": 1,
            "action": "allow" if verdict == "ALLOW" else "deny",
            "description": f"UFW {verdict}: {src}:{spt} → {dst}:{dpt} ({proto})",
            "raw_log": line.strip(),
        }
    return None


def parse_http_line(line: str) -> Optional[Dict]:
    m = _HTTP_LOG.search(line)
    if m:
        src_ip, method, path, status_code, resp_bytes = m.groups()
        return {
            "event_type": "network",
            "src_ip": _ip(src_ip), "dst_ip": HOSTNAME,
            "src_port": random.randint(40000, 65535),
            "dst_port": 80,
            "protocol": "TCP",
            "bytes_sent": int(resp_bytes),
            "bytes_received": random.randint(200, 2000),
            "duration": round(random.uniform(0.01, 2.0), 3),
            "packet_count": random.randint(2, 30),
            "action": "allow" if int(status_code) < 400 else "deny",
            "resource": path,
            "description": f"HTTP {method} {path} → {status_code}",
            "raw_log": line.strip(),
        }
    return None


def parse_syslog_line(line: str) -> Optional[Dict]:
    # Only forward notable syslog/kernel events
    if _KERN_OOM.search(line):
        return {
            "event_type": "system", "src_ip": "127.0.0.1", "dst_ip": HOSTNAME,
            "bytes_sent": 0, "bytes_received": 0, "duration": 0.0, "packet_count": 0,
            "action": "alert",
            "description": "OOM killer triggered — process killed",
            "raw_log": line.strip(),
        }
    if _SEGFAULT.search(line):
        return {
            "event_type": "system", "src_ip": "127.0.0.1", "dst_ip": HOSTNAME,
            "bytes_sent": 0, "bytes_received": 0, "duration": 0.0, "packet_count": 0,
            "action": "alert",
            "description": "Segfault detected in kernel log",
            "raw_log": line.strip(),
        }
    m = _KERN_NET.search(line)
    if m:
        in_iface, out_iface, src, dst, spt, dpt = m.groups()
        return {
            "event_type": "network",
            "src_ip": _ip(src), "dst_ip": _ip(dst),
            "src_port": int(spt), "dst_port": int(dpt),
            "protocol": "TCP",
            "bytes_sent": random.randint(40, 1500),
            "bytes_received": 0,
            "duration": 0.0, "packet_count": 1,
            "action": "alert",
            "description": f"Kernel netfilter: {src}:{spt}→{dst}:{dpt}",
            "raw_log": line.strip(),
        }
    return None


PARSERS = {
    "login":   parse_auth_line,
    "network": parse_ufw_line,
    "system":  parse_syslog_line,
    "http":    parse_http_line,
}

# Built dynamically so env-var toggles can silence entire log sources
LOG_PARSER_MAP = {}
if ENABLE_AUTH_LOG:
    LOG_PARSER_MAP["/var/log/auth.log"] = parse_auth_line
if ENABLE_SYSLOG:
    LOG_PARSER_MAP["/var/log/syslog"]  = parse_syslog_line
if ENABLE_KERN_LOG:
    LOG_PARSER_MAP["/var/log/kern.log"] = parse_syslog_line
if ENABLE_UFW_LOG:
    LOG_PARSER_MAP["/var/log/ufw.log"]  = parse_ufw_line
LOG_PARSER_MAP["/var/log/nginx/access.log"]   = parse_http_line
LOG_PARSER_MAP["/var/log/apache2/access.log"] = parse_http_line


# ─── API client ────────────────────────────────────────────────────────────────

def post_events(events: List[Dict]) -> bool:
    """POST a batch of events to the AI-SOC API"""
    if not events:
        return True
    payload = json.dumps({"events": events}).encode()
    url = f"{API_BASE}/events/bulk"
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    try:
        req = __import__("urllib.request", fromlist=["Request", "urlopen"])
        import urllib.request as ureq
        r = ureq.urlopen(
            ureq.Request(
                url, data=payload,
                headers=headers,
                method="POST"
            ),
            timeout=10
        )
        result = json.loads(r.read())
        anomalies = result.get("anomalies_detected", 0)
        if anomalies:
            logger.warning(f"🚨 {anomalies} ANOMALIES detected in batch of {len(events)}")
        else:
            logger.info(f"✅ {result.get('successful',len(events))} events ingested")
        return True
    except Exception as e:
        logger.error(f"API error: {e}")
        return False


# ─── Log tailer ────────────────────────────────────────────────────────────────

class LogTailer:
    """Tails a single log file using subprocess tail -F (follows rotations)"""

    def __init__(self, path: str, parser, event_queue: list):
        self.path = path
        self.parser = parser
        self.queue = event_queue
        self._process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if not Path(self.path).exists():
            logger.warning(f"Log file not found, skipping: {self.path}")
            return False
        try:
            # Check read permission
            with open(self.path, "r") as f:
                pass
        except PermissionError:
            logger.warning(f"No read permission for {self.path} — run agent as root or add log group")
            return False

        self._process = subprocess.Popen(
            ["tail", "-F", "-n", "0", self.path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()
        logger.info(f"📂 Tailing: {self.path}")
        return True

    def _read_loop(self):
        for line in self._process.stdout:
            line = line.rstrip()
            if not line:
                continue
            try:
                event = self.parser(line)
                if event:
                    # ── Quality gate: skip events with no useful description ──
                    if not event.get("description"):
                        continue
                    # ── Deduplication: suppress identical events in window ───
                    if _deduplicator.is_duplicate(event):
                        continue
                    # Stamp behavioral features (request_rate, deny_rate, inter_arrival)
                    _event_enricher.enrich(event)
                    self.queue.append(event)
            except Exception as e:
                logger.debug(f"Parse error [{self.path}]: {e}")

    def stop(self):
        if self._process:
            self._process.terminate()


# ─── Event Enricher (behavioral features) ────────────────────────────────────
#
# Adds rate/timing features per source so the ML model can distinguish
# a burst of 50 identical failures from 1 legitimate login attempt.

RATE_WINDOW = int(os.getenv("RATE_WINDOW", "60"))   # seconds for rate calculation


class EventEnricher:
    """
    Computes per-source behavioral features using a sliding time window:
      request_rate  – events/minute from this source in the last RATE_WINDOW seconds
      deny_rate     – fraction of denied (action=deny/alert) events from this source
      inter_arrival – seconds since last event from this source

    These features are stamped onto every event dict before it enters the queue,
    giving the Isolation Forest models temporal/rate context that makes brute-force
    bursts statistically distinguishable from normal isolated events.
    """

    def __init__(self):
        self._lock  = threading.Lock()
        # {source_key: [(timestamp, is_denied)]}
        self._history: Dict[str, list] = {}
        self._last_ts: Dict[str, float] = {}

    def _source_key(self, event: Dict) -> str:
        """Group events by container name (from description) or src_ip."""
        desc = event.get('description', '') or ''
        # Extract [container_name] prefix added by parse_docker_log_line
        if desc.startswith('['):
            end = desc.find(']')
            if end > 0:
                return desc[1:end]
        return event.get('src_ip', 'unknown')

    def enrich(self, event: Dict) -> Dict:
        """Stamp request_rate, deny_rate, inter_arrival onto the event dict."""
        now = time.time()
        key = self._source_key(event)
        is_denied = event.get('action', 'allow') in ('deny', 'alert')

        with self._lock:
            # Purge entries outside the window
            bucket = self._history.setdefault(key, [])
            self._history[key] = [(t, d) for t, d in bucket if now - t < RATE_WINDOW]
            self._history[key].append((now, is_denied))

            bucket = self._history[key]
            count  = len(bucket)
            denied = sum(1 for _, d in bucket if d)

            last    = self._last_ts.get(key, now - RATE_WINDOW)
            inter   = now - last
            self._last_ts[key] = now

        # events/minute
        request_rate = count / (RATE_WINDOW / 60.0)
        deny_rate    = denied / max(count, 1)

        event['request_rate']  = round(request_rate, 4)
        event['deny_rate']     = round(deny_rate, 4)
        event['inter_arrival'] = round(inter, 4)
        return event


# Global enricher — shared across all tailers
_event_enricher = EventEnricher()

# ─── Event Deduplicator ──────────────────────────────────────────────────────
#
# Builds a fingerprint from (event_type, src_ip, dst_ip, action, description)
# and suppresses duplicate events seen within DEDUP_WINDOW seconds.
# This prevents UFW blocks, CRON pam sessions, and identical syslog lines
# from flooding the database and poisoning the ML training set.

class EventDeduplicator:
    """
    Sliding-window deduplication: each unique event fingerprint is allowed
    through AT MOST ONCE per DEDUP_WINDOW seconds.
    """

    def __init__(self):
        self._lock  = threading.Lock()
        self._seen: Dict[str, float] = {}  # {fingerprint: last_seen_ts}
        self._suppressed = 0

    def _fingerprint(self, event: Dict) -> str:
        key = "|".join([
            event.get("event_type", ""),
            event.get("src_ip", ""),
            event.get("dst_ip", ""),
            event.get("action", ""),
            (event.get("description") or "")[:80],
        ])
        return hashlib.md5(key.encode()).hexdigest()

    def is_duplicate(self, event: Dict) -> bool:
        """Return True if this event is a duplicate and should be suppressed."""
        now = time.time()
        fp  = self._fingerprint(event)

        with self._lock:
            # Purge old cache entries to prevent unbounded growth
            if len(self._seen) > DEDUP_MAX_CACHE:
                cutoff = now - DEDUP_WINDOW
                self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

            last = self._seen.get(fp)
            if last is not None and (now - last) < DEDUP_WINDOW:
                self._suppressed += 1
                return True
            self._seen[fp] = now
            return False

    def stats(self) -> int:
        return self._suppressed


# Global deduplicator — shared across all tailers
_deduplicator = EventDeduplicator()

# ─── Brute-Force Rate Detector ────────────────────────────────────────────────
#
# The ML model cannot distinguish individual 401 events from normal traffic
# because all Docker log events share the same feature values.
# This detector watches for BURSTS of auth failures within a time window and
# synthesizes a high-feature event that the Isolation Forest WILL flag.

BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "10"))  # failures before alert
BRUTE_FORCE_WINDOW    = int(os.getenv("BRUTE_FORCE_WINDOW", "30"))     # sliding window seconds



class BruteForceDetector:
    """
    Sliding-window counter for HTTP auth failures per container.
    When BRUTE_FORCE_THRESHOLD failures occur within BRUTE_FORCE_WINDOW seconds,
    emits a synthetic event with extreme feature values so the ML model flags it.
    """

    def __init__(self, event_queue: list):
        self.queue  = event_queue
        self._lock  = threading.Lock()
        self._counts: Dict[str, list] = {}  # {container_name: [timestamps]}

    def record_failure(self, container_name: str, path: str = "/", status: str = "401"):
        now = time.time()
        with self._lock:
            bucket = self._counts.setdefault(container_name, [])
            # Purge old entries outside the window
            self._counts[container_name] = [t for t in bucket if now - t < BRUTE_FORCE_WINDOW]
            self._counts[container_name].append(now)
            count = len(self._counts[container_name])

        if count == BRUTE_FORCE_THRESHOLD:
            self._emit(container_name, path, status, count)

    def _emit(self, container_name: str, path: str, status: str, count: int):
        """Emit synthetic event with extreme features — guaranteed anomaly."""
        logger.warning(
            f"🚨 BRUTE-FORCE on [{container_name}]: "
            f"{count} failures in {BRUTE_FORCE_WINDOW}s → {path} (HTTP {status})"
        )
        self.queue.append({
            "event_type": "login",
            "src_ip": "127.0.0.1",
            "dst_ip": HOSTNAME,
            "src_port": 0,
            "dst_port": 80,
            "protocol": "TCP",
            # Extreme values — far outside the normal ML baseline
            "bytes_sent":     count * 512,
            "bytes_received": count * 200,
            "duration":       float(BRUTE_FORCE_WINDOW),
            "packet_count":   count,
            "action": "deny",
            "description": (
                f"[BRUTE-FORCE] {container_name}: {count} failed auth "
                f"attempts on {path} in {BRUTE_FORCE_WINDOW}s (HTTP {status})"
            ),
            "raw_log": f"brute_force_detected container={container_name} count={count} path={path}",
        })


# Global brute-force detector (shared across all container tailers)
_brute_force_detector: Optional["BruteForceDetector"] = None


# ─── Docker container log watcher ────────────────────────────────────────────

# Security-relevant patterns inside container log lines
_DOCKER_HTTP_ERR  = re.compile(r'"(GET|POST|PUT|DELETE|PATCH|HEAD) (\S+) HTTP/[\d.]+" (4\d\d|5\d\d)')
_DOCKER_AUTH_FAIL = re.compile(r'(?i)(unauthorized|forbidden|authentication failed|invalid (token|credential|password|key)|access denied)')
_DOCKER_CRASH     = re.compile(r'(?i)(panic|segfault|segmentation fault|fatal error|out of memory|killed|exception|traceback)')
_DOCKER_SCAN      = re.compile(r'(?i)(sqlmap|nmap|nikto|masscan|dirbuster|gobuster|nuclei|hydra|medusa)')
_DOCKER_SQLI      = re.compile(r"(?i)(union select|' or '1'='1|drop table|xp_cmdshell|exec\()")
_DOCKER_DB_ERR    = re.compile(r'(?i)(sql error|database error|connection refused|max connections)')


def _get_container_name(container_dir: Path) -> str:
    """Read container name from Docker config.v2.json"""
    try:
        cfg = json.loads((container_dir / "config.v2.json").read_text())
        name = cfg.get("Name", "").lstrip("/")
        return name or container_dir.name[:12]
    except Exception:
        return container_dir.name[:12]


def parse_docker_log_line(line: str, container_name: str) -> Optional[Dict]:
    """
    Parse a Docker JSON log line:
      {"log": "actual message\n", "stream": "stdout", "time": "..."}
    Only emits an event if the message contains a security-relevant pattern.
    """
    try:
        entry = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    msg = entry.get("log", "").strip()
    if not msg:
        return None

    base = {
        "event_type": "network",
        "src_ip": "127.0.0.1",
        "dst_ip": HOSTNAME,
        "src_port": 0,
        "dst_port": 0,
        "protocol": "TCP",
        "bytes_sent": 0,
        "bytes_received": len(msg),
        "duration": 0.0,
        "packet_count": 1,
        "action": "alert",
        "raw_log": msg[:500],
    }

    m = _DOCKER_HTTP_ERR.search(msg)
    if m:
        method, path, status = m.groups()
        # 4xx and 5xx are both security-relevant "denies" for the ML model
        is_error = status.startswith("4") or status.startswith("5")
        
        if _brute_force_detector and is_error:
            _brute_force_detector.record_failure(container_name, path, status)
        base.update({
            "action": "deny" if is_error else "allow",
            "resource": path,
            "description": f"[{container_name}] HTTP {method} {path} \u1c12 {status}",
        })
        return base

    if _DOCKER_AUTH_FAIL.search(msg):
        if _brute_force_detector:
            _brute_force_detector.record_failure(container_name, "/auth", "401")
        base.update({
            "event_type": "login",
            "action": "deny",
            "description": f"[{container_name}] Auth failure: {msg[:120]}",
        })
        return base

    if _DOCKER_SQLI.search(msg):
        base.update({
            "action": "deny",
            "description": f"[{container_name}] Possible SQL injection: {msg[:120]}",
        })
        return base

    if _DOCKER_SCAN.search(msg):
        base.update({
            "action": "deny",
            "description": f"[{container_name}] Scanner detected: {msg[:120]}",
        })
        return base

    if _DOCKER_CRASH.search(msg):
        base.update({
            "event_type": "system",
            "description": f"[{container_name}] Crash/OOM: {msg[:120]}",
        })
        return base

    if _DOCKER_DB_ERR.search(msg):
        base.update({
            "event_type": "system",
            "description": f"[{container_name}] DB error: {msg[:120]}",
        })
        return base

    return None


class DockerContainerWatcher:
    """
    Periodically discovers Docker container log files under DOCKER_LOG_ROOT
    and starts a LogTailer for each new container found.
    Containers that disappear are cleaned up automatically.
    """

    def __init__(self, log_root: str, event_queue: list):
        self.log_root    = Path(log_root)
        self.queue       = event_queue
        self._tailers: Dict[str, LogTailer] = {}   # key = container_id
        self._lock       = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if not self.log_root.exists():
            logger.warning(f"Docker log root not found: {self.log_root} — skipping Docker monitoring")
            return
        self._scan()
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()
        logger.info(f"🐳 Docker container watcher started (scanning every {DOCKER_SCAN_INTERVAL}s)")

    def _scan_loop(self):
        while True:
            time.sleep(DOCKER_SCAN_INTERVAL)
            self._scan()

    def _scan(self):
        """Find all container log files and start tailers for new ones."""
        if not self.log_root.exists():
            return

        current_ids = set()
        for container_dir in self.log_root.iterdir():
            if not container_dir.is_dir():
                continue
            cid = container_dir.name
            log_file = container_dir / f"{cid}-json.log"
            if not log_file.exists():
                continue
            current_ids.add(cid)
            with self._lock:
                if cid not in self._tailers:
                    name = _get_container_name(container_dir)
                    # Skip the AI-SOC containers themselves to avoid a feedback loop
                    if any(x in name for x in ["aisoc-app", "aisoc-db", "aisoc-redis",
                                                "aisoc-dashboard", "aisoc-log-agent"]):
                        continue
                    parser = lambda line, n=name: parse_docker_log_line(line, n)
                    tailer = LogTailer(str(log_file), parser, self.queue)
                    if tailer.start():
                        self._tailers[cid] = tailer
                        logger.info(f"🐳 Now monitoring container: {name} ({cid[:12]})")

        # Stop tailers for containers that no longer exist
        with self._lock:
            gone = set(self._tailers.keys()) - current_ids
            for cid in gone:
                self._tailers[cid].stop()
                del self._tailers[cid]
                logger.info(f"🐳 Container removed: {cid[:12]}")


# ─── Main agent loop ──────────────────────────────────────────────────────────

def wait_for_api(retries=30, delay=5):
    """Wait until the AI-SOC API is reachable"""
    import urllib.request as ureq
    for i in range(retries):
        try:
            ureq.urlopen(f"{API_BASE.replace('/api/v1','')}/health", timeout=5)
            logger.info("✅ AI-SOC API is reachable")
            return True
        except Exception:
            logger.info(f"⏳ Waiting for API… ({i+1}/{retries})")
            time.sleep(delay)
    logger.error("❌ API not reachable after retries — exiting")
    return False


def main():
    logger.info("=" * 60)
    logger.info("  AI-SOC Real-Time Host Log Agent")
    logger.info(f"  Host    : {HOSTNAME}")
    logger.info(f"  API     : {API_BASE}")
    logger.info(f"  Batch   : {BATCH_SIZE} events every {POLL_INTERVAL}s")
    logger.info(f"  Docker : {DOCKER_LOG_ROOT}")
    logger.info("=" * 60)

    if not wait_for_api():
        return

    event_queue: List[Dict] = []

    if CURRENT_OS == "Windows":
        _run_windows(event_queue)
    elif CURRENT_OS == "Darwin":
        _run_macos(event_queue)
    else:
        _run_linux(event_queue)


# ─── Linux runner (original behaviour) ────────────────────────────────────────

def _run_linux(event_queue: List[Dict]):
    tailers: List[LogTailer] = []
    active_sources = 0

    global _brute_force_detector
    _brute_force_detector = BruteForceDetector(event_queue)
    logger.info(f"🛡️  Brute-force detector: threshold={BRUTE_FORCE_THRESHOLD} failures in {BRUTE_FORCE_WINDOW}s")

    for log_path, parser_fn in LOG_PARSER_MAP.items():
        tailer = LogTailer(log_path, parser_fn, event_queue)
        if tailer.start():
            tailers.append(tailer)
            active_sources += 1

    if active_sources == 0:
        logger.error("No log files accessible. Run as root or with log group access.")
        logger.info("Tip: sudo usermod -aG adm $USER && su - $USER")
        return

    if ENABLE_DOCKER_MON:
        docker_watcher = DockerContainerWatcher(DOCKER_LOG_ROOT, event_queue)
        docker_watcher.start()
    else:
        docker_watcher = None
        logger.info("🐳 Docker monitoring DISABLED")

    logger.info(f"🐧 Linux — monitoring {active_sources} log sources. Events → {API_BASE}")
    _event_loop(event_queue)

    for t in tailers:
        t.stop()
    if docker_watcher:
        with docker_watcher._lock:
            for t in docker_watcher._tailers.values():
                t.stop()


# ─── Windows runner ────────────────────────────────────────────────────────────

# Windows Event IDs of interest
_WIN_EVENT_IDS = {
    4624: ("login",   "allow",  "Successful logon"),
    4625: ("login",   "deny",   "Failed logon"),
    4634: ("login",   "allow",  "Logoff"),
    4648: ("login",   "deny",   "Logon with explicit credentials"),
    4688: ("system",  "allow",  "Process created"),
    4697: ("system",  "deny",   "Service installed"),
    7036: ("system",  "allow",  "Service state changed"),
    1102: ("system",  "deny",   "Audit log cleared"),
}

def _wevtutil_tail(log_name: str, event_queue: List[Dict], stop_event: threading.Event):
    """Poll Windows Event Log using wevtutil, yield new events."""
    import xml.etree.ElementTree as ET

    # Track last record number we've seen
    last_record = 0
    NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

    while not stop_event.is_set():
        try:
            # Query events newer than last_record
            query = f"*[System[EventRecordID > {last_record}]]"
            cmd = ["wevtutil", "qe", log_name, f"/q:{query}",
                   "/f:xml", "/rd:false", "/c:50"]
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=10, encoding="utf-8", errors="replace")
            if result.returncode != 0 or not result.stdout.strip():
                time.sleep(POLL_INTERVAL)
                continue

            # wevtutil returns multiple XML fragments; wrap them
            xml_text = f"<Events>{result.stdout}</Events>"
            try:
                root = ET.fromstring(xml_text)
            except ET.ParseError:
                time.sleep(POLL_INTERVAL)
                continue

            for evt in root.findall(f"{NS}Event"):
                sys_el  = evt.find(f"{NS}System")
                if sys_el is None:
                    continue

                eid_el  = sys_el.find(f"{NS}EventID")
                rid_el  = sys_el.find(f"{NS}EventRecordID")
                time_el = sys_el.find(f"{NS}TimeCreated")

                if eid_el is None or rid_el is None:
                    continue

                eid = int(eid_el.text or 0)
                rid = int(rid_el.text or 0)
                if rid <= last_record:
                    continue
                last_record = max(last_record, rid)

                if eid not in _WIN_EVENT_IDS:
                    continue

                ev_type, action, desc = _WIN_EVENT_IDS[eid]

                # Try to extract username from EventData
                username = None
                data_el = evt.find(f"{NS}EventData")
                if data_el is not None:
                    for d in data_el.findall(f"{NS}Data"):
                        name = d.get("Name", "")
                        if name in ("TargetUserName", "SubjectUserName") and d.text:
                            username = d.text
                            break

                event_queue.append({
                    "event_type": ev_type,
                    "src_ip": "127.0.0.1",
                    "dst_ip": HOSTNAME,
                    "bytes_sent": 0, "bytes_received": 0,
                    "duration": 0.0, "packet_count": 1,
                    "username": username,
                    "action": action,
                    "description": f"[Win EventID {eid}] {desc}" + (f": {username}" if username else ""),
                    "raw_log": f"EventLog:{log_name} EID:{eid} RID:{rid}",
                })

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug(f"wevtutil error ({log_name}): {e}")

        time.sleep(POLL_INTERVAL)


def _win_firewall_tail(event_queue: List[Dict], stop_event: threading.Event):
    """Tail the Windows Firewall log file."""
    fw_log = Path(os.environ.get(
        "WIN_FIREWALL_LOG",
        r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
    ))
    if not fw_log.exists():
        logger.warning(f"Windows Firewall log not found: {fw_log}")
        return

    # Pattern: date time action proto src-ip dst-ip src-port dst-port ...
    _fw = re.compile(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+) (\S+) ([\d\.]+) ([\d\.]+) (\d+) (\d+)"
    )
    try:
        with open(fw_log, "r", errors="replace") as f:
            f.seek(0, 2)   # seek to end
            while not stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                m = _fw.search(line)
                if m:
                    _, action, proto, src, dst, sport, dport = m.groups()
                    event_queue.append({
                        "event_type": "network",
                        "src_ip": src, "dst_ip": dst,
                        "src_port": int(sport), "dst_port": int(dport),
                        "protocol": proto.upper(),
                        "bytes_sent": 0, "bytes_received": 0,
                        "duration": 0.0, "packet_count": 1,
                        "action": "allow" if action.upper() == "ALLOW" else "deny",
                        "description": f"Windows Firewall {action}: {src}:{sport} → {dst}:{dport}/{proto}",
                        "raw_log": line.strip(),
                    })
    except PermissionError:
        logger.warning("Cannot read Windows Firewall log — run agent as Administrator")


def _run_windows(event_queue: List[Dict]):
    logger.info("🪟  Windows mode — reading Security + System Event Logs + Firewall log")
    stop_event = threading.Event()
    threads = [
        threading.Thread(target=_wevtutil_tail,
                         args=("Security", event_queue, stop_event), daemon=True),
        threading.Thread(target=_wevtutil_tail,
                         args=("System",   event_queue, stop_event), daemon=True),
        threading.Thread(target=_win_firewall_tail,
                         args=(event_queue, stop_event), daemon=True),
    ]
    for t in threads:
        t.start()
    logger.info(f"🎯 Windows agent running. Events → {API_BASE}")
    try:
        _event_loop(event_queue)
    finally:
        stop_event.set()


# ─── macOS runner ──────────────────────────────────────────────────────────────

# macOS predicates for `log stream`
_MACOS_PREDICATES = [
    'process == "sshd"',
    'process == "sudo"',
    'process == "socketfilterfw"',
    'eventMessage CONTAINS "authentication failure"',
    'eventMessage CONTAINS "Invalid user"',
    'eventMessage CONTAINS "Failed password"',
]

_MAC_SSH_ACCEPT = re.compile(r"Accepted (\w+) for (\S+) from ([\d\.]+) port (\d+)")
_MAC_SSH_FAIL   = re.compile(r"Failed (\w+) for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)")
_MAC_SUDO       = re.compile(r"sudo:\s+(\S+) : .* COMMAND=(.*)")
_MAC_FIREWALL   = re.compile(r"(Allow|Deny) (TCP|UDP) .* (\d+\.\d+\.\d+\.\d+):(\d+) <-> (\d+\.\d+\.\d+\.\d+):(\d+)")


def _parse_macos_line(line: str) -> Optional[Dict]:
    m = _MAC_SSH_ACCEPT.search(line)
    if m:
        _, user, src_ip, port = m.groups()
        return {"event_type": "login", "src_ip": src_ip, "dst_ip": HOSTNAME,
                "src_port": int(port), "dst_port": 22, "protocol": "TCP",
                "bytes_sent": 512, "bytes_received": 512, "duration": 0.5, "packet_count": 10,
                "username": user, "action": "allow",
                "description": f"SSH login accepted: {user} from {src_ip}:{port}",
                "raw_log": line.strip()}
    m = _MAC_SSH_FAIL.search(line)
    if m:
        _, user, src_ip, port = m.groups()
        return {"event_type": "login", "src_ip": src_ip, "dst_ip": HOSTNAME,
                "src_port": int(port), "dst_port": 22, "protocol": "TCP",
                "bytes_sent": 128, "bytes_received": 128, "duration": 0.1, "packet_count": 3,
                "username": user, "action": "deny",
                "description": f"SSH login FAILED: {user} from {src_ip}:{port}",
                "raw_log": line.strip()}
    m = _MAC_SUDO.search(line)
    if m:
        user, cmd = m.groups()
        return {"event_type": "system", "src_ip": "127.0.0.1", "dst_ip": HOSTNAME,
                "bytes_sent": 0, "bytes_received": 0, "duration": 0.0, "packet_count": 0,
                "username": user, "action": "allow", "resource": cmd.strip(),
                "description": f"sudo: {user} ran {cmd.strip()}",
                "raw_log": line.strip()}
    m = _MAC_FIREWALL.search(line)
    if m:
        action, proto, src, sport, dst, dport = m.groups()
        return {"event_type": "network", "src_ip": src, "dst_ip": dst,
                "src_port": int(sport), "dst_port": int(dport), "protocol": proto,
                "bytes_sent": 0, "bytes_received": 0, "duration": 0.0, "packet_count": 1,
                "action": action.lower(),
                "description": f"macOS Firewall {action}: {src}:{sport} → {dst}:{dport}/{proto}",
                "raw_log": line.strip()}
    return None


def _run_macos(event_queue: List[Dict]):
    """Stream macOS Unified Log via `log stream --predicate`."""
    logger.info("🍎  macOS mode — streaming Unified Log via `log stream`")
    predicate = " OR ".join(f"({p})" for p in _MACOS_PREDICATES)
    cmd = ["log", "stream", "--predicate", predicate, "--style", "syslog"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
    except FileNotFoundError:
        logger.error("`log` command not found — macOS 10.12+ required")
        return

    logger.info(f"🎯 macOS agent running. Events → {API_BASE}")

    def _reader():
        for line in proc.stdout:
            evt = _parse_macos_line(line)
            if evt:
                event_queue.append(evt)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    try:
        _event_loop(event_queue)
    finally:
        proc.terminate()


# ─── Shared event loop (all platforms) ────────────────────────────────────────

def _event_loop(event_queue: List[Dict]):
    """Drain event_queue in batches and POST to API. Runs until KeyboardInterrupt."""
    try:
        _last_dedup_log = time.time()
        while True:
            time.sleep(POLL_INTERVAL)
            if event_queue:
                batch = event_queue[:BATCH_SIZE]
                del event_queue[:BATCH_SIZE]
                post_events(batch)
            if time.time() - _last_dedup_log > 300:
                suppressed = _deduplicator.stats()
                if suppressed:
                    logger.info(f"🔇 Deduplicator: {suppressed} duplicates suppressed")
                _last_dedup_log = time.time()
    except KeyboardInterrupt:
        logger.info("\nStopping AI-SOC log agent…")


if __name__ == "__main__":
    main()
