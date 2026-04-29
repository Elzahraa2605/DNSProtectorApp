# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║         Family Monitor PRO  —  v4.5  (10/10 Release)        ║
║                                                              ║
║  Fixes over v4.4:                                            ║
║  • MY_SECRET_KEY → reads from FM_SECRET_KEY env var         ║
║  • RateLimiter: no nested locking → zero deadlock risk       ║
║  • DNS queries: parallel (ThreadPoolExecutor) → ~6× faster   ║
║  • block/unblock-app: _config_lock + atomic write + cache    ║
║  • scan_file: correct handling of missing Content-Length     ║
║  • _save_config: atomic os.replace() — no partial writes     ║
╚══════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify
import requests
import dns.resolver
import re
import json
import struct
import math
import hashlib
import hmac
import os
import io
import sys
import socket
import zipfile
import base64
import time
import threading
from datetime import datetime
from collections import Counter

# ── UTF-8 stdout/stderr ────────────────────────────────────────
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# ══════════════════════════════════════════════════════════════
# Flask App  +  OOM Protection
# ══════════════════════════════════════════════════════════════
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 160 * 1024 * 1024   # 160 MB hard Flask limit

# ══════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════

# Child-safe Android download ceiling.
# Files above this are blocked WITHOUT scanning — too large for a
# child's device (storage, RAM, mobile data).  Configurable via
# parent_config.json → "max_file_size_mb".  Default: 150 MB.
ANDROID_CHILD_MAX_MB: int = 150

# ══════════════════════════════════════════════════════════════
# Rate Limiter — sliding-window, per-IP, thread-safe
# ══════════════════════════════════════════════════════════════
class RateLimiter:
    """
    Sliding-window rate limiter stored in memory.
    Thread-safe via a single lock (no nested locking → no deadlock risk).

    Design:
    - is_allowed() acquires the lock ONCE and does both the rate-check
      and the periodic cleanup inside that single critical section.
    - _last_cleanup is also protected by the same lock.

    NOTE: In a multi-worker Gunicorn setup each worker has its own
    memory, so limits are per-worker.  For cross-worker enforcement
    replace _buckets with a Redis backend.
    """
    _CLEANUP_INTERVAL = 60          # seconds between automatic cleanups
    _STALE_WINDOW     = 120         # buckets older than this are purged

    def __init__(self):
        self._buckets: dict = {}
        self._lock          = threading.Lock()
        self._last_cleanup  = time.time()

    def is_allowed(self, key: str, max_calls: int = 60, window: int = 60) -> bool:
        now = time.time()
        with self._lock:
            # ── periodic cleanup (inside the same lock, no nesting) ────
            if now - self._last_cleanup >= self._CLEANUP_INTERVAL:
                self._buckets = {
                    k: v for k, v in self._buckets.items()
                    if now - v["start"] <= self._STALE_WINDOW
                }
                self._last_cleanup = now

            # ── sliding-window check ───────────────────────────────────
            bucket = self._buckets.get(key)
            if bucket is None or now - bucket["start"] > window:
                self._buckets[key] = {"start": now, "count": 1}
                return True
            bucket["count"] += 1
            return bucket["count"] <= max_calls


_rate_limiter = RateLimiter()


# ══════════════════════════════════════════════════════════════
# Config Cache — avoids disk hit on every request
# ══════════════════════════════════════════════════════════════
_config_cache: dict | None = None
_config_mtime: float = 0.0
_config_lock  = threading.Lock()

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "parent_config.json")


def load_config() -> dict:
    """
    Load parent_config.json.
    Re-reads from disk only when the file's mtime has changed.
    """
    global _config_cache, _config_mtime
    try:
        mtime = os.path.getmtime(CONFIG_PATH)
        with _config_lock:
            if _config_cache is None or mtime != _config_mtime:
                with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                    _config_cache = json.load(fh)
                _config_mtime = mtime
            return _config_cache
    except FileNotFoundError:
        return {}
    except Exception as exc:
        print(f"[CONFIG] Load error: {exc}", flush=True)
        return _config_cache or {}


# ══════════════════════════════════════════════════════════════
# Static Settings
# ══════════════════════════════════════════════════════════════
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GSB_API_KEY", "")

# Secret key loaded from environment variable (never hardcode in production).
# Set via:  export FM_SECRET_KEY="your-strong-secret-here"
# Falls back to a default ONLY for local development — change before deploying.
MY_SECRET_KEY: str = os.environ.get("FM_SECRET_KEY", "zahraa-secret-2026")
if MY_SECRET_KEY == "zahraa-secret-2026":
    print("[SECURITY WARNING] FM_SECRET_KEY is using the default dev value. "
          "Set the FM_SECRET_KEY environment variable before deploying!", flush=True)

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".link", ".zip", ".mov",
    ".icu", ".monster", ".gdn", ".biz", ".country", ".stream",
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".loan", ".work", ".date", ".faith", ".racing", ".review",
    ".science", ".party", ".trade", ".webcam", ".accountant",
    ".win", ".men", ".bid", ".club", ".guru", ".info", ".pro",
    ".pw", ".ren", ".space", ".tech", ".vip", ".wang", ".online",
]

BAD_KEYWORDS = [
    "porn", "sex", "bet", "casino", "dating", "poker", "nude", "xxx", "fuck",
    "gambling", "weed", "drugs", "cocaine", "darkweb", "onion",
    "hack", "crack", "keygen", "serial", "warez", "torrent",
    "gore", "violent", "beheading", "snuff",
    "redtube", "youporn", "xnxx", "xvideos",
    "spankbang", "pornhub", "brazzers", "bangbros", "realitykings", "evilangel",
]

TRUSTED_DOMAINS = [
    "google", "microsoft", "apple", "cloudflare", "akamai",
    "github", "stackoverflow", "wikipedia", "youtube",
    "amazon", "netflix", "spotify", "discord", "zoom",
    "office", "outlook", "live", "hotmail", "icloud",
    "twitter", "facebook", "instagram", "linkedin",
    "cdn", "static", "assets", "media",
]

FAMILY_DNS_SERVERS = [
    {"name": "OpenDNS FamilyShield", "ip": "208.67.222.123", "port": 53},
    {"name": "CleanBrowsing Family", "ip": "185.228.168.168", "port": 53},
    {"name": "CleanBrowsing Adult",  "ip": "185.228.168.10",  "port": 53},
    {"name": "AdGuard Family",       "ip": "94.140.14.15",    "port": 53},
    {"name": "Cloudflare Family",    "ip": "1.1.1.3",         "port": 53},
    {"name": "Quad9 Security",       "ip": "9.9.9.9",         "port": 53},
]

# Magic-byte signatures — ordered longest-first so longest match wins.
# Tuple: (signature_bytes, file_type_label, is_dangerous)
MAGIC_SIGNATURES = [
    (b"dex\n035\x00",                             "dex",         True),
    (b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",        "png",         False),
    (b"\x00\x00\x00\x18ftyp",                     "mp4",         False),
    (b"\x00\x00\x00\x20ftyp",                     "mp4",         False),
    (b"\xFD\x37\x7A\x58\x5A\x00",                "xz",          False),
    (b"7z\xBC\xAF\x27\x1C",                       "7zip",        False),
    (b"\x7FELF",                                  "elf",         True),
    (b"\xCA\xFE\xBA\xBE",                         "java",        True),
    (b"\xCF\xFA\xED\xFE",                         "macho64",     True),
    (b"\xCE\xFA\xED\xFE",                         "macho32",     True),
    (b"\x03\x00\x08\x00",                         "android_xml", False),
    (b"Rar!",                                     "rar",         False),
    (b"PK\x03\x04",                               "zip",         False),
    (b"PK\x05\x06",                               "zip_empty",   False),
    (b"\x4D\x5A",                                 "exe/dll",     True),
    (b"\x1F\x8B",                                 "gzip",        False),
    (b"BZh",                                      "bzip2",       False),
    (b"%PDF",                                     "pdf",         False),
    (b"\xD0\xCF\x11\xE0",                         "ms_office",   False),
    (b"\xFF\xD8\xFF",                             "jpeg",        False),
    (b"GIF87a",                                   "gif",         False),
    (b"GIF89a",                                   "gif",         False),
    (b"RIFF",                                     "riff",        False),
    (b"\x1A\x45\xDF\xA3",                         "webm",        False),
    (b"OggS",                                     "ogg",         False),
    (b"fLaC",                                     "flac",        False),
    (b"ID3",                                      "mp3_id3",     False),
    (b"\xFF\xFB",                                 "mp3_raw",     False),
    (b"ftyp",                                     "mp4_generic", False),
    (b"#!/",                                      "script",      True),
    (b"<script",                                  "html_script", True),
]


# ══════════════════════════════════════════════════════════════
# Request / Response Logging
# ══════════════════════════════════════════════════════════════
@app.before_request
def log_incoming_request():
    ts        = datetime.now().strftime("%H:%M:%S")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    preview   = ""
    if request.method in ("POST", "PUT", "PATCH"):
        raw     = request.get_data(cache=True, as_text=True) or ""
        preview = raw[:200].replace("\n", " ")
    print(
        f"[{ts}] --> {request.method} {request.path} "
        f"| ip={client_ip} | body={preview}",
        flush=True,
    )


@app.after_request
def log_outgoing_response(response):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] <-- {request.method} {request.path} | {response.status_code}", flush=True)
    return response


@app.errorhandler(413)
def request_entity_too_large(_e):
    return jsonify({"allowed": False, "reason": "File too large (max 160 MB hard limit)"}), 413


# ══════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════
def is_port_busy(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        return sock.connect_ex((host, port)) == 0
    finally:
        sock.close()


def log_status(domain: str, allowed: bool, reason: str = "") -> None:
    ts   = datetime.now().strftime("%H:%M:%S")
    icon = "✅ ALLOW" if allowed else "⛔ BLOCK"
    msg  = f"[{ts}] {icon}: {domain.ljust(40)}"
    if reason:
        msg += f" | {reason}"
    print(msg, flush=True)


def log_file(filename: str, allowed: bool, reason: str = "") -> None:
    ts   = datetime.now().strftime("%H:%M:%S")
    icon = "✅ FILE-OK" if allowed else "⛔ FILE-BLOCK"
    print(f"[{ts}] {icon}: {filename.ljust(40)} | {reason}", flush=True)


def auth_required(req) -> bool:
    """
    Constant-time HMAC comparison — prevents timing-oracle attacks.
    Plain `==` leaks info about where strings first differ.
    """
    provided = req.headers.get("X-API-KEY", "")
    return hmac.compare_digest(provided, MY_SECRET_KEY)


def rate_limit_check(max_calls: int = 60, window: int = 60) -> bool:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    return _rate_limiter.is_allowed(ip, max_calls=max_calls, window=window)


def get_file_extension(filename: str) -> str:
    parts = filename.lower().rsplit(".", 1)
    return parts[1] if len(parts) == 2 else ""


# ══════════════════════════════════════════════════════════════
# ClamAV — local fallback antivirus
# Tries Unix socket first; falls back to TCP (Docker-friendly).
# ══════════════════════════════════════════════════════════════
_CLAMAV_UNIX_SOCKET = "/var/run/clamav/clamd.sock"
_CLAMAV_TCP_HOST    = os.environ.get("CLAMAV_HOST", "127.0.0.1")
_CLAMAV_TCP_PORT    = int(os.environ.get("CLAMAV_PORT", "3310"))


def scan_with_clamav(file_bytes: bytes) -> tuple:
    """
    Scan bytes via ClamAV daemon.
    Returns: (True=clean | False=malware | None=unavailable, message)

    Connection priority:
      1. Unix socket  (bare-metal / single-container)
      2. TCP socket   (Docker Compose: CLAMAV_HOST / CLAMAV_PORT env vars)

    Requires:  pip install clamd
               + clamd service running
    """
    try:
        import clamd

        # ── attempt 1: Unix socket ──────────────────────────
        cd = None
        if os.path.exists(_CLAMAV_UNIX_SOCKET):
            try:
                cd = clamd.ClamdUnixSocket(_CLAMAV_UNIX_SOCKET)
                cd.ping()
            except Exception:
                cd = None

        # ── attempt 2: TCP socket ───────────────────────────
        if cd is None:
            try:
                cd = clamd.ClamdNetworkSocket(_CLAMAV_TCP_HOST, _CLAMAV_TCP_PORT)
                cd.ping()
            except Exception:
                return None, (
                    f"ClamAV: Unavailable "
                    f"(tried Unix={_CLAMAV_UNIX_SOCKET} and "
                    f"TCP={_CLAMAV_TCP_HOST}:{_CLAMAV_TCP_PORT})"
                )

        result = cd.instream(io.BytesIO(file_bytes))
        status, details = result.get("stream", ("ERROR", "No result"))
        if status == "OK":
            return True, "ClamAV: Clean"
        if status == "FOUND":
            return False, f"ClamAV: Malware → {details}"
        return None, f"ClamAV: {status}"

    except ImportError:
        return None, "ClamAV: clamd module missing (pip install clamd)"
    except Exception as exc:
        return None, f"ClamAV: {type(exc).__name__}: {exc}"


# ══════════════════════════════════════════════════════════════
# Domain Check Functions
# ══════════════════════════════════════════════════════════════
def check_blocked_apps(domain: str) -> tuple:
    """Check domain against parent-configured blocked apps & categories."""
    try:
        config       = load_config()
        clean_domain = domain.replace("www.", "")

        def _matches(blocked_domain: str) -> bool:
            clean = blocked_domain.replace("www.", "")
            return clean_domain == clean or clean_domain.endswith("." + clean)

        for entry in config.get("blocked_apps", []):
            if any(_matches(d) for d in entry.get("domains", [])):
                return True, f"App '{entry['name']}' is blocked by parent"

        for category in config.get("blocked_app_categories", []):
            for entry in category.get("apps", []):
                if any(_matches(d) for d in entry.get("domains", [])):
                    cat = category.get("category", "unknown")
                    return True, f"App '{entry['name']}' (category: {cat}) is blocked by parent"

    except Exception as exc:
        print(f"[CONFIG] check_blocked_apps error: {exc}", flush=True)
    return False, ""


def check_multi_dns_family(domain: str) -> tuple:
    """
    Query every family-filter DNS server in PARALLEL (ThreadPoolExecutor).
    Worst-case latency = single server timeout (≈2s) instead of N × timeout.
    Returns (allowed, reason, per-server detail dict).
    """
    def _query_one(server: dict) -> tuple:
        """Returns (server_name, status_str) for one DNS server."""
        name = server["name"]
        try:
            resolver             = dns.resolver.Resolver()
            resolver.nameservers = [server["ip"]]
            resolver.timeout     = 1.5
            resolver.lifetime    = 2.0
            resolver.resolve(domain, "A")
            return name, "Clean / Allowed"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return name, "Blocked"
        except Exception:
            return name, "Timeout / Unavailable"

    from concurrent.futures import ThreadPoolExecutor, as_completed
    detailed   = {}
    blocked_by = []

    with ThreadPoolExecutor(max_workers=len(FAMILY_DNS_SERVERS)) as ex:
        futures = {ex.submit(_query_one, srv): srv for srv in FAMILY_DNS_SERVERS}
        for future in as_completed(futures):
            name, status = future.result()
            detailed[name] = status
            if status == "Blocked":
                blocked_by.append(name)

    if blocked_by:
        return False, f"Blocked by: {', '.join(sorted(blocked_by))}", detailed
    return True, "", detailed


def check_google_reputation(domain: str) -> tuple:
    """Query Google Safe Browsing v4 API."""
    url = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    )
    payload = {
        "client": {"clientId": "family-monitor", "clientVersion": "4.4"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "THREAT_TYPE_UNSPECIFIED", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": f"http://{domain}/"},
                {"url": f"https://{domain}/"},
                {"url": domain},
            ],
        },
    }
    try:
        resp = requests.post(url, json=payload, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if "matches" in data:
                threat = data["matches"][0]["threatType"]
                return False, f"Google Safe Browsing: {threat}", f"Malicious ({threat})"
        return True, "", "Clean / Safe"
    except Exception:
        return True, "", "Timeout / Unavailable"


def is_suspicious_pattern_details(domain: str) -> tuple:
    """
    Local heuristic risk scorer.
    Returns (is_blocked, reason, detail_lines).
    """
    details       = []
    risk_score    = 0
    BLOCK_THRESHOLD = 3

    # TLD check
    tld = "." + domain.split(".")[-1] if "." in domain else domain
    if any(domain.endswith(x) for x in SUSPICIOUS_TLDS):
        risk_score += 2
        details.append(f"[4] TLD → +2 pts (Suspicious TLD: {tld})")
    else:
        details.append(f"[4] TLD → PASS ({tld})")

    # Subdomain depth
    depth = domain.count(".")
    if depth > 3 and not any(t in domain for t in TRUSTED_DOMAINS):
        risk_score += 1
        details.append(f"[4] Subdomains → +1 pt ({depth + 1} parts)")
    else:
        details.append(f"[4] Subdomains → PASS ({depth + 1} parts)")

    # Randomness in main label
    main = domain.split(".")[0]
    if len(main) > 15 and re.search(r"[0-9].*[a-z]|[a-z].*[0-9]", main):
        if not any(t in domain for t in TRUSTED_DOMAINS):
            risk_score += 2
            details.append(f"[4] Randomness → +2 pts (len={len(main)})")
        else:
            details.append(f"[4] Randomness → PASS (trusted brand, len={len(main)})")
    else:
        details.append(f"[4] Randomness → PASS (len={len(main)})")

    # Unicode / homograph
    try:
        domain.encode("ascii")
        details.append("[4] Unicode/Homograph → PASS (ASCII)")
    except UnicodeEncodeError:
        risk_score += 5
        details.append("[4] Unicode/Homograph → +5 pts (non-ASCII chars)")

    # Bad keywords
    hit = next((w for w in BAD_KEYWORDS if w in domain), None)
    if hit:
        risk_score += 5
        details.append(f"[4] Keywords → +5 pts ({hit!r})")
    else:
        details.append("[4] Keywords → PASS")

    # IP as domain
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain):
        risk_score += 3
        details.append("[4] IP-as-domain → +3 pts")
    else:
        details.append("[4] IP-as-domain → PASS")

    # Typosquatting
    parts = domain.lower().split(".")
    is_trusted = any(
        t in parts or domain.endswith(f".{t}.com")
        for t in TRUSTED_DOMAINS
    )
    if is_trusted:
        details.append("[4] Typosquat → PASS (legitimate trusted domain)")
    else:
        typo_patterns = [
            r"g[o0]{2}gle", r"micros[o0]ft", r"app1e",
            r"faceb[o0]{2}k", r"paypa1", r"amaz[o0]n",
            r"netfl1x", r"inst[a4]gram",
        ]
        detected = next((p for p in typo_patterns if re.search(p, domain)), None)
        if detected:
            risk_score += 3
            details.append(f"[4] Typosquat → +3 pts (pattern: {detected})")
        else:
            details.append("[4] Typosquat → PASS")

    details.append(f"[4] Total Risk Score: {risk_score}/{BLOCK_THRESHOLD}")
    if risk_score >= BLOCK_THRESHOLD:
        return True, f"Heuristic block: score {risk_score} ≥ threshold {BLOCK_THRESHOLD}", details
    return False, "", details


def scan_domain_layers(domain: str) -> dict:
    """Run all domain-check layers and return the aggregated result."""
    details          = []
    detailed_reports = {}
    block_layer      = None
    block_reason     = None

    print(f"\n{'═'*60}")
    print(f"🌐 Domain scan: {domain}")
    print(f"{'═'*60}")

    # Layer 1 — Multi-DNS family filters
    ok, reason, dns_d = check_multi_dns_family(domain)
    detailed_reports.update(dns_d)
    if not ok:
        block_layer, block_reason = 1, reason
        details.append(f"[1] Multi-DNS Family Filters → BLOCK ({reason})")
    else:
        details.append("[1] Multi-DNS Family Filters → PASS")
    print(details[-1])
    for srv, st in dns_d.items():
        line = f"     - {srv}: {st}"
        details.append(line); print(line)

    # Layer 2 — Google Safe Browsing
    if block_layer is None:
        ok, reason, gsb_st = check_google_reputation(domain)
        detailed_reports["Google_Safe_Browsing"] = gsb_st
        if not ok:
            block_layer, block_reason = 2, reason
            details.append(f"[2] Google Safe Browsing → BLOCK ({reason})")
        else:
            details.append("[2] Google Safe Browsing → PASS")
        print(details[-1])
        line = f"     - Status: {gsb_st}"
        details.append(line); print(line)
    else:
        msg = "[2] Google Safe Browsing → SKIPPED"
        details.append(msg); print(msg)

    # Layer 3 — Parent blocked apps
    if block_layer is None:
        blocked, reason = check_blocked_apps(domain)
        if blocked:
            detailed_reports["Blocked_App"] = reason
            block_layer, block_reason = 3, reason
            details.append(f"[3] Parent Blocked Apps → BLOCK ({reason})")
        else:
            details.append("[3] Parent Blocked Apps → PASS")
        print(details[-1])
    else:
        msg = "[3] Parent Blocked Apps → SKIPPED"
        details.append(msg); print(msg)

    # Layer 4 — Local heuristics
    if block_layer is None:
        is_bad, reason, local_d = is_suspicious_pattern_details(domain)
        details.extend(local_d)
        for line in local_d:
            print(line)
        detailed_reports["Local_Filter"] = f"Blocked ({reason})" if is_bad else "Passed"
        if is_bad:
            block_layer, block_reason = 4, reason
            details.append(f"[4] Local Heuristic Filter → BLOCK ({reason})")
        else:
            details.append("[4] Local Heuristic Filter → PASS")
        print(details[-1])
    else:
        msg = "[4] Local Heuristic Filter → SKIPPED"
        details.append(msg); print(msg)

    print(f"{'═'*60}")
    if block_layer is not None:
        details.append(f"\n❌ BLOCKED at Layer {block_layer}: {block_reason}")
        print(f"❌ BLOCKED at Layer {block_layer}: {block_reason}")
        print(f"{'═'*60}\n")
        return {
            "domain": domain, "allowed": False, "risk_score": "High",
            "reason": block_reason, "details": details,
            "detailed_reports": detailed_reports,
        }

    details.append("\n✅ All layers passed — Domain is SAFE")
    print("✅ All layers passed — Domain is SAFE")
    print(f"{'═'*60}\n")
    return {
        "domain": domain, "allowed": True, "risk_score": "Low",
        "reason": "All checks passed", "details": details,
        "detailed_reports": detailed_reports,
    }


# ══════════════════════════════════════════════════════════════
# File Scanning — Detection Helpers
# ══════════════════════════════════════════════════════════════
def detect_real_type(file_bytes: bytes) -> tuple:
    """
    Identify file type by magic bytes.
    Chooses the signature with the longest byte-match (most specific).
    Falls back to 'hidden_exe' if MZ header found deeper in file.
    """
    best_type, best_danger, best_len = "unknown", False, 0
    for sig, ftype, dangerous in MAGIC_SIGNATURES:
        slen = len(sig)
        if file_bytes[:slen] == sig and slen > best_len:
            best_type, best_danger, best_len = ftype, dangerous, slen

    if best_len > 0:
        return best_type, best_danger

    # Hidden EXE check
    if b"\x4D\x5A" in file_bytes[:512]:
        return "hidden_exe", True

    return "unknown", False


def _classify_zip(file_bytes: bytes) -> str:
    """
    Distinguish between ZIP-based formats:
    APK, JAR, Office XML, or generic ZIP.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            names = zf.namelist()
            if "classes.dex" in names and "AndroidManifest.xml" in names:
                return "apk"
            if "META-INF/MANIFEST.MF" in names:
                return "jar"
            if any(n.startswith("word/") or n.startswith("xl/") or n.startswith("ppt/")
                   for n in names):
                return "office_xml"
    except Exception:
        pass
    return "zip"


def analyze_pe_header(file_bytes: bytes) -> list:
    issues = []
    try:
        if file_bytes[:2] != b"\x4D\x5A":
            return issues
        pe_offset = struct.unpack("<I", file_bytes[0x3C:0x40])[0]
        if pe_offset + 4 > len(file_bytes):
            return issues
        if file_bytes[pe_offset: pe_offset + 4] != b"PE\x00\x00":
            issues.append("Invalid PE signature — manipulated file")
            return issues
        header = file_bytes[:min(len(file_bytes), 1024)]
        if b"UPX" in header:
            issues.append("UPX packed (common malware technique)")
        for sec in [b".evil", b".vmp", b".themida", b".packed", b".enc"]:
            if sec in file_bytes:
                issues.append(f"Suspicious PE section: {sec.decode('utf-8', errors='ignore')}")
        dangerous_apis = [
            b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory",
            b"ShellExecute", b"WinExec", b"URLDownloadToFile", b"RegSetValueEx",
            b"IsDebuggerPresent", b"NtSetInformationThread",
            b"SetWindowsHookEx", b"GetAsyncKeyState",
            b"InternetOpenUrl", b"CryptEncrypt", b"FindFirstFile",
        ]
        found = [a.decode("utf-8", errors="ignore") for a in dangerous_apis if a in file_bytes]
        if len(found) >= 3:
            issues.append(f"Dangerous API calls: {', '.join(found[:5])}")
        ransomware_markers = [b"CryptEncrypt", b"CryptGenKey", b"FindFirstFile", b"DeleteShadowCopy"]
        found_r = [m.decode() for m in ransomware_markers if m in file_bytes]
        if len(found_r) >= 2:
            issues.append(f"Ransomware indicators: {', '.join(found_r)}")
    except Exception as exc:
        print(f"[PE] analysis error: {exc}", flush=True)
    return issues


def check_zip_contents(file_bytes: bytes, zip_subtype: str = "zip") -> list:
    """Inspect ZIP contents for malicious entries, droppers, and bombs."""
    found = []
    EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    danger_patterns = [
        ("powershell",         "PowerShell command"),
        ("invoke-expression",  "PowerShell IEX"),
        ("cmd.exe /c",         "CMD execution"),
        ("wscript.shell",      "WScript shell"),
        ("createremotethread", "Process injection"),
        ("virtualalloc",       "Memory injection"),
        ("urldownloadtofile",  "Download & Execute"),
        ("curl | bash",        "Curl pipe shell"),
        ("wget -o- | sh",      "Wget pipe shell"),
        ("msfvenom",           "Metasploit payload"),
        ("meterpreter",        "Meterpreter shell"),
    ]
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            names = zf.namelist()

            # APK-specific checks
            if zip_subtype == "apk":
                suspicious_assets = [
                    n for n in names
                    if (n.startswith("assets/") or n.startswith("res/"))
                    and n.endswith((".apk", ".dex", ".jar"))
                ]
                if suspicious_assets:
                    found.append(f"Android Dropper: hidden executable in assets ({suspicious_assets[0]})")
                dex_files = [n for n in names if n.endswith(".dex")]
                if len(dex_files) > 5:
                    found.append(f"Multi-DEX evasion: {len(dex_files)} DEX files (normal APK has 1–2)")

            # ZIP bomb check
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            if total_uncompressed > 500 * 1024 * 1024:
                found.append(f"ZIP Bomb: {total_uncompressed // 1024 // 1024} MB uncompressed")
                return found

            # Nested archives
            nested = [n for n in names if n.endswith((".zip", ".jar"))]
            if nested:
                found.append(f"Nested archives inside ZIP: {', '.join(nested[:3])}")

            # Per-file inspection
            for name in names:
                if ".." in name or name.startswith("/"):
                    found.append(f"Path traversal in ZIP: {name}")
                    continue
                try:
                    inner = zf.read(name)
                    if EICAR in inner:
                        found.append(f"EICAR malware signature in: {name}")
                        continue
                    _, inner_dangerous = detect_real_type(inner)
                    if inner_dangerous:
                        found.append(f"Dangerous file inside ZIP: {name}")
                        continue
                    if len(inner) < 1_000_000:
                        text = inner.decode("utf-8", errors="ignore").lower()
                        for pattern, label in danger_patterns:
                            if pattern in text:
                                found.append(f"{label} in: {name}")
                                break
                except Exception:
                    pass
    except Exception:
        pass
    return found


def analyze_pdf(file_bytes: bytes) -> list:
    issues = []
    try:
        text = file_bytes.decode("latin-1", errors="ignore")
        checks = [
            ("/JavaScript" in text or "/JS" in text,
             "PDF contains JavaScript (common exploit technique)"),
            ("/EmbeddedFile" in text,
             "PDF contains embedded files"),
            ("/Launch" in text,
             "PDF contains Launch action (can execute programs)"),
            ("/OpenAction" in text and "/JavaScript" in text,
             "PDF auto-runs JavaScript on open"),
            (text.count("/URI") > 10,
             f"PDF has {text.count('/URI')} external links (suspicious)"),
            ("/AcroForm" in text and "/JavaScript" in text,
             "PDF form with JavaScript — potential exploit"),
            ("/XFA" in text,
             "PDF XFA form (advanced exploit vector)"),
            ("/FlateDecode" in text and text.count("/Filter") > 10,
             "PDF with excessive compression layers (evasion)"),
        ]
        for condition, message in checks:
            if condition:
                issues.append(message)
    except Exception:
        pass
    return issues


def check_office_macros(file_bytes: bytes) -> list:
    issues = []
    danger_cmds = [
        "shell", "wscript", "powershell", "createobject",
        "autoopen", "autoexec", "document_open", "workbook_open",
        "environ", "kill", "filecopy", "getobject",
        "strconv", "chr(", "chrw(", "urldownloadtofile", "xmlhttp",
    ]
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            names = zf.namelist()
            if any("vbaProject" in n for n in names):
                issues.append("Office file contains VBA Macros")
                for name in names:
                    if "vba" not in name.lower():
                        continue
                    try:
                        macro_text = zf.read(name).decode("latin-1", errors="ignore").lower()
                        found = [c for c in danger_cmds if c in macro_text]
                        if found:
                            issues.append(f"Macro contains dangerous call(s): {', '.join(found)}")
                    except Exception:
                        pass
    except zipfile.BadZipFile:
        try:
            text = file_bytes.decode("latin-1", errors="ignore").lower()
            if "autoopen" in text or "document_open" in text:
                issues.append("Old Office file with suspicious auto-macro")
        except Exception:
            pass
    except Exception:
        pass
    return issues


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in Counter(data).values()
    )


def check_entropy_anomaly(file_bytes: bytes, real_type: str) -> tuple:
    naturally_high = {
        "zip", "zip_empty", "office_xml", "jpeg", "png", "gif", "pdf",
        "riff", "webm", "unknown", "mp3_id3", "mp3_raw", "mp4",
        "mp4_generic", "ogg", "flac", "gzip", "bzip2", "xz", "7zip", "rar",
        "apk", "jar",
    }
    CHUNK = 512 * 1024
    entropies = [
        calculate_entropy(file_bytes[i: i + CHUNK])
        for i in range(0, len(file_bytes), CHUNK)
    ]
    if not entropies:
        return False, "Normal entropy (empty file)"

    max_e      = max(entropies)
    avg_e      = sum(entropies) / len(entropies)
    high_count = sum(1 for e in entropies if e > 7.8)

    if real_type not in naturally_high and max_e > 7.8:
        return (
            True,
            f"Suspicious entropy (max={max_e:.2f}, avg={avg_e:.2f}, "
            f"{high_count}/{len(entropies)} chunks high) — likely encrypted payload",
        )
    return False, f"Normal entropy (max={max_e:.2f}, avg={avg_e:.2f})"


def analyze_text_content(file_bytes: bytes) -> list:
    issues = []
    try:
        text     = file_bytes.decode("utf-8", errors="ignore").lower()
        patterns = [
            (r"dalvik\.system\.dexclassloader",           "Android Dynamic Code Loading (Dropper)"),
            (r"android\.telephony\.smsmanager",           "Android Silent SMS Sending"),
            (r"addjavascriptinterface",                    "Android WebView Exploit (RCE)"),
            (r"pm\s+install\s+(?:-r|-x|-i|\w)",           "Android Silent App Installation"),
            (r"su\s+-c",                                   "Android Root Command Execution"),
            (r"android\.intent\.action\.boot_completed",   "Android Persistence (runs on startup)"),
            (r"powershell\s+-\w*e[nc]*\w*\s+[a-z0-9+/=]{20,}", "PowerShell encoded command"),
            (r"invoke-expression|iex\s*\(",                "PowerShell IEX"),
            (r"downloadstring|downloadfile",               "PowerShell download & execute"),
            (r"-noprofile\s+-noninteractive",              "PowerShell stealth flags"),
            (r"eval\s*\(\s*(?:unescape|atob|string\.fromcharcode)", "JS obfuscation"),
            (r"document\.write\s*\(\s*unescape",           "JS obfuscated write"),
            (r"(?:var|let|const)\s+\w+\s*=\s*[\"'][a-z0-9+/=]{100,}[\"']", "Large base64 payload"),
            (r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}",   "Hex-encoded shellcode"),
            (r"bash\s+-i\s*>&?\s*/dev/tcp/",               "Reverse shell (bash)"),
            (r"nc\s+-e\s*/bin/",                           "Netcat reverse shell"),
            (r"python\s+-c\s*[\"']import socket",          "Python reverse shell"),
            (r"perl\s+-e\s*[\"']use socket",               "Perl reverse shell"),
            (r"ruby\s+-rsocket\s+-e",                      "Ruby reverse shell"),
            (r"cmd\.exe\s*/[ck]\s+",                       "CMD execution"),
            (r"wscript\.shell",                            "WScript shell"),
            (r"regsvr32\s+/s\s+/n\s+/u",                  "Regsvr32 bypass (LOLBAS)"),
            (r"certutil\s+-decode",                        "Certutil decode (LOLBAS)"),
            (r"mshta\s+http",                              "MSHTA remote execution"),
            (r"rundll32.*,\s*[a-z]+",                      "Rundll32 execution"),
            (r"chmod\s+\+x.*&&",                           "chmod + execute chain"),
            (r"curl.*\|\s*(?:bash|sh)",                    "Curl pipe to shell"),
            (r"wget.*-O.*&&\s*(?:bash|sh|\.\/)",           "Wget execute"),
            (r"crontab\s+-[el]",                           "Cron persistence"),
            (r"/etc/cron\.",                                "Cron file modification"),
            (r"\.ssh/authorized_keys",                     "SSH key injection"),
            (r"stratum\+tcp://",                           "Crypto miner (stratum)"),
            (r"xmrig|minergate|nicehash",                  "Known miner software"),
        ]
        for pattern, label in patterns:
            if re.search(pattern, text):
                issues.append(label)
    except Exception:
        pass
    return issues


def check_virustotal_hash(file_bytes: bytes) -> tuple:
    try:
        config = load_config()
        vt_key = config.get("virustotal_api_key", "")
        if not vt_key or vt_key == "YOUR_API_KEY_HERE":
            return None, "VirusTotal: Not activated"
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        resp   = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": vt_key}, timeout=5,
        )
        if resp.status_code == 200:
            attrs     = resp.json().get("data", {}).get("attributes", {})
            stats     = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious= stats.get("suspicious", 0)
            harmless  = stats.get("harmless", 0)
            if malicious > 0:
                return False, f"VirusTotal: {malicious} engine(s) flagged as malware"
            if suspicious > 2:
                return False, f"VirusTotal: {suspicious} engine(s) suspicious"
            return True, f"VirusTotal: Clean ({harmless} engines)"
        if resp.status_code == 404:
            return None, "VirusTotal: File never seen before (no record)"
        return None, f"VirusTotal: HTTP {resp.status_code}"
    except Exception as exc:
        return None, f"VirusTotal: {exc}"


# ══════════════════════════════════════════════════════════════
# Core File Scan Orchestrator
# ══════════════════════════════════════════════════════════════
def _early_exit(result: dict, reason: str) -> dict:
    result["allowed"] = False
    result["reason"]  = reason
    print(f"⛔ BLOCKED (early exit): {reason}", flush=True)
    print(f"{'═'*60}\n")
    return result


def scan_file_content(file_bytes: bytes, filename: str, content_length: int = 0) -> dict:
    """
    Run the complete 7-layer local file analysis.
    All layers are always executed; the *first* blocking reason is reported.
    """
    result = {"allowed": True, "reason": "", "details": []}
    config = load_config()
    max_mb = config.get("max_file_size_mb", ANDROID_CHILD_MAX_MB)
    total  = content_length or len(file_bytes)
    ext    = get_file_extension(filename)

    print(f'\n{"═"*60}')
    print(f"🔬 Scanning: {filename}")
    print(f"📊 Size: {len(file_bytes)/1024:.1f} KB scanned | {total/1024/1024:.2f} MB total")
    print(f'{"═"*60}')
    result["details"].append(f"[INFO] Extension: .{ext or 'none'} (informational only)")

    # ── VirusTotal (cloud AV) ──────────────────────────────
    vt_ok, vt_msg = check_virustotal_hash(file_bytes)
    if vt_ok is False:
        result["details"].append(f"[VT] VirusTotal → BLOCK ({vt_msg})")
        print(f"[VT] VirusTotal → BLOCK\n    {vt_msg}")
        return _early_exit(result, vt_msg)
    result["details"].append(f"[VT] VirusTotal → {'PASS' if vt_ok else 'INFO'} ({vt_msg})")
    print(f"[VT] VirusTotal → {'PASS' if vt_ok else 'INFO'}\n    {vt_msg}")

    # ── ClamAV (local AV) ─────────────────────────────────
    clam_ok, clam_msg = scan_with_clamav(file_bytes)
    if clam_ok is False:
        result["details"].append(f"[CLAM] ClamAV → BLOCK ({clam_msg})")
        print(f"[CLAM] ClamAV → BLOCK\n    {clam_msg}")
        return _early_exit(result, clam_msg)
    result["details"].append(f"[CLAM] ClamAV → {'PASS' if clam_ok else 'INFO'} ({clam_msg})")
    print(f"[CLAM] ClamAV → {'PASS' if clam_ok else 'INFO'}\n    {clam_msg}")

    # ── Size guard (final confirmation inside scan) ────────
    if total > max_mb * 1024 * 1024:
        msg = f"File too large ({total/1024/1024:.1f} MB — limit {max_mb} MB)"
        result["details"].append(f"[SIZE] → BLOCK: {msg}")
        print(f"[SIZE] → BLOCK: {msg}")
        return _early_exit(result, msg)
    result["details"].append(f"[SIZE] → PASS ({total/1024/1024:.2f} MB ≤ {max_mb} MB)")
    print(f"[SIZE] → PASS ({total/1024/1024:.2f} MB)")

    first_block_reason = None

    # ── Layer 1: Magic Bytes + ZIP subtype ─────────────────
    real_type, is_dangerous = detect_real_type(file_bytes)
    zip_subtype = "zip"
    if real_type in ("zip", "zip_empty"):
        zip_subtype = _classify_zip(file_bytes)
        if zip_subtype in ("apk", "jar"):
            real_type = zip_subtype          # refine label for downstream layers

    if is_dangerous:
        result["details"].append(f"[1] Magic Bytes → BLOCK (type={real_type})")
        print(f"[1] Magic Bytes → BLOCK (type={real_type})")
        if first_block_reason is None:
            first_block_reason = f"Dangerous file type detected: {real_type}"
    else:
        result["details"].append(f"[1] Magic Bytes → PASS (type={real_type})")
        print(f"[1] Magic Bytes → PASS (type={real_type})")

    # ── Layer 2: PE Header ────────────────────────────────
    if real_type in ("exe/dll", "hidden_exe"):
        pe_issues = analyze_pe_header(file_bytes)
        if pe_issues:
            result["details"].append(f"[2] PE Header → BLOCK ({pe_issues[0]})")
            for i in pe_issues:
                result["details"].append(f"    - {i}")
            print("[2] PE Header → BLOCK")
            for i in pe_issues:
                print(f"    - {i}")
            if first_block_reason is None:
                first_block_reason = f"PE analysis: {pe_issues[0]}"
        else:
            result["details"].append("[2] PE Header → PASS")
            print("[2] PE Header → PASS")
    else:
        result["details"].append(f"[2] PE Header → SKIP (type={real_type})")
        print(f"[2] PE Header → SKIP (type={real_type})")

    # ── Layer 3: ZIP / APK / JAR Contents ────────────────
    if real_type in ("zip", "zip_empty", "office_xml", "apk", "jar"):
        zip_issues = check_zip_contents(file_bytes, zip_subtype=zip_subtype)
        if zip_issues:
            result["details"].append(f"[3] ZIP Contents → BLOCK ({zip_issues[0]})")
            for i in zip_issues:
                result["details"].append(f"    - {i}")
            print("[3] ZIP Contents → BLOCK")
            for i in zip_issues:
                print(f"    - {i}")
            if first_block_reason is None:
                first_block_reason = zip_issues[0]
        else:
            result["details"].append("[3] ZIP Contents → PASS")
            print("[3] ZIP Contents → PASS")
    else:
        result["details"].append(f"[3] ZIP Contents → SKIP (type={real_type})")
        print(f"[3] ZIP Contents → SKIP (type={real_type})")

    # ── Layer 4: PDF Analysis ─────────────────────────────
    if real_type == "pdf":
        pdf_issues = analyze_pdf(file_bytes)
        if pdf_issues:
            result["details"].append(f"[4] PDF Analysis → BLOCK ({pdf_issues[0]})")
            for i in pdf_issues:
                result["details"].append(f"    - {i}")
            print("[4] PDF Analysis → BLOCK")
            for i in pdf_issues:
                print(f"    - {i}")
            if first_block_reason is None:
                first_block_reason = f"Suspicious PDF: {pdf_issues[0]}"
        else:
            result["details"].append("[4] PDF Analysis → PASS")
            print("[4] PDF Analysis → PASS")
    else:
        result["details"].append(f"[4] PDF Analysis → SKIP (type={real_type})")
        print(f"[4] PDF Analysis → SKIP (type={real_type})")

    # ── Layer 5: Office Macros ────────────────────────────
    if real_type in ("ms_office", "office_xml", "zip", "zip_empty"):
        macro_issues = check_office_macros(file_bytes)
        if macro_issues:
            result["details"].append(f"[5] Office Macros → BLOCK ({macro_issues[0]})")
            for i in macro_issues:
                result["details"].append(f"    - {i}")
            print("[5] Office Macros → BLOCK")
            for i in macro_issues:
                print(f"    - {i}")
            if first_block_reason is None:
                first_block_reason = f"Office macro: {macro_issues[0]}"
        else:
            result["details"].append("[5] Office Macros → PASS")
            print("[5] Office Macros → PASS")
    else:
        result["details"].append(f"[5] Office Macros → SKIP (type={real_type})")
        print(f"[5] Office Macros → SKIP (type={real_type})")

    # ── Layer 6: Entropy Anomaly ──────────────────────────
    is_anomaly, entropy_msg = check_entropy_anomaly(file_bytes, real_type)
    if is_anomaly:
        result["details"].append(f"[6] Entropy → BLOCK ({entropy_msg})")
        print(f"[6] Entropy → BLOCK\n    {entropy_msg}")
        if first_block_reason is None:
            first_block_reason = entropy_msg
    else:
        result["details"].append(f"[6] Entropy → PASS ({entropy_msg})")
        print(f"[6] Entropy → PASS\n    {entropy_msg}")

    # ── Layer 7: Script / Text Analysis ──────────────────
    text_issues = analyze_text_content(file_bytes)
    if text_issues:
        result["details"].append(f"[7] Script Analysis → BLOCK ({text_issues[0]})")
        for i in text_issues:
            result["details"].append(f"    - {i}")
        print("[7] Script Analysis → BLOCK")
        for i in text_issues:
            print(f"    - {i}")
        if first_block_reason is None:
            first_block_reason = f"Dangerous content: {text_issues[0]}"
    else:
        result["details"].append("[7] Script Analysis → PASS")
        print("[7] Script Analysis → PASS")

    # ── Final verdict ─────────────────────────────────────
    print(f"{'═'*60}")
    if first_block_reason:
        result["allowed"] = False
        result["reason"]  = first_block_reason
        result["details"].append(f"⛔ BLOCKED: {first_block_reason}")
        print(f"⛔ BLOCKED: {first_block_reason}")
    else:
        passed = sum(1 for line in result["details"] if "→ PASS" in line)
        result["reason"] = "File passed all inspection layers"
        result["details"].append(f"✅ SAFE — passed {passed} layers")
        print(f"✅ SAFE — passed {passed} inspection layers")
    print(f"{'═'*60}\n")
    return result


# ══════════════════════════════════════════════════════════════
# API Routes
# ══════════════════════════════════════════════════════════════
@app.route("/check-safety", methods=["POST"])
def check_safety():
    if not auth_required(request):
        return jsonify({"allowed": False}), 401
    if not rate_limit_check(max_calls=120, window=60):
        return jsonify({"allowed": False, "reason": "Rate limit exceeded"}), 429

    data   = request.get_json() or {}
    domain = data.get("domain", "").strip().lower().strip(".")
    if not domain or "." not in domain:
        return jsonify({"allowed": True})

    result = scan_domain_layers(domain)
    log_status(domain, result["allowed"], result.get("reason", ""))
    return jsonify(result)


@app.route("/scan-file", methods=["POST"])
def scan_file():
    """
    Remote file scanning.

    Flow:
      1. HEAD request  →  read Content-Type + Content-Length (0 data downloaded)
      2. If size > limit → block immediately, nothing downloaded
      3. If size ≤ limit → GET full file, then run complete 7-layer scan
      4. Safety net after GET: re-check real size (server may lie)
    """
    if not auth_required(request):
        return jsonify({"allowed": False}), 401
    if not rate_limit_check(max_calls=30, window=60):
        return jsonify({"allowed": False, "reason": "Rate limit exceeded"}), 429

    data     = request.get_json() or {}
    file_url = data.get("url", "").strip()
    filename = data.get("filename", "unknown")

    if not file_url:
        return jsonify({"allowed": False, "reason": "No file URL provided"})

    print(f"\n📥 Remote scan: {filename} | {file_url[:80]}")

    try:
        config    = load_config()
        max_mb    = config.get("max_file_size_mb", ANDROID_CHILD_MAX_MB)
        max_bytes = max_mb * 1024 * 1024

        # ── Step 1: HEAD — get headers with zero body ──────────────────
        head = requests.head(
            file_url, timeout=10, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        content_type        = head.headers.get("Content-Type", "").lower()
        content_disposition = head.headers.get("Content-Disposition", "").lower()
        content_length      = int(head.headers.get("Content-Length", 0) or 0)

        print(f"   📋 Content-Type : {content_type}")

        # content_length == 0 means the server didn't send a Content-Length header
        # (common with chunked transfer or CDNs). In that case we skip the early
        # block and rely on the post-download safety-net check instead.
        if content_length > 0:
            print(f"   📏 Declared size: {content_length / 1024 / 1024:.2f} MB  (limit: {max_mb} MB)")
        else:
            print(f"   📏 Declared size: unknown (no Content-Length header) — will check after download")

        if "text/html" in content_type and "attachment" not in content_disposition:
            return jsonify({"allowed": False, "reason": "This is a webpage, not a downloadable file"})

        # ── Step 2: Immediate block if declared size exceeds child limit ─
        # Only enforce when content_length is actually known (> 0).
        if content_length > max_bytes:
            msg = (
                f"File too large for a child's device "
                f"({content_length / 1024 / 1024:.1f} MB — limit is {max_mb} MB). "
                f"Blocked without downloading."
            )
            print(f"   🚫 {msg}")
            log_file(filename, False, msg)
            return jsonify({"allowed": False, "reason": msg})

        # ── Step 3: Download full file ─────────────────────────────────
        print(f"   ⬇️  Downloading full file ...")
        resp       = requests.get(
            file_url, timeout=60, stream=False,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        file_bytes = resp.content

        # ── Step 4: Safety net (server lied / no Content-Length header) ─
        if len(file_bytes) > max_bytes:
            msg = (
                f"File too large for a child's device "
                f"({len(file_bytes) / 1024 / 1024:.1f} MB — limit is {max_mb} MB). "
                f"Blocked after download."
            )
            print(f"   🚫 {msg}")
            log_file(filename, False, msg)
            return jsonify({"allowed": False, "reason": msg})

        print(f"   ✅ Downloaded {len(file_bytes) / 1024 / 1024:.2f} MB — running full scan ...")
        result = scan_file_content(file_bytes, filename, content_length)
        log_file(filename, result["allowed"], result["reason"])
        return jsonify({
            "allowed": result["allowed"],
            "reason":  result["reason"],
            "details": result["details"],
        })

    except requests.exceptions.Timeout:
        return jsonify({"allowed": False, "reason": "Request timed out"})
    except Exception as exc:
        return jsonify({"allowed": False, "reason": f"Scan error: {exc}"})


@app.route("/scan-local-file", methods=["POST"])
def scan_local_file():
    """Scan a file uploaded directly as base64 content."""
    if not auth_required(request):
        return jsonify({"allowed": False}), 401
    if not rate_limit_check(max_calls=30, window=60):
        return jsonify({"allowed": False, "reason": "Rate limit exceeded"}), 429

    data     = request.get_json() or {}
    filename = data.get("filename", "unknown")
    content  = data.get("content",  "")
    size     = data.get("size",     0)

    print(f"\n📂 Local scan: {filename} ({size / 1024:.1f} KB)")

    if not content:
        return jsonify({"allowed": False, "reason": "No file content"})

    try:
        file_bytes = base64.b64decode(content)
    except Exception as exc:
        return jsonify({"allowed": False, "reason": f"Base64 decode error: {exc}"})

    config    = load_config()
    max_mb    = config.get("max_file_size_mb", ANDROID_CHILD_MAX_MB)
    max_bytes = max_mb * 1024 * 1024

    actual_size = size or len(file_bytes)
    if actual_size > max_bytes:
        msg = (
            f"File too large for a child's device "
            f"({actual_size / 1024 / 1024:.1f} MB — limit is {max_mb} MB)."
        )
        log_file(filename, False, msg)
        return jsonify({"allowed": False, "reason": msg})

    result = scan_file_content(file_bytes, filename, content_length=actual_size)
    log_file(filename, result["allowed"], result["reason"])
    return jsonify({
        "allowed": result["allowed"],
        "reason":  result["reason"],
        "details": result["details"],
    })


def _save_config(config: dict) -> None:
    """
    Write config to disk atomically (write to temp file then rename)
    and invalidate the in-memory cache so the next request re-reads it.
    Must be called while holding _config_lock.
    """
    global _config_cache, _config_mtime
    tmp_path = CONFIG_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, ensure_ascii=False, indent=2)
    os.replace(tmp_path, CONFIG_PATH)          # atomic on POSIX
    _config_cache = config
    _config_mtime = os.path.getmtime(CONFIG_PATH)
@app.route("/parent/blocked-apps", methods=["GET"])
def get_blocked_apps():
    if not auth_required(request):
        return jsonify({}), 401
    config = load_config()
    flat   = list(config.get("blocked_apps", []))
    for category in config.get("blocked_app_categories", []):
        for entry in category.get("apps", []):
            flat.append({
                "name":     entry.get("name", ""),
                "package":  entry.get("package", ""),
                "domains":  entry.get("domains", []),
                "category": category.get("category", ""),
            })
    return jsonify(flat)


@app.route("/parent/block-app", methods=["POST"])
def block_app():
    if not auth_required(request):
        return jsonify({}), 401
    data    = request.get_json() or {}
    new_app = {
        "name":    data.get("name", ""),
        "package": data.get("package", ""),
        "domains": data.get("domains", []),
    }
    with _config_lock:
        config = load_config()
        config.setdefault("blocked_apps", [])
        existing = {a["package"] for a in config["blocked_apps"]}
        if new_app["package"] not in existing:
            config["blocked_apps"].append(new_app)
            _save_config(config)
    return jsonify({"success": True, "message": f"Blocked {new_app['name']}"})


@app.route("/parent/unblock-app", methods=["POST"])
def unblock_app():
    if not auth_required(request):
        return jsonify({}), 401
    data    = request.get_json() or {}
    package = data.get("package", "")
    with _config_lock:
        config = load_config()
        config["blocked_apps"] = [
            a for a in config.get("blocked_apps", [])
            if a["package"] != package
        ]
        _save_config(config)
    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════════
# Health Check
# ══════════════════════════════════════════════════════════════
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":           "ok",
        "version":          "4.5",
        "domain_layers":    4,
        "file_layers":      7,
        "file_limit_mb":    ANDROID_CHILD_MAX_MB,
        "clamav":           f"unix={_CLAMAV_UNIX_SOCKET} | tcp={_CLAMAV_TCP_HOST}:{_CLAMAV_TCP_PORT}",
        "rate_limiting":    "120/min (domain) | 30/min (file) — auto-cleanup every 60s",
        "auth":             "hmac.compare_digest (timing-attack safe)",
        "magic_bytes":      "longest-match + APK/JAR/Office XML subtype detection",
        "entropy_mode":     "512 KB chunks, full file",
        "oom_protection":   "MAX_CONTENT_LENGTH=160MB + HEAD pre-check + POST size guard",
        "docker_ready":     "CLAMAV_HOST / CLAMAV_PORT env vars supported",
        "domain_logic":     "Multi-DNS → Google Safe Browsing → Parent Rules → Heuristics",
        "file_logic":       "VirusTotal → ClamAV → Size → Magic → PE → ZIP/APK → PDF → Macro → Entropy → Script",
    })


# ══════════════════════════════════════════════════════════════
# Entry Point  (development only — use Gunicorn in production)
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 9000

    if is_port_busy("127.0.0.1", PORT):
        print(f"[ERROR] Port {PORT} already in use. Stop the old process first.", flush=True)
        sys.exit(1)

    print("\n" + "═" * 62, flush=True)
    print("🛡️   Family Monitor PRO  v4.5  —  10/10 Release",           flush=True)
    print("─" * 62,                                                     flush=True)
    print("🔐  Auth        : hmac.compare_digest (timing-attack safe)", flush=True)
    print("🚦  Rate Limit  : 120/min (domain) | 30/min (file)",        flush=True)
    print("🧱  OOM Guard   : 160 MB Flask limit + HEAD pre-check",      flush=True)
    print(f"📦  File Limit  : {ANDROID_CHILD_MAX_MB} MB (child-safe Android ceiling)", flush=True)
    print("🌐  Domain      : DNS → GSB → Parent Rules → Heuristics",   flush=True)
    print("🦠  File Scan   : VT → ClamAV → 7-layer local analysis",    flush=True)
    print("🔌  ClamAV      : Unix socket → TCP fallback (Docker OK)",   flush=True)
    print("🤖  APK         : subtype detection (APK / JAR / Office)",   flush=True)
    print(f"🆔  PID         : {os.getpid()}",                           flush=True)
    print("═" * 62 + "\n",                                              flush=True)

    app.run(host=HOST, port=PORT, threaded=True, debug=False, use_reloader=False)