#!/usr/bin/env python3
"""
Scan new files in ~/Downloads against VirusTotal, alert via ntfy.

- Polls ~/Downloads every 10s
- On a new stable file: SHA-256 hash → VirusTotal hash lookup (no upload)
- Notifies on: clean / low-risk / threat / unknown-to-VT
- Caches scanned hashes so restarts don't re-alert
"""
import hashlib
import json
import os
import sys
import time
import threading
from pathlib import Path

try:
    import requests
except ImportError:
    sys.stderr.write("Missing 'requests'. Install with: pip3 install --user requests\n")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent
DOWNLOADS = Path.home() / "Downloads"
CACHE = ROOT / "scanned_hashes.txt"
ENV_FILE = ROOT / ".env"

# ---- load .env ----
def load_env():
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
load_env()

VT_KEY = os.environ.get("VT_API_KEY", "").strip()
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "rl-downloads").strip()
POLL = int(os.environ.get("POLL_SECONDS", "10"))
MIN_FLAGS = int(os.environ.get("MIN_FLAGS_FOR_THREAT", "3"))

if not VT_KEY:
    sys.stderr.write("VT_API_KEY not set. Add it to ~/download-scanner/.env and restart.\n")
    sys.exit(1)

# ---- partial-download extensions to skip until they finalize ----
SKIP_EXT = (".crdownload", ".download", ".part", ".tmp", ".partial")
SKIP_PREFIX = (".",)

# ---- cache ----
def load_cache():
    if CACHE.exists():
        return set(CACHE.read_text().splitlines())
    return set()

def cache_add(sha):
    with CACHE.open("a") as f:
        f.write(sha + "\n")

SCANNED = load_cache()

# ---- helpers ----
def log(msg):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {msg}"
    print(line, flush=True)

def notify(title, body, priority=3, tags=""):
    try:
        payload = {
            "topic": NTFY_TOPIC,
            "title": title,
            "message": body,
            "priority": priority,
        }
        if tags:
            payload["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
        requests.post("https://ntfy.sh/", json=payload, timeout=10)
    except Exception as e:
        log(f"ntfy error: {e}")

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def wait_stable(path, checks=10, interval=2):
    """Wait until file size is stable for two consecutive checks."""
    last = -1
    for _ in range(checks):
        time.sleep(interval)
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return False
        if size > 0 and size == last:
            return True
        last = size
    return False

def vt_lookup(sha):
    r = requests.get(
        f"https://www.virustotal.com/api/v3/files/{sha}",
        headers={"x-apikey": VT_KEY},
        timeout=20,
    )
    if r.status_code == 404:
        return None
    if r.status_code == 429:
        log("VirusTotal rate-limited, backing off 60s")
        time.sleep(60)
        return vt_lookup(sha)
    r.raise_for_status()
    return r.json().get("data", {}).get("attributes", {})

def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"

# ---- core scan ----
def scan(path: Path):
    try:
        if not wait_stable(path):
            log(f"gave up waiting for stability: {path.name}")
            return
        size = path.stat().st_size
        sha = sha256(path)
        if sha in SCANNED:
            log(f"already scanned: {path.name}")
            return
        SCANNED.add(sha)
        cache_add(sha)

        log(f"scanning {path.name} ({human_size(size)}) sha={sha[:12]}…")
        attrs = vt_lookup(sha)

        if attrs is None:
            notify(
                f"❓ Unknown file: {path.name}",
                f"VirusTotal has never seen this file.\nSize: {human_size(size)}\nSHA-256: {sha[:16]}…\nOpen with care — consider uploading to virustotal.com for a full scan.",
                priority=3,
                tags="question,grey_question",
            )
            log(f"unknown to VT: {path.name}")
            return

        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        signer = attrs.get("signature_info", {}).get("signers") if attrs.get("signature_info") else None

        if malicious >= MIN_FLAGS:
            notify(
                f"⚠️ Threat detected: {path.name}",
                f"{malicious}/{total} engines flagged this file as malicious ({suspicious} suspicious).\n\nDO NOT OPEN. Consider deleting.\n\nSize: {human_size(size)}\nSHA-256: {sha[:16]}…",
                priority=5,
                tags="rotating_light,warning",
            )
            log(f"THREAT: {path.name} {malicious}/{total}")
        elif malicious > 0 or suspicious > 0:
            notify(
                f"🟡 Low-confidence hit: {path.name}",
                f"{malicious} malicious, {suspicious} suspicious of {total} engines. Likely false positive but review.\n\nSize: {human_size(size)}",
                priority=3,
                tags="yellow_circle",
            )
            log(f"low-hit: {path.name} {malicious}/{total}")
        else:
            body = f"0/{total} engines flagged this. Safe to open.\nSize: {human_size(size)}"
            if signer:
                body += f"\nSigned: {signer}"
            notify(
                f"✅ Clean: {path.name}",
                body,
                priority=2,
                tags="white_check_mark",
            )
            log(f"clean: {path.name} 0/{total}")
    except Exception as e:
        log(f"error scanning {path.name}: {e}")

# ---- watcher ----
def should_skip(name):
    return name.startswith(SKIP_PREFIX) or name.endswith(SKIP_EXT)

def snapshot():
    return {p.name for p in DOWNLOADS.iterdir() if p.is_file()}

def main():
    log(f"download-scanner started — watching {DOWNLOADS} every {POLL}s, alerts to ntfy.sh/{NTFY_TOPIC}")
    notify(
        "🛡️ Download scanner online",
        f"Watching {DOWNLOADS}. New downloads will be auto-scanned against VirusTotal.",
        priority=2,
        tags="shield",
    )
    seen = snapshot()
    while True:
        time.sleep(POLL)
        try:
            current = snapshot()
        except FileNotFoundError:
            log(f"{DOWNLOADS} missing, waiting…")
            continue
        new = current - seen
        seen = current
        for name in new:
            if should_skip(name):
                continue
            p = DOWNLOADS / name
            threading.Thread(target=scan, args=(p,), daemon=True).start()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("stopped")
