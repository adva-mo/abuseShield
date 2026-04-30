#!/usr/bin/env python3
"""
AbuseShield MVP — Fake Signup Simulation
=========================================
Sends two flows against a running AbuseShield instance to verify
that SecurityEvent JSON logs are produced with correct decisions and reasons.

Usage:
    # Terminal 1 — start a mock upstream (Python's built-in server is fine):
    python3 -m http.server 9090

    # Terminal 2 — start AbuseShield (shadow_mode must be true in config.json):
    ./abuseshield -config config.json 2>&1 | tee /tmp/abuseshield.log

    # Terminal 3 — run this script:
    python3 scripts/test_abuse.py

    # Pretty-print the captured SecurityEvent lines:
    grep '^{' /tmp/abuseshield.log | python3 -m json.tool

Requirements: Python 3.6+, no external dependencies.
"""

import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8080"

# ── Shared headers for each persona ─────────────────────────────────────────
# X-Forwarded-For uses TEST-NET addresses (RFC 5737) — non-routable, safe for docs.
# AbuseShield reads the leftmost XFF entry as the originating client IP.

BOT_HEADERS = {
    "User-Agent": "python-bot/1.0 (signup-spam)",
    "X-Forwarded-For": "198.51.100.42",   # TEST-NET-3 — simulated bot IP
}

HUMAN_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "X-Forwarded-For": "203.0.113.17",    # TEST-NET-3 — simulated real-user IP
}


# ── HTTP helper ──────────────────────────────────────────────────────────────

def request(method: str, path: str, headers: dict | None = None) -> tuple[int, bytes]:
    """Send a plain HTTP request; return (status_code, body_bytes)."""
    url = BASE + path
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception as exc:  # noqa: BLE001
        print(f"  [ERROR] {exc}", file=sys.stderr)
        return 0, b""


def separator(title: str) -> None:
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


# ── Flow A: Fake Signup (bot) ────────────────────────────────────────────────
#
# A scripted bot hits /register directly — no prior /home visit —
# and fires 8 requests in quick succession to exceed the burst window.
#
# Expected SecurityEvent pattern in the logs:
#   • First requests: decision=ALLOW,     reason="",               confidence=1.0
#                     (but reason="sequence_violation" from L2)
#                     → decision=SUSPICIOUS, reason="sequence_violation", confidence=0.7
#   • Later requests: decision=BLOCK,     reason="burst_detected",  confidence=0.95
#   All events:       shadow_mode=true  (request always forwarded in MVP)

def flow_a_fake_signup() -> None:
    separator("Flow A — Fake Signup (bot skips /home, rapid /register POSTs)")
    print(f"  User-Agent: {BOT_HEADERS['User-Agent']}")
    print()

    num_requests = 11
    delay_sec    = 0.05   # 50 ms → 20 req/s, well above the 5-burst / 2s default

    for i in range(1, num_requests + 1):
        status, _ = request("POST", "/register", headers=BOT_HEADERS)
        # AbuseShield in shadow mode always proxies, so we get a real upstream
        # response (or 502 if no upstream is running — both are expected).
        label = "proxied" if status not in (403, 429) else "blocked"
        print(f"  [{i:02d}] POST /register → HTTP {status}  ({label})")
        time.sleep(delay_sec)

    print()
    print("  Expected SecurityEvents in AbuseShield stdout:")
    print("    - First few:  decision=SUSPICIOUS, reason=sequence_violation, confidence=0.7")
    print("    - After burst: decision=BLOCK,      reason=burst_detected,    confidence=0.95")


# ── Flow B: Real User ────────────────────────────────────────────────────────
#
# A human browser visits /home first, waits a moment, then POSTs to /register.
#
# Expected SecurityEvent pattern:
#   GET  /home     → decision=ALLOW, reason="",    confidence=1.0
#   POST /register → decision=ALLOW, reason="",    confidence=1.0
#                    (seenHome=true → no sequence_violation)

def flow_b_real_user() -> None:
    separator("Flow B — Real User (/home first, then /register)")
    print(f"  User-Agent: {HUMAN_HEADERS['User-Agent'][:60]}...")
    print()

    status, _ = request("GET", "/home", headers=HUMAN_HEADERS)
    print(f"  [01] GET  /home     → HTTP {status}")

    wait = 1.5
    print(f"  [--] thinking for {wait}s (simulating human behaviour)…")
    time.sleep(wait)

    status, _ = request("POST", "/register", headers=HUMAN_HEADERS)
    print(f"  [02] POST /register → HTTP {status}")

    print()
    print("  Expected SecurityEvents in AbuseShield stdout:")
    print("    - GET  /home     → decision=ALLOW, reason=''")
    print("    - POST /register → decision=ALLOW, reason=''  (seenHome=true, no violation)")


# ── Flow C: Kill-Switch test (optional) ─────────────────────────────────────
#
# Enable the kill switch and verify that requests are still forwarded
# (and that AbuseShield logs a warning, not a SecurityEvent block).

def flow_c_kill_switch(secret: str = "change-me") -> None:
    separator("Flow C — Kill-Switch toggle (optional, requires correct secret)")

    status, _ = request(
        "POST",
        "/admin/kill-switch?enable=true",
        headers={"X-Kill-Switch-Secret": secret},
    )
    print(f"  Enable kill-switch → HTTP {status}  (expected 200)")

    status, _ = request("POST", "/register", headers=BOT_HEADERS)
    print(f"  POST /register with KS active → HTTP {status}  (should still proxy, no SecurityEvent)")

    status, _ = request(
        "POST",
        "/admin/kill-switch?enable=false",
        headers={"X-Kill-Switch-Secret": secret},
    )
    print(f"  Disable kill-switch → HTTP {status}  (expected 200)")
    print()
    print("  Check AbuseShield stdout for '[AbuseShield] kill switch ACTIVE' log line.")


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    print()
    print("AbuseShield — Fake Signup Simulation")
    print(f"Target: {BASE}")
    print()
    print("Make sure AbuseShield is running and piping its stdout to a log file:")
    print("  ./abuseshield -config config.json 2>&1 | tee /tmp/abuseshield.log")
    print()
    print("After the script, inspect SecurityEvent JSON with:")
    print("  grep '^{' /tmp/abuseshield.log | python3 -m json.tool")

    flow_a_fake_signup()
    print()
    time.sleep(1.0)   # brief pause so Flow A events have flushed before Flow B starts

    flow_b_real_user()
    print()

    # Run kill-switch flow only when --kill-switch flag is passed.
    if "--kill-switch" in sys.argv:
        flow_c_kill_switch()

    separator("Done")
    print("  Review AbuseShield logs to verify SecurityEvent decisions and reasons.")
    print()


if __name__ == "__main__":
    main()
