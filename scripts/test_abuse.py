#!/usr/bin/env python3
"""
AbuseShield — High-Volume Abuse Simulation
===========================================
Simulates realistic attack and real-user traffic against a running AbuseShield
instance, then prints a live metrics summary from the /metrics endpoint.

Usage:
    python3 scripts/mock_upstream.py         # Terminal 1: mock upstream on :9090
    ./abuseshield -config config.json \\
        2>&1 | tee /tmp/shield.log           # Terminal 2: AbuseShield on :8080
    python3 scripts/test_abuse.py            # Terminal 3: this script
    python3 scripts/print_events.py /tmp/shield.log   # inspect SecurityEvents

Flags:
    --kill-switch   Also run the kill-switch toggle flow (Flow D)

Requirements: Python 3.9+, no external dependencies.
"""

import concurrent.futures
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8080"

_total_sent = 0
_total_lock = threading.Lock()


def _inc(n: int = 1) -> None:
    global _total_sent
    with _total_lock:
        _total_sent += n


# ── HTTP helper ──────────────────────────────────────────────────────────────

def req(method: str, path: str, headers: dict | None = None) -> int:
    """Fire a single request; return the HTTP status code."""
    url = BASE + path
    r = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def separator(title: str) -> None:
    print()
    print("=" * 64)
    print(f"  {title}")
    print("=" * 64)


# ── Metrics helper ────────────────────────────────────────────────────────────

def fetch_metrics() -> dict[str, int]:
    """Pull /metrics and parse Prometheus plaintext into {name: value}."""
    out: dict[str, int] = {}
    try:
        with urllib.request.urlopen(BASE + "/metrics", timeout=5) as resp:
            for line in resp.read().decode().splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                if len(parts) == 2:
                    try:
                        out[parts[0]] = int(float(parts[1]))
                    except ValueError:
                        pass
    except Exception:
        pass
    return out


# ── Flow A: Single-bot burst (100 requests, 20 concurrent workers) ────────────
#
# One bot entity (fixed IP + UA) hammers /register with no prior /home visit.
# With the default config (entity_burst=5, entity_rate_per_sec=2.5), the first
# few requests pass or are flagged as SUSPICIOUS (sequence_violation), then the
# token bucket empties and subsequent requests are BLOCK (burst_detected).
#
# Expected SecurityEvent breakdown (approximate, shadow_mode=true → all proxied):
#   First 1-5 requests  → SUSPICIOUS  (sequence_violation, confidence=0.70)
#   Request 6+          → BLOCK       (burst_detected,      confidence=0.95)

BOT_A_HEADERS = {
    "User-Agent": "python-bot/2.0 (signup-spam)",
    "X-Forwarded-For": "198.51.100.42",
}

def _fire_a(_: int) -> int:
    status = req("POST", "/register", headers=BOT_A_HEADERS)
    _inc()
    return status


def flow_a_single_bot_burst() -> None:
    num = 100
    workers = 20
    separator(f"Flow A — Single-bot burst  ({num} POST /register, {workers} concurrent workers)")
    print(f"  Entity:       IP=198.51.100.42  UA={BOT_A_HEADERS['User-Agent']}")
    print(f"  Requests:     {num} × POST /register  (no prior /home visit)")
    print(f"  Concurrency:  {workers} parallel workers")
    print()
    print("  Expected SecurityEvents (shadow_mode=true — all requests still proxied):")
    print("    First ~5  →  SUSPICIOUS  reason=sequence_violation  confidence=0.70")
    print("    Remaining →  BLOCK       reason=burst_detected      confidence=0.95")
    print()

    counters: dict[int, int] = {}
    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for status in pool.map(_fire_a, range(num)):
            counters[status] = counters.get(status, 0) + 1
    elapsed = time.monotonic() - t0

    print(f"  Completed {num} requests in {elapsed:.2f}s  "
          f"({num / elapsed:.0f} req/s)")
    for code, cnt in sorted(counters.items()):
        label = "proxied (shadow)" if code not in (403, 429) else "blocked"
        print(f"    HTTP {code}: {cnt:>4}×  ({label})")


# ── Flow B: Distributed bot swarm (8 IPs × 15 requests) ─────────────────────
#
# Eight distinct bot IPs each send 15 rapid /register POSTs — no /home visit.
# Each entity trips the burst detector independently; useful for verifying that
# the per-entity sharding works correctly across multiple source IPs.
#
# Expected: all entities hit BLOCK after ~5 requests; total 120 requests sent.

BOT_B_UA = "python-swarm/1.0 (distributed-signup)"

BOT_B_IPS = [
    "192.0.2.1",  "192.0.2.2",  "192.0.2.3",  "192.0.2.4",
    "192.0.2.5",  "192.0.2.6",  "192.0.2.7",  "192.0.2.8",
]


def _fire_b(ip: str) -> tuple[str, dict[int, int]]:
    counters: dict[int, int] = {}
    for _ in range(15):
        status = req("POST", "/register", headers={
            "User-Agent": BOT_B_UA,
            "X-Forwarded-For": ip,
        })
        counters[status] = counters.get(status, 0) + 1
        _inc()
    return ip, counters


def flow_b_distributed_swarm() -> None:
    n_ips = len(BOT_B_IPS)
    reqs_each = 15
    total = n_ips * reqs_each
    separator(
        f"Flow B — Distributed swarm  ({n_ips} IPs × {reqs_each} requests = {total} total)"
    )
    print(f"  User-Agent:  {BOT_B_UA}")
    print(f"  Source IPs:  {', '.join(BOT_B_IPS)}")
    print(f"  Each entity: {reqs_each} × POST /register  (no prior /home)")
    print()
    print("  Expected: each IP independently trips burst_detected after ~5 requests.")
    print()

    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_ips) as pool:
        results = list(pool.map(_fire_b, BOT_B_IPS))
    elapsed = time.monotonic() - t0

    all_counters: dict[int, int] = {}
    for ip, counters in results:
        for code, cnt in counters.items():
            all_counters[code] = all_counters.get(code, 0) + cnt

    print(f"  Completed {total} requests in {elapsed:.2f}s  "
          f"({total / elapsed:.0f} req/s)")
    for code, cnt in sorted(all_counters.items()):
        label = "proxied (shadow)" if code not in (403, 429) else "blocked"
        print(f"    HTTP {code}: {cnt:>4}×  ({label})")


# ── Flow C: Legitimate user (/home → pause → /register) ──────────────────────
#
# A real human browser visits /home first, waits 1.5 s, then POSTs /register.
# AbuseShield should mark both requests ALLOW (seenHome=true, rate within limits).
#
# Expected SecurityEvents:
#   GET  /home     → ALLOW  reason=""  confidence=1.0
#   POST /register → ALLOW  reason=""  confidence=1.0  (seenHome=true)

HUMAN_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "X-Forwarded-For": "203.0.113.17",
}


def flow_c_real_user() -> None:
    separator("Flow C — Real user  (GET /home → 1.5 s pause → POST /register)")
    print(f"  User-Agent:  {HUMAN_HEADERS['User-Agent'][:60]}…")
    print(f"  Source IP:   {HUMAN_HEADERS['X-Forwarded-For']}")
    print()
    print("  Expected: both requests → ALLOW  (seenHome=true, well within rate limits)")
    print()

    status = req("GET", "/home", headers=HUMAN_HEADERS)
    _inc()
    print(f"  [01] GET  /home     → HTTP {status}")

    wait = 1.5
    print(f"  [--] pause {wait}s (simulating human think-time)…")
    time.sleep(wait)

    status = req("POST", "/register", headers=HUMAN_HEADERS)
    _inc()
    print(f"  [02] POST /register → HTTP {status}")


# ── Flow D: Kill-switch toggle (optional) ────────────────────────────────────
#
# Enables the kill switch, fires one request (should bypass all detection,
# no SecurityEvent emitted), then disables it again.

def flow_d_kill_switch(secret: str = "change-me") -> None:
    separator("Flow D — Kill-switch toggle  (optional, requires correct secret)")

    status = req("POST", "/admin/kill-switch?enable=true",
                 headers={"X-Kill-Switch-Secret": secret})
    print(f"  Enable kill-switch   → HTTP {status}  (expected 200)")

    status = req("POST", "/register", headers=BOT_A_HEADERS)
    _inc()
    print(f"  POST /register (KS)  → HTTP {status}  (proxied, no SecurityEvent)")

    status = req("POST", "/admin/kill-switch?enable=false",
                 headers={"X-Kill-Switch-Secret": secret})
    print(f"  Disable kill-switch  → HTTP {status}  (expected 200)")
    print()
    print("  Check AbuseShield stdout for '[AbuseShield] kill switch ACTIVE'.")


# ── Metrics summary ───────────────────────────────────────────────────────────

def print_metrics_summary() -> None:
    separator("Metrics summary  (GET /metrics)")
    m = fetch_metrics()
    if not m:
        print("  Could not reach /metrics — is AbuseShield running?")
        return

    def show(label: str, key: str) -> None:
        v = m.get(key)
        print(f"    {label:<34}  {v if v is not None else '—'}")

    print("  Traffic")
    show("Allowed (proxied)",               "abuseshield_allowed_requests_total")
    show("Blocked (0 in shadow mode)",      "abuseshield_blocked_requests_total")

    print("\n  L0 Rate Limiter (enforcement)")
    show("By IP rate limit",    'abuseshield_blocked_by_reason_total{reason="ip"}')
    show("By API key limit",    'abuseshield_blocked_by_reason_total{reason="api_key"}')
    show("By hot-key cooldown", 'abuseshield_blocked_by_reason_total{reason="cooldown"}')

    print("\n  Detection signals (L1/L2 — fire in shadow mode too)")
    show("burst_detected     (L1)", 'abuseshield_detected_by_reason_total{reason="burst_detected"}')
    show("sequence_violation (L2)", 'abuseshield_detected_by_reason_total{reason="sequence_violation"}')

    print("\n  SecurityEvents")
    show("Logged",            'abuseshield_security_events_total{status="logged"}')
    show("Dropped (buf full)",'abuseshield_security_events_total{status="dropped"}')
    show("Active entities",   "abuseshield_active_entities_count")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print()
    print("AbuseShield — High-Volume Abuse Simulation")
    print(f"Target: {BASE}")
    print()
    print("Prerequisites:")
    print("  Terminal 1: python3 scripts/mock_upstream.py")
    print("  Terminal 2: ./abuseshield -config config.json 2>&1 | tee /tmp/shield.log")
    print()
    print("After this script, inspect SecurityEvents with:")
    print("  python3 scripts/print_events.py /tmp/shield.log")

    flow_a_single_bot_burst()
    print()
    time.sleep(0.5)

    flow_b_distributed_swarm()
    print()
    time.sleep(0.5)

    flow_c_real_user()
    print()

    if "--kill-switch" in sys.argv:
        flow_d_kill_switch()
        print()

    print_metrics_summary()

    separator("Done")
    with _total_lock:
        sent = _total_sent
    print(f"  Total requests sent this run: {sent}")
    print()


if __name__ == "__main__":
    main()
