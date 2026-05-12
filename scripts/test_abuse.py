#!/usr/bin/env python3
"""
AbuseShield — High-Volume Abuse Simulation
===========================================
Simulates realistic attack and real-user traffic against a running AbuseShield
instance. Each response carries an X-AbuseShield-Decision header so the script
can report what the engine decided regardless of shadow mode.

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

def req(method: str, path: str, headers: dict | None = None) -> tuple[int, str]:
    """Fire a request; return (status_code, X-AbuseShield-Decision header)."""
    url = BASE + path
    r = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            decision = resp.headers.get("X-AbuseShield-Decision", "—")
            return resp.status, decision
    except urllib.error.HTTPError as exc:
        decision = exc.headers.get("X-AbuseShield-Decision", "—") if exc.headers else "—"
        return exc.code, decision
    except Exception:
        return 0, "—"


def separator(title: str) -> None:
    print()
    print("=" * 64)
    print(f"  {title}")
    print("=" * 64)


# ── Mode banner ───────────────────────────────────────────────────────────────

def print_mode_banner() -> None:
    """Detect and display the current enforcement mode."""
    # Send a preflight request that will trip sequence_violation so we can
    # check whether AbuseShield actually blocks it or just logs it.
    status, decision = req("POST", "/register", headers={
        "User-Agent": "abuseshield-preflight/1.0",
        "X-Forwarded-For": "100.64.255.1",
    })
    _inc()

    shadow = status not in (403, 429)
    print()
    print(f"  Engine decision on preflight: {decision}")
    print(f"  Shadow mode:                  {'ON  — detections logged, nothing blocked' if shadow else 'OFF — detections enforced'}")
    print()
    print("  Each request below shows:  decision=<engine verdict>  →  proxied / blocked")


# ── Metrics helper ────────────────────────────────────────────────────────────

def fetch_metrics() -> dict[str, int]:
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

BOT_A_HEADERS = {
    "User-Agent": "python-bot/2.0 (signup-spam)",
    "X-Forwarded-For": "198.51.100.42",
}


def _fire_a(_: int) -> tuple[int, str]:
    status, decision = req("POST", "/register", headers=BOT_A_HEADERS)
    _inc()
    return status, decision


def flow_a_single_bot_burst() -> None:
    num = 100
    workers = 20
    separator(f"Flow A — Single-bot burst  ({num} POST /register, {workers} workers)")
    print(f"  Entity:      IP=198.51.100.42  UA={BOT_A_HEADERS['User-Agent']}")
    print(f"  Requests:    {num} × POST /register  (no prior /home visit)")
    print()

    counters: dict[tuple[str, str], int] = {}
    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for status, decision in pool.map(_fire_a, range(num)):
            proxied = "proxied" if status not in (403, 429) else "blocked"
            key = (decision, proxied)
            counters[key] = counters.get(key, 0) + 1
    elapsed = time.monotonic() - t0

    print(f"  Completed {num} requests in {elapsed:.2f}s  ({num / elapsed:.0f} req/s)")
    print()
    for (decision, proxied), cnt in sorted(counters.items()):
        print(f"    decision={decision:<12}  {proxied:<8}  {cnt:>4}×")


# ── Flow B: Distributed bot swarm (8 IPs × 15 requests) ─────────────────────

BOT_B_UA = "python-swarm/1.0 (distributed-signup)"

BOT_B_IPS = [
    "10.0.1.1",  # 10.0.1.0/24
    "10.0.2.1",  # 10.0.2.0/24
    "10.0.3.1",  # 10.0.3.0/24
    "10.0.4.1",  # 10.0.4.0/24
    "10.0.5.1",  # 10.0.5.0/24
    "10.0.6.1",  # 10.0.6.0/24
    "10.0.7.1",  # 10.0.7.0/24
    "10.0.8.1",  # 10.0.8.0/24
]


def _fire_b(ip: str) -> tuple[str, dict[tuple[str, str], int]]:
    counters: dict[tuple[str, str], int] = {}
    for _ in range(15):
        status, decision = req("POST", "/register", headers={
            "User-Agent": BOT_B_UA,
            "X-Forwarded-For": ip,
        })
        proxied = "proxied" if status not in (403, 429) else "blocked"
        key = (decision, proxied)
        counters[key] = counters.get(key, 0) + 1
        _inc()
    return ip, counters


def flow_b_distributed_swarm() -> None:
    n_ips = len(BOT_B_IPS)
    reqs_each = 15
    total = n_ips * reqs_each
    separator(f"Flow B — Distributed swarm  ({n_ips} IPs × {reqs_each} requests = {total} total)")
    print(f"  User-Agent:  {BOT_B_UA}")
    print(f"  Source IPs:  {', '.join(BOT_B_IPS)}")
    print()

    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_ips) as pool:
        results = list(pool.map(_fire_b, BOT_B_IPS))
    elapsed = time.monotonic() - t0

    all_counters: dict[tuple[str, str], int] = {}
    for _, counters in results:
        for key, cnt in counters.items():
            all_counters[key] = all_counters.get(key, 0) + cnt

    print(f"  Completed {total} requests in {elapsed:.2f}s  ({total / elapsed:.0f} req/s)")
    print()
    for (decision, proxied), cnt in sorted(all_counters.items()):
        print(f"    decision={decision:<12}  {proxied:<8}  {cnt:>4}×")


# ── Flow C: Legitimate user (/home → pause → /register) ──────────────────────

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

    status, decision = req("GET", "/home", headers=HUMAN_HEADERS)
    _inc()
    proxied = "proxied" if status not in (403, 429) else "blocked"
    print(f"  [01] GET  /home      decision={decision:<12}  →  {proxied}  (HTTP {status})")

    wait = 1.5
    print(f"  [--] pause {wait}s…")
    time.sleep(wait)

    status, decision = req("POST", "/register", headers=HUMAN_HEADERS)
    _inc()
    proxied = "proxied" if status not in (403, 429) else "blocked"
    print(f"  [02] POST /register  decision={decision:<12}  →  {proxied}  (HTTP {status})")


# ── Flow D: Kill-switch toggle (optional) ────────────────────────────────────

def flow_d_kill_switch(secret: str = "change-me") -> None:
    separator("Flow D — Kill-switch toggle  (optional, requires correct secret)")

    status, _ = req("POST", "/admin/kill-switch?enable=true",
                    headers={"X-Kill-Switch-Secret": secret})
    print(f"  Enable kill-switch   → HTTP {status}  (expected 200)")

    status, decision = req("POST", "/register", headers=BOT_A_HEADERS)
    _inc()
    print(f"  POST /register       decision={decision:<12}  →  HTTP {status}  (no SecurityEvent emitted)")

    status, _ = req("POST", "/admin/kill-switch?enable=false",
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
    show("Allowed (proxied)",          "abuseshield_allowed_requests_total")
    show("Blocked (0 in shadow mode)", "abuseshield_blocked_requests_total")

    print("\n  L0 Rate Limiter (enforcement)")
    show("By IP rate limit",    'abuseshield_blocked_by_reason_total{reason="ip"}')
    show("By API key limit",    'abuseshield_blocked_by_reason_total{reason="api_key"}')
    show("By hot-key cooldown", 'abuseshield_blocked_by_reason_total{reason="cooldown"}')

    print("\n  Detection signals (L1/L2 — fire in shadow mode too)")
    show("burst_detected     (L1)", 'abuseshield_detected_by_reason_total{reason="burst_detected"}')
    show("rate_limited       (L1)", 'abuseshield_detected_by_reason_total{reason="rate_limited"}')
    show("sequence_violation (L2)", 'abuseshield_detected_by_reason_total{reason="sequence_violation"}')

    print("\n  SecurityEvents")
    show("Logged",             'abuseshield_security_events_total{status="logged"}')
    show("Dropped (buf full)", 'abuseshield_security_events_total{status="dropped"}')
    show("Active entities",    "abuseshield_active_entities_count")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print()
    print("AbuseShield — High-Volume Abuse Simulation")
    print(f"Target: {BASE}")
    print()
    print("Prerequisites:")
    print("  Terminal 1: python3 scripts/mock_upstream.py")
    print("  Terminal 2: ./abuseshield -config config.json 2>&1 | tee /tmp/shield.log")

    print_mode_banner()

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
