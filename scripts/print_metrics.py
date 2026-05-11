#!/usr/bin/env python3
"""Fetch and pretty-print AbuseShield /metrics in a human-readable table.

Usage:
    python3 scripts/print_metrics.py
    python3 scripts/print_metrics.py http://localhost:8080
"""

import sys
import urllib.request

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"


def fetch(url: str) -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        with urllib.request.urlopen(url + "/metrics", timeout=5) as resp:
            for line in resp.read().decode().splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                if len(parts) == 2:
                    try:
                        out[parts[0]] = int(float(parts[1]))
                    except ValueError:
                        pass
    except Exception as exc:
        print(f"ERROR: could not reach {url}/metrics — {exc}", file=sys.stderr)
    return out


def _row(label: str, value: str) -> None:
    print(f"    {label:<38}  {value}")


def _val(m: dict, key: str, color: str = "") -> str:
    v = m.get(key)
    raw = str(v) if v is not None else f"{DIM}—{RESET}"
    return f"{color}{raw}{RESET}" if color and v else raw


def _section(title: str) -> None:
    print(f"\n  {BOLD}{title}{RESET}")
    print(f"  {'─' * 50}")


def main() -> None:
    m = fetch(BASE)
    if not m:
        sys.exit(1)

    blocked  = m.get("abuseshield_blocked_requests_total", 0)
    burst    = m.get('abuseshield_detected_by_reason_total{reason="burst_detected"}', 0)
    seq      = m.get('abuseshield_detected_by_reason_total{reason="sequence_violation"}', 0)
    dropped  = m.get('abuseshield_security_events_total{status="dropped"}', 0)

    print(f"\n  {BOLD}AbuseShield Metrics{RESET}  —  {BASE}")

    _section("Traffic")
    _row("Allowed (proxied to upstream)",       _val(m, "abuseshield_allowed_requests_total", GREEN))
    _row("Blocked  (0 when shadow_mode=true)",  _val(m, "abuseshield_blocked_requests_total", RED if blocked else ""))

    _section("L0 Rate Limiter  (enforcement — 0 in shadow mode)")
    _row("  By IP rate limit",    _val(m, 'abuseshield_blocked_by_reason_total{reason="ip"}'))
    _row("  By API key limit",    _val(m, 'abuseshield_blocked_by_reason_total{reason="api_key"}'))
    _row("  By hot-key cooldown", _val(m, 'abuseshield_blocked_by_reason_total{reason="cooldown"}'))

    _section("Detection signals  (L1 / L2 — fire in shadow mode too)")
    ratelim = m.get('abuseshield_detected_by_reason_total{reason="rate_limited"}', 0)
    _row("  burst_detected     (L1)", _val(m, 'abuseshield_detected_by_reason_total{reason="burst_detected"}',  YELLOW if burst else ""))
    _row("  rate_limited       (L1)", _val(m, 'abuseshield_detected_by_reason_total{reason="rate_limited"}',    YELLOW if ratelim else ""))
    _row("  sequence_violation (L2)", _val(m, 'abuseshield_detected_by_reason_total{reason="sequence_violation"}', YELLOW if seq else ""))

    _section("SecurityEvents")
    _row("  Logged",              _val(m, 'abuseshield_security_events_total{status="logged"}'))
    _row("  Dropped (buf full)",  _val(m, 'abuseshield_security_events_total{status="dropped"}', RED if dropped else ""))

    _section("State")
    _row("  Active entity fingerprints", _val(m, "abuseshield_active_entities_count"))
    _row("  Active limiter keys",        _val(m, "abuseshield_active_keys_count"))

    print()


if __name__ == "__main__":
    main()
