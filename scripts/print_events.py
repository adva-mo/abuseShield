#!/usr/bin/env python3
"""Pretty-print SecurityEvent JSON lines from AbuseShield stdout.

Usage:
    grep '^{' /tmp/shield.log | python3 scripts/print_events.py
    # or
    python3 scripts/print_events.py /tmp/shield.log
"""
import json
import sys

RESET  = "\033[0m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
BOLD   = "\033[1m"

COLORS = {"BLOCK": RED, "SUSPICIOUS": YELLOW, "ALLOW": GREEN}

DECISION_COL = 24  # wide enough for "SUSPICIOUS [ENFORCED]" (21 chars) + breathing room


def color(text, code):
    return f"{code}{text}{RESET}"


def decision_column(decision, blocked, shadow):
    """Return a fixed-width decision+tag string with correct ANSI-aware padding."""
    if shadow:
        tag = " [shadow]"
        tag_display = tag
    elif blocked:
        tag = " [ENFORCED]"
        tag_display = color(tag, BOLD)
    else:
        tag = ""
        tag_display = ""

    col = COLORS.get(decision, RESET)
    padding = " " * max(0, DECISION_COL - len(decision) - len(tag))
    return color(decision, col) + tag_display + padding


source = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin

print(f"\n{'TIME':12} {'DECISION':{DECISION_COL}} {'PRIMARY REASON':28} {'CONF':5}  {'SIGNALS':38} {'PATH':18} {'IP':20} USER-AGENT")
print("-" * 148)

for line in source:
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue

    ts       = e.get("timestamp", "")[11:23]  # "HH:MM:SS.mmm" from RFC3339Nano
    decision = e.get("decision", "?")
    reason   = e.get("reason") or "(clean)"
    conf     = e.get("confidence", 0.0)
    path     = e.get("path", "")
    ip       = e.get("ip", "")
    ua       = e.get("user_agent", "")[:35]

    raw_signals = e.get("signals") or []
    sig_str = "  ".join(
        f"{s['layer']}:{s['reason']}({s['confidence']:.2f})"
        for s in raw_signals
    ) or "(none)"

    dec_col = decision_column(decision, e.get("blocked"), e.get("shadow_mode"))

    print(
        f"{ts:12} "
        f"{dec_col}"
        f"{reason:28} "
        f"{conf:4.2f}  "
        f"{sig_str:38} "
        f"{path:18} "
        f"{ip:20} "
        f"{ua}"
    )
