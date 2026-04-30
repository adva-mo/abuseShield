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

def color(text, code):
    return f"{code}{text}{RESET}"

source = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin

print(f"\n{'TIME':12} {'DECISION':12} {'PRIMARY REASON':28} {'CONF':5}  {'SIGNALS':38} {'PATH':18} {'IP':20} USER-AGENT")
print("-" * 140)

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
    if e.get("shadow_mode"):
        tag = " [shadow]"
    elif e.get("blocked"):
        tag = color(" [ENFORCED]", BOLD)
    else:
        tag = ""

    # Format all fired signals as "L1:burst_detected(0.95) L2:sequence_violation(0.70)"
    raw_signals = e.get("signals") or []
    sig_str = "  ".join(
        f"{s['layer']}:{s['reason']}({s['confidence']:.2f})"
        for s in raw_signals
    ) or "(none)"

    col = COLORS.get(decision, RESET)
    print(
        f"{ts:12} "
        f"{color(decision, col)}{tag:25} "
        f"{reason:28} "
        f"{conf:4.2f}  "
        f"{sig_str:38} "
        f"{path:18} "
        f"{ip:20} "
        f"{ua}"
    )
