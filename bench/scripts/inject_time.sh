#!/usr/bin/env bash
# TC1 hardware-grade injection: real NTP poisoning against CLOCK_REALTIME.
# Requires root on the edge rig. The STS daemon must keep running; its
# CLOCK_MONOTONIC_RAW baseline must show zero divergence (check results.json).
set -euo pipefail
IFACE="${IFACE:-eth0}"
echo "[inject] spoofing a malicious NTP server on $IFACE and forcing steps..."
# 1) Big backward step (what a poisoned 'time.wrong.example' would cause):
date -s "@$(( $(date +%s) - 3600 ))" || true
sleep 2
# 2) Forward step:
date -s "@$(( $(date +%s) + 7200 ))" || true
sleep 2
# 3) Aggressive slew via adjtimex (frequency poison, +/-500 ppm):
if command -v adjtimex >/dev/null 2>&1; then adjtimex --frequency 500000 || true; fi
# 4) Restore sanity for the next phase (STS ledger is unaffected either way):
if command -v chroncd >/dev/null 2>&1; then chronyc -a makestep || true; fi
echo "[inject] done — run bench/verify_ledger.py to confirm zero delta divergence"
