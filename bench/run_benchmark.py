#!/usr/bin/env python3
"""STS Edge-Agentic Validation Benchmark — orchestrator.

Runs the full matrix in the documented three-phase methodology:

  Phase 1  Baseline   : nominal conditions (no fault injection) for TC1-TC4
  Phase 2  Stress     : fault-injection active (NTP poisoning, CPU saturation,
                        burst ingestion, packet storm/partition)
  Phase 3  Verification: bench/verify_ledger.py audits every SQLite ledger and
                        JSONL assurance chain produced by phases 1-2; plus a
                        tamper-control that proves the auditor catches edits.

Outputs:
  $STS_BENCH_OUT/results.json          machine-readable metrics per category
  $STS_BENCH_OUT/bench_report.md       whitepaper-ready markdown report

Usage:
  python -m bench.run_benchmark [--quick] [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench import tc1_ntp_poisoning, tc2_jitter_saturation, \
    tc3_ledger_throughput, tc4_network_adversary  # noqa: E402

MATRIX = [
    ("1. Temporal Isolation & Drift", "tc1", tc1_ntp_poisoning),
    ("2. High-Frequency Jitter", "tc2", tc2_jitter_saturation),
    ("3. Ledger Throughput & SEAL Integrity", "tc3", tc3_ledger_throughput),
    ("4. Adversarial Network Attacks", "tc4", tc4_network_adversary),
]


def _scale(module_id: str, quick: bool) -> Dict[str, Any]:
    """Phase arguments; 'quick' shrinks durations for CI smoke runs."""
    if module_id == "tc1":
        return {"duration_s": 1.0 if quick else 3.0}
    if module_id == "tc2":
        return {"duration_s": 1.5 if quick else 4.0,
                "extra_loaders": 0 if quick else 2}
    if module_id == "tc3":
        return {"events_per_stream": 200 if quick else 1500,
                "streams": 4, "burst_every": 50}
    return {"cycles": 25 if quick else 60}


def run(name: str, quick: bool, inject_faults: bool) -> Dict[str, Any]:
    print(f"\n=== {name} ===")
    results: Dict[str, Any] = {}
    for title, mid, module in MATRIX:
        kwargs = _scale(mid, quick)
        if mid == "tc1":
            # Baseline phase: no poisoning; stress phase: full attack schedule.
            kwargs = dict(kwargs, seed_attacks=inject_faults)
        elif mid == "tc2":
            # Baseline keeps loaders minimal; stress saturates extra cores.
            kwargs = dict(kwargs, extra_loaders=kwargs["extra_loaders"]
                          if inject_faults else 0)
        t0 = time.perf_counter()
        res = module.run(**kwargs)
        wall = time.perf_counter() - t0
        results[mid] = {
            "category": title,
            "passed": res.passed,
            "wall_time_s": round(wall, 2),
            "metrics": res.metrics,
            "failures": res.failures,
        }
        status = "PASS" if res.passed else "FAIL"
        print(f"[{name}] {title}: {status} ({wall:.1f}s)")
        for f in res.failures:
            print(f"    ! {f}")
    return results


def verify_phase(out_dir: str) -> Dict[str, Any]:
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "verify_ledger.py")
    proc = subprocess.run([sys.executable, script, out_dir],
                          capture_output=True, text=True)
    print(proc.stdout.rstrip())
    if proc.stderr.strip():
        print("stderr:", proc.stderr.strip())
    try:
        return json.loads(proc.stdout.splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"ok": False, "error": "verifier produced no JSON summary"}


def write_report(path: str, baseline: Dict, stress: Dict,
                 verification: Dict) -> None:
    lines = ["# STS Edge-Agentic Validation — Benchmark Report", "",
             f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}", "",
             "| Category | Phase | Result | Key metrics |",
             "|---|---|---|---|"]
    for phase_name, data in (("Baseline", baseline), ("Stress", stress)):
        for mid, r in data.items():
            keys = ", ".join(f"{k}={v}" for k, v in list(r["metrics"].items())[:4])
            lines.append(f"| {r['category']} | {phase_name} | "
                         f"{'✅ PASS' if r['passed'] else '❌ FAIL'} | {keys} |")
    lines += ["", "## Verification Phase",
              "```json", json.dumps(verification, indent=2), "```", ""]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bench.run_benchmark")
    ap.add_argument("--quick", action="store_true",
                    help="short durations for CI smoke testing")
    ap.add_argument("--out", default=os.environ.get("STS_BENCH_OUT",
                                                    "/tmp/sts_bench"))
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    os.environ["STS_BENCH_OUT"] = args.out

    baseline = run("Phase 1 — Baseline (nominal)", args.quick,
                   inject_faults=False)
    stress = run("Phase 2 — Stress Injection", args.quick, inject_faults=True)
    verification = verify_phase(args.out)

    overall = (all(r["passed"] for r in baseline.values())
               and all(r["passed"] for r in stress.values())
               and verification.get("ok", False))

    payload = {"baseline": baseline, "stress": stress,
               "verification": verification, "overall_pass": overall,
               "generated": time.time()}
    rp = os.path.join(args.out, "results.json")
    with open(rp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    write_report(os.path.join(args.out, "bench_report.md"),
                 baseline, stress, verification)

    print(f"\n=== OVERALL: {'PASS' if overall else 'FAIL'} ===")
    print(f"results:    {rp}")
    print(f"report:     {os.path.join(args.out, 'bench_report.md')}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
