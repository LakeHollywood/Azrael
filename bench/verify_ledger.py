#!/usr/bin/env python3
"""Verification Phase — automated audit of everything the benchmark produced.

For each SQLite ledger in the output directory:
  * re-hash the full SEAL chain (seal + prev-seal linkage + seq contiguity)
  * assert monotonic stamps are nondecreasing (zero temporal anomalies)
If an audit.jsonl exists (repo's hash-chained AuditLogger format), run
audit_log.verify_chain over it.

Tamper control (negative test): a copy of one ledger gets one payload byte
edited via raw SQL; the auditor MUST flag it. If the tamper goes unnoticed,
the assurance property is vacuous and this script exits non-zero.

Emits a single-line JSON summary on the last stdout line for the orchestrator.

Usage: python bench/verify_ledger.py [OUTPUT_DIR]
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import sqlite3
import sys
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.sts_time import AssuranceLedger  # noqa: E402


def audit_ledger(path: str) -> Dict[str, Any]:
    ledger = AssuranceLedger(path)
    try:
        ok, errors = ledger.verify()
        stamps = ledger.all_stamps()
        backward = sum(1 for a, b in zip(stamps, stamps[1:]) if b < a)
        rows = len(stamps)
    finally:
        ledger.close()
    return {"path": path, "rows": rows, "seal_chain_ok": ok,
            "temporal_anomalies": backward,
            "errors": errors[:10]}


def tamper_control(dir_out: str, ledgers: List[str]) -> Dict[str, Any]:
    """Edit one sealed row in a throwaway copy; verification must fail."""
    if not ledgers:
        return {"ran": False}
    for src in ledgers:
        probe = os.path.join(dir_out, "_tamper_probe.db")
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(src + suffix):
                shutil.copy(src + suffix, probe + suffix)
        conn = sqlite3.connect(probe)
        try:
            # Rewrite the payload of the lowest seq row that has NOT already
            # been edited (previous probes leave '"BX"' behind — skip those).
            cur = conn.execute(
                "UPDATE ledger SET payload = replace(payload, '\"Bz\"', "
                "'\"BX\"') WHERE seq = (SELECT MIN(seq) FROM ledger "
                "WHERE payload LIKE '%\"Bz\"%')")
            changed = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if not changed:
            continue
        ledger = AssuranceLedger(probe)
        try:
            ok, errors = ledger.verify()
        finally:
            ledger.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(probe + suffix)
            except OSError:
                pass
        return {"ran": True, "source": os.path.basename(src),
                "tamper_detected": not ok,
                "sample_error": errors[0] if errors else None}
    return {"ran": False, "reason": "no sealable rows found"}


def main(argv: List[str]) -> int:
    dir_out = argv[0] if argv else os.environ.get("STS_BENCH_OUT",
                                                  "/tmp/sts_bench")
    ledgers = sorted(glob.glob(os.path.join(dir_out, "*ledger*.db")))
    reports = [audit_ledger(p) for p in ledgers]

    audit_jsonl = os.path.join(dir_out, "audit.jsonl")
    chain_result = None
    if os.path.exists(audit_jsonl):
        from audit_log import verify_chain
        ok, errs = verify_chain(audit_jsonl)
        chain_result = {"path": audit_jsonl, "ok": ok, "errors": errs[:10]}

    tamper = tamper_control(dir_out, ledgers)

    ledgers_clean = (all(r["seal_chain_ok"] and r["temporal_anomalies"] == 0
                         for r in reports) and len(reports) > 0)
    ok = ledgers_clean and tamper.get("tamper_detected", False) and \
        (chain_result is None or chain_result["ok"])

    summary = {
        "ok": ok,
        "ledgers_audited": len(reports),
        "total_rows": sum(r["rows"] for r in reports),
        "temporal_anomalies_total": sum(r["temporal_anomalies"]
                                        for r in reports),
        "seal_failures_total": sum(0 if r["seal_chain_ok"] else 1
                                   for r in reports),
        "audit_jsonl_chain": chain_result,
        "tamper_control": tamper,
    }
    for r in reports:
        print(f"ledger {os.path.basename(r['path'])}: rows={r['rows']} "
              f"seal={'OK' if r['seal_chain_ok'] else 'BROKEN'} "
              f"anomalies={r['temporal_anomalies']}")
    if tamper.get("ran"):
        print(f"tamper control: detected={tamper['tamper_detected']}")
    print(json.dumps(summary))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
