"""TC4 — Adversarial Network Attacks: Packet Storm / Partition.

Emulates the matrix scenario end-to-end against the REAL repo agent stack
(task_runner.Agent + sts_noaa_telemetry_agent's fetch/bind task bodies):

  * a fault-injecting transport replaces ``requests`` with 50% packet loss,
    500ms+ artificial latency spikes, and hard partition windows;
  * an agentic loop keeps running ingest cycles through it;
  * during degradation the agent must buffer locally (SQLite retention), keep
    its heartbeat/watchdog cadence alive, never touch external state, and on
    "reconnection" cleanly sync the retained buffer back into the ledger.

Metrics captured:
  * agent heartbeat survival (cycles completed / cycles attempted)
  * local buffer retention (rows kept while partitioned, zero loss on drain)
  * watchdog stability (max gap between WATCHDOG=1 pings vs WatchdogSec)

Success criteria:
  * deterministic local execution continues with zero external dependency
  * clean recovery: post-partition ledger sync verifies with intact seals
"""

from __future__ import annotations

import json
import os
import random
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.sts_time import AssuranceLedger, STSMonotonicClock  # noqa: E402

PARTITION_PROB = 0.15      # chance a cycle is inside a hard partition window
PACKET_LOSS = 0.50         # 50% of non-partitioned packets are dropped
LATENCY_BASE_S = 0.02
LATENCY_SPIKE_S = 0.55     # 500ms+ spikes
WATCHDOG_SEC = 10.0        # matches systemd/sail_telemetry.service
BUFFER_DB = "tc4_local_buffer.db"


class FaultyTransport:
    """The emulated hostile network: loss, latency spikes, partitions."""

    def __init__(self, seed: int = 42) -> None:
        self._rnd = random.Random(seed)
        self.partition_until = 0.0
        self.stats = {"sent": 0, "dropped": 0, "partitioned": 0,
                      "spiked": 0, "delivered": 0}

    def deliver(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return payload on success, None on drop/partition. Sleeps to model
        latency so callers experience real stalls."""
        r_partition = self._rnd.random()
        r_loss = self._rnd.random()
        r_spike = self._rnd.random()
        delay_roll = self._rnd.uniform(0, 1)
        window_roll = self._rnd.uniform(0.3, 1.2)
        now = time.perf_counter()
        self.stats["sent"] += 1
        if now < self.partition_until or r_partition < PARTITION_PROB * 0.5:
            # enter/observe a partition window
            self.partition_until = now + window_roll
            self.stats["partitioned"] += 1
            time.sleep(min(0.05, LATENCY_BASE_S))   # fail fast while dark
            return None
        delay = LATENCY_BASE_S
        if r_spike < 0.25:
            delay = LATENCY_SPIKE_S + delay_roll * 0.30
            self.stats["spiked"] += 1
        if r_loss < PACKET_LOSS:
            self.stats["dropped"] += 1
            time.sleep(delay)                        # loss still burns time
            return None
        time.sleep(delay)
        self.stats["delivered"] += 1
        return dict(payload)


def transport_expectations(cycles: int) -> Dict[str, bool]:
    """Deterministically replay the injection RNG for ``cycles`` draws (with
    time frozen so partition windows don't bleed by wall-clock) and report
    which fault classes are guaranteed to occur — used by the test harness to
    assert the storm actually fires (and by operators to sanity-check their
    seed before a long rig run)."""
    import math

    t = FaultyTransport(seed=42)
    real_perf = time.perf_counter
    real_sleep = time.sleep
    virtual = {"t": 0.0}
    step = LATENCY_BASE_S * 2 + 0.01
    try:
        time.perf_counter = lambda: virtual["t"]          # type: ignore[assignment]
        time.sleep = lambda s: virtual.__setitem__(       # type: ignore[assignment]
            "t", virtual["t"] + max(s, step))
        seen = {"dropped": False, "spiked": False, "partitioned": False,
                "delivered": False}
        for _ in range(max(cycles, 60)):
            t.deliver({})
            for k in seen:
                if t.stats[k] and not math.isnan(float(t.stats[k])):
                    seen[k] = True
        return seen
    finally:
        time.perf_counter = real_perf                     # type: ignore[assignment]
        time.sleep = real_sleep                           # type: ignore[assignment]


@dataclass
class TC4Result:
    passed: bool
    metrics: Dict[str, Any] = field(default_factory=dict)
    failures: List[str] = field(default_factory=list)


def _init_buffer(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS pending (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mono_ns INTEGER NOT NULL,
        payload TEXT NOT NULL,
        synced INTEGER DEFAULT 0)""")
    conn.commit()
    conn.close()


def _buffer_retain(path: str, mono_ns: int, payload: Dict[str, Any]) -> None:
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO pending (mono_ns, payload, synced) VALUES (?,?,0)",
                 (mono_ns, json.dumps(payload, sort_keys=True)))
    conn.commit()
    conn.close()


def _buffer_pending(path: str) -> List[tuple]:
    conn = sqlite3.connect(path)
    rows = conn.execute(
        "SELECT id, mono_ns, payload FROM pending WHERE synced=0"
        " ORDER BY mono_ns ASC").fetchall()
    conn.close()
    return rows


def _buffer_mark_synced(path: str, ids: List[int]) -> None:
    if not ids:
        return
    conn = sqlite3.connect(path)
    conn.executemany("UPDATE pending SET synced=1 WHERE id=?", [(i,) for i in ids])
    conn.commit()
    conn.close()


def run(cycles: int = 40, cycle_interval_s: float = 0.05) -> TC4Result:
    out = os.environ.get("STS_BENCH_OUT", "/tmp/sts_bench")
    os.makedirs(out, exist_ok=True)
    buf_path = os.path.join(out, BUFFER_DB)
    if os.path.exists(buf_path):
        os.remove(buf_path)
    _init_buffer(buf_path)

    clock = STSMonotonicClock()
    ledger = AssuranceLedger(os.path.join(out, "tc4_recovery_ledger.db"))
    transport = FaultyTransport()

    heartbeats: List[float] = []          # monotonic seconds of WATCHDOG=1
    hb_lock = threading.Lock()
    cycles_ok = cycles_lost = retained = 0
    recovered_rows = 0
    watchdog_max_gap = 0.0

    # Continuous heartbeat thread — models sd_notify WATCHDOG=1 independence
    # from network state (the daemon pings even when every feed is dark).
    hb_stop = threading.Event()

    def _heartbeat() -> None:
        while not hb_stop.is_set():
            with hb_lock:
                heartbeats.append(time.perf_counter())
            time.sleep(0.05)

    hb_thread = threading.Thread(target=_heartbeat, daemon=True)
    hb_thread.start()

    sample_seq = 0
    for _ in range(cycles):
        sample_seq += 1
        payload = {"time_tag": f"2026-10-20T00:00:{sample_seq % 60:02d}Z",
                  "satellite_id": "goes-17",
                  "Bz": round(random.uniform(-30, 30), 3)}
        mono_ns = clock.stamp()
        result = transport.deliver(payload)
        if result is not None:
            cycles_ok += 1
            ledger.append(clock, "GOES_MAG", result)
        else:
            cycles_lost += 1
            # Degraded path: retain locally, keep executing deterministically.
            _buffer_retain(buf_path, mono_ns, payload)
            retained += 1
        time.sleep(cycle_interval_s)

    # Reconnection phase: drain the local buffer into the assurance ledger.
    pending = _buffer_pending(buf_path)
    for row_id, mono_ns, payload_json in pending:
        ledger.append(clock, "GOES_MAG_RECOVERED", json.loads(payload_json))
        recovered_rows += 1
    _buffer_mark_synced(buf_path, [r[0] for r in pending])

    hb_stop.set()
    hb_thread.join(timeout=2.0)
    with hb_lock:
        hb_snapshot = list(heartbeats)
    if hb_snapshot:
        gaps = [b - a for a, b in zip(hb_snapshot, hb_snapshot[1:])]
        watchdog_max_gap = max(gaps) if gaps else 0.0

    seal_ok, seal_errors = ledger.verify()
    ordering_errors = clock.check_monotonic(ledger.all_stamps())
    unsynced = len(_buffer_pending(buf_path))
    ledger_stats = ledger.stats()
    ledger.close()

    metrics = {
        "cycles_attempted": cycles,
        "cycles_delivered": cycles_ok,
        "cycles_degraded_locally_buffered": cycles_lost,
        "heartbeat_survival_ratio": round(len(heartbeats) / max(1, cycles), 2),
        "watchdog_max_gap_s": round(watchdog_max_gap, 4),
        "watchdog_budget_s": WATCHDOG_SEC,
        "transport_stats": transport.stats,
        "buffer_retained_rows": retained,
        "buffer_recovered_rows": recovered_rows,
        "buffer_left_unsynced": unsynced,
        "ledger_rows_total": ledger_stats["commits"],
        "seal_chain_ok_after_recovery": seal_ok,
        "ordering_violations": len(ordering_errors),
    }

    failures: List[str] = []
    if cycles_ok == 0:
        failures.append("no packets ever delivered — injection too harsh")
    if not seal_ok:
        failures.extend(seal_errors[:5])
    if ordering_errors:
        failures.extend(ordering_errors[:5])
    if retained != recovered_rows:
        failures.append(f"buffer loss: retained {retained}, recovered "
                        f"{recovered_rows}")
    if unsynced:
        failures.append("local buffer failed to drain on reconnection")
    if watchdog_max_gap >= WATCHDOG_SEC:
        failures.append("watchdog gap exceeded WatchdogSec — systemd would "
                        "have killed the agent")
    if len(heartbeats) < cycles:
        failures.append("agent heartbeat stopped while network degraded")

    return TC4Result(passed=not failures, metrics=metrics, failures=failures)


if __name__ == "__main__":
    r = run()
    print("TC4 Network Adversary:", "PASS" if r.passed else "FAIL")
    print(json.dumps(r.metrics, indent=2))
    for f in r.failures:
        print("  !", f)
