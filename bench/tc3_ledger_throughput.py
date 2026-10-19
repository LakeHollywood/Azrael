"""TC3 — Ledger Throughput & SEAL Integrity: Burst Telemetry Ingestion.

Feeds high-volume simulated NOAA space-weather telemetry (GOES magnetometer,
DSCOVR plasma, SESS electron flux — realistic record shapes drawn from the
swpc.noaa.gov JSON schemas) into the Event-Driven Assurance Ledger in bursts,
with concurrent producer threads, then cryptographically verifies every seal.

Metrics captured:
  * transactions processed per second (TPS), sustained + burst
  * SQLite write latency distribution (p50 / p99 / max)
  * cryptographic verification overhead (verify wall-time, hashes/s)

Success criteria:
  * stable commit throughput across bursts (burst TPS >= 60% of nominal)
  * zero SEAL verification failures / payload corruption at peak load
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

from bench.sts_time import AssuranceLedger, STSMonotonicClock

STREAMS = ("GOES_MAG", "DSCOVR_MAG", "DSCOVR_PLASMA", "SESS_ELECTRON")


def make_noaa_record(stream: str, seq: int, rnd: random.Random) -> Dict[str, Any]:
    """Realistic-shaped synthetic NOAA sample (no live network needed)."""
    ts = "2026-10-20T%02d:%02d:%02dZ" % (rnd.randrange(24),
                                         rnd.randrange(60), rnd.randrange(60))
    if stream == "GOES_MAG":
        sat = rnd.choice([7, 8, 9])
        return {"time_tag": ts, "satellite_id": f"goes-{sat}",
                "Bz": round(rnd.uniform(-40, 40), 3),
                "Bt": round(rnd.uniform(0, 60), 3),
                "Lambda": round(rnd.uniform(-180, 180), 2)}
    if stream == "DSCOVR_MAG":
        return {"time_tag": ts, "mag/nt/Bx": round(rnd.uniform(-60, 60), 4),
                "mag/nt/By": round(rnd.uniform(-60, 60), 4),
                "mag/nt/Bz": round(rnd.uniform(-60, 60), 4),
                "mag/nt/Bm": round(rnd.uniform(0, 90), 4)}
    if stream == "DSCOVR_PLASMA":
        return {"time_tag": ts, "plasma_speed_km_p_s":
                round(rnd.uniform(280, 900), 1),
                "proton_density_n_cm^-3": round(abs(rnd.gauss(6, 4)), 3),
                "bulk_flow_pressure_p_n_m^-2": round(rnd.uniform(0.1, 20), 3)}
    return {"time_tag": ts, "channel": f"te{rnd.choice((30, 60, 100, 200, 300))}",
            "flux": round(10 ** rnd.uniform(0, 4), 2),
            "quality_flag": rnd.choice((0, 0, 0, 1))}


@dataclass
class TC3Result:
    passed: bool
    metrics: Dict[str, Any] = field(default_factory=dict)
    failures: List[str] = field(default_factory=list)


def _producer(clock: STSMonotonicClock, ledger: AssuranceLedger, stream: str,
              count: int, burst_every: int, stop: threading.Event,
              lock: threading.Lock, written: List[int]) -> None:
    rnd = random.Random(os.getpid() ^ hash(stream) & 0xFFFF)
    for i in range(count):
        if stop.is_set():
            return
        ledger.append(clock, stream, make_noaa_record(stream, i, rnd))
        with lock:
            written.append(1)
        if burst_every and i % burst_every == burst_every - 1:
            # micro-pause between bursts to exercise checkpoint/WAL behaviour
            time.sleep(0.02)


def run(events_per_stream: int = 1500, streams: int = 4,
        burst_every: int = 50) -> TC3Result:
    out = os.environ.get("STS_BENCH_OUT", "/tmp/sts_bench")
    clock = STSMonotonicClock()
    ledger = AssuranceLedger(os.path.join(out, "tc3_ledger.db"))
    written: List[int] = []
    lock = threading.Lock()

    names = [f"{s}_{i}" for i, s in enumerate(STREAMS[:streams])]
    producers = [threading.Thread(target=_producer,
                                  args=(clock, ledger, n.split("_")[0],
                                        events_per_stream, burst_every,
                                        threading.Event(), lock, written))
                 for n in names]
    # NOTE: each producer gets its own stop event so we can pre-set none;
    # simpler: they all run to completion.
    t0 = time.perf_counter()
    for p in producers:
        p.start()
    for p in producers:
        p.join(timeout=120)
    elapsed = time.perf_counter() - t0

    total = ledger.commits
    sustained_tps = total / elapsed if elapsed else 0.0

    # Burst measurement: hammer a single flush window with a dense batch.
    burst_events = [("GOES_MAG", make_noaa_record(
        "GOES_MAG", i, random.Random(i))) for i in range(500)]
    b0 = time.perf_counter()
    ledger.append_many(clock, burst_events)
    b_elapsed = time.perf_counter() - b0
    burst_tps = len(burst_events) / b_elapsed if b_elapsed else 0.0

    # Cryptographic verification pass over the whole ledger.
    v0 = time.perf_counter()
    ok, errors = ledger.verify()
    verify_ms = (time.perf_counter() - v0) * 1000.0
    stamps = ledger.all_stamps()
    ordering_errors = clock.check_monotonic(stamps)
    stats = ledger.stats()
    ledger.close()

    metrics = {
        "rows_committed": total + len(burst_events),
        "sustained_tps": round(sustained_tps, 1),
        "burst_tps": round(burst_tps, 1),
        "burst_ratio_vs_sustained": round(burst_tps / sustained_tps, 3)
                                    if sustained_tps else None,
        "sqlite_write_latency_ms": stats["write_latency_ms"],
        "seal_verification_ok": ok,
        "seal_verification_failures": len(errors),
        "verification_overhead_ms": round(verify_ms, 2),
        "hashes_per_second": round((total + len(burst_events))
                                   / (verify_ms / 1000.0), 1)
                              if verify_ms else None,
        "ordering_violations": len(ordering_errors),
        "payload_corruptions": 0 if ok else len(errors),
    }

    failures: List[str] = []
    if not ok:
        failures.extend(errors[:5])
    if ordering_errors:
        failures.extend(ordering_errors[:5])
    if total + len(burst_events) < events_per_stream * streams:
        failures.append("producers dropped events")
    if burst_tps < 0.6 * sustained_tps:
        failures.append("burst throughput collapsed below 60% of sustained")

    return TC3Result(passed=not failures, metrics=metrics, failures=failures)


if __name__ == "__main__":
    r = run()
    print("TC3 Ledger Throughput:", "PASS" if r.passed else "FAIL")
    print(json.dumps(r.metrics, indent=2))
    for f in r.failures:
        print("  !", f)
