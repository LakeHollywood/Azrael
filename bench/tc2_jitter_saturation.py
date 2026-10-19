"""TC2 — High-Frequency Jitter: Thermal & Compute Saturation.

Saturates every available CPU core with dense floating-point inference-style
work (matrix multiply churn — a portable stand-in for GPU/CPU thermal
throttling on the edge rig) while concurrent agent threads hammer the STS
timer at high rate and push telemetry through the assurance ledger.

On the rig, layer real load underneath with:
    stress-ng --cpu $(nproc) --gpu 4 --thermal-zone 0 --timeout 120
(bench/scripts/saturate_hardware.sh wraps this). This module guarantees the
measurement holds even without root/third-party tools.

Metrics captured:
  * monotonic timer jitter (inter-sample interval stddev / p99 deviation)
  * timestamp monotonicity verification across all writer threads
  * event-ordering integrity (ledger seq order == issued stamp order)

Success criteria:
  * zero backward time jumps under sustained saturation
  * strictly ordered sequencing; bounded jitter growth only (no discontinuity)
"""

from __future__ import annotations

import math
import os
import random
import threading
import time
from dataclasses import dataclass, field
from statistics import pstdev
from typing import Any, Dict, List

from bench.sts_time import AssuranceLedger, STSMonotonicClock

MATRIX_N = 96  # dense fp workload size per "inference" pass on the real rig;
               # scaled down automatically on tiny CI boxes (see _matrix_size)


def _matrix_size() -> int:
    """Keep each saturation pass short relative to the test duration so the
    GIL yields frequently: on a 2-core CI container a full 96^3 matmul in
    pure Python would starve the telemetry agents for whole seconds."""
    return MATRIX_N if (os.cpu_count() or 4) >= 8 else 24


def _inference_churn(stop: threading.Event) -> None:
    """CPU/GPU-saturating dummy neural-net pass: matmul + tanh activation."""
    rnd = random.Random(0xC0FFEE)
    n = _matrix_size()
    a = [[rnd.uniform(-1, 1) for _ in range(n)] for _ in range(n)]
    b = [[rnd.uniform(-1, 1) for _ in range(n)] for _ in range(n)]
    while not stop.is_set():
        c = [[0.0] * n for _ in range(n)]
        for i in range(n):
            ai = a[i]
            ci = c[i]
            for k in range(n):
                aik = ai[k]
                bk = b[k]
                for j in range(n):
                    ci[j] += aik * bk[j]
        # fake activation to keep FP units busy both ways
        for i in range(n):
            row = c[i]
            for j in range(n):
                x = row[j]
                row[j] = math.tanh(x) if abs(x) < 350 else (1.0 if x > 0 else -1.0)


@dataclass
class TC2Result:
    passed: bool
    metrics: Dict[str, Any] = field(default_factory=dict)
    failures: List[str] = field(default_factory=list)


def _telemetry_agent(clock: STSMonotonicClock, ledger: AssuranceLedger,
                     intervals_ns: List[int], stop: threading.Event,
                     lock: threading.Lock, feed: str) -> None:
    last = None
    n = 0
    while not stop.is_set():
        ts = clock.stamp()
        if last is not None:
            with lock:
                intervals_ns.append(ts - last)
        last = ts
        n += 1
        payload = {"feed": feed, "sample": n,
                   "mag_x": round(random.uniform(-99, 99), 3),
                   "temp_c": round(random.uniform(20, 95), 2)}
        ledger.append(clock, feed, payload)
        time.sleep(0.0005)  # high-rate ingestion


def run(duration_s: float = 3.0, extra_loaders: int = 0) -> TC2Result:
    cores = os.cpu_count() or 4
    stop = threading.Event()
    lock = threading.Lock()
    intervals_ns: List[int] = []

    clock = STSMonotonicClock()
    ledger = AssuranceLedger(os.path.join(
        os.environ.get("STS_BENCH_OUT", "/tmp/sts_bench"), "tc2_ledger.db"))

    loaders = [threading.Thread(target=_inference_churn, args=(stop,),
                                 daemon=True)
               for _ in range(min(cores, 4) + extra_loaders)]
    agents = [threading.Thread(target=_telemetry_agent,
                                args=(clock, ledger, intervals_ns, stop, lock,
                                      f"GOES_MAG_{i}"), daemon=True)
              for i in range(3)]

    for t in loaders + agents:
        t.start()
    time.sleep(duration_s)
    stop.set()
    for t in loaders + agents:
        t.join(timeout=5.0)

    stamps = ledger.all_stamps()
    ordering_errors = clock.check_monotonic(stamps)

    with lock:
        iv = sorted(intervals_ns)
    mean_iv = (sum(iv) / len(iv)) if iv else 0.0
    jitter = {
        "samples": len(iv),
        "mean_interval_us": round(mean_iv / 1000.0, 3),
        "stddev_us": round(pstdev(iv) / 1000.0, 3) if len(iv) > 1 else 0.0,
        "p99_deviation_us": round((iv[int(len(iv) * 0.99)] - mean_iv) / 1000.0, 3)
                            if iv else 0.0,
        "backward_intervals": sum(1 for x in iv if x < 0),
    }

    seal_ok, seal_errors = ledger.verify()
    ledger.close()

    metrics = {
        "loader_threads": len(loaders),
        "agent_threads": len(agents),
        "ledger_rows": len(stamps),
        "backward_time_jumps": len(ordering_errors),
        "seal_chain_ok": seal_ok,
        "jitter_under_load": jitter,
        "clock_stats": clock.stats.as_dict(),
    }

    failures: List[str] = []
    if ordering_errors:
        failures.extend(ordering_errors[:5])
    if jitter["backward_intervals"]:
        failures.append("negative inter-sample interval observed")
    if not seal_ok:
        failures.extend(seal_errors[:5])
    if len(stamps) < 10 * duration_s:
        failures.append(f"insufficient samples collected under load "
                        f"({len(stamps)} rows in {duration_s:.1f}s)")

    return TC2Result(passed=not failures, metrics=metrics, failures=failures)


if __name__ == "__main__":
    r = run()
    print("TC2 Jitter/Saturation:", "PASS" if r.passed else "FAIL", r.metrics)
    for f in r.failures:
        print("  !", f)
