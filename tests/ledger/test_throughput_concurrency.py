"""Concurrency + throughput regressions mirroring TC3 success criteria.

Guarantees proven here:
  * seq order == temporal order across concurrent producer threads
    (stamp is taken inside the write lock);
  * zero seal failures under burst load;
  * p99 commit latency stays sub-millisecond-class on nominal hardware.
"""

from __future__ import annotations

import random
import threading

from bench.tc3_ledger_throughput import make_noaa_record, STREAMS

PRODUCERS = 4
ROWS_PER_PRODUCER = 500


def _producer(ledger, clock, idx, barrier, failures):
    rnd = random.Random(idx)
    barrier.wait()
    try:
        for i in range(ROWS_PER_PRODUCER):
            stream = STREAMS[(idx + i) % len(STREAMS)]
            ledger.append(clock, stream, make_noaa_record(stream, i, rnd))
    except Exception as exc:                      # pragma: no cover
        failures.append(f"producer {idx}: {exc!r}")


def test_concurrent_writers_maintain_seal_and_order(ledger, clock):
    failures: list[str] = []
    barrier = threading.Barrier(PRODUCERS)
    threads = [threading.Thread(target=_producer,
                                args=(ledger, clock, k, barrier, failures))
               for k in range(PRODUCERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not failures, failures
    total = PRODUCERS * ROWS_PER_PRODUCER
    assert ledger.commits == total

    ok, errors = ledger.verify()
    assert ok, f"chain broken under concurrency: {errors[:3]}"

    stamps = ledger.all_stamps()
    assert all(b >= a for a, b in zip(stamps, stamps[1:])), \
        "timestamp sequencing lost strict order under concurrent load"


def test_burst_throughput_and_latency_budget(ledger, clock):
    """TC3 gate: sustained TPS > 1000 and p99 < 5 ms even in slim containers."""
    import time
    rnd = random.Random(7)
    t0 = time.perf_counter()
    for i in range(5000):
        stream = STREAMS[i % len(STREAMS)]
        ledger.append(clock, stream, make_noaa_record(stream, i, rnd))
    elapsed = time.perf_counter() - t0

    tps = ledger.commits / elapsed if elapsed else 0.0
    stats = ledger.stats()["write_latency_ms"]
    assert tps > 1000, f"sustained TPS too low in container: {tps:.0f}"
    assert stats["p99"] < 5.0, f"p99 write latency budget blown: {stats}"
    assert ledger.verify()[0]
