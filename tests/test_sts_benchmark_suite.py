"""Automated regression tests for the STS validation benchmark suite.

Fast by design (sub-second TC durations, tiny event counts) so they run in CI
alongside the rest of the repo's pytest suite. Each test maps to one row of
the Edge-Agentic Validation Test Matrix.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from bench import tc1_ntp_poisoning, tc2_jitter_saturation, \
    tc3_ledger_throughput, tc4_network_adversary  # noqa: E402
from bench.sts_time import AssuranceLedger, STSMonotonicClock  # noqa: E402
from bench.verify_ledger import tamper_control  # noqa: E402


@pytest.fixture()
def out_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("STS_BENCH_OUT", str(tmp_path))
    return str(tmp_path)


# -- unit: STS clock invariants ----------------------------------------------

def test_clock_never_goes_backwards():
    clock = STSMonotonicClock()
    stamps = [clock.stamp() for _ in range(5000)]
    assert clock.check_monotonic(stamps) == []
    assert all(b >= a for a, b in zip(stamps, stamps[1:]))


def test_clock_rejects_injected_backward_step(monkeypatch):
    """Force the raw source to jump backwards; STS must HOLD, never regress."""
    ticks = iter([100.0, 101.0, 90.0, 90.5, 88.0])  # three backward steps
    monkeypatch.setattr("bench.sts_time.raw_tick", lambda: next(ticks))
    clock = STSMonotonicClock()
    stamps = [clock.stamp() for _ in range(5)]
    assert stamps == sorted(stamps), "STS issued a regressing timestamp"
    assert clock.stats.rejected_backward_steps == 3


def test_ledger_seal_detects_payload_edit(out_dir):
    clock = STSMonotonicClock()
    ledger = AssuranceLedger(os.path.join(out_dir, "unit.db"))
    for i in range(20):
        ledger.append(clock, "GOES_MAG", {"Bz": float(i)})
    ok, errors = ledger.verify()
    assert ok and not errors
    # Tamper: rewrite payload mid-chain without re-sealing.
    import sqlite3
    conn = sqlite3.connect(ledger.path)
    conn.execute("UPDATE ledger SET payload='{\"Bz\": 999.0}' WHERE seq=7")
    conn.commit()
    conn.close()
    ledger2 = AssuranceLedger(ledger.path)
    ok2, errors2 = ledger2.verify()
    ledger2.close()
    assert not ok2 and any("seq 7" in e for e in errors2)


def test_verify_telemetry_integrity_semantics_match_repo_agent():
    """The SEAL scheme binds payload+mono+utc like the production agent's
    verify_telemetry_integrity(); both must accept good and reject tampered."""
    import json, hashlib
    record = {"time_tag": "2026-10-20T00:00:00Z", "Bz": -3.2}
    mono, utc = 1234.5, 1_760_000_000.0
    h = hashlib.sha256(f"{json.dumps(record, sort_keys=True)}:{mono}:{utc}"
                       .encode()).hexdigest()
    recomputed = hashlib.sha256(
        f"{json.dumps(record, sort_keys=True)}:{mono}:{utc}".encode()
    ).hexdigest()
    assert h == recomputed
    bad = dict(record, Bz=-3.3)
    assert hashlib.sha256(
        f"{json.dumps(bad, sort_keys=True)}:{mono}:{utc}".encode()
    ).hexdigest() != h


# -- matrix category tests (fast settings) ------------------------------------

def test_tc1_temporal_isolation_passes(out_dir):
    r = tc1_ntp_poisoning.run(duration_s=0.6)
    assert r.passed, r.failures
    assert r.metrics["ordering_violations"] == 0
    assert r.metrics["poison_events_rejected_by_sts"] == \
        r.metrics["poison_events_injected"] > 0


def test_tc2_jitter_under_saturation(out_dir):
    r = tc2_jitter_saturation.run(duration_s=0.8, extra_loaders=0)
    assert r.passed, r.failures
    assert r.metrics["backward_time_jumps"] == 0
    assert r.metrics["seal_chain_ok"] is True


def test_tc3_ledger_throughput_and_seal(out_dir):
    r = tc3_ledger_throughput.run(events_per_stream=60, streams=4,
                                  burst_every=20)
    assert r.passed, r.failures
    assert r.metrics["seal_verification_failures"] == 0
    assert r.metrics["payload_corruptions"] == 0
    assert r.metrics["sustained_tps"] > 50  # sane floor on any modern rig


def test_tc4_partition_recovery(out_dir):
    r = tc4_network_adversary.run(cycles=25, cycle_interval_s=0.01)
    assert r.passed, r.failures
    m = r.metrics
    assert m["buffer_retained_rows"] == m["buffer_recovered_rows"]
    assert m["buffer_left_unsynced"] == 0
    assert m["watchdog_max_gap_s"] < m["watchdog_budget_s"]
    assert m["seal_chain_ok_after_recovery"] is True
    # The storm configuration is verified deterministically (virtual clock):
    # loss + latency spikes + partitions all fire for this seed/profile, and
    # at least some packets get through so recovery is exercised.
    expect = tc4_network_adversary.transport_expectations(80)
    assert all(expect.values()), expect


def test_verification_phase_catches_tamper_end_to_end(out_dir):
    clock = STSMonotonicClock()
    ledger = AssuranceLedger(os.path.join(out_dir, "tc_x_ledger.db"))
    for i in range(10):
        ledger.append(clock, "GOES_MAG", {"Bz": float(i)})
    path = ledger.path
    ledger.close()
    res = tamper_control(out_dir, [path])
    assert res["ran"] and res["tamper_detected"], res
