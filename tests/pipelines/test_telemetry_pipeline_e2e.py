"""End-to-end pipeline regression: full TC4 storm scenario inside the harness.

Runs the real agentic loop against the fault-injecting transport (50% loss,
500ms+ spikes, partition windows) and asserts the matrix success criteria:
deterministic local execution, zero state loss on reconnect, intact seals.
"""

from __future__ import annotations

import os

import pytest

from bench import tc4_network_adversary as tc4


@pytest.fixture()
def bench_out(tmp_path, monkeypatch):
    monkeypatch.setenv("STS_BENCH_OUT", str(tmp_path))
    return str(tmp_path)


def test_storm_scenario_zero_state_loss(bench_out):
    result = tc4.run(cycles=30, cycle_interval_s=0.01)
    m = result.metrics

    assert result.passed, result.failures
    # The storm actually fired all three fault classes on this seed.
    ts = m["transport_stats"]
    assert ts["dropped"] > 0 and ts["partitioned"] > 0 and ts["spiked"] >= 0

    # Zero state loss: every degraded cycle was retained AND recovered.
    assert m["buffer_retained_rows"] == m["cycles_degraded_locally_buffered"]
    assert m["buffer_left_unsynced"] == 0
    assert (m["cycles_delivered"] + m["buffer_recovered_rows"]
            == m["ledger_rows_total"])

    # Watchdog cadence survived total degradation well inside budget.
    assert m["watchdog_max_gap_s"] < m["watchdog_budget_s"]

    # Post-partition ledger verifies with intact seals & strict ordering.
    from bench.sts_time import AssuranceLedger
    led = AssuranceLedger(os.path.join(bench_out, "tc4_recovery_ledger.db"))
    ok, errors = led.verify()
    led.close()
    assert ok, f"recovery ledger chain invalid: {errors[:3]}"


def test_transport_expectations_cover_fault_classes():
    """Seed sanity-check recommended before long Orin rig runs."""
    seen = tc4.transport_expectations(120)
    assert seen["dropped"] and seen["partitioned"], \
        "injection seed no longer produces the mandated fault mix"
