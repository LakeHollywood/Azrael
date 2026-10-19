"""Local spool-buffer retention + drain semantics used by every agent pipeline.

Exercises bench.tc4_network_adversary's buffer primitives directly so CI
catches regressions in the degraded path (the zero-state-loss guarantee)
without paying for a full storm simulation.
"""

from __future__ import annotations

import json

from bench.tc4_network_adversary import (
    _buffer_retain, _buffer_pending, _buffer_mark_synced, _init_buffer,
)


def test_retain_drain_roundtrip_zero_loss(tmp_path, clock):
    buf = str(tmp_path / "spool.db")
    _init_buffer(buf)

    payloads = [{"Bz": i * 0.5, "satellite_id": "goes-18"} for i in range(25)]
    stamps = [clock.stamp() for _ in payloads]
    for mono_ns, p in zip(stamps, payloads):
        _buffer_retain(buf, mono_ns, p)

    pending = _buffer_pending(buf)
    assert len(pending) == 25
    # Drain order must be temporal (ORDER BY mono_ns), never insertion luck.
    drained_stamps = [row[1] for row in pending]
    assert drained_stamps == sorted(drained_stamps)
    for (_, _, pj), expected in zip(pending, payloads):
        assert json.loads(pj) == expected

    ids = [row[0] for row in pending]
    _buffer_mark_synced(buf, ids)
    assert _buffer_pending(buf) == []          # fully acknowledged, nothing lost


def test_partial_ack_keeps_unsynced_rows(tmp_path, clock):
    buf = str(tmp_path / "spool2.db")
    _init_buffer(buf)
    for i in range(10):
        _buffer_retain(buf, clock.stamp(), {"flux": i})

    first_five = _buffer_pending(buf)[:5]
    _buffer_mark_synced(buf, [r[0] for r in first_five])
    remaining = _buffer_pending(buf)
    assert len(remaining) == 5
    assert [json.loads(r[2])["flux"] for r in remaining] == [5, 6, 7, 8, 9]
