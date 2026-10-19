"""SEAL ledger core invariants: seals, chain linkage, monotonic ordering."""

from __future__ import annotations

import sqlite3

from bench.tc3_ledger_throughput import make_noaa_record, STREAMS


def test_fresh_ledger_verifies_empty(ledger):
    ok, errors = ledger.verify()
    assert ok and errors == []


def test_append_seals_chain_and_preserves_order(ledger, clock):
    import random
    rnd = random.Random(0xC0FFEE)
    for i in range(1, 201):
        stream = STREAMS[i % len(STREAMS)]
        ledger.append(clock, stream, make_noaa_record(stream, i, rnd))

    ok, errors = ledger.verify()
    assert ok, f"seal chain failed: {errors[:3]}"

    stamps = ledger.all_stamps()
    assert all(b >= a for a, b in zip(stamps, stamps[1:])), \
        "monotonic stamp ordering violated inside the ledger"
    assert ledger.commits == 200


def test_payload_tampering_is_detected(ledger, clock):
    for i in range(1, 51):
        ledger.append(clock, "GOES_MAG", {"Bz": float(i), "seq_hint": i})
    assert ledger.verify()[0]

    # Malicious editor rewrites one payload byte-for-byte.
    conn = sqlite3.connect(ledger.path)
    conn.execute("UPDATE ledger SET payload = ? WHERE seq = 25",
                 ('{"Bz":9999.0,"seq_hint":25}',))
    conn.commit()
    conn.close()

    ok, errors = ledger.verify()
    assert not ok
    assert any("seal mismatch" in e for e in errors)


def test_row_deletion_breaks_prev_seal_linkage(ledger, clock):
    for i in range(1, 41):
        ledger.append(clock, "DSCOVR_MAG", {"Bm": float(i)})

    conn = sqlite3.connect(ledger.path)
    conn.execute("DELETE FROM ledger WHERE seq = 20")
    conn.commit()
    conn.close()

    ok, errors = ledger.verify()
    assert not ok
    assert any("prev_seal break" in e or "seq gap" in e for e in errors)


def test_reopen_resumes_chain_from_persisted_tail(tmp_path, clock):
    from bench.sts_time import AssuranceLedger

    path = str(tmp_path / "resume.db")
    led1 = AssuranceLedger(path)
    for i in range(10):
        led1.append(clock, "SESS_ELECTRON", {"flux": i})
    led1.close()

    led2 = AssuranceLedger(path)          # cold restart must not fork the chain
    led2.append(clock, "SESS_ELECTRON", {"flux": 99})
    ok, errors = led2.verify()
    assert ok, f"resumed chain invalid: {errors[:3]}"
    assert led2._seq == 11
    led2.close()
