#!/usr/bin/env python3
"""Pytest harness used as mutmut's validator.

Covers every mutable line of sts_noaa_telemetry_agent.py that carries policy
meaning, with network and sleep fully mocked so mutants get fast, deterministic
verdicts. Kept separate from the unittest suites because mutmut's default
pytest collection chokes on mixed fixture/mark plugins in this environment.
"""

import os
import sqlite3
import tempfile
from unittest import mock

import pytest

import sts_noaa_telemetry_agent as agent


# ---------- sd_notify ----------

def test_sd_notify_noop_without_socket():
    env = {k: v for k, v in os.environ.items() if k != "NOTIFY_SOCKET"}
    with mock.patch.dict(os.environ, env, clear=True):
        agent.sd_notify("WATCHDOG=1")  # must not raise


def test_sd_notify_abstract_socket_translation():
    sent = {}

    class FakeSock:
        def sendto(self, data, addr):
            sent["data"], sent["addr"] = data, addr
        def close(self):
            pass

    with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": "@/run/systemd"}), \
         mock.patch("socket.socket", return_value=FakeSock()):
        agent.sd_notify("READY=1")
    assert sent["data"] == b"READY=1"
    # exact translation: NUL + everything after '@' (kills [1:] vs [2:] mutants)
    assert sent["addr"] == "\0/run/systemd"


def test_sd_notify_path_socket_passthrough():
    sent = {}

    class FakeSock:
        def sendto(self, data, addr):
            sent["addr"] = addr
        def close(self):
            pass

    with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": "/run/x.notify"}), \
         mock.patch("socket.socket", return_value=FakeSock()):
        agent.sd_notify("STOPPING=1")
    assert sent["addr"] == "/run/x.notify"


def test_sd_notify_sends_exact_state_bytes():
    sent = {}

    class FakeSock:
        def sendto(self, data, addr):
            sent["data"] = data
        def close(self):
            pass

    with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": "/run/x"}), \
         mock.patch("socket.socket", return_value=FakeSock()):
        agent.sd_notify("READY=1\nSTATUS=x")
    assert sent["data"] == b"READY=1\nSTATUS=x"


# ---------- get_max_safe_backoff ----------

def test_backoff_half_of_watchdog():
    with mock.patch.dict(os.environ, {"WATCHDOG_USEC": "30000000"}):
        assert agent.get_max_safe_backoff() == pytest.approx(15.0)


def test_backoff_default_when_unset():
    env = {k: v for k, v in os.environ.items() if k != "WATCHDOG_USEC"}
    with mock.patch.dict(os.environ, env, clear=True):
        assert agent.get_max_safe_backoff(default_cap=7.5) == 7.5


def test_backoff_default_on_garbage():
    with mock.patch.dict(os.environ, {"WATCHDOG_USEC": "abc"}):
        assert agent.get_max_safe_backoff(default_cap=9.0) == 9.0


def test_backoff_unit_conversion_is_microseconds():
    # explicit call with default_cap pins the constant; USEC->sec->half math
    with mock.patch.dict(os.environ, {"WATCHDOG_USEC": "2000000"}):
        assert agent.get_max_safe_backoff(default_cap=15.0) == pytest.approx(1.0)


# ---------- init_db / bind_and_buffer ----------

@pytest.fixture()
def tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old = agent.DB_PATH
    agent.DB_PATH = path
    yield path
    agent.DB_PATH = old
    os.unlink(path)


def test_init_db_creates_expected_table(tmp_db):
    agent.init_db()
    conn = sqlite3.connect(tmp_db)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(telemetry_buffer)")}
    conn.close()
    assert {"endpoint", "monotonic_ts", "telemetry_hash", "synced"} <= cols


def test_bind_and_buffer_roundtrip(tmp_db):
    agent.init_db()
    with mock.patch.object(agent.time, "time", return_value=999.5):
        agent.bind_and_buffer("GOES_MAG", {"time_tag": "2026-10-15T00:00:00Z",
                                           "B_strength": 5.0},
                              jitter=0.25, mono_ts=100.5)
    conn = sqlite3.connect(tmp_db)
    row = conn.execute(
        "SELECT endpoint, monotonic_ts, utc_ts, ingress_jitter,"
        " telemetry_hash, noaa_time_tag, synced"
        " FROM telemetry_buffer").fetchone()
    conn.close()
    assert row[0] == "GOES_MAG"
    assert row[1] == pytest.approx(100.5)
    assert row[2] == pytest.approx(999.5)   # kills `utc_ts = None` mutant
    assert row[3] == pytest.approx(0.25)
    assert len(row[4]) == 64
    assert row[5] == "2026-10-15T00:00:00Z"
    assert row[6] == 0


def test_bind_and_buffer_hash_binds_all_three_components(tmp_db):
    """Policy: hash must cover payload + mono_ts + utc_ts jointly."""
    import hashlib, json
    agent.init_db()
    record = {"v": 7}
    with mock.patch.object(agent.time, "time", return_value=42.0):
        agent.bind_and_buffer("E", record, jitter=0.1, mono_ts=8.0)
    expected = hashlib.sha256(
        f"{json.dumps(record, sort_keys=True)}:8.0:42.0".encode()
    ).hexdigest()
    conn = sqlite3.connect(tmp_db)
    stored = conn.execute("SELECT telemetry_hash FROM telemetry_buffer") \
                  .fetchone()[0]
    conn.close()
    assert stored == expected  # kills None/swap/drop-component mutants


# ---------- verify_telemetry_integrity ----------

def _hash(record, mono_ts, utc_ts):
    import hashlib, json
    payload_str = json.dumps(record, sort_keys=True)
    return hashlib.sha256(
        f"{payload_str}:{mono_ts}:{utc_ts}".encode()).hexdigest()


def test_integrity_accepts_valid():
    rec, m, u = {"a": 1}, 1.0, 2.0
    assert agent.verify_telemetry_integrity(rec, m, u, _hash(rec, m, u)) is True


def test_integrity_rejects_wrong_hash():
    with pytest.raises(RuntimeError):
        agent.verify_telemetry_integrity({"a": 1}, 1.0, 2.0, "f" * 64)


def test_integrity_rejects_tampered_record():
    rec, m, u = {"a": 1}, 1.0, 2.0
    h = _hash(rec, m, u)
    with pytest.raises(RuntimeError):
        agent.verify_telemetry_integrity({"a": 2}, m, u, h)


# ---------- fetch_noaa ----------

def _resp(payload, status=200):
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = payload
    return r


def test_fetch_returns_last_dict_and_passes_real_url():
    with mock.patch.object(agent.session, "get",
                           return_value=_resp([{"v": 1}, {"v": 2}, "junk"])) as g:
        rec, jitter, ts = agent.fetch_noaa("T", "https://example/feed")
    # url argument identity check kills `session.get(None, ...)` mutants
    assert g.call_args[0][0] == "https://example/feed"
    assert rec == {"v": 2}
    assert jitter >= 0


def test_fetch_jitter_is_end_minus_start():
    times = iter([100.0, 103.5])  # start_ts, end_ts
    with mock.patch.object(agent, "get_monotonic_time", side_effect=lambda: next(times)), \
         mock.patch.object(agent.session, "get", return_value=_resp([{"v": 1}])):
        rec, jitter, ts = agent.fetch_noaa("T", "https://x")
    assert jitter == pytest.approx(3.5)   # kills +/- and swap mutants
    assert ts == pytest.approx(103.5)


def test_fetch_timeout_is_bounded():
    with mock.patch.object(agent.session, "get", return_value=_resp([{"v": 1}])) as g:
        agent.fetch_noaa("T", "https://x")
    timeout = g.call_args[1]["timeout"]
    assert 0 < timeout <= 10.0, "requests must use a bounded timeout"


def test_fetch_bad_status():
    with mock.patch.object(agent.session, "get", return_value=_resp([], 500)):
        rec, _, _ = agent.fetch_noaa("T", "https://x")
    assert rec is None


def test_fetch_empty_payload():
    with mock.patch.object(agent.session, "get", return_value=_resp([])):
        rec, _, _ = agent.fetch_noaa("T", "https://x")
    assert rec is None


def test_fetch_non_list_payload():
    # payload is a list but contains no dict records -> must yield None
    with mock.patch.object(agent.session, "get", return_value=_resp([[], "x"])):
        rec, _, _ = agent.fetch_noaa("T", "https://x")
    assert rec is None


def test_fetch_network_error():
    with mock.patch.object(agent.session, "get",
                           side_effect=ConnectionError("boom")):
        rec, _, _ = agent.fetch_noaa("T", "https://x")
    assert rec is None


# ---------- run_ingestion_cycle / daemon_loop ----------

def test_cycle_success_when_records_available(tmp_db):
    agent.init_db()
    with mock.patch.object(agent, "fetch_noaa",
                           return_value=({"time_tag": "t"}, 0.1, 5.0)), \
         mock.patch.object(agent, "sd_notify"):
        assert agent.run_ingestion_cycle() is True


def test_cycle_failure_when_all_feeds_down():
    with mock.patch.object(agent, "fetch_noaa",
                           return_value=(None, None, 0.0)), \
         mock.patch.object(agent, "sd_notify"):
        assert agent.run_ingestion_cycle() is False


def test_cycle_pings_watchdog_once():
    with mock.patch.object(agent, "fetch_noaa",
                           return_value=(None, None, 0.0)), \
         mock.patch.object(agent, "sd_notify") as n:
        agent.run_ingestion_cycle()
    n.assert_called_once_with("WATCHDOG=1")


def test_daemon_loop_bounded_and_sleeps_safely():
    sleeps = []
    with mock.patch.object(time_module(), "sleep",
                           side_effect=lambda s: sleeps.append(s)), \
         mock.patch.object(agent, "run_ingestion_cycle", return_value=True), \
         mock.patch.object(agent, "sd_notify"), \
         mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("WATCHDOG_USEC", None)
        agent.daemon_loop(max_cycles=2)
    assert len(sleeps) == 2
    assert all(s <= 10.0 for s in sleeps)


def test_daemon_loop_backoff_growth_and_cap():
    sleeps = []
    calls = {"n": 0}

    def fake_cycle():
        calls["n"] += 1
        return False

    with mock.patch.object(time_module(), "sleep",
                           side_effect=lambda s: sleeps.append(s)), \
         mock.patch.object(agent, "run_ingestion_cycle", side_effect=fake_cycle), \
         mock.patch.object(agent, "sd_notify"), \
         mock.patch.dict(os.environ, {"WATCHDOG_USEC": "60000000"}):
        agent.daemon_loop(max_cycles=4)
    # WATCHDOG_USEC=60s -> cap 30s; backoff 1,2,4,8 all under cap
    assert sleeps == [1.0, 2.0, 4.0, 8.0]


def time_module():
    import time as t
    return t
