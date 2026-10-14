#!/usr/bin/env python3
"""Unit tests for sts_noaa_telemetry_agent.py

Covers:
  - sd_notify (unix socket delivery, abstract sockets, no-op, error swallowing)
  - get_max_safe_backoff (WATCHDOG_USEC parsing, invalid values, default cap)
  - init_db (SQLite schema creation)
  - fetch_noaa (success paths, HTTP errors, malformed payloads, exceptions)
  - bind_and_buffer (hash construction + DB row insertion)
  - verify_telemetry_integrity (match / mismatch)
"""

import hashlib
import json
import os
import socket
import sqlite3
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sts_noaa_telemetry_agent as agent


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Point the module-level DB_PATH at a temporary SQLite file."""
    db_path = str(tmp_path / "telemetry_test.db")
    monkeypatch.setattr(agent, "DB_PATH", db_path)
    return db_path


class FakeResponse:
    def __init__(self, status_code=200, payload=None, exc=None):
        self.status_code = status_code
        self._payload = payload
        self._exc = exc

    def json(self):
        if self._exc:
            raise self._exc
        return self._payload


# ── sd_notify ───────────────────────────────────────────────────────────────

def test_sd_notify_noop_without_socket_env(monkeypatch):
    """With NOTIFY_SOCKET unset, sd_notify must not touch the network at all."""
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    with mock.patch.object(socket, "socket") as mock_sock:
        agent.sd_notify("READY=1")
        mock_sock.assert_not_called()


def test_sd_notify_sends_to_filesystem_socket(tmp_path, monkeypatch):
    path = str(tmp_path / "notify.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(path)
    server.settimeout(2.0)
    try:
        monkeypatch.setenv("NOTIFY_SOCKET", path)
        agent.sd_notify("WATCHDOG=1")
        data, _ = server.recvfrom(4096)
        assert data == b"WATCHDOG=1"
    finally:
        server.close()


def test_sd_notify_translates_abstract_socket(monkeypatch):
    """Abstract sockets ('@prefix') must be converted to a leading NUL byte."""
    captured = {}

    class FakeSock:
        def sendto(self, payload, address):
            captured["payload"] = payload
            captured["address"] = address

        def close(self):
            pass

    monkeypatch.setenv("NOTIFY_SOCKET", "@/systemd/notify")
    with mock.patch.object(socket, "socket", return_value=FakeSock()):
        agent.sd_notify("READY=1")

    assert captured["address"] == "\0/systemd/notify"
    assert captured["payload"] == b"READY=1"


def test_sd_notify_swallows_errors(monkeypatch):
    """Socket failures must be logged, never raised into the daemon loop."""
    monkeypatch.setenv("NOTIFY_SOCKET", "/nonexistent/path/socket")
    with mock.patch.object(agent.logging, "error") as mock_err:
        agent.sd_notify("READY=1")  # should not raise
        mock_err.assert_called_once()
        assert "sd_notify failed" in mock_err.call_args[0][0]


# ── get_max_safe_backoff ────────────────────────────────────────────────────

@pytest.mark.parametrize("usec,expected", [
    ("30000000", 15.0),   # 30s watchdog -> half = 15s
    ("1000000", 0.5),     # 1s watchdog  -> half = 0.5s
    ("600000000", 300.0), # 10min watchdog -> half = 300s
])
def test_max_safe_backoff_parses_watchdog_usec(monkeypatch, usec, expected):
    monkeypatch.setenv("WATCHDOG_USEC", usec)
    assert agent.get_max_safe_backoff() == pytest.approx(expected)


def test_max_safe_backoff_invalid_value_uses_default(monkeypatch):
    monkeypatch.setenv("WATCHDOG_USEC", "not-a-number")
    assert agent.get_max_safe_backoff(default_cap=15.0) == 15.0


def test_max_safe_backoff_unset_env_uses_default(monkeypatch):
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    assert agent.get_max_safe_backoff(default_cap=7.5) == 7.5


def test_max_safe_backoff_custom_default_cap(monkeypatch):
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    assert agent.get_max_safe_backoff(default_cap=42.0) == 42.0


# ── init_db ─────────────────────────────────────────────────────────────────

def test_init_db_creates_schema(tmp_db):
    agent.init_db()
    conn = sqlite3.connect(tmp_db)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(telemetry_buffer)")}
        assert cols == {
            "id", "endpoint", "monotonic_ts", "utc_ts",
            "ingress_jitter", "telemetry_hash", "noaa_time_tag", "synced",
        }
    finally:
        conn.close()


def test_init_db_is_idempotent(tmp_db):
    agent.init_db()
    agent.init_db()  # second run must not fail (CREATE TABLE IF NOT EXISTS)
    conn = sqlite3.connect(tmp_db)
    count = conn.execute("SELECT COUNT(*) FROM telemetry_buffer").fetchone()[0]
    conn.close()
    assert count == 0


# ── fetch_noaa ──────────────────────────────────────────────────────────────

def test_fetch_returns_latest_dict_record():
    payload = [
        {"time_tag": "2026-10-01T00:00:00Z", "value": 1},
        {"time_tag": "2026-10-01T00:01:00Z", "value": 2},
        "garbage-entry",
    ]
    fake_session = mock.Mock()
    fake_session.get.return_value = FakeResponse(200, payload)
    times = iter([100.0, 100.25])

    with mock.patch.object(agent, "session", fake_session), \
         mock.patch.object(agent, "get_monotonic_time", side_effect=lambda: next(times)):
        record, jitter, mono_ts = agent.fetch_noaa("GOES_MAG", "https://example.invalid/x.json")

    assert record == {"time_tag": "2026-10-01T00:01:00Z", "value": 2}
    assert jitter == pytest.approx(0.25)
    assert mono_ts == pytest.approx(100.25)
    fake_session.get.assert_called_once_with("https://example.invalid/x.json", timeout=3.0)


def test_fetch_skips_non_dict_records_from_tail():
    payload = [{"time_tag": "A"}, "junk", ["also", "junk"]]
    fake_session = mock.Mock()
    fake_session.get.return_value = FakeResponse(200, payload)

    with mock.patch.object(agent, "session", fake_session), \
         mock.patch.object(agent, "get_monotonic_time", return_value=1.0):
        record, _, _ = agent.fetch_noaa("DSCOVR_MAG", "https://example.invalid/y.json")

    assert record == {"time_tag": "A"}


@pytest.mark.parametrize("payload", [[], None, {"not": "a list"}])
def test_fetch_rejects_empty_or_invalid_structure(payload):
    fake_session = mock.Mock()
    fake_session.get.return_value = FakeResponse(200, payload)

    with mock.patch.object(agent, "session", fake_session), \
         mock.patch.object(agent, "get_monotonic_time", return_value=1.0), \
         mock.patch.object(agent.logging, "error") as mock_err:
        record, jitter, ts = agent.fetch_noaa("GOES_MAG", "https://example.invalid/z.json")

    assert record is None and jitter is None
    mock_err.assert_called_once()
    assert "Ingestion failure" in mock_err.call_args[0][0]


def test_fetch_all_non_dict_records_returns_none():
    fake_session = mock.Mock()
    fake_session.get.return_value = FakeResponse(200, ["junk", 42])

    with mock.patch.object(agent, "session", fake_session), \
         mock.patch.object(agent, "get_monotonic_time", return_value=1.0):
        record, jitter, _ = agent.fetch_noaa("GOES_MAG", "https://example.invalid/z.json")

    assert record is None and jitter is None


def test_fetch_http_error_status_returns_none():
    fake_session = mock.Mock()
    fake_session.get.return_value = FakeResponse(503, None)

    with mock.patch.object(agent, "session", fake_session), \
         mock.patch.object(agent, "get_monotonic_time", return_value=1.0), \
         mock.patch.object(agent.logging, "error") as mock_err:
        record, jitter, _ = agent.fetch_noaa("GOES_MAG", "https://example.invalid/z.json")

    assert record is None and jitter is None
    assert "HTTP 503" in mock_err.call_args[0][0]


def test_fetch_network_exception_returns_none():
    fake_session = mock.Mock()
    fake_session.get.side_effect = ConnectionError("network down")

    with mock.patch.object(agent, "session", fake_session), \
         mock.patch.object(agent, "get_monotonic_time", return_value=5.0):
        record, jitter, ts = agent.fetch_noaa("GOES_MAG", "https://example.invalid/z.json")

    assert record is None and jitter is None
    assert ts == 5.0  # still returns a fresh monotonic timestamp on failure


def test_fetch_bad_json_returns_none():
    fake_session = mock.Mock()
    fake_session.get.return_value = FakeResponse(200, exc=ValueError("bad json"))

    with mock.patch.object(agent, "session", fake_session), \
         mock.patch.object(agent, "get_monotonic_time", return_value=1.0):
        record, jitter, _ = agent.fetch_noaa("GOES_MAG", "https://example.invalid/z.json")

    assert record is None and jitter is None


# ── bind_and_buffer ─────────────────────────────────────────────────────────

def test_bind_and_buffer_writes_expected_row(tmp_db):
    agent.init_db()
    record = {"time_tag": "2026-10-14T12:00:00Z", "Bz": -1.2}
    mono_ts, utc_ts, jitter = 123.456, 1_700_000_000.0, 0.05

    with mock.patch.object(agent.time, "time", return_value=utc_ts):
        agent.bind_and_buffer("GOES_MAG", record, jitter, mono_ts)

    conn = sqlite3.connect(tmp_db)
    row = conn.execute(
        "SELECT endpoint, monotonic_ts, utc_ts, ingress_jitter, telemetry_hash,"
        " noaa_time_tag, synced FROM telemetry_buffer"
    ).fetchone()
    conn.close()

    expected_hash = hashlib.sha256(
        f"{json.dumps(record, sort_keys=True)}:{mono_ts}:{utc_ts}".encode()
    ).hexdigest()

    assert row[0] == "GOES_MAG"
    assert row[1] == pytest.approx(mono_ts)
    assert row[2] == pytest.approx(utc_ts)
    assert row[3] == pytest.approx(jitter)
    assert row[4] == expected_hash
    assert row[5] == "2026-10-14T12:00:00Z"
    assert row[6] == 0  # unsynced


def test_bind_and_buffer_missing_time_tag_defaults_unknown(tmp_db):
    agent.init_db()
    with mock.patch.object(agent.time, "time", return_value=1.0):
        agent.bind_and_buffer("DSCOVR_MAG", {"Bt": 5.0}, 0.01, 2.0)

    conn = sqlite3.connect(tmp_db)
    tag = conn.execute("SELECT noaa_time_tag FROM telemetry_buffer").fetchone()[0]
    conn.close()
    assert tag == "UNKNOWN"


def test_bind_and_buffer_roundtrips_through_verify(tmp_db):
    """Hash written by bind_and_buffer must pass verify_telemetry_integrity."""
    agent.init_db()
    record = {"time_tag": "T", "x": 1}
    with mock.patch.object(agent.time, "time", return_value=999.0):
        agent.bind_and_buffer("GOES_MAG", record, 0.02, 888.0)

    conn = sqlite3.connect(tmp_db)
    mono_ts, utc_ts, stored_hash = conn.execute(
        "SELECT monotonic_ts, utc_ts, telemetry_hash FROM telemetry_buffer"
    ).fetchone()
    conn.close()

    assert agent.verify_telemetry_integrity(record, mono_ts, utc_ts, stored_hash) is True


# ── verify_telemetry_integrity ──────────────────────────────────────────────

def test_verify_integrity_success():
    record = {"time_tag": "abc", "proton_density": 3.4}
    mono, utc = 10.5, 1_700_000_000.5
    good = hashlib.sha256(
        f"{json.dumps(record, sort_keys=True)}:{mono}:{utc}".encode()
    ).hexdigest()
    assert agent.verify_telemetry_integrity(record, mono, utc, good) is True


def test_verify_integrity_detects_tampered_payload():
    record = {"time_tag": "abc", "proton_density": 3.4}
    mono, utc = 10.5, 1_700_000_000.5
    good = hashlib.sha256(
        f"{json.dumps(record, sort_keys=True)}:{mono}:{utc}".encode()
    ).hexdigest()

    tampered = dict(record, proton_density=9.9)
    with pytest.raises(RuntimeError, match="integrity verification failed"):
        agent.verify_telemetry_integrity(tampered, mono, utc, good)


def test_verify_integrity_detects_timestamp_swap():
    """Reordering mono/utc timestamps must not validate (classic binding bug)."""
    record = {"time_tag": "abc"}
    mono, utc = 10.5, 1_700_000_000.5
    good = hashlib.sha256(
        f"{json.dumps(record, sort_keys=True)}:{mono}:{utc}".encode()
    ).hexdigest()

    with pytest.raises(RuntimeError):
        agent.verify_telemetry_integrity(record, utc, mono, good)


# ── Module constants sanity checks ─────────────────────────────────────────

def test_noaa_endpoints_are_https_json():
    assert set(agent.NOAA_ENDPOINTS) == {"GOES_MAG", "DSCOVR_MAG"}
    for url in agent.NOAA_ENDPOINTS.values():
        assert url.startswith("https://services.swpc.noaa.gov/")
        assert url.endswith(".json")


def test_get_monotonic_time_is_raw_clock():
    with mock.patch.object(agent.time, "clock_gettime", return_value=42.0) as m:
        assert agent.get_monotonic_time() == 42.0
        m.assert_called_once_with(agent.time.CLOCK_MONOTONIC_RAW)
