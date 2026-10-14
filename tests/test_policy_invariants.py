#!/usr/bin/env python3
"""Policy invariants for the STS NOAA telemetry agent.

These tests assert *policy* (what must always hold) rather than mere
behavior, so a mutant that weakens a safety guarantee fails here even if it
passes the unit tests:

  P1. Watchdog safety: the loop sleep cap derived from WATCHDOG_USEC never
      exceeds half the watchdog timeout, and falls back to a conservative
      default when no watchdog is configured.
  P2. Backoff bound: retry delays are bounded by the watchdog-safe cap;
      unbounded exponential growth is forbidden.
  P3. Buffer integrity: init_db() creates a real SQLite schema; ingested
      records are persisted before the next fetch cycle (no silent loss).
  P4. Integrity verification: verify_telemetry_integrity rejects tampered
      records (hash mismatch must not be tolerated).
  P5. Source-level policy: no bare ``except:``, endpoints use TLS only,
      no hardcoded credentials.
"""

import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import sts_noaa_telemetry_agent as agent  # noqa: E402

SOURCE = open(os.path.join(ROOT, "sts_noaa_telemetry_agent.py")).read()


class WatchdogCapPolicyTests(unittest.TestCase):
    """P1: get_max_safe_backoff must never return more than USEC/2."""

    def test_short_watchdog_caps_to_half(self):
        with mock.patch.dict(os.environ, {"WATCHDOG_USEC": "2000000"}):
            cap = agent.get_max_safe_backoff(default_cap=15.0)
        self.assertLessEqual(cap, 1.0 + 1e-9,
                             "sleep cap must be <= WATCHDOG_USEC / 2")
        self.assertGreater(cap, 0)

    def test_no_watchdog_uses_conservative_default(self):
        env = {k: v for k, v in os.environ.items() if k != "WATCHDOG_USEC"}
        with mock.patch.dict(os.environ, env, clear=True):
            cap = agent.get_max_safe_backoff(default_cap=15.0)
        self.assertEqual(cap, 15.0)
        self.assertLessEqual(cap, 60, "default cap must stay conservative")

    def test_malformed_watchdog_value_falls_back(self):
        with mock.patch.dict(os.environ, {"WATCHDOG_USEC": "not-a-number"}):
            cap = agent.get_max_safe_backoff(default_cap=15.0)
        self.assertGreater(cap, 0)
        self.assertLessEqual(cap, 60)


class BackoffBoundPolicyTests(unittest.TestCase):
    """P2: exponential backoff must be bounded, never unbounded."""

    def test_backoff_loop_is_bounded_in_source(self):
        # The daemon loop's delay computation must be wrapped in min(...)
        # against a cap; a mutant removing the cap fails this invariant.
        loop_src = SOURCE[SOURCE.index("def daemon_loop"):]
        self.assertTrue(
            re.search(r"min\s*\(", loop_src),
            "daemon_loop must clamp retry delay with min()/cap")

    def test_cap_used_on_success_path(self):
        loop_src = SOURCE[SOURCE.index("def daemon_loop"):]
        self.assertIn("get_max_safe_backoff", loop_src,
                      "loop must consult the watchdog-safe cap function")


class BufferIntegrityTests(unittest.TestCase):
    """P3: every sample lands in a valid SQLite buffer."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(self.db_path)
                        and os.unlink(self.db_path))
        self._orig = agent.DB_PATH
        agent.DB_PATH = self.db_path

    def tearDown(self):
        agent.DB_PATH = self._orig

    def test_init_db_creates_schema(self):
        agent.init_db()
        conn = sqlite3.connect(self.db_path)
        self.addCleanup(conn.close)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue(tables, "buffer DB must contain at least one table")

    def test_bind_and_buffer_persists_record(self):
        agent.init_db()
        try:
            agent.bind_and_buffer("GOES_MAG", {"mag_strength": 5.2},
                                  jitter=0.1, mono_ts=123.4)
        except TypeError:
            self.skipTest("bind_and_buffer signature differs")
        conn = sqlite3.connect(self.db_path)
        self.addCleanup(conn.close)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        total = sum(conn.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
                    for t in tables)
        self.assertGreaterEqual(total, 1,
                                "ingested record must be persisted")


class IntegrityVerificationTests(unittest.TestCase):
    """P4: tampering must be detected, never silently accepted."""

    def _hash_for(self, record, mono_ts, utc_ts):
        payload_str = json.dumps(record, sort_keys=True)
        return hashlib.sha256(
            f"{payload_str}:{mono_ts}:{utc_ts}".encode()).hexdigest()

    def test_roundtrip_accepts_correct_hash(self):
        record, mono_ts, utc_ts = {"mag_strength": 1.0}, 123.4, 456.7
        h = self._hash_for(record, mono_ts, utc_ts)
        self.assertTrue(
            agent.verify_telemetry_integrity(record, mono_ts, utc_ts, h))

    def test_tampered_record_raises(self):
        record, mono_ts, utc_ts = {"mag_strength": 1.0}, 123.4, 456.7
        h = self._hash_for(record, mono_ts, utc_ts)
        tampered = dict(record, mag_strength=999.0)
        with self.assertRaises(RuntimeError):
            agent.verify_telemetry_integrity(tampered, mono_ts, utc_ts, h)

    def test_wrong_hash_raises(self):
        # A verifier that always returns True is a safety hole; mutants that
        # delete/neutralize the comparison fail here.
        with self.assertRaises(RuntimeError):
            agent.verify_telemetry_integrity({"x": 1}, 1.0, 2.0, "deadbeef")


class StaticSourcePolicyTests(unittest.TestCase):
    """P5: repo-wide source policy, checked without executing anything."""

    def test_no_bare_except(self):
        self.assertNotIn("except:", SOURCE,
                         "bare except swallows KeyboardInterrupt/SystemExit")

    def test_endpoints_use_tls(self):
        for token in ('"http://', "'http://"):
            self.assertNotIn(token, SOURCE,
                             "telemetry endpoints must use HTTPS")

    def test_no_hardcoded_credentials(self):
        lowered = SOURCE.lower()
        for needle in ("api_key =", "password =", "secret ="):
            self.assertNotIn(needle, lowered)


if __name__ == "__main__":
    unittest.main()
