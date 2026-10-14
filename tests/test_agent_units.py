#!/usr/bin/env python3
"""Unit tests for sts_noaa_telemetry_agent pure/near-pure functions."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import sts_noaa_telemetry_agent as agent


class SdNotifyTests(unittest.TestCase):
    def test_no_socket_env_is_noop(self):
        env = {k: v for k, v in os.environ.items() if k != "NOTIFY_SOCKET"}
        with mock.patch.dict(os.environ, env, clear=True):
            agent.sd_notify("WATCHDOG=1")  # must not raise

    def test_abstract_socket_translates_to_nul_prefix(self):
        sent = {}

        class FakeSock:
            def sendto(self, data, addr):
                sent["data"], sent["addr"] = data, addr
            def close(self):
                pass

        with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": "@/run/systemd"}), \
             mock.patch("socket.socket", return_value=FakeSock()):
            agent.sd_notify("READY=1")
        self.assertEqual(sent["data"], b"READY=1")
        self.assertTrue(sent["addr"].startswith("\0"))


class GetMaxSafeBackoffTests(unittest.TestCase):
    def test_half_of_watchdog(self):
        with mock.patch.dict(os.environ, {"WATCHDOG_USEC": "30000000"}):
            self.assertAlmostEqual(agent.get_max_safe_backoff(), 15.0)

    def test_default_when_unset(self):
        env = {k: v for k, v in os.environ.items() if k != "WATCHDOG_USEC"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(agent.get_max_safe_backoff(default_cap=7.5), 7.5)


class FetchNoaaTests(unittest.TestCase):
    def _fake_response(self, payload, status=200):
        r = mock.Mock()
        r.status_code = status
        r.json.return_value = payload
        return r

    def test_returns_latest_dict_record(self):
        payload = [{"v": 1}, {"v": 2}, "junk"]
        fake = self._fake_response(payload)
        with mock.patch.object(agent.session, "get", return_value=fake):
            record, jitter, ts = agent.fetch_noaa("TEST", "https://x")
        self.assertEqual(record, {"v": 2})
        self.assertGreaterEqual(jitter, 0)

    def test_http_error_returns_none(self):
        fake = self._fake_response([], status=500)
        with mock.patch.object(agent.session, "get", return_value=fake):
            record, _, _ = agent.fetch_noaa("TEST", "https://x")
        self.assertIsNone(record)

    def test_non_list_payload_returns_none(self):
        fake = self._fake_response({"unexpected": "object"})
        with mock.patch.object(agent.session, "get", return_value=fake):
            record, _, _ = agent.fetch_noaa("TEST", "https://x")
        self.assertIsNone(record)

    def test_network_exception_is_swallowed_to_none(self):
        with mock.patch.object(agent.session, "get",
                               side_effect=ConnectionError("boom")):
            record, _, _ = agent.fetch_noaa("TEST", "https://x")
        self.assertIsNone(record)


if __name__ == "__main__":
    unittest.main()
