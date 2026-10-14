#!/usr/bin/env python3
"""
Sovereign Time System (STS) - NOAA Continuous Telemetry Ingestion Daemon
Target: Splinter Command Tactical Edge Node
Features: Continuous daemon loop, exponential backoff, local SQLite buffer,
          dynamic WATCHDOG_USEC parsing, and systemd sd_notify integration.
"""

import os
import sys
import time
import json
import socket
import sqlite3
import hashlib
import logging
import requests

NOAA_ENDPOINTS = {
    "GOES_MAG": "https://services.swpc.noaa.gov/json/goes/primary/magnetometers-7-day.json",
    "DSCOVR_MAG": "https://services.swpc.noaa.gov/json/dscovr/dscovr_mag_1s.json"
}

DB_PATH = os.path.expanduser("~/sts_telemetry_buffer.db")
LOG_PATH = os.path.expanduser("~/sts_noaa_ingestion.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

session = requests.Session()


def sd_notify(state: str):
    """Sends state notifications directly to systemd via unix domain socket."""
    socket_path = os.environ.get("NOTIFY_SOCKET")
    if not socket_path:
        return
    # Abstract namespace sockets are prefixed with '@'; the kernel expects a
    # leading NUL byte instead.
    if socket_path.startswith("@"):
        socket_path = "\0" + socket_path[1:]

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.sendto(state.encode('utf-8'), socket_path)
        sock.close()
    except Exception as e:
        logging.error(f"sd_notify failed: {e}")


def get_max_safe_backoff(default_cap=15.0):
    """Dynamically calculates max safe backoff as half of systemd's configured WatchdogSec."""
    watchdog_usec = os.environ.get("WATCHDOG_USEC")
    if watchdog_usec:
        try:
            # WATCHDOG_USEC is in microseconds; target half the timeout interval
            return (float(watchdog_usec) / 1_000_000.0) / 2.0
        except ValueError:
            pass
    return default_cap


def init_db():
    """Initializes local SQLite database for offline telemetry buffering."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry_buffer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT,
            monotonic_ts REAL,
            utc_ts REAL,
            ingress_jitter REAL,
            telemetry_hash TEXT,
            noaa_time_tag TEXT,
            synced INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


def get_monotonic_time():
    """Fetches raw hardware monotonic timestamp."""
    return time.clock_gettime(time.CLOCK_MONOTONIC_RAW)


def fetch_noaa(name, url):
    """Fetches real-time payload with monotonic jitter calculation."""
    start_ts = get_monotonic_time()
    try:
        response = session.get(url, timeout=3.0)
        end_ts = get_monotonic_time()
        jitter = end_ts - start_ts

        if response.status_code != 200:
            raise RuntimeError(f"HTTP {response.status_code}")

        data = response.json()
        if not data or not isinstance(data, list):
            raise RuntimeError("Empty or invalid NOAA payload structure")

        record = next((r for r in reversed(data) if isinstance(r, dict)), None)
        if record is None:
            raise RuntimeError("No valid dict record found in NOAA payload")

        return record, jitter, end_ts

    except Exception as e:
        logging.error(f"[{name}] Ingestion failure: {e}")
        return None, None, get_monotonic_time()


def bind_and_buffer(name, record, jitter, mono_ts):
    """Generates dual-bound hash and writes entry to local SQLite buffer."""
    utc_ts = time.time()
    payload_str = json.dumps(record, sort_keys=True)

    telemetry_hash = hashlib.sha256(
        f"{payload_str}:{mono_ts}:{utc_ts}".encode()
    ).hexdigest()

    noaa_time_tag = record.get("time_tag", "UNKNOWN")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO telemetry_buffer (endpoint, monotonic_ts, utc_ts, ingress_jitter, telemetry_hash, noaa_time_tag, synced)
        VALUES (?, ?, ?, ?, ?, ?, 0)
    ''', (name, mono_ts, utc_ts, jitter, telemetry_hash, noaa_time_tag))
    conn.commit()
    conn.close()

    logging.info(f"BOUND_TELEMETRY: {name} | Mono: {mono_ts:.6f}s | Hash: {telemetry_hash[:16]}")
    print(f"[STS DAEMON] {name} Ingested | Jitter: {jitter*1000:.2f}ms | Hash: {telemetry_hash[:16]}...")


def verify_telemetry_integrity(record, mono_ts, utc_ts, expected_hash):
    """Cross-checks ingested telemetry against known-good hash using original observation timestamps."""
    payload_str = json.dumps(record, sort_keys=True)
    computed_hash = hashlib.sha256(
        f"{payload_str}:{mono_ts}:{utc_ts}".encode()
    ).hexdigest()

    if computed_hash != expected_hash:
        logging.critical(f"[INTEGRITY FAILURE] Expected: {expected_hash[:16]} | Computed: {computed_hash[:16]}")
        raise RuntimeError("Telemetry integrity verification failed")

    logging.info(f"[INTEGRITY VERIFIED] Hash match: {expected_hash[:16]}")
    return True


def daemon_loop():
    """Continuous execution loop with dynamic watchdog backoff and systemd keep-alive."""
    poll_interval = 10.0
    backoff = 1.0
    max_backoff = 300.0

    sd_notify("READY=1\nSTATUS=STS NOAA Ingestion Daemon Active")
    print("=== STS NOAA Ingestion Daemon Started ===")

    while True:
        cycle_success = False

        for name, url in NOAA_ENDPOINTS.items():
            record, jitter, mono_ts = fetch_noaa(name, url)
            if record:
                bind_and_buffer(name, record, jitter, mono_ts)
                cycle_success = True

        # Ping systemd watchdog keep-alive signal
        sd_notify("WATCHDOG=1")

        if cycle_success:
            backoff = 1.0
            time.sleep(poll_interval)
        else:
            # Dynamically cap sleep to half of WATCHDOG_USEC (or 15s fallback)
            # BEFORE sleeping so the watchdog ping cadence never exceeds
            # WatchdogSec — otherwise systemd would kill the daemon during a
            # network dip and defeat the whole backoff strategy.
            max_safe = get_max_safe_backoff(default_cap=15.0)
            safe_backoff = min(backoff, max_safe)
            logging.warning(f"Ingestion failed on all feeds. Backing off for {safe_backoff:.1f}s")
            print(f"[STS DAEMON] Network/Ingestion Dip. Retrying in {safe_backoff:.1f}s...")
            time.sleep(safe_backoff)
            backoff = min(backoff * 2.0, max_backoff)


if __name__ == "__main__":
    init_db()
    daemon_loop()
