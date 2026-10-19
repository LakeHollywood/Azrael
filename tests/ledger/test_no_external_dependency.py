"""Prove STS independence from external infrastructure (TC4 architectural claim).

The compose harness deliberately exposes DB_URL / KAFKA_BOOTSTRAP_SERVERS.
These tests assert the agents NEVER use them: with Postgres/Kafka unreachable
(or simply absent, as in bare-metal runs), every commit, seal, and buffered
event still succeeds locally. If any future refactor introduces a hard
dependency on remote services, these tests fail loudly.
"""

from __future__ import annotations

import os
import socket

from bench.tc3_ledger_throughput import make_noaa_record
import random


def _tcp_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def test_ledger_commits_with_all_external_services_down(ledger, clock):
    """Total-infrastructure-outage simulation: local sealing must not flinch."""
    saved = {k: os.environ.get(k) for k in
             ("DB_URL", "KAFKA_BOOTSTRAP_SERVERS")}
    # Point env vars at dead endpoints — black-hole port 9/ or unroutable host.
    os.environ["DB_URL"] = "postgresql://validator:x@unreachable.invalid:5432/none"
    os.environ["KAFKA_BOOTSTRAP_SERVERS"] = "unreachable.invalid:9092"
    try:
        rnd = random.Random(1)
        for i in range(200):
            ledger.append(clock, "GOES_MAG", make_noaa_record("GOES_MAG", i, rnd))
        ok, errors = ledger.verify()
        assert ok, f"external outage corrupted local chain: {errors[:3]}"
        assert ledger.commits == 200
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_compose_negative_controls_are_not_required(tmp_path, clock):
    """In the harness, postgres/kafka may be down; outside it they are absent.

    Either way the assertion is identical: STS operation must not depend on
    their reachability. We only *record* reachability to document the test
    matrix condition; we never gate functionality on it.
    """
    db_url = os.environ.get("DB_URL", "")
    kafka = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "")
    reachable = []
    if db_url:
        host = db_url.split("@")[-1].split(":")[0]
        reachable.append(("postgres", _tcp_reachable(host, 5432)))
    if kafka:
        host = kafka.split(":")[0]
        reachable.append(("kafka", _tcp_reachable(host, 9092)))

    led_path = str(tmp_path / "noext.db")
    from bench.sts_time import AssuranceLedger
    led = AssuranceLedger(led_path)
    rnd = random.Random(2)
    for i in range(50):
        led.append(clock, "DSCOVR_PLASMA",
                   make_noaa_record("DSCOVR_PLASMA", i, rnd))
    ok, _ = led.verify()
    led.close()
    assert ok, "local ledger failed regardless of external service state"
    # Documented, not asserted: services may legitimately be unreachable.
    print(f"negative-control reachability: {reachable}")
