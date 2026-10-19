"""tests/pipelines — event-driven telemetry pipeline regressions.

Mirrors the compose command `pytest tests/ledger/ tests/pipelines/`.
Covers the TC4 pipeline contract: buffer-retain under fault, drain-on-
reconnect with zero loss, watchdog cadence independence, and end-to-end
ingest ordering through the STS clock.
"""
