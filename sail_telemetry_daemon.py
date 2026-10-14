#!/usr/bin/env python3
"""
SAIL / AZRAEL Continuous Telemetry Ingestion Daemon — config loader.

Parses the TOML file referenced by `--config` (default: /etc/sail/config.toml)
and validates it into a Config dataclass. Deliberately stdlib-only so the unit
can run on minimal edge nodes without third-party dependencies.

Validation rules (fail-fast, raise ConfigError with an actionable message):
  * watchdog_interval_seconds must be > 0 and strictly less than the unit's
    WatchdogSec (10s). The daemon pings WATCHDOG=1 once per cycle; if the
    configured cadence ever reaches or exceeds WatchdogSec, systemd kills a
    merely-slow (not dead) daemon during a network dip.
  * endpoints must contain at least one name -> https URL mapping.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - fallback for < 3.11
    import tomli as tomllib  # type: ignore

DEFAULT_CONFIG_PATH = "/etc/sail/config.toml"
UNIT_WATCHDOG_SEC = 10.0  # must match WatchdogSec in systemd/sail_telemetry.service


class ConfigError(ValueError):
    """Raised when the on-disk configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    watchdog_interval_seconds: float
    http_timeout_seconds: float
    db_path: str
    log_path: str
    endpoints: dict = field(default_factory=dict)


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> Config:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as e:
        raise ConfigError(f"cannot read config file {p}: {e.strerror or e}") from e

    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except Exception as e:  # tomllib.TOMLDecodeError + UnicodeDecodeError
        raise ConfigError(f"invalid TOML in {p}: {e}") from e

    watchdog = data.get("watchdog_interval_seconds")
    if not isinstance(watchdog, (int, float)) or isinstance(watchdog, bool):
        raise ConfigError(
            "watchdog_interval_seconds must be a number "
            f"(got {type(watchdog).__name__})"
        )
    if not 0 < float(watchdog) < UNIT_WATCHDOG_SEC:
        raise ConfigError(
            f"watchdog_interval_seconds={watchdog} is unsafe: it must be greater "
            f"than 0 and strictly less than the unit's WatchdogSec="
            f"{UNIT_WATCHDOG_SEC:g}s, otherwise systemd will kill the daemon "
            "between watchdog pings"
        )

    endpoints = data.get("endpoints")
    if not isinstance(endpoints, dict) or not endpoints:
        raise ConfigError("endpoints must be a non-empty table of name -> url")
    for name, url in endpoints.items():
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ConfigError(
                f"endpoint {name!r} must be an https:// URL (got {url!r})"
            )

    return Config(
        watchdog_interval_seconds=float(watchdog),
        http_timeout_seconds=float(data.get("http_timeout_seconds", 3.0)),
        db_path=data.get("db_path", "/var/run/sail/telemetry_buffer.db"),
        log_path=data.get("log_path", "/var/log/sail/ingestion.log"),
        endpoints=dict(endpoints),
    )


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sail_telemetry_daemon",
        description="SAIL / AZRAEL Continuous Telemetry Ingestion Daemon",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"path to TOML config (default: {DEFAULT_CONFIG_PATH})",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"Loaded config: {cfg}")
