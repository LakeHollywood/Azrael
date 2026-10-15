"""Unit tests for systemd/sail_telemetry.service and the SAIL config loader.

The service unit is parsed with configparser (systemd unit files are INI-shaped)
so these tests run anywhere — no systemd, no root, no `systemd-analyze verify`
required. They enforce the same invariants the ansible playbook already encodes
for sts_noaa.service, plus the watchdog-cadence safety contract shared between
the unit file and /etc/sail/config.toml.
"""

import configparser
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_PATH = REPO_ROOT / "systemd" / "sail_telemetry.service"
CONFIG_EXAMPLE = REPO_ROOT / "systemd" / "config.toml.example"

import sail_telemetry_daemon as daemon_mod


@pytest.fixture(scope="module")
def unit():
    parser = configparser.ConfigParser(
        # systemd allows duplicate keys across sections; keep values verbatim
        interpolation=None,
        strict=False,
        delimiters=("=",),
    )
    # Units have no %(...)s-style interpolation but DO have bare $-vars; disable
    # configparser's own interpolation entirely.
    parser.optionxform = str
    text = UNIT_PATH.read_text()
    parser.read_string(text)
    return parser


# ---------------------------------------------------------------------------
# [Unit] section
# ---------------------------------------------------------------------------

def test_unit_description(unit):
    assert unit["Unit"]["Description"] == (
        "SAIL / AZRAEL Continuous Telemetry Ingestion Daemon"
    )


def test_ordering_against_network_and_time_sync(unit):
    # network-online.target (not just network.target): the daemon must not start
    # before routes/DNS are actually usable, or its first fetch always fails.
    after = unit["Unit"]["After"].split()
    wants = unit["Unit"]["Wants"].split()
    assert "network-online.target" in after
    assert "time-sync.target" in after  # monotonic/UTC binding needs a slewed clock
    assert "network-online.target" in wants
    assert "network.target" not in after or "network-online.target" in after


# ---------------------------------------------------------------------------
# [Service] section: type, exec, restart, watchdog
# ---------------------------------------------------------------------------

def test_service_type_is_notify(unit):
    assert unit["Service"]["Type"] == "notify"


def test_execstart_matches_pasted_unit(unit):
    exec_start = unit["Service"]["ExecStart"]
    assert exec_start.startswith("/usr/local/bin/sail_telemetry_daemon ")
    # --config flag must point at the canonical path
    assert "--config" in exec_start.split()
    cfg_arg = exec_start.split()[exec_start.split().index("--config") + 1]
    assert cfg_arg == "/etc/sail/config.toml"


def test_restart_policy(unit):
    assert unit["Service"]["Restart"] == "on-failure"
    assert unit["Service"]["RestartSec"] == "5s"


def test_watchdog_sec_present_and_valid(unit):
    raw = unit["Service"]["WatchdogSec"]
    assert raw.endswith("s")
    seconds = int(raw[:-1])
    assert seconds > 0


def test_timeout_start_sec_covers_notify_startup(unit):
    # Type=notify daemons that block on slow DNS would hit the 90s default;
    # pin an explicit value so regressions are visible in review.
    raw = unit["Service"]["TimeoutStartSec"]
    assert raw.endswith("s")
    assert int(raw[:-1]) >= 30


# ---------------------------------------------------------------------------
# [Service] section: isolation & security hardening
# ---------------------------------------------------------------------------

def test_required_hardening_directives(unit):
    svc = unit["Service"]
    assert svc["ProtectSystem"] == "strict"
    assert svc["ProtectHome"] == "true"
    assert svc["NoNewPrivileges"] == "true"
    assert svc["PrivateTmp"] == "true"


def test_unit_drops_privileges_to_dedicated_user(unit):
    # ProtectSystem=strict + User=root was the latent footgun in the pasted
    # draft: a root-owned process with the whole FS read-only except two paths.
    # The hardened unit must run unprivileged.
    assert unit["Service"].get("User", "root") != "root"
    assert unit["Service"].get("Group", "root") != "root"


def test_readwrite_paths_cover_declared_state_dirs(unit):
    rw = unit["Service"]["ReadWritePaths"].split()
    assert "/var/log/sail" in rw
    # both spellings of the runtime dir: /run/sail is canonical, /var/run is the
    # legacy symlink; listing both keeps behavior identical across distros.
    assert "/run/sail" in rw and "/var/run/sail" in rw


def test_state_runtime_logs_directories_declared(unit):
    # With PrivateTmp/ProtectHome/strict fs, the daemon can only write where
    # systemd pre-creates and chowns directories for it.
    for key in ("StateDirectory", "LogsDirectory", "RuntimeDirectory"):
        assert unit["Service"][key].strip() == "sail"


def test_no_writable_path_outside_whitelist(unit):
    # Constitutional guardrail: nothing writable under /home or /root.
    rw = unit["Service"]["ReadWritePaths"].split()
    for path in rw:
        assert not path.startswith(("/home", "/root"))


# ---------------------------------------------------------------------------
# Cross-file invariant: config cadence < WatchdogSec
# ---------------------------------------------------------------------------

def _unit_watchdog_seconds(unit) -> float:
    raw = unit["Service"]["WatchdogSec"]
    return float(raw.rstrip("s"))


def test_example_config_parses_and_loads(tmp_path, unit):
    cfg_text = CONFIG_EXAMPLE.read_text()
    p = tmp_path / "config.toml"
    p.write_text(cfg_text)
    cfg = daemon_mod.load_config(p)
    assert cfg.watchdog_interval_seconds > 0
    assert set(cfg.endpoints) == {"GOES_MAG", "DSCOVR_MAG"}


def test_example_config_cadence_below_watchdog_sec(unit):
    # The example shipped next to the unit must satisfy the loader's own rule.
    cfg = daemon_mod.load_config(CONFIG_EXAMPLE)
    assert cfg.watchdog_interval_seconds < _unit_watchdog_seconds(unit)


def test_loader_constant_matches_unit_watchdog(unit):
    assert daemon_mod.UNIT_WATCHDOG_SEC == _unit_watchdog_seconds(unit)


def test_loader_rejects_cadence_at_or_above_watchdog(tmp_path):
    base = CONFIG_EXAMPLE.read_text()
    for bad in ("10.0", "30"):  # equal-to and above WatchdogSec both kill the daemon
        p = tmp_path / f"bad-{bad}.toml"
        p.write_text(base.replace("watchdog_interval_seconds = 5.0",
                                  f"watchdog_interval_seconds = {bad}"))
        with pytest.raises(daemon_mod.ConfigError, match="WatchdogSec"):
            daemon_mod.load_config(p)
