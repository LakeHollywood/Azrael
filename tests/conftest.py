"""Shared fixtures/constants for the SAIL constitutional test suites.

``ROOT`` is the repository root (the directory containing ``sail.py``,
``pyproject.toml`` and the ``tests/`` package).  Gate tests that shell out
to pytest or read first-party sources pin their paths here so they run
identically from any working directory.
"""

from pathlib import Path

# tests/conftest.py -> parents[0]=tests, parents[1]=repo root
ROOT = Path(__file__).resolve().parents[1]

# Declare tests.sovereign.fixtures as a global pytest plugin for all subtrees.
# Pytest loads root-level pytest_plugins before initiating collection, so the
# shared fixtures (sts, ledger, gate, quarantine, boundary, armed_gate) become
# universally discoverable across tests/unit/, tests/abide/, and tests/harness/
# without duplicating conftest.py shims in every subtree.  Single source of
# truth: tests/sovereign/fixtures.py remains the authoritative definition file.
pytest_plugins = ["tests.sovereign.fixtures"]
