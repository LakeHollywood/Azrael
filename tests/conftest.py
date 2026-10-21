"""Shared fixtures/constants for the SAIL constitutional test suites.

``ROOT`` is the repository root (the directory containing ``sail.py``,
``pyproject.toml`` and the ``tests/`` package).  Gate tests that shell out
to pytest or read first-party sources pin their paths here so they run
identically from any working directory.
"""

from pathlib import Path

# tests/conftest.py -> parents[0]=tests, parents[1]=repo root
ROOT = Path(__file__).resolve().parents[1]

# Compatibility shim: tests/ is a package (tests/__init__.py), so pytest's
# default "prepend" import mode imports this file as ``tests.conftest`` and
# sibling modules can no longer resolve the bare ``conftest`` name they used
# before tests/ was packaged (e.g. tests/test_production_gates.py does
# ``from conftest import ROOT``).  Registering this module under the plain
# ``conftest`` alias keeps those legacy imports working from any CWD without
# editing the gate suite itself.
import sys as _sys

if "conftest" not in _sys.modules:
    _sys.modules["conftest"] = _sys.modules[__name__]
del _sys

# Declare tests.sovereign.fixtures as a global pytest plugin for all subtrees.
# Pytest loads root-level pytest_plugins before initiating collection, so the
# shared fixtures (sts, ledger, gate, quarantine, boundary, armed_gate) become
# universally discoverable across tests/unit/, tests/abide/, and tests/harness/
# without duplicating conftest.py shims in every subtree.  Single source of
# truth: tests/sovereign/fixtures.py remains the authoritative definition file.
pytest_plugins = ["tests.sovereign.fixtures"]
