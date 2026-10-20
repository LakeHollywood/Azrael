"""Shared fixtures/constants for the SAIL constitutional test suites.

``ROOT`` is the repository root (the directory containing ``sail.py``,
``pyproject.toml`` and the ``tests/`` package).  Gate tests that shell out
to pytest or read first-party sources pin their paths here so they run
identically from any working directory.
"""

from pathlib import Path

# tests/conftest.py -> parents[0]=tests, parents[1]=repo root
ROOT = Path(__file__).resolve().parents[1]
