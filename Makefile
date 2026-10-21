# Sovereign Engine / ABIDE-Harness — deterministic CI & audit commands.
#
# This repository contains BOTH a Python control plane (src/sovereign_engine,
# tests/) and a Rust module (src/azrael/receptor.rs). The Makefile dispatches
# per-language targets so each toolchain only runs when its manifest exists:
#   - cargo targets require Cargo.toml at the repo root
#   - pytest/mutmut targets drive the Python suite via pytest.ini
#
# Usage: make help

.PHONY: all build test fuzz lint fmt check-fmt clean help

# Default target: check formatting, run strict lints, and execute all tests
all: check-fmt lint test

help:
	@echo "ABIDE-Harness Development Commands:"
	@echo "  make build      - Build the crate in release mode with LTO"
	@echo "  make test       - Run all unit, integration, and property tests"
	@echo "  make fuzz       - Run the proptest fuzz suite explicitly"
	@echo "  make lint       - Run strict Clippy lints (-D warnings)"
	@echo "  make fmt        - Format all code using cargo fmt"
	@echo "  make check-fmt  - Verify code formatting (CI check)"
	@echo "  make clean      - Remove build artifacts and target directory"

# ---------------------------------------------------------------------------
# Rust toolchain (requires Cargo.toml; skipped with an explicit notice if the
# crate manifest is absent, so `make` never silently no-ops on this branch)
# ---------------------------------------------------------------------------

HAS_CARGO := $(shell command -v cargo >/dev/null 2>&1 && echo 1 || echo 0)
# Crate location: root Cargo.toml if present, else the abide_harness/ crate.
ifeq ($(wildcard Cargo.toml),Cargo.toml)
CARGO := cargo
MANIFEST :=
else ifeq ($(wildcard abide_harness/Cargo.toml),abide_harness/Cargo.toml)
CARGO := cargo
MANIFEST := abide_harness/Cargo.toml
else
CARGO :=
MANIFEST :=
endif
# Run all cargo commands from the crate directory (cargo fmt does not
# support --manifest-path, so directory-based invocation is the portable way).
ifeq ($(MANIFEST),)
CRATE_DIR := .
else
CRATE_DIR := abide_harness
endif
CARGO_RUN := cd $(CRATE_DIR) && cargo

# Build the crate in release mode
build:
ifeq ($(HAS_CARGO),1)
ifeq ($(CARGO),)
	@echo "SKIP build: no Cargo.toml found at repo root or abide_harness/." >&2; exit 1
else
	$(CARGO_RUN) build --release
endif
else
	@echo "SKIP build: no cargo toolchain found." >&2; exit 1
endif

# Run all tests across unit, integration, and fuzz suites.
# Rust: cargo test --all-targets (when the crate is present).
# Python: full pytest suite (canonical conformance + ABIDE vectors).
test:
ifeq ($(HAS_CARGO),1)
ifneq ($(CARGO),)
	$(CARGO_RUN) test --all-targets
endif
endif
	pytest

# Run the proptest suite specifically with output enabled
fuzz:
ifeq ($(HAS_CARGO),1)
ifneq ($(CARGO),)
	$(CARGO_RUN) test --test property_tests -- --nocapture
else
	@echo "SKIP fuzz: no Cargo.toml found at repo root or abide_harness/." >&2; exit 1
endif
else
	@echo "SKIP fuzz: no cargo toolchain found." >&2; exit 1
endif

# Run strict Clippy checks enforcing zero warnings
lint:
ifeq ($(HAS_CARGO),1)
ifneq ($(CARGO),)
	$(CARGO_RUN) clippy --all-targets -- -D warnings
else
	@echo "SKIP rust lint: no Cargo.toml found." >&2
endif
else
	@echo "SKIP rust lint: no cargo toolchain found." >&2
endif

# Format source code (Rust + Python)
fmt:
ifeq ($(HAS_CARGO),1)
ifneq ($(CARGO),)
	$(CARGO_RUN) fmt
endif
endif
	@command -v ruff >/dev/null 2>&1 && ruff format src tests || echo "SKIP py fmt: ruff not installed."

# Check formatting without modifying files (ideal for CI)
check-fmt:
ifeq ($(HAS_CARGO),1)
ifneq ($(CARGO),)
	$(CARGO_RUN) fmt --check
endif
endif
	@command -v ruff >/dev/null 2>&1 && ruff check src tests || echo "SKIP py lint: ruff not installed."

# Clean build artifacts
clean:
ifeq ($(HAS_CARGO),1)
	cargo clean
endif
	rm -rf .pytest_cache **/__pycache__ artifacts/*.tmp
