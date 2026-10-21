# Azrael — S.A.I.L. / Sovereign Engine & ABIDE-Harness

Enterprise Design Partner Briefing

A high-assurance security framework combining a cryptographic reference monitor harness with a native Python runtime execution boundary for autonomous AI agents.

## Architecture Overview

* **Strict Capability Attenuation**: Mathematical invariant enforcement ensuring $A_{i+1} \subseteq A_i \subseteq P_{\text{root}}$, preventing privilege amplification by construction.
* **Cryptographic Token Binding**: Ed25519-backed ephemeral tokens with domain-separated signing bytes, epoch validation, and single-use nonces.
* **Python Runtime Enforcement (`abide_monitor.py`)**: Live agent execution loop boundary enforcement, SEAL-shaped telemetry emission, and automated `QUARANTINE_HOLD` triggers. See [`docs/spec/05-runtime-enforcement.md`](docs/spec/05-runtime-enforcement.md) for the full parity architecture.
* **Rust Parity Mirror (`abide_harness/` crate)**: Reference monitor verification (predicate P, STS window, scope binding, single-use consumption), engine state machine with QUARANTINE_HOLD handoff checks, and compile-time evidence/authorization type isolation. Note: empirical leakage tracking ($R_A, R_D, R_{RD}$) and `proptest` fuzzing are not yet implemented in the crate (no external deps vendored); they remain planned.
* **Stateless Agent State**: Agents maintain zero authorization fields by design, neutralizing confused-deputy vectors.

## Usage & Verification

```bash
# Run Python unit and ABIDE conformance tests (94 passing)
pytest tests/unit/ tests/abide/

# Full CI gate (formatting check + lints + tests)
make

# Rust parity mirror crate (from abide_harness/, or via `make test` at root):
cd abide_harness && cargo test --all-targets
cargo clippy --all-targets -- -D warnings   # strict zero-warning gate
cargo fmt --check                            # formatting gate
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

Copyright 2026 LakeHollywood + Kris Park.
