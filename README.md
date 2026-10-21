# Azrael — S.A.I.L. / Sovereign Engine & ABIDE-Harness

Enterprise Design Partner Briefing

A high-assurance security framework combining a cryptographic reference monitor harness with a native Python runtime execution boundary for autonomous AI agents.

## Architecture Overview

* **Strict Capability Attenuation**: Mathematical invariant enforcement ensuring $A_{i+1} \subseteq A_i \subseteq P_{\text{root}}$, preventing privilege amplification by construction.
* **Cryptographic Token Binding**: Ed25519-backed ephemeral tokens with domain-separated signing bytes, epoch validation, and single-use nonces.
* **Python Runtime Enforcement (`abide_monitor.py`)**: Live agent execution loop boundary enforcement, SEAL-shaped telemetry emission, and automated `QUARANTINE_HOLD` triggers. See [`docs/spec/05-runtime-enforcement.md`](docs/spec/05-runtime-enforcement.md) for the full parity architecture.
* **Rust Parity Target (`ABIDE-Harness`, planned)**: Reference monitor verification, empirical leakage tracking ($R_A, R_D, R_{RD}$), and property-based fuzzing via `proptest`. The Rust crate is not yet vendored in this repository; the Makefile dispatches cargo targets automatically once `Cargo.toml` lands.
* **Stateless Agent State**: Agents maintain zero authorization fields by design, neutralizing confused-deputy vectors.

## Usage & Verification

```bash
# Run Python unit and ABIDE conformance tests (94 passing)
pytest tests/unit/ tests/abide/

# Full CI gate (formatting check + lints + tests)
make

# Once the Rust crate is vendored (requires Cargo.toml):
#   cargo test --all-targets
#   cargo clippy --all-targets -- -D warnings
#   cargo fmt --check
```

## License
License pending (no `LICENSE` file has been adopted yet).
