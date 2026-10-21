# Runtime Enforcement & Python Parity Architecture

## 1. Overview
While the Rust `ABIDE-Harness` provides high-assurance cryptographic fuzzing and reference monitor verification, the **Sovereign Engine** utilizes a native Python parity mirror (`src/sovereign_engine/execution/abide_monitor.py`) to enforce identical capability lattice and token verification rules directly within the live agent execution loop.

## 2. Core Runtime Components
* **Ed25519 Cryptographic Verification**: Integrates with a pluggable `SignatureVerifier` protocol to validate cryptographic tokens over domain-separated signing bytes (agent identity, epoch, expiry, nonce, and sorted capability sets).
* **Three-Way Lattice Enforcement**: Dynamically asserts:
  1. Context capabilities remain bounded by root policy ($A_i \subseteq P_{\text{root}}$).
  2. Presented token capabilities remain bounded by root policy ($\tau_{\text{caps}} \subseteq P_{\text{root}}$).
  3. Token scope does not exceed session privileges ($\tau_{\text{caps}} \subseteq A_{\text{session}}$).
* **Single-Use Liveness Ledger**: Tracks cryptographic nonces to prevent replay attacks, token resurrection, and multi-round leakage across hierarchy levels.

## 3. Breach vs. Denial Semantics
To maintain clean telemetry and precise audit records, the runtime strictly separates policy checks:
* **Policy Denials**: When an agent requests an action outside its valid capability set (but within valid administrative bounds), the monitor returns `False`. This logs a denial without triggering false alarms.
* **Security Breaches**: Structural invariant violations (e.g., signature forgeries, token consumption replays, root policy escapes, expired token reuse) raise a `SecurityError` and immediately invoke the `on_breach` quarantine callback.

## 4. Closed-Loop Quarantine Integration (`QUARANTINE_HOLD`)
The runtime execution boundary (`ABIDEExecutionBoundary`) wraps standard dispatch mechanisms. When `on_breach` is triggered, it hooks directly into `quarantine.hold(resource=..., epoch=..., reason=...)`, automatically transitioning compromised or adversarial agent contexts into an audited quarantine state accompanied by SEAL-shaped telemetry.
