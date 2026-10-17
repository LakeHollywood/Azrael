# Azrael — Technical Annex
### DARPA / Enterprise Documentation Package

| | |
|---|---|
| **Document** | Technical Annex (Rev. A) |
| **Prepared for** | DARPA program review & Enterprise design-partner briefing |
| **System under review** | `Azrael` — Human-in-the-Loop (HITL) approval-gate and tamper-evident ledger runtime for autonomous agents |
| **Date** | 2026-10-17 |
| **Repository state** | Branch tip `1d8a7b9`, clean working tree |
| **Classification** | Unclassified / company confidential — dev signing material excluded (§7) |

> **Note on milestone figures.** The programmatic brief referenced "43 passing tests."
> At the time of this annex, the TypeScript gate reports **49 passing tests across 4
> suites** (the agent-capability suite added 9 tests after that figure was quoted).
> All numbers in §5 are re-measured live against the repository at commit `1d8a7b9`
> and supersede any earlier verbal milestones.

---

## 1. Scope

This annex compiles the verified engineering milestones for the Azrael control plane:

1. **Full HITL loop** — a closed Propose → Approve → Execute lifecycle with cryptographic
   scope enforcement (Milestone M-1).
2. **Ledger anchoring** — fail-closed verification of hash-chained workflow ledgers with
   Ed25519 root-of-trust signatures and anchored balance snapshots (Milestone M-2).
3. **Capability confinement for agents** — a typed execution-context model in which delegated
   tasks can never widen their parent's gate allowlist or risk ceiling (Milestone M-3).
4. **Automated verification gates** — the current test corpus, CI compliance gate, and
   secret-hygiene controls (Milestones M-4, M-5).

## 2. System Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│ Agent / Task execution plane (TypeScript, src/lib)                 │
│  ExecutionContext ── AgentCapabilities ── TaskDefinition            │
│  capabilities.ts: validateTaskDelegation / deriveChildContext      │
└───────────────┬────────────────────────────────────────────────────┘
                │ gated invocations carry AuditContext {traceId, …}
┌───────────────▼────────────────────────────────────────────────────┐
│ Approval gate (Python, approval_gate/risk.py)                      │
│  risk score 0–100 → AUTONOMOUS / SINGLE / SENIOR / DUAL / RESTRICTED│
└───────────────┬────────────────────────────────────────────────────┘
                │ every transition appended to a signed ledger chain
┌───────────────▼────────────────────────────────────────────────────┐
│ Tamper-evident ledger (ledger_verifier.py + data/ledgers/*.json)   │
│  canonical JSON → payload_hash → HMAC prev|payload|ts → Ed25519 sig │
│  state machine: PROPOSED→APPROVED→EXECUTING→terminal               │
└───────────────┬────────────────────────────────────────────────────┘
                │ anchor snapshot (log_4492) pins balances
┌───────────────▼────────────────────────────────────────────────────┐
│ Ledger API server (scripts/ledger_api_server.py)                   │
│  POST transaction → velocity monitor → balance safety → verdict    │
└────────────────────────────────────────────────────────────────────┘
```

Key properties by construction:

* **Fail-closed everywhere.** Missing trace links, truncated digests, unverifiable anchors,
  or absent signing material all produce rejection, never implicit acceptance.
* **No privilege inheritance by default.** Approval scope is an explicit allowlist
  (`approval_context.authorized_targets`); successors outside it are rejected.
* **Monotone privilege decay.** Delegation down an agent→task chain is subset-constrained
  on gates and ceiling-constrained on risk score.

## 3. Milestone M-1 — Full HITL Loop (Verified)

The human-in-the-loop cycle is implemented as an enforced ledger state machine
(`ledger_verifier.py`, `_ALLOWED_TRANSITIONS`):

| Transition | Meaning | Enforcement |
|---|---|---|
| `PROPOSED → APPROVED` | Human/operator sign-off recorded with `approval_context` | Only legal successor besides `REJECTED`; approval must enumerate `authorized_targets` |
| `PROPOSED → REJECTED` | Denial closes the proposal | Terminal state |
| `APPROVED → EXECUTING` | Execution may begin | Rejected unless the approved ancestor's scope covers every extracted target |
| `EXECUTING → COMPLETED / FAILED / RESOLVED / ABORTED` | Outcome recording | Terminal states accept no successors |

Risk-tiered approval bar (`approval_gate/risk.py`), applied before the loop is entered:

| Composite risk score | Minimum policy |
|---|---|
| 0–19 | `AUTONOMOUS` (no human sign-off) |
| 20–39 | `SINGLE_APPROVAL` |
| 40–59 | `SENIOR_APPROVAL` |
| 60–79 | `DUAL_APPROVAL` (authz-impacting floor) |
| 80–100 | `RESTRICTED` (deny by default; break-glass only) |

Out-of-range scores are clamped to [0, 100]; the same bounds are mirrored in the
TypeScript capability layer so both planes agree on ceilings.

**Evidence (live run):** `data/ledgers/wf_992.json` contains the three-entry loop
`log_4492 (PROPOSED) → log_4493 (APPROVED, authorized_targets=["cash"]) →
log_4494 (EXECUTING)` and verifies end-to-end (§6, command V-1).

## 4. Milestone M-2 — Ledger Anchoring (Verified)

### 4.1 Chain construction
Each entry carries:

* `payload_hash = sha256(canonical_json(execution_context))` — sorted keys, compact
  separators, so serialization ambiguity cannot break verification;
* `current_hash = HMAC-SHA256(secret, "previous_ledger_hash|payload_hash|timestamp")` —
  canonicalization-explicit HMAC input string;
* `signature = Ed25519(current_hash digest bytes)` — root of trust; HMAC alone proves
  only shared-secret knowledge, the signature binds non-repudiable authorship;
* `previous_ledger_hash` — full 64-hex digest linking to the predecessor. Truncated or
  annotated digests (e.g. `8f7d…`) are rejected outright.

### 4.2 Anchor snapshot
The financial API server (`scripts/ledger_api_server.py`) refuses to price any
transaction unless it can load and self-verify the anchor entry `log_4492`:

* `_load_anchor()` recomputes the anchor's `payload_hash` and returns
  `503 anchor_snapshot_unverifiable` on any mismatch (fail-closed);
* money is handled exclusively in integer minor units (cents) from the anchored
  snapshot, with a float64-exactness guard (`MAX_DELTA_CENTS = 2^53`);
* each verdict echoes `anchor_ledger_id` and `anchor_payload_hash` so downstream
  consumers can confirm which state the decision was pinned to.

### 4.3 Key resolution
Verification keys resolve environment-first (`LEDGER_HMAC_SECRET_B64`,
`LEDGER_ED25519_PUBKEY_B64`) for production/CI, falling back to gitignored
`.ledgerdev/` files for local development only. Either half missing ⇒ verification
refused.

## 5. Milestone Verification Matrix

All results below were re-measured on 2026-10-17 at commit `1d8a7b9`.

| ID | Gate | Command | Result |
|---|---|---|---|
| V-1 | Ledger chain verify (full file) | `python ledger_verifier.py verify-ledger --ledger data/ledgers/wf_992.json --hmac-secret-file .ledgerdev/secret --pubkey-file .ledgerdev/pub.b64` | **PASS** (exit 0): "digests full, canonical hashes match, ed25519 signature valid, transitions and approval scope enforced" |
| V-2 | Single-entry scoped verify | `python ledger_verifier.py verify-ledger --ledger data/ledgers/export_job_9912.json --entry-id log_export_7732 …` | **PASS** (exit 0) |
| V-3 | Fail-closed negative case | same command with `--entry-id log_export_approval_7730` (no predecessor in file) | **PASS** — correctly emits `::error:: … (fail closed)` and exits 1 |
| V-4 | Python test corpus | `python -m pytest -q` | **506 passed**, 0 failed |
| V-5 | Ledger subsystem tests | `pytest test_ledger_verifier.py test_ledger_api_server.py` | **67 passed** |
| V-6 | TypeScript unit gate | `npx vitest run` | **49 passed / 4 suites** (supersedes the earlier "43 passing tests" milestone figure) |
| V-7 | Strict typecheck | `npm run typecheck` (`tsc --noEmit`) | **PASS** (exit 0) |
| V-8 | Secret hygiene | `python scripts/secret_scan.py --working` | **PASS** — deny-list covers `.ledgerdev/`, `*.pem`, `*.key`, `__pycache__/`; high-entropy blob detection active |

### Test-corpus breakdown (V-4, V-6)

| Suite | Coverage focus |
|---|---|
| `test_ledger_verifier.py` | Digest completeness, canonical hashing, HMAC binding, Ed25519 verification, transition legality, approval-scope enforcement incl. wf_992 remediation cases |
| `test_ledger_api_server.py` | Anchored pricing path, `anchor_snapshot_unverifiable` fail-closed behavior, idempotency cache, velocity limits, tenant routing |
| `test_balance_safety.py`, `test_risk_scoring.py`, `tests/unit/test_risk_thresholds.py` | Minor-unit arithmetic, clamping, policy-band boundaries |
| `test_sts_noaa_telemetry_agent.py`, `test_velocity_monitor.py`, `tests/unit/test_sail_telemetry_unit.py` | Operational agents and rate monitoring |
| `tests/unit/test_secret_scan.py` | Scanner self-tests |
| `src/__tests__/agentCapabilities.test.ts` (9) | Subset rejection, ceiling escalation, equal-ceiling acceptance, missing-traceId fail-closed, child-context derivation, execution guards |
| `src/__tests__/{tokenizeLine,analyzeDigestDiff,simulateEval}.test.ts` (40) | Frontend analysis primitives |

## 6. Milestone M-3 — Capability Confinement Model (`src/lib/agent`)

The unified execution context formalizes what an agent may do and how privileges
decay through delegation:

```ts
interface ExecutionContext {
  identity: { type: 'agent' | 'task'; id: string; rootAgentId: string };
  capabilities: { allowedGates: string[]; maxAutonomousRiskScore: number };
  audit: AuditContext;   // traceId-linked provenance; missing traceId ⇒ fail closed
}
```

Invariants enforced by `capabilities.ts` (unit-tested, V-6):

1. **Gate allowlist is subset-monotone:** a `TaskDefinition` may request only a subset
   of the parent's `allowedGates`; any unknown gate rejects the delegation.
2. **Risk ceiling is non-increasing:** `requestedMaxRiskScore ≤ parent.maxAutonomousRiskScore`;
   escalation attempts are rejected; values clamp to the shared [0, 100] bounds.
3. **Provenance is mandatory:** delegation without a resolvable `audit.traceId` fails
   closed, mirroring the verifier's rule that an entry with no verifiable APPROVED
   ancestor cannot inherit scope.
4. **Derivation, not mutation:** `deriveChildContext` produces a fresh context whose
   `rootAgentId` propagates unchanged, preserving full-chain attribution.

## 7. Security Posture & Known Limitations

* **Root of trust:** Ed25519 public key (base64url) supplied via env/file; dev keypair
  lives in `.ledgerdev/` (gitignored, secret-scanner deny-listed) and must never be used
  outside local development.
* **Residual limitation (acknowledged):** historical commits pre-dating the fixture repair
  contain legacy truncated/annotated digests; git history is append-only and is *not*
  rewritten here. Any CI run verifying historical blobs uses the repaired fixtures
  (`data/ledgers/*.json`) instead. This is tracked as open item O-1.
* **HMAC vs. signature:** HMAC links prove chain continuity under a shared secret;
  the Ed25519 layer is required for non-repudiable authorship. Both must pass.
* **Terminal-state immutability:** completed/failed/rejected entries legally admit no
  successors, preventing retroactive extension of closed workflows.

## 8. Reproduction Steps

```bash
# Python verification gates
python -m pytest -q                                   # V-4
python -m pytest test_ledger_verifier.py test_ledger_api_server.py -q   # V-5
python ledger_verifier.py verify-ledger \
  --ledger data/ledgers/wf_992.json \
  --hmac-secret-file .ledgerdev/secret \
  --pubkey-file .ledgerdev/pub.b64                    # V-1

# TypeScript gates
npm run typecheck                                     # V-7
npx vitest run                                        # V-6

# Secret hygiene
python scripts/secret_scan.py --working               # V-8
```

---
*End of Technical Annex. Companion narrative material is maintained separately in the
Enterprise Design Partner Briefing (README).*
