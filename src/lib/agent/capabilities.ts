import type {
  AgentCapabilities,
  ExecutionContext,
  TaskDefinition,
} from '@/lib/agent/types';

// ---------------------------------------------------------
// Capability Enforcement (fail-closed delegation rules)
// ---------------------------------------------------------
// Mirrors the ledger verifier's authorization-scope model:
//   * a child may only hold a SUBSET of the parent's gates
//     (no implicit scope inheritance), and
//   * a child's risk ceiling may only be LOWER or EQUAL to the
//     parent's — privileges can never expand down a delegation chain.

/** Well-known risk-score bounds shared with the approval gate. */
export const MIN_RISK_SCORE = 0;
export const MAX_RISK_SCORE = 100;

export interface ValidationResult {
  ok: boolean;
  /** Human-readable reasons for rejection (empty when `ok` is true). */
  errors: string[];
}

const okResult = (): ValidationResult => ({ ok: true, errors: [] });
const failResult = (errors: string[]): ValidationResult => ({ ok: false, errors });

/** Clamp any score into the canonical [MIN_RISK_SCORE, MAX_RISK_SCORE] band. */
export function clampRiskScore(score: number): number {
  if (!Number.isFinite(score)) return MAX_RISK_SCORE; // unknown → worst case
  return Math.min(MAX_RISK_SCORE, Math.max(MIN_RISK_SCORE, score));
}

/** True when every gate in `child` also appears in `parent`. */
export function isGateSubset(parent: readonly string[], child: readonly string[]): boolean {
  const allowed = new Set(parent);
  return child.every((gate) => allowed.has(gate));
}

/**
 * Validate a requested sub-task against the delegating parent context.
 * Rejects (fail closed) when the task asks for gates the parent does not
 * hold, a higher risk ceiling than the parent, or an invalid baseline.
 */
export function validateTaskDelegation(
  parent: ExecutionContext,
  task: TaskDefinition,
): ValidationResult {
  const errors: string[] = [];

  if (!task.name.trim()) {
    errors.push('Task name must be a non-empty string');
  }

  const extraGates = task.requestedGates.filter(
    (gate) => !parent.capabilities.allowedGates.includes(gate),
  );
  if (extraGates.length > 0) {
    errors.push(
      `Requested gate(s) outside parent scope: ${extraGates.join(', ')}`,
    );
  }

  if (task.requestedMaxRiskScore > parent.capabilities.maxAutonomousRiskScore) {
    errors.push(
      `Requested risk ceiling ${task.requestedMaxRiskScore} exceeds ` +
        `parent cap ${parent.capabilities.maxAutonomousRiskScore}`,
    );
  }

  if (task.requestedMaxRiskScore < MIN_RISK_SCORE) {
    errors.push(`Requested risk ceiling must be >= ${MIN_RISK_SCORE}`);
  }

  if (!parent.audit.traceId) {
    errors.push('Parent audit context has no traceId; scope cannot be verified (fail closed)');
  }

  return errors.length > 0 ? failResult(errors) : okResult();
}

/**
 * Derive the child context produced by an approved delegation.
 * The child inherits the parent's root agent id and trace, but its own
 * identity, gate list and risk cap come from the validated task request —
 * capabilities are intersected/capped so they can never exceed the parent.
 */
export function deriveChildContext(
  parent: ExecutionContext,
  task: TaskDefinition,
  childId: string,
): ExecutionContext {
  const capabilities: AgentCapabilities = {
    allowedGates: task.requestedGates.filter(
      (gate) => parent.capabilities.allowedGates.includes(gate),
    ),
    maxAutonomousRiskScore: clampRiskScore(
      Math.min(task.requestedMaxRiskScore, parent.capabilities.maxAutonomousRiskScore),
    ),
  };

  return {
    identity: {
      type: 'task',
      id: childId,
      rootAgentId: parent.identity.rootAgentId,
    },
    capabilities,
    audit: {
      ...parent.audit,
      state: 'PENDING',
      actor: childId,
      timestamp: new Date().toISOString(),
    },
  };
}

/** Convenience guard: may this context invoke `gateId` at `riskScore`? */
export function canExecute(
  ctx: ExecutionContext,
  gateId: string,
  riskScore: number,
): boolean {
  return (
    ctx.capabilities.allowedGates.includes(gateId) &&
    clampRiskScore(riskScore) <= ctx.capabilities.maxAutonomousRiskScore &&
    Boolean(ctx.audit.traceId)
  );
}
