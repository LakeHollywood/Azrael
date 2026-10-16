/**
 * approvalGates — TypeScript mirror of the Python control plane in
 * `approval_gate/risk.py` (POLICY_THRESHOLDS / clamp_score / determine_policy).
 *
 * INVARIANT: the band table below must stay identical in meaning to the
 * Python source. This is enforced at test time by
 * `src/__tests__/riskParity.test.ts`, which shells out to python3 and compares
 * `determine_policy(score).value` against `policyValueForScore(score)` for
 * every score 0..100 plus boundary cases, and pins 70 -> DUAL_APPROVAL.
 */

// ---------------------------------------------------------
// Risk bands (mirrors POLICY_THRESHOLDS in approval_gate/risk.py)
// Inclusive lower bound of each band; a score maps to the band with the
// highest lower bound it reaches. Scores outside [0, 100] are clamped.
// ---------------------------------------------------------

export const RISK_SCORE_MIN = 0;
export const RISK_SCORE_MAX = 100;

/** Authz-impacting operations can never evaluate below this score (floor). */
export const AUTHZ_RISK_FLOOR = 60;
/** Operations that modify the approval gate itself are forced here. */
export const GATE_MODIFICATION_RISK_FLOOR = RISK_SCORE_MAX; // 100 -> RESTRICTED

export type ApprovalPolicy =
  | 'AUTONOMOUS'
  | 'SINGLE_APPROVAL'
  | 'SENIOR_APPROVAL'
  | 'DUAL_APPROVAL'
  | 'RESTRICTED';

/** Serialized (snake_case) policy names — match ApprovalPolicy enum values in Python. */
export type ApprovalPolicyValue =
  | 'autonomous'
  | 'single_approval'
  | 'senior_approval'
  | 'dual_approval'
  | 'restricted';

interface PolicyBand {
  readonly lowerBound: number;
  readonly policy: ApprovalPolicy;
  readonly value: ApprovalPolicyValue;
}

export const POLICY_THRESHOLDS: readonly PolicyBand[] = [
  { lowerBound: 0, policy: 'AUTONOMOUS', value: 'autonomous' },
  { lowerBound: 20, policy: 'SINGLE_APPROVAL', value: 'single_approval' },
  { lowerBound: 40, policy: 'SENIOR_APPROVAL', value: 'senior_approval' },
  { lowerBound: 60, policy: 'DUAL_APPROVAL', value: 'dual_approval' },
  { lowerBound: 80, policy: 'RESTRICTED', value: 'restricted' },
];

/** Constrain a raw risk score to the valid [0, 100] range. */
export function clampScore(score: number): number {
  if (score < RISK_SCORE_MIN) return RISK_SCORE_MIN;
  if (score > RISK_SCORE_MAX) return RISK_SCORE_MAX;
  return score;
}

/** Return the approval policy required for a given risk score. */
export function policyForScore(score: number): ApprovalPolicy {
  const clamped = clampScore(score);
  let policy = POLICY_THRESHOLDS[0].policy;
  for (const band of POLICY_THRESHOLDS) {
    if (clamped >= band.lowerBound) {
      policy = band.policy;
    } else {
      break;
    }
  }
  return policy;
}

/** Snake-case serialized form, e.g. "dual_approval" (parity with Python `.value`). */
export function policyValueForScore(score: number): ApprovalPolicyValue {
  const clamped = clampScore(score);
  let value = POLICY_THRESHOLDS[0].value;
  for (const band of POLICY_THRESHOLDS) {
    if (clamped >= band.lowerBound) {
      value = band.value;
    } else {
      break;
    }
  }
  return value;
}

// Minimum approvers implied by each policy band.
const APPROVER_COUNT: Record<ApprovalPolicy, number> = {
  AUTONOMOUS: 0,
  SINGLE_APPROVAL: 1,
  SENIOR_APPROVAL: 1,
  DUAL_APPROVAL: 2,
  RESTRICTED: 2, // break-glass: still needs two, plus elevated authority
};

export function requiredApprovalsForPolicy(policy: ApprovalPolicy): number {
  return APPROVER_COUNT[policy];
}

// ---------------------------------------------------------
// Gate definition & registry types
// ---------------------------------------------------------

export interface RiskProfile {
  actionRisk: number;
  assetCriticality: number;
  blastRadius: number;
  privilegeEscalation: number;
  modelConfidencePenalty: number;
  reversibility: number;
  anomalyMultiplier: number;
}

export interface GateRegistry<A> {
  /** Derived from the resolved policy unless explicitly overridden. */
  requiredApprovals?: number;
  allowlistRoles: string[];
  expiryMs: number;
  idempotencyKey: (args: A) => string;
}

export interface GateDefinition<A> {
  id: string;
  name: string;
  description: string;
  risk: RiskProfile;
  registry: GateRegistry<A>;
}

export interface ResolvedGate<A> extends GateDefinition<A> {
  /** Sum of the risk components, clamped to [0, 100]. */
  readonly riskScore: number;
  /** Policy derived from riskScore via the mirrored band table. */
  readonly policy: ApprovalPolicy;
  /** Effective minimum approver count (registry override may raise, never relax). */
  readonly effectiveRequiredApprovals: number;
}

export function computeRiskScore(risk: RiskProfile): number {
  const total =
    risk.actionRisk +
    risk.assetCriticality +
    risk.blastRadius +
    risk.privilegeEscalation +
    risk.modelConfidencePenalty +
    risk.reversibility +
    risk.anomalyMultiplier;
  return clampScore(total);
}

/**
 * Define an approval gate. The score/policy are computed eagerly from the
 * risk profile so consumers never hardcode them (fixes the drift issue where
 * UI payloads pinned `tier: 'DUAL_APPROVAL'` as a literal).
 */
export function defineGate<A>(def: GateDefinition<A>): ResolvedGate<A> {
  const riskScore = computeRiskScore(def.risk);
  const policy = policyForScore(riskScore);
  const policyMinimum = requiredApprovalsForPolicy(policy);
  const registryOverride = def.registry.requiredApprovals ?? 0;
  // Escalate-only: a registry may demand MORE approvals than the band
  // requires, but can never relax below the policy floor.
  const effectiveRequiredApprovals = Math.max(policyMinimum, registryOverride);

  return Object.freeze({
    ...def,
    riskScore,
    policy,
    effectiveRequiredApprovals,
  });
}

// ---------------------------------------------------------
// Approval requests & errors
// ---------------------------------------------------------

export type ApprovalStatus =
  | 'pending'
  | 'approved'
  | 'denied'
  | 'expired'
  | 'executed';

export interface ApprovalRequestMetadata {
  readonly requiredApprovals: number;
  readonly allowlistRoles: readonly string[];
  readonly expiryMs: number;
  readonly idempotencyKey: string;
}

export interface ApprovalRequest {
  readonly id: string;
  readonly gateId: string;
  readonly riskScore: number;
  readonly tier: ApprovalPolicy;
  readonly metadata: ApprovalRequestMetadata;
  readonly status: ApprovalStatus;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/** Thrown by gated() when no completed approval exists for the action yet. */
export class ApprovalRequiredError extends Error {
  readonly approvalRequest: ApprovalRequest;

  constructor(approvalRequest: ApprovalRequest) {
    super(
      `Action '${approvalRequest.gateId}' requires human approval ` +
        `(risk ${approvalRequest.riskScore}, tier ${approvalRequest.tier}, ` +
        `${approvalRequest.metadata.requiredApprovals} approval(s)). ` +
        `Request ${approvalRequest.id} is pending.`
    );
    this.name = 'ApprovalRequiredError';
    this.approvalRequest = approvalRequest;
  }
}

/** Thrown when a prior request exists but is denied or expired. */
export class ApprovalRejectedError extends Error {
  readonly approvalRequest: ApprovalRequest;

  constructor(approvalRequest: ApprovalRequest) {
    super(
      `Approval request ${approvalRequest.id} for '${approvalRequest.gateId}' ` +
        `was ${approvalRequest.status}. Re-request with a fresh nonce to retry.`
    );
    this.name = 'ApprovalRejectedError';
    this.approvalRequest = approvalRequest;
  }
}

// ---------------------------------------------------------
// Registry (in-memory default; swap for a durable store in production)
// ---------------------------------------------------------

export interface ApprovalRegistry {
  find(idempotencyKey: string): ApprovalRequest | undefined;
  create(
    partial: Omit<ApprovalRequest, 'id' | 'status' | 'createdAt' | 'expiresAt'>
  ): ApprovalRequest;
  resolve(id: string, status: ApprovalStatus): void;
}

export function createInMemoryRegistry(
  now: () => number = Date.now
): ApprovalRegistry {
  const byKey = new Map<string, ApprovalRequest>();
  const byId = new Map<string, ApprovalRequest>();
  let counter = 0;

  return {
    find(idempotencyKey) {
      return byKey.get(idempotencyKey);
    },
    create(partial) {
      counter += 1;
      const createdAt = now();
      const request: ApprovalRequest = Object.freeze({
        ...partial,
        id: `apr_${createdAt.toString(36)}_${counter}`,
        status: 'pending' as ApprovalStatus,
        createdAt,
        expiresAt: createdAt + partial.metadata.expiryMs,
      });
      byKey.set(request.metadata.idempotencyKey, request);
      byId.set(request.id, request);
      return request;
    },
    resolve(id, status) {
      const req = byId.get(id);
      if (!req) throw new Error(`Unknown approval request: ${id}`);
      const updated: ApprovalRequest = { ...req, status };
      byId.set(id, updated);
      byKey.set(updated.metadata.idempotencyKey, updated);
    },
  };
}

// Default process-wide registry; injectable per-call for tests/multi-tenant.
export const defaultRegistry = createInMemoryRegistry();

// ---------------------------------------------------------
// gated() wrapper
// ---------------------------------------------------------

export interface GatedCallContext {
  /** Actor requesting execution; must hold one of the gate's allowlist roles. */
  actorRole?: string;
  /** Fresh nonce per logical attempt so retries after expiry get new requests. */
  requestId?: string;
  registry?: ApprovalRegistry;
  now?: () => number;
}

export type GatedAction<A> = (args: A) => Promise<unknown>;

export interface GatedFunction<A> {
  (args: A, ctx?: GatedCallContext): Promise<any>;
  readonly gate: ResolvedGate<A>;
}

/**
 * Wrap a raw side-effecting function so it only executes when the gate's
 * approval requirement is satisfied:
 *
 *  - AUTONOMOUS (0 approvals): executes immediately.
 *  - Otherwise: looks up the idempotency key in the registry.
 *      * No request yet   -> creates one, throws ApprovalRequiredError.
 *      * Pending          -> throws ApprovalRequiredError (same request),
 *                            or ApprovalRejectedError once past expiryMs.
 *      * Approved         -> executes raw fn, marks request 'executed'.
 *      * Denied/Expired   -> throws ApprovalRejectedError.
 *      * Executed         -> refuses silent re-run; caller must pass a new
 *                            requestId nonce to intentionally repeat.
 */
export function gated<A>(
  gate: ResolvedGate<A>,
  raw: GatedAction<A>
): GatedFunction<A> {
  const fn = async (args: A, ctx: GatedCallContext = {}): Promise<any> => {
    const registry = ctx.registry ?? defaultRegistry;
    const now = ctx.now?.() ?? Date.now();

    // Authorization check against the allowlist before touching the registry.
    if (gate.policy !== 'AUTONOMOUS' && ctx.actorRole !== undefined) {
      if (!gate.registry.allowlistRoles.includes(ctx.actorRole)) {
        throw new Error(
          `Actor role '${ctx.actorRole}' is not in the allowlist for gate '${gate.id}' ` +
            `(${gate.registry.allowlistRoles.join(', ')}).`
        );
      }
    }

    // Autonomous actions bypass the registry entirely.
    if (gate.effectiveRequiredApprovals === 0) {
      return raw(args);
    }

    // Nonce suffix ensures a retry after expiry/denial creates a NEW request
    // instead of colliding with the terminal-state one.
    const idempotencyKey =
      gate.registry.idempotencyKey(args) +
      (ctx.requestId ? `#${ctx.requestId}` : '');

    const existing = registry.find(idempotencyKey);
    if (existing) {
      switch (existing.status) {
        case 'approved': {
          const result = await raw(args);
          registry.resolve(existing.id, 'executed');
          return result;
        }
        case 'pending': {
          if (now > existing.expiresAt) {
            registry.resolve(existing.id, 'expired');
            throw new ApprovalRejectedError({ ...existing, status: 'expired' });
          }
          throw new ApprovalRequiredError(existing);
        }
        case 'denied':
        case 'expired':
          throw new ApprovalRejectedError(existing);
        case 'executed':
          throw new Error(
            `Approval request ${existing.id} was already executed; ` +
              `retry with a new requestId (nonce) to intentionally repeat the action.`
          );
      }
    }

    const request = registry.create({
      gateId: gate.id,
      riskScore: gate.riskScore,
      tier: gate.policy,
      metadata: {
        requiredApprovals: gate.effectiveRequiredApprovals,
        allowlistRoles: gate.registry.allowlistRoles,
        expiryMs: gate.registry.expiryMs,
        idempotencyKey,
      },
    });
    throw new ApprovalRequiredError(request);
  };

  return Object.assign(fn, { gate });
}
