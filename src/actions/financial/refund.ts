// src/actions/financial/refund.ts
import { defineGate, gated } from '@/lib/approvalGates';
import { stripeClient } from '@/lib/external/stripe';
import type { AuditContext } from '@/lib/audit/types';

// ---------------------------------------------------------
// 1. Define the Gate & Risk Profile
// ---------------------------------------------------------
export interface RefundArgs {
  paymentIntentId: string;
  amount: number; // in cents
  reason: 'duplicate' | 'fraudulent' | 'requested_by_customer';
  auditContext: AuditContext;
  /** Fresh nonce per logical attempt so retries after expiry/denial create a new approval request. */
  requestId?: string;
}

const issueRefundGate = defineGate<RefundArgs>({
  id: 'financial.issue_stripe_refund',
  name: 'Issue Stripe Refund',
  description: 'Processes a financial refund to a customer via Stripe.',

  // Risk Scoring (0-100 Scale)
  // Total Score: 25 + 20 + 15 + 0 + 5 + 5 + 0 = 70
  // Tier: 60-79 -> DUAL APPROVAL REQUIRED
  risk: {
    actionRisk: 25, // Financial mutation
    assetCriticality: 20, // Real money / company funds
    blastRadius: 15, // Affects specific customer & ledger
    privilegeEscalation: 0, // No IAM/Role changes
    modelConfidencePenalty: 5, // AI might miscalculate amount/currency
    reversibility: 5, // Hard to reverse once settled in bank
    anomalyMultiplier: 0, // Standard operation (no anomaly detected)
  },

  // Approval Registry Configuration
  registry: {
    requiredApprovals: 2, // Dual approval for score 70
    allowlistRoles: ['finance_admin', 'support_lead'],
    expiryMs: 1000 * 60 * 15, // Approval expires in 15 minutes
    // Key includes actor + amount + intent. The gate wrapper additionally
    // appends `#requestId` (nonce) when supplied, so expired/denied retries
    // never collide with the terminal-state record.
    idempotencyKey: (args) =>
      `refund_${args.auditContext.actorId}_${args.paymentIntentId}_${args.amount}`,
  },
});

// Export resolved metadata so UI/HITL layers read derived values instead of
// hardcoding literals (prevents score/tier drift).
export const REFUND_RISK_SCORE = issueRefundGate.riskScore; // 70
export const REFUND_TIER = issueRefundGate.policy; // 'DUAL_APPROVAL'

// ---------------------------------------------------------
// 2. Define the Raw External Action
// ---------------------------------------------------------
async function rawIssueRefund(args: RefundArgs) {
  // TOCTOU guard: re-validate refundable balance at EXECUTION time (i.e.
  // after approval), not just when the request was created. If Stripe says
  // less is refundable than approved, refuse rather than over-refund.
  if (stripeClient.paymentIntents) {
    const intent = await stripeClient.paymentIntents.retrieve(
      args.paymentIntentId
    );
    const refundable = intent.amount - intent.amount_refunded;
    if (args.amount > refundable) {
      throw new Error(
        `Refund of ${args.amount} exceeds refundable balance ${refundable} ` +
          `for ${args.paymentIntentId} (approved against stale state).`
      );
    }
  }

  // The actual external API call
  const refund = await stripeClient.refunds.create({
    payment_intent: args.paymentIntentId,
    amount: args.amount,
    reason: args.reason,
  });

  return {
    refundId: refund.id,
    status: refund.status,
    amount: refund.amount,
  };
}

// ---------------------------------------------------------
// 3. Wrap with the `gated()` API
// ---------------------------------------------------------
// The resulting function enforces the gate before executing `rawIssueRefund`.
// The second parameter (GatedCallContext: actorRole/requestId/registry/now)
// is injected by the agent runtime and is optional for direct callers.
export const issueRefund = gated(issueRefundGate, rawIssueRefund);
