/**
 * End-to-end behavior tests for the gated refund action + support agent.
 * Uses an injected in-memory registry and mock Stripe client; no network.
 */
import { beforeEach, describe, expect, it } from 'vitest';

import {
  ApprovalRejectedError,
  ApprovalRequiredError,
  createInMemoryRegistry,
} from '@/lib/approvalGates';
import type { AuditContext } from '@/lib/audit/types';
import type { AgentContext, HITLPayload } from '@/lib/agent/types';
import { setStripeClient, type StripeClient } from '@/lib/external/stripe';
import { issueRefund } from '@/actions/financial/refund';
import { handleCustomerRefundRequest } from '@/agents/CustomerSupportAgent';

const audit: AuditContext = {
  actorId: 'cust_123',
  actorRole: 'support_lead',
  sessionId: 'sess_1',
  correlationId: 'corr_1',
  agentId: 'support-agent-v1',
  requestedAt: new Date('2026-10-17T00:00:00Z').toISOString(),
};

function makeArgs(over: Partial<Parameters<typeof issueRefund>[0]> = {}) {
  return {
    paymentIntentId: 'pi_test_1',
    amount: 5000,
    reason: 'requested_by_customer' as const,
    auditContext: audit,
    ...over,
  };
}

let calls: number;
function mockStripe(refundable = 10000): StripeClient {
  calls = 0;
  return {
    refunds: {
      async create(params) {
        calls += 1;
        return {
          id: 're_mock_1',
          status: 'succeeded',
          amount: params.amount,
          payment_intent: params.payment_intent,
        };
      },
    },
    paymentIntents: {
      async retrieve(id) {
        return {
          id,
          amount: refundable,
          amount_refunded: 0,
          currency: 'usd',
          status: 'succeeded',
        };
      },
    },
  };
}

describe('issueRefund gate lifecycle', () => {
  beforeEach(() => {
    setStripeClient(mockStripe());
  });

  it('throws ApprovalRequiredError with score 70 / DUAL_APPROVAL on first call', async () => {
    const registry = createInMemoryRegistry();
    await expect(
      issueRefund(makeArgs(), { registry, requestId: 'r1' })
    ).rejects.toBeInstanceOf(ApprovalRequiredError);

    let captured: ApprovalRequiredError | undefined;
    try {
      await issueRefund(makeArgs(), { registry, requestId: 'r1' });
    } catch (e) {
      captured = e as ApprovalRequiredError;
    }
    expect(captured?.approvalRequest.riskScore).toBe(70);
    expect(captured?.approvalRequest.tier).toBe('DUAL_APPROVAL');
    expect(captured?.approvalRequest.metadata.requiredApprovals).toBe(2);
    // Idempotent: same nonce -> same pending request, no duplicates.
    expect(captured?.approvalRequest.id).toBeDefined();
  });

  it('executes raw refund once approved, then blocks silent re-run', async () => {
    const registry = createInMemoryRegistry();
    let err!: ApprovalRequiredError;
    try {
      await issueRefund(makeArgs(), { registry, requestId: 'r1' });
    } catch (e) {
      err = e as ApprovalRequiredError;
    }
    registry.resolve(err.approvalRequest.id, 'approved');

    const result = await issueRefund(makeArgs(), { registry, requestId: 'r1' });
    expect(result).toMatchObject({ refundId: 're_mock_1', amount: 5000 });
    expect(calls).toBe(1);

    // Second execution attempt under the same key must NOT hit Stripe again.
    await expect(
      issueRefund(makeArgs(), { registry, requestId: 'r1' })
    ).rejects.toThrow(/already executed/);
    expect(calls).toBe(1);
  });

  it('expired pending requests raise ApprovalRejectedError, not a silent loop', async () => {
    const registry = createInMemoryRegistry(() => 0); // frozen clock at t=0
    let err!: ApprovalRequiredError;
    try {
      await issueRefund(makeArgs(), { registry, requestId: 'r1' });
    } catch (e) {
      err = e as ApprovalRequiredError;
    }
    expect(err.approvalRequest.expiresAt).toBe(15 * 60 * 1000);

    // Call at t = 16 minutes -> past expiry.
    await expect(
      issueRefund(makeArgs(), { registry, requestId: 'r1', now: () => 16 * 60 * 1000 })
    ).rejects.toBeInstanceOf(ApprovalRejectedError);

    // Fresh nonce after expiry creates a brand-new pending request.
    let fresh!: ApprovalRequiredError;
    try {
      await issueRefund(makeArgs(), { registry, requestId: 'r2', now: () => 16 * 60 * 1000 });
    } catch (e) {
      fresh = e as ApprovalRequiredError;
    }
    expect(fresh.approvalRequest.status).toBe('pending');
    expect(fresh.approvalRequest.id).not.toBe(err.approvalRequest.id);
  });

  it('rejects actors outside the allowlist', async () => {
    const registry = createInMemoryRegistry();
    await expect(
      issueRefund(makeArgs(), {
        registry,
        requestId: 'r1',
        actorRole: 'intern',
      })
    ).rejects.toThrow(/not in the allowlist/);
  });

  it('TOCTOU guard: refuses execution if balance shrank below approved amount', async () => {
    const registry = createInMemoryRegistry();
    let err!: ApprovalRequiredError;
    try {
      await issueRefund(makeArgs({ amount: 9000 }), { registry, requestId: 'r1' });
    } catch (e) {
      err = e as ApprovalRequiredError;
    }
    registry.resolve(err.approvalRequest.id, 'approved');
    // Meanwhile another refund consumed part of the balance (9000 > 8000 left).
    setStripeClient({
      ...mockStripe(),
      paymentIntents: {
        async retrieve(id) {
          return { id, amount: 10000, amount_refunded: 2000, currency: 'usd', status: 'succeeded' };
        },
      },
    });
    await expect(
      issueRefund(makeArgs({ amount: 9000 }), { registry, requestId: 'r1' })
    ).rejects.toThrow(/exceeds refundable balance 8000/);
  });
});

describe('handleCustomerRefundRequest', () => {
  function makeCtx(registry: ReturnType<typeof createInMemoryRegistry>) {
    const tickets: string[] = [];
    const notifications: HITLPayload[] = [];
    const ctx: AgentContext & { registry: typeof registry } = {
      audit,
      registry,
      async updateTicket(_id, note) {
        tickets.push(note);
      },
      async notifyHITL(payload) {
        notifications.push(payload);
      },
    };
    return { ctx, tickets, notifications };
  }

  it('returns pending_approval with derived tier/score (no hardcoded literals)', async () => {
    setStripeClient(mockStripe());
    const registry = createInMemoryRegistry();
    const { ctx, notifications } = makeCtx(registry);

    const out = await handleCustomerRefundRequest(ctx, 'TCK-1');
    expect(out.status).toBe('pending_approval');
    expect(notifications).toHaveLength(1);
    expect(notifications[0].uiPayload).toEqual({
      action: 'financial.issue_stripe_refund',
      riskScore: 70,
      tier: 'DUAL_APPROVAL',
    });
    expect(notifications[0].message).toContain('$50');
  });

  it('survives notifyHITL failure without losing the requestId', async () => {
    setStripeClient(mockStripe());
    const registry = createInMemoryRegistry();
    const { ctx } = makeCtx(registry);
    ctx.notifyHITL = async () => {
      throw new Error('push service down');
    };

    const out = await handleCustomerRefundRequest(ctx, 'TCK-2');
    expect(out.status).toBe('pending_approval');
    expect(out.requestId).toMatch(/^apr_/); // id retained for out-of-band retry
    expect((out as { hitlNotified?: boolean }).hitlNotified).toBe(false);
  });

  it('completes successfully after approval resolves', async () => {
    setStripeClient(mockStripe());
    const registry = createInMemoryRegistry();
    const { ctx, tickets } = makeCtx(registry);

    const first = await handleCustomerRefundRequest(ctx, 'TCK-3');
    expect(first.status).toBe('pending_approval');
    registry.resolve(first.requestId!, 'approved');

    // Runtime resumes the same logical attempt (same nonce).
    const second = await handleCustomerRefundRequest(ctx, 'TCK-3');
    expect(second.status).toBe('success');
    expect(tickets.some((t) => t.includes('re_mock_1'))).toBe(true);
  });

  it('denied approvals surface as approval_denied, not an infinite pending loop', async () => {
    setStripeClient(mockStripe());
    const registry = createInMemoryRegistry();
    const { ctx, tickets } = makeCtx(registry);

    const first = await handleCustomerRefundRequest(ctx, 'TCK-4');
    registry.resolve(first.requestId!, 'denied');

    const second = await handleCustomerRefundRequest(ctx, 'TCK-4');
    expect(second.status).toBe('approval_denied');
    expect(tickets.some((t) => t.includes('DENIED'))).toBe(true);
  });
});
