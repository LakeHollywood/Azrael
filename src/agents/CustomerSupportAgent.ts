// src/agents/CustomerSupportAgent.ts
import { issueRefund } from '@/actions/financial/refund';
import {
  ApprovalRequiredError,
  ApprovalRejectedError,
} from '@/lib/approvalGates';
import type { AgentContext } from '@/lib/agent/types';

export async function handleCustomerRefundRequest(
  ctx: AgentContext,
  ticketId: string
) {
  // 1. Agent gathers context (simulated). In production these come from the
  //    ticket/order lookup, not fixtures.
  const paymentIntentId = 'pi_3MtwBwLkdIwHu7ix28a3tqPa';
  const refundAmount = 5000; // $50.00

  try {
    // 2. Agent attempts to execute the gated action. The requestId nonce ties
    //    this logical attempt to one approval record; a retry after expiry or
    //    denial must use a fresh nonce so it creates a NEW request instead of
    //    colliding with the terminal-state record.
    const result = await issueRefund(
      {
        paymentIntentId,
        amount: refundAmount,
        reason: 'requested_by_customer',
        auditContext: ctx.audit,
        requestId: `ticket_${ticketId}`,
      },
      { actorRole: ctx.audit.actorRole, registry: ctx.registry }
    );

    // 3. Success path (Autonomous execution or already approved)
    await ctx.updateTicket(ticketId, `Refund processed: ${result.refundId}`);
    return { status: 'success' as const, refundId: result.refundId };
  } catch (error) {
    // 4. Approval Required path
    if (error instanceof ApprovalRequiredError) {
      const pendingApproval = error.approvalRequest;

      // Read tier/riskScore from the resolved request — never hardcode them.
      // If the risk profile changes, the HITL card shows the new values.
      const payload = {
        type: 'APPROVAL_REQUIRED' as const,
        requestId: pendingApproval.id,
        message:
          `Agent requests to refund $${refundAmount / 100} for ticket ${ticketId}. ` +
          `Requires ${pendingApproval.metadata.requiredApprovals} approvals.`,
        uiPayload: {
          action: pendingApproval.gateId,
          riskScore: pendingApproval.riskScore, // derived: 70
          tier: pendingApproval.tier, // derived: 'DUAL_APPROVAL'
        },
      };

      // Fix #4: notifyHITL failing must NOT lose the requestId — otherwise the
      // human is never notified and the ticket silently stalls. We still
      // return pending_approval with the id so the runtime can retry delivery
      // out-of-band (e.g. durable queue / reconciliation sweep).
      let notified = true;
      try {
        await ctx.notifyHITL(payload);
      } catch (notifyError) {
        notified = false;
        console.error(
          `[refund-agent] HITL notification failed for approval ` +
            `${pendingApproval.id} (ticket ${ticketId}); returning request id ` +
            `for out-of-band retry.`,
          notifyError
        );
      }

      // Agent pauses its execution loop and waits for the registry to resolve.
      return {
        status: 'pending_approval' as const,
        requestId: pendingApproval.id,
        hitlNotified: notified,
      };
    }

    // 4b. Terminal approval states (denied/expired): do NOT re-notify or spin;
    // surface to the operator so the ticket gets a decision, not a zombie.
    if (error instanceof ApprovalRejectedError) {
      const rejected = error.approvalRequest;
      await ctx.updateTicket(
        ticketId,
        `Refund approval ${rejected.status.toUpperCase()} ` +
          `(request ${rejected.id}). Escalate to a human or open a fresh request.`
      );
      return {
        status: `approval_${rejected.status}` as const,
        requestId: rejected.id,
      };
    }

    // 5. Actual execution error (e.g. Stripe API failure)
    throw error;
  }
}
