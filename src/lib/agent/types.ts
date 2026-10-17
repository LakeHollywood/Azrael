import type { AuditContext } from '@/lib/audit/types';

/** HITL notification payload shapes understood by the approval UI. */
export interface ApprovalRequiredPayload {
  type: 'APPROVAL_REQUIRED';
  requestId: string;
  message: string;
  uiPayload: {
    action: string;
    riskScore: number;
    tier: string;
  };
}

export type HITLPayload = ApprovalRequiredPayload;

/** Execution context handed to agent handlers by the runtime loop. */
export interface AgentContext {
  audit: AuditContext;

  /**
   * Approval registry shared between the agent and the HITL approvers.
   * The agent passes it into gated actions so an approval recorded by a
   * human (via `resolve(id, 'approved')`) is visible on resume.
   */
  registry?: import('@/lib/approvalGates').ApprovalRegistry;

  /** Update the support ticket with an agent-visible note. */
  updateTicket(ticketId: string, note: string): Promise<void>;

  /**
   * Notify the human-in-the-loop layer. Implementations MUST be robust:
   * if notification fails the caller must still retain the requestId so
   * the approval can be tracked/resumed out-of-band.
   */
  notifyHITL(payload: HITLPayload): Promise<void>;
}
