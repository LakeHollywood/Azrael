import { AuditContext } from '@/lib/audit/types';

// ---------------------------------------------------------
// 1. Capability Manifest (The "Allowlist")
// ---------------------------------------------------------
export interface AgentCapabilities {
  // Explicit list of Gate IDs this context is allowed to invoke
  allowedGates: string[];
  // Hard ceiling for autonomous execution (e.g., an agent might be capped at risk score 15)
  maxAutonomousRiskScore: number;
}

// ---------------------------------------------------------
// 2. The Unified Execution Context
// ---------------------------------------------------------
export interface ExecutionContext {
  identity: {
    type: 'agent' | 'task';
    id: string;           // The specific Agent ID or Task ID
    rootAgentId: string;  // The original Agent that started the chain
  };
  capabilities: AgentCapabilities;
  audit: AuditContext;    // The verified audit context (traceId, etc.)
}

// ---------------------------------------------------------
// 3. Task Definition (How an Agent requests a sub-task)
// ---------------------------------------------------------
export interface TaskDefinition {
  name: string;
  // The task can only request a SUBSET of the parent's allowed gates
  requestedGates: string[];
  // The task can only request a LOWER or EQUAL risk ceiling
  requestedMaxRiskScore: number;
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
