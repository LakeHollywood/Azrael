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
}
