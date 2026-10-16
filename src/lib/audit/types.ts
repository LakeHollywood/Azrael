// ---------------------------------------------------------
// Audit Context (The "Verified Provenance")
// ---------------------------------------------------------
// Mirrors the ledger's execution-context / approval-scope model
// (see ledger_verifier.py): every gated action must carry a trace id
// that links it back to an APPROVED ancestor entry, and scope checks
// fail closed when that link is missing.

/** Lifecycle states an audited action can be in. */
export type AuditState =
  | 'PENDING'    // declared, awaiting approval
  | 'APPROVED'   // a human/policy approved this exact scope
  | 'EXECUTING'  // gate invocation in flight
  | 'RESOLVED'   // terminal: succeeded within approved scope
  | 'COMPLETED'  // terminal: task finished
  | 'REJECTED';  // terminal: denied by a gate

/**
 * The verified audit context attached to every execution.
 * A missing `traceId` means the action cannot be tied back to an
 * approved ledger entry — callers MUST treat that as fail-closed.
 */
export interface AuditContext {
  /** Correlation id linking all entries of one execution chain. */
  traceId: string;
  /** Current lifecycle state of this audited action. */
  state: AuditState;
  /** Id of the APPROVED ledger entry authorizing this action, if any. */
  approvedByEntryId?: string;
  /** Who/what performed the action (agent or task identity). */
  actor: string;
  /** ISO-8601 timestamp captured at context creation. */
  timestamp: string;
/** Audit context propagated through every gated action invocation. */

export interface AuditContext {
  /** Identity of the principal on whose behalf the agent acted. */
  actorId: string;
  /** Role used for gate allowlist authorization (e.g. 'support_lead'). */
  actorRole: string;
  /** Session / run identifier tying together all actions from one agent loop. */
  sessionId: string;
  /** Correlation id for the originating ticket/request. */
  correlationId: string;
  /** Identifier of the model/agent that requested the action. */
  agentId: string;
  /** Wall-clock ISO timestamp when the request entered the system. */
  requestedAt: string;
}
