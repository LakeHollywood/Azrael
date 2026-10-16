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
