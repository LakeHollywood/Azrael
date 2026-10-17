//! Sovereign engine service — Agent v2 pipeline.
//!
//! Mirrors the semantics of the Python components this repo already ships:
//! - `risk_scoring.py`        -> [`risk`]   (weighted score + thresholds)
//! - `approval_gate.py`       -> [`gate`]   (auto-approve / hold / veto rules)
//! - `audit_log.py`           -> [`audit`]  (hash-chained, tamper-evident log)
//!
//! The pipeline is: parse -> validate -> risk-score -> approval-gate -> execute,
//! and every stage emits a structured audit record chained to the previous one.

pub mod audit;
pub mod gate;
pub mod pipeline;
pub mod risk;

/// Re-exported so integration tests can `use sovereign_engine_service::prelude::*`.
pub mod prelude {
    pub use crate::audit::{AuditLog, AuditRecord};
    pub use crate::gate::{GateDecision, ApprovalGate};
    pub use crate::pipeline::{AgentAction, Pipeline, PipelineOutcome, StageError};
    pub use crate::risk::{RiskAssessment, RiskLevel};
}
