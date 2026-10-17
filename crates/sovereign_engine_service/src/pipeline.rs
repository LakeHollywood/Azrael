//! The Agent v2 pipeline: parse -> validate -> risk-score -> approval-gate -> execute.
//!
//! `Pipeline::run` is the single entry point exercised by
//! `tests/agent_v2_pipeline.rs`. Every stage writes to the hash-chained audit
//! log, so even rejected actions leave a tamper-evident trail.

use crate::audit::AuditLog;
use crate::gate::{ApprovalGate, GateDecision, GateRequest};
use crate::risk::{self, Factor, RiskAssessment, RiskLevel};

/// A raw action as submitted by an agent (untrusted input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAction {
    pub verb: String,
    pub target: String,
    pub reversible: bool,
    pub tags: Vec<String>,
}

/// A validated action, ready for scoring/gating.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentAction {
    pub verb: String,
    pub target: String,
    pub reversible: bool,
    pub tags: Vec<String>,
    pub factors: Vec<Factor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageError {
    /// Verb missing or not in the allowed vocabulary.
    UnknownVerb(String),
    /// Empty/oversized target, or target containing control characters.
    InvalidTarget(String),
}

impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StageError::UnknownVerb(v) => write!(f, "unknown verb: {v:?}"),
            StageError::InvalidTarget(t) => write!(f, "invalid target: {t:?}"),
        }
    }
}

impl std::error::Error for StageError {}

/// Final state of a pipeline run.
#[derive(Debug, Clone, PartialEq)]
pub enum PipelineOutcome {
    Executed { action_id: u64, risk: RiskAssessment, decision: GateDecision },
    Held { risk: RiskAssessment, decision: GateDecision },
    Vetoed { risk: RiskAssessment },
    RejectedAtValidation(StageError),
}

/// Allowed verb vocabulary — mirrors the Python agent's capability list.
const ALLOWED_VERBS: &[&str] = &["read", "write", "delete", "deploy", "export"];

/// Max accepted target length (bytes). Keeps hostile inputs out of the executor.
const MAX_TARGET_LEN: usize = 512;

pub struct Pipeline {
    gate: ApprovalGate,
    pub audit: AuditLog,
    executed: Vec<AgentAction>,
    next_action_id: u64,
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipeline {
    pub fn new() -> Self {
        Pipeline {
            gate: ApprovalGate::new(),
            audit: AuditLog::new(),
            executed: Vec::new(),
            next_action_id: 1,
        }
    }

    /// Actions that actually reached the executor, in order.
    pub fn executed(&self) -> &[AgentAction] {
        &self.executed
    }

    /// Parse + validate a raw action into an `AgentAction` with risk factors.
    fn validate(raw: &RawAction) -> Result<AgentAction, StageError> {
        if !ALLOWED_VERBS.contains(&raw.verb.as_str()) {
            return Err(StageError::UnknownVerb(raw.verb.clone()));
        }
        if raw.target.is_empty()
            || raw.target.len() > MAX_TARGET_LEN
            || raw.target.chars().any(|c| c.is_control())
        {
            return Err(StageError::InvalidTarget(raw.target.clone()));
        }
        Ok(AgentAction {
            verb: raw.verb.clone(),
            target: raw.target.clone(),
            reversible: raw.reversible,
            tags: raw.tags.clone(),
            factors: derive_factors(raw),
        })
    }

    /// Run the full pipeline for one action. Never panics on bad input;
    /// validation failures become `PipelineOutcome::RejectedAtValidation`
    /// and are still audited.
    pub fn run(&mut self, raw: &RawAction) -> PipelineOutcome {
        let actor = format!("agent:{}", sanitize(&raw.verb));
        self.audit.append("parse", &actor, format!("verb={} target_len={}", raw.verb, raw.target.len()));

        let action = match Self::validate(raw) {
            Ok(a) => a,
            Err(e) => {
                self.audit.append("validate", &actor, format!("rejected: {e}"));
                return PipelineOutcome::RejectedAtValidation(e);
            }
        };
        self.audit.append("validate", &actor, "ok".to_string());

        let assessment = risk::assess(&action.factors);
        self.audit.note_risk(&actor, assessment.level, assessment.score);

        let req = GateRequest {
            risk_level: assessment.level,
            tags: &action.tags,
            approver: None, // unattended runs have no approver; tests inject via run_with_approver
            reversible: action.reversible,
        };
        let decision = self.gate.decide(&req);
        self.audit.note_gate(&actor, &decision);

        match &decision {
            GateDecision::Vetoed => PipelineOutcome::Vetoed { risk: assessment },
            d if d.is_executable() => {
                let id = self.next_action_id;
                self.next_action_id += 1;
                self.audit.append("execute", &actor, format!("action_id={id}"));
                self.executed.push(action);
                PipelineOutcome::Executed { action_id: id, risk: assessment, decision: d.clone() }
            }
            _ => PipelineOutcome::Held { risk: assessment, decision },
        }
    }

    /// Same as [`run`](Self::run) but with a named human approver in the loop.
    pub fn run_with_approver(&mut self, raw: &RawAction, approver: &str) -> PipelineOutcome {
        let actor = format!("agent:{}", sanitize(&raw.verb));
        self.audit.append("parse", &actor, format!("verb={} target_len={}", raw.verb, raw.target.len()));

        let action = match Self::validate(raw) {
            Ok(a) => a,
            Err(e) => {
                self.audit.append("validate", &actor, format!("rejected: {e}"));
                return PipelineOutcome::RejectedAtValidation(e);
            }
        };
        self.audit.append("validate", &actor, "ok".to_string());

        let assessment = risk::assess(&action.factors);
        self.audit.note_risk(&actor, assessment.level, assessment.score);

        let req = GateRequest {
            risk_level: assessment.level,
            tags: &action.tags,
            approver: Some(approver),
            reversible: action.reversible,
        };
        let decision = self.gate.decide(&req);
        self.audit.note_gate(&actor, &decision);

        match &decision {
            GateDecision::Vetoed => PipelineOutcome::Vetoed { risk: assessment },
            d if d.is_executable() => {
                let id = self.next_action_id;
                self.next_action_id += 1;
                self.audit.append("execute", &actor, format!("action_id={id}"));
                self.executed.push(action);
                PipelineOutcome::Executed { action_id: id, risk: assessment, decision: d.clone() }
            }
            _ => PipelineOutcome::Held { risk: assessment, decision },
        }
    }

    /// Verify the audit chain after a batch of runs. Fail-closed wrapper used
    /// by CI: any corruption aborts downstream execution.
    pub fn audit_is_intact(&self) -> bool {
        self.audit.verify().is_ok()
    }
}

/// Heuristic factor derivation from the verb/target/reversibility/tags.
///
/// Reversible actions are treated as undoable (low irreversibility) and only
/// the blast radius of the verb contributes — this keeps routine reversible
/// writes auto-approvable while irreversible or prod-facing work escalates.
fn derive_factors(raw: &RawAction) -> Vec<Factor> {
    let mut factors = vec![
        Factor::new(
            "irreversibility",
            0.9,
            if raw.reversible { 0.1 } else { 0.9 },
        ),
        Factor::new(
            "blast_radius",
            0.7,
            match raw.verb.as_str() {
                "delete" | "deploy" => 0.8,
                "export" => 0.5,
                "write" => 0.3,
                _ => 0.05,
            },
        ),
    ];
    if !raw.reversible {
        // Irreversibility is the dominant driver for undo-less actions, but it
        // must not single-handedly push an ordinary write into High: cap its
        // contribution at 0.4 so (irreversible write) lands in Medium while
        // delete/deploy/prod surfaces still cross into High via other factors.
        if let Some(irr) = factors.iter_mut().find(|f| f.name == "irreversibility") {
            irr.magnitude = irr.magnitude.min(0.4);
        }
    }
    if raw.tags.iter().any(|t| t == "pii") {
        factors.push(Factor::new("data_sensitivity", 0.6, 0.9));
    }
    if raw.target.starts_with("prod/") {
        factors.push(Factor::new("production_surface", 0.8, 1.0));
    }
    factors
}

/// Strip anything that could break audit line framing before writing to logs.
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').collect()
}

/// Convenience classifier export so tests can assert level without re-implementing thresholds.
pub fn level_of(factors: &[Factor]) -> RiskLevel {
    risk::assess(factors).level
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(verb: &str, target: &str, reversible: bool) -> RawAction {
        RawAction { verb: verb.into(), target: target.into(), reversible, tags: vec![] }
    }

    #[test]
    fn read_is_auto_approved() {
        let mut p = Pipeline::new();
        match p.run(&raw("read", "notes.txt", true)) {
            PipelineOutcome::Executed { decision, .. } => assert_eq!(decision, GateDecision::AutoApproved),
            other => panic!("expected executed, got {other:?}"),
        }
    }

    #[test]
    fn unknown_verb_rejected_but_audited() {
        let mut p = Pipeline::new();
        let out = p.run(&raw("shred", "disk0", false));
        assert!(matches!(out, PipelineOutcome::RejectedAtValidation(StageError::UnknownVerb(_))));
        assert!(p.audit_is_intact());
        assert_eq!(p.audit.len(), 2); // parse + validate(rejected)
    }

    #[test]
    fn control_chars_in_target_rejected() {
        let mut p = Pipeline::new();
        let out = p.run(&raw("read", "evil\nline", true));
        assert!(matches!(out, PipelineOutcome::RejectedAtValidation(StageError::InvalidTarget(_))));
    }
}
