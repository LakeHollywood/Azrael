//! Approval gate, ported from the semantics of `approval_gate/`.
//!
//! Rules (in precedence order):
//! 1. An explicit veto token in the action's tags -> `Vetoed` (overrides everything).
//! 2. Risk level High or Medium without a valid approver -> `HeldForApproval`.
//! 3. A valid approver (non-empty) clears Medium risk -> `Approved`.
//! 4. High risk is never cleared by an approver alone — it additionally requires
//!    the action to be reversible; otherwise -> `HeldForApproval`.
//! 5. Low risk -> `AutoApproved`.

use crate::risk::RiskLevel;

/// Outcome of the approval gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// No human needed: below all thresholds.
    AutoApproved,
    /// A named approver signed off.
    Approved,
    /// Blocked pending a human decision.
    HeldForApproval,
    /// Permanently blocked by policy/veto — not resumable.
    Vetoed,
}

impl GateDecision {
    pub fn is_executable(&self) -> bool {
        matches!(self, GateDecision::AutoApproved | GateDecision::Approved)
    }
}

/// Inputs the gate needs for one action.
#[derive(Debug, Clone)]
pub struct GateRequest<'a> {
    pub risk_level: RiskLevel,
    /// Tag list on the action; a tag exactly equal to a veto token blocks it.
    pub tags: &'a [String],
    /// Some("") counts as *no* approver (defensive against empty form fields).
    pub approver: Option<&'a str>,
    /// Whether the action can be undone if it turns out wrong.
    pub reversible: bool,
}

/// The only tag value that triggers a hard veto.
pub const VETO_TOKEN: &str = "policy:veto";

#[derive(Debug, Default, Clone)]
pub struct ApprovalGate;

impl ApprovalGate {
    pub fn new() -> Self {
        ApprovalGate
    }

    pub fn decide(&self, req: &GateRequest) -> GateDecision {
        if req.tags.iter().any(|t| t == VETO_TOKEN) {
            return GateDecision::Vetoed;
        }
        let has_approver = req.approver.map(str::trim).is_some_and(|a| !a.is_empty());

        match req.risk_level {
            RiskLevel::Low => GateDecision::AutoApproved,
            RiskLevel::Medium => {
                if has_approver {
                    GateDecision::Approved
                } else {
                    GateDecision::HeldForApproval
                }
            }
            RiskLevel::High => {
                if has_approver && req.reversible {
                    GateDecision::Approved
                } else {
                    GateDecision::HeldForApproval
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(level: RiskLevel, tags: &'a [String], approver: Option<&'a str>, reversible: bool) -> GateRequest<'a> {
        GateRequest { risk_level: level, tags, approver, reversible }
    }

    #[test]
    fn veto_overrides_low_risk() {
        let tags = vec!["policy:veto".to_string()];
        assert_eq!(ApprovalGate::new().decide(&req(RiskLevel::Low, &tags, None, true)), GateDecision::Vetoed);
    }

    #[test]
    fn high_risk_needs_approver_and_reversibility() {
        let g = ApprovalGate::new();
        let none: Vec<String> = vec![];
        assert_eq!(g.decide(&req(RiskLevel::High, &none, Some("alice"), false)), GateDecision::HeldForApproval);
        assert_eq!(g.decide(&req(RiskLevel::High, &none, Some("alice"), true)), GateDecision::Approved);
    }

    #[test]
    fn whitespace_approver_is_no_approver() {
        let none: Vec<String> = vec![];
        assert_eq!(ApprovalGate::new().decide(&req(RiskLevel::Medium, &none, Some("   "), true)), GateDecision::HeldForApproval);
    }
}
