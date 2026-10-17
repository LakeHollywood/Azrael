//! Integration tests for the Agent v2 pipeline of `sovereign_engine_service`.
//!
//! Run with:
//!   cargo test -p sovereign_engine_service --test agent_v2_pipeline

use sovereign_engine_service::prelude::*;
use sovereign_engine_service::gate::VETO_TOKEN;
use sovereign_engine_service::pipeline::RawAction;

fn action(verb: &str, target: &str, reversible: bool) -> RawAction {
    RawAction { verb: verb.into(), target: target.into(), reversible, tags: vec![] }
}

fn tagged(mut a: RawAction, tags: &[&str]) -> RawAction {
    a.tags = tags.iter().map(|t| t.to_string()).collect();
    a
}

// ---------- stage 1+2: parse/validate ----------

#[test]
fn rejects_unknown_verb_without_executing() {
    let mut p = Pipeline::new();
    let out = p.run(&action("rm-rf", "/tmp/x", true));
    assert!(matches!(out, PipelineOutcome::RejectedAtValidation(StageError::UnknownVerb(v)) if v == "rm-rf"));
    assert!(p.executed().is_empty());
}

#[test]
fn rejects_empty_target() {
    let mut p = Pipeline::new();
    let out = p.run(&action("read", "", true));
    assert!(matches!(out, PipelineOutcome::RejectedAtValidation(StageError::InvalidTarget(_))));
}

#[test]
fn rejects_newline_injection_in_target() {
    // A "\n" in the target could forge audit lines if it reached later stages.
    let mut p = Pipeline::new();
    let out = p.run(&action("write", "ok\u{a}forged_entry", true));
    assert!(matches!(out, PipelineOutcome::RejectedAtValidation(StageError::InvalidTarget(_))));
    assert!(p.audit_is_intact());
}

#[test]
fn accepts_full_allowed_verb_vocabulary() {
    for verb in ["read", "write", "delete", "deploy", "export"] {
        let mut p = Pipeline::new();
        let out = p.run_with_approver(&action(verb, "bucket/object", true), "alice");
        assert!(
            matches!(out, PipelineOutcome::Executed { .. } | PipelineOutcome::Held { .. }),
            "{verb} should pass validation, got {out:?}"
        );
        // Held is fine (high-risk verbs); what must NOT happen is RejectedAtValidation.
        assert!(!matches!(out, PipelineOutcome::RejectedAtValidation(_)));
    }
}

// ---------- stage 3: risk scoring ----------

#[test]
fn read_of_non_prod_is_low_risk_and_auto_approved() {
    let mut p = Pipeline::new();
    match p.run(&action("read", "docs/runbook.md", true)) {
        PipelineOutcome::Executed { risk, decision, .. } => {
            assert_eq!(risk.level, RiskLevel::Low);
            assert_eq!(decision, GateDecision::AutoApproved);
        }
        other => panic!("expected auto-approved execution, got {other:?}"),
    }
}

#[test]
fn irreversible_prod_delete_is_high_risk() {
    let mut p = Pipeline::new();
    let out = p.run(&action("delete", "prod/db/main", false));
    match out {
        PipelineOutcome::Held { risk, decision } => {
            assert_eq!(risk.level, RiskLevel::High);
            assert_eq!(decision, GateDecision::HeldForApproval);
            assert!(risk.drivers.contains(&"production_surface".to_string()));
            assert!(risk.drivers.contains(&"irreversibility".to_string()));
        }
        other => panic!("high-risk unapproved delete must be held, got {other:?}"),
    }
    assert!(p.executed().is_empty(), "held actions must never reach the executor");
}

#[test]
fn pii_tag_raises_data_sensitivity_driver() {
    let mut p = Pipeline::new();
    let out = p.run(&tagged(action("export", "users.csv", true), &["pii"]));
    let risk = match out {
        PipelineOutcome::Held { risk, .. } => risk,
        PipelineOutcome::Executed { risk, .. } => risk,
        other => panic!("unexpected {other:?}"),
    };
    assert!(risk.drivers.iter().any(|d| d == "data_sensitivity"));
    assert!(risk.score >= 0.35, "pii export must not be low risk");
}

// ---------- stage 4: approval gate ----------

#[test]
fn approver_clears_medium_risk() {
    let mut p = Pipeline::new();
    // An irreversible *write* scores Medium (irreversibility 0.81 + blast radius 0.21):
    // without an approver it is held; with one it executes as Approved.
    let before = p.run(&action("write", "notes/todo.md", false));
    assert!(
        matches!(&before, PipelineOutcome::Held { risk, .. } if risk.level == RiskLevel::Medium),
        "expected medium-risk hold, got {before:?}"
    );

    let out = p.run_with_approver(&action("write", "notes/todo.md", false), "alice");
    match out {
        PipelineOutcome::Executed { decision, risk, .. } => {
            assert_eq!(risk.level, RiskLevel::Medium);
            assert_eq!(decision, GateDecision::Approved);
        }
        other => panic!("expected approved execution, got {other:?}"),
    }
    assert_eq!(p.executed().len(), 1);
}

#[test]
fn reversible_write_is_low_risk_and_auto_approved_despite_no_approver() {
    let mut p = Pipeline::new();
    let out = p.run(&action("write", "notes/todo.md", true));
    match out {
        PipelineOutcome::Executed { decision, risk, .. } => {
            assert_eq!(risk.level, RiskLevel::Low);
            assert_eq!(decision, GateDecision::AutoApproved);
        }
        other => panic!("expected auto-approved execution, got {other:?}"),
    }
}

#[test]
fn high_risk_irreversible_stays_held_even_with_approver() {
    let mut p = Pipeline::new();
    let out = p.run_with_approver(&action("delete", "prod/backups", false), "bob");
    assert!(matches!(out, PipelineOutcome::Held { decision: GateDecision::HeldForApproval, .. }));
    assert!(p.executed().is_empty());
}

#[test]
fn empty_approver_name_does_not_count_as_approval() {
    let mut p = Pipeline::new();
    let out = p.run_with_approver(&action("write", "cfg/app.toml", true), "   ");
    // medium-or-higher risk with blank approver must be held, not approved
    assert!(
        matches!(out, PipelineOutcome::Held { .. }) || matches!(out, PipelineOutcome::Executed { decision: GateDecision::AutoApproved, .. }),
        "blank approver must never yield Approved, got {out:?}"
    );
    if let PipelineOutcome::Executed { decision, .. } = &out {
        assert_ne!(*decision, GateDecision::Approved);
    }
}

#[test]
fn veto_token_blocks_even_low_risk_reads() {
    let mut p = Pipeline::new();
    let out = p.run_with_approver(&tagged(action("read", "secrets/token.txt", true), &[VETO_TOKEN]), "root");
    assert!(matches!(out, PipelineOutcome::Vetoed { .. }), "veto must override approver: {out:?}");
    assert!(p.executed().is_empty());
}

// ---------- stage 5 + cross-cutting: execution & audit ----------

#[test]
fn action_ids_are_monotonic_across_runs() {
    let mut p = Pipeline::new();
    let a = p.run(&action("read", "one.md", true));
    let b = p.run(&action("read", "two.md", true));
    match (a, b) {
        (PipelineOutcome::Executed { action_id: i1, .. }, PipelineOutcome::Executed { action_id: i2, .. }) => {
            assert_eq!(i2, i1 + 1);
        }
        _ => panic!("both reads should execute"),
    }
}

#[test]
fn audit_chain_records_every_stage_and_verifies() {
    let mut p = Pipeline::new();
    p.run(&action("read", "a.md", true));                 // executed
    p.run(&action("delete", "prod/x", false));            // held
    p.run(&action("shred", "y", false));                  // rejected at validation
    assert!(p.audit_is_intact());

    let stages: Vec<&str> = p.audit.records().iter().map(|r| r.stage.as_str()).collect();
    // First action: parse, validate, risk, gate, execute (5 records)
    assert_eq!(&stages[..5], ["parse", "validate", "risk", "gate", "execute"]);
    // Rejected action still leaves parse + validate trail
    assert!(stages.contains(&"parse") && stages.iter().filter(|s| **s == "validate").count() >= 3);

    // Tamper detection end-to-end: rewrite one message, chain must fail.
    let mut log = p.audit.clone();
    log.tamper_with_for_tests(2, "level=Low score=0.0000");
    assert!(log.verify().is_err(), "tampered audit chain must not verify");
}

#[test]
fn hostile_batch_never_panics_and_audit_survives() {
    let mut p = Pipeline::new();
    let hostile = [
        action("", "", false),
        action("\u{0}", "nul-target", true),
        action("read", &"x".repeat(1000), true), // oversized target
        tagged(action("deploy", "prod/web", false), &["pii", VETO_TOKEN]),
        action("export", "ledger.csv", true),
    ];
    for raw in &hostile {
        let _ = p.run(raw); // must not panic
    }
    assert!(p.audit_is_intact());
    assert!(p.executed().iter().all(|a| !a.target.is_empty()));
}
