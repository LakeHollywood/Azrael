//! Sovereign Engine state machine, hardware locks & quarantine (Rust parity).
//!
//! Parity source: `src/sovereign_engine/engine/{quarantine,transition_gate}.py`
//! and `execution/boundary.py`. Consumes the eligibility token and executes
//! the authorized state transition only when all structural conditions are
//! met. Invariant III: an EligibilityToken alone mutates nothing — the engine
//! re-verifies locks and scope at the execution handoff.

use crate::types::{EligibilityToken, TransitionScope};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EngineState {
    Locked,
    ActiveOperational,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    HardwareLockEngaged,
    ScopeMismatch,
    SystemQuarantined,
}

pub struct SovereignEngine {
    state: EngineState,
    epoch_counter: u64,
    last_quarantine_reason: Option<String>,
}

impl Default for SovereignEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SovereignEngine {
    pub fn new() -> Self {
        Self {
            state: EngineState::Locked,
            epoch_counter: 0,
            last_quarantine_reason: None,
        }
    }

    /// Invariant III & recovery check: eligibility does not automatically
    /// grant execution. The engine verifies hardware locks and consumes the
    /// eligibility token at the dispatch boundary.
    pub fn execute_transition(
        &mut self,
        token: EligibilityToken,
        target_scope: TransitionScope,
    ) -> Result<(), EngineError> {
        if self.state == EngineState::Quarantined {
            return Err(EngineError::SystemQuarantined);
        }

        // Verify token scope matches requested transition execution target.
        // A mismatch here is a structural breach (delegation-substitution),
        // so it trips quarantine rather than merely denying.
        if token.scope() != target_scope {
            self.trigger_quarantine("Scope mismatch detected during engine execution handoff.");
            return Err(EngineError::ScopeMismatch);
        }

        // Verify hardware safety interlocks: release requires an explicit
        // physical unlock signal (see execution/boundary.py locks).
        if self.state == EngineState::Locked
            && target_scope == TransitionScope::ActiveOperationalRelease
        {
            return Err(EngineError::HardwareLockEngaged);
        }

        // State mutation on successful validation only.
        self.epoch_counter += 1;
        self.state = EngineState::ActiveOperational;
        Ok(())
    }

    pub fn trigger_quarantine(&mut self, reason: &str) {
        self.state = EngineState::Quarantined;
        self.last_quarantine_reason = Some(reason.to_owned());
    }

    pub fn state(&self) -> EngineState {
        self.state
    }

    pub fn epoch(&self) -> u64 {
        self.epoch_counter
    }

    pub fn quarantine_reason(&self) -> Option<&str> {
        self.last_quarantine_reason.as_deref()
    }
}
