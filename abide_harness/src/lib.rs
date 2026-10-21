//! ABIDE-Harness: Rust parity mirror of the Sovereign Engine authority
//! boundary (SAIL-SPEC-2026 frozen invariants I–III).
//!
//! Module map (strict isolation by construction):
//! * [`types`] — structural type boundaries; evidence/authorization can never
//!   be confused at compile time.
//! * [`predicate`] — pure evaluation predicate P with STS window + scope +
//!   single-use consumption.
//! * [`engine`] — state machine, hardware locks, QUARANTINE_HOLD.

pub mod engine;
pub mod predicate;
pub mod types;

pub use engine::{EngineError, EngineState, SovereignEngine};
pub use predicate::{DevVerifier, PredicateEngine, PredicateError, Verifier};
pub use types::{
    EligibilityToken, HistoricalEvidence, LatencyClock, LiveAuthorization, LiveEvidence,
    TransitionScope,
};
