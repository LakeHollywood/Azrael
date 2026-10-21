//! ABIDE conformance vectors, Rust parity mirror.
//! Mirrors tests/abide/ (A2/A4/A5 + RD) and the SAIL invariant suite.

use abide_harness::predicate::{PredicateEngine, PredicateError};
use abide_harness::types::{HistoricalEvidence, LiveAuthorization, LiveEvidence, TransitionScope};
use abide_harness::{DevVerifier, EngineState, SovereignEngine};

fn sig(first: u8) -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0] = first;
    s
}

fn grant(scope: TransitionScope, ts: u64) -> LiveAuthorization {
    LiveAuthorization::new(sig(0x01), scope, ts)
}

fn hist() -> HistoricalEvidence {
    HistoricalEvidence {
        payload_blob: b"prior mission log".to_vec(),
        timestamp: 0,
    }
}

fn live(ts: u64) -> LiveEvidence {
    LiveEvidence {
        sensor_feed: b"telemetry frame".to_vec(),
        timestamp: ts,
    }
}

/// A2/A3: forged cryptographic provenance is rejected before any other layer.
#[test]
fn a3_provenance_forgery_rejected() {
    let engine = PredicateEngine::new(120);
    let mut auth = LiveAuthorization::new(sig(0x00), TransitionScope::CalibrateRadar, 1000);
    let err = engine
        .evaluate(
            &hist(),
            &live(1000),
            &mut auth,
            TransitionScope::CalibrateRadar,
            1000,
            &DevVerifier,
        )
        .unwrap_err();
    assert_eq!(err, PredicateError::CryptographicVerificationFailed);
    assert!(!auth.is_consumed(), "rejected grant must not be consumed");
}

/// A4: STS epoch window — drift beyond delta_max fails closed.
#[test]
fn a4_temporal_window_violation() {
    let engine = PredicateEngine::new(120);
    let mut auth = grant(TransitionScope::UpdateTrajectory, 1000);
    let err = engine
        .evaluate(
            &hist(),
            &live(1200),
            &mut auth,
            TransitionScope::UpdateTrajectory,
            1000,
            &DevVerifier,
        )
        .unwrap_err();
    assert_eq!(err, PredicateError::TemporalWindowViolation);
}

/// A5: scope substitution — grant for one target cannot authorize another.
#[test]
fn a5_scope_substitution_denied() {
    let engine = PredicateEngine::new(120);
    let mut auth = grant(TransitionScope::SensorModePassive, 1000);
    let err = engine
        .evaluate(
            &hist(),
            &live(1000),
            &mut auth,
            TransitionScope::ActiveOperationalRelease,
            1000,
            &DevVerifier,
        )
        .unwrap_err();
    assert_eq!(err, PredicateError::ScopeMismatch);
}

/// Vector RD: token resurrection — second consume attempt fails.
#[test]
fn rd_token_resurrection_blocked() {
    let mut auth = grant(TransitionScope::CalibrateRadar, 1000);
    assert!(auth.consume().is_ok());
    let err = auth.consume().unwrap_err();
    assert!(err.contains("Resurrection"));
}

/// End-to-end happy path: predicate -> eligibility -> execution handoff.
#[test]
fn eligible_transition_executes_and_bumps_epoch() {
    let engine = PredicateEngine::new(120);
    let mut auth = grant(TransitionScope::CalibrateRadar, 1000);
    let token = engine
        .evaluate(
            &hist(),
            &live(1000),
            &mut auth,
            TransitionScope::CalibrateRadar,
            1000,
            &DevVerifier,
        )
        .expect("eligible");
    let mut se = SovereignEngine::new();
    assert_eq!(se.epoch(), 0);
    se.execute_transition(token.clone(), TransitionScope::CalibrateRadar)
        .unwrap();
    assert_eq!(se.state(), EngineState::ActiveOperational);
    assert_eq!(se.epoch(), 1);
}

/// Invariant III: an eligibility token for scope X cannot execute scope Y,
/// and the mismatch trips QUARANTINE_HOLD at the handoff boundary.
#[test]
fn eligibility_is_not_execution_scope_mismatch_quarantines() {
    let engine = PredicateEngine::new(120);
    let mut auth = grant(TransitionScope::CalibrateRadar, 1000);
    let token = engine
        .evaluate(
            &hist(),
            &live(1000),
            &mut auth,
            TransitionScope::CalibrateRadar,
            1000,
            &DevVerifier,
        )
        .unwrap();
    let mut se = SovereignEngine::new();
    let err = se
        .execute_transition(token, TransitionScope::ActiveOperationalRelease)
        .unwrap_err();
    assert_eq!(err, abide_harness::EngineError::ScopeMismatch);
    assert_eq!(se.state(), EngineState::Quarantined);
    assert!(se.quarantine_reason().unwrap().contains("Scope mismatch"));
    // Quarantine is terminal for dispatch: everything else fails closed.
    let mut auth2 = grant(TransitionScope::CalibrateRadar, 1000);
    let t2 = engine
        .evaluate(
            &hist(),
            &live(1000),
            &mut auth2,
            TransitionScope::CalibrateRadar,
            1000,
            &DevVerifier,
        )
        .unwrap();
    assert_eq!(
        se.execute_transition(t2, TransitionScope::CalibrateRadar)
            .unwrap_err(),
        abide_harness::EngineError::SystemQuarantined
    );
}

/// Hardware interlock: ActiveOperationalRelease requires physical unlock.
#[test]
fn hardware_lock_blocks_release_while_locked() {
    let engine = PredicateEngine::new(120);
    let mut auth = grant(TransitionScope::ActiveOperationalRelease, 1000);
    let token = engine
        .evaluate(
            &hist(),
            &live(1000),
            &mut auth,
            TransitionScope::ActiveOperationalRelease,
            1000,
            &DevVerifier,
        )
        .unwrap();
    let mut se = SovereignEngine::new(); // state == Locked
    assert_eq!(
        se.execute_transition(token, TransitionScope::ActiveOperationalRelease)
            .unwrap_err(),
        abide_harness::EngineError::HardwareLockEngaged
    );
    assert_eq!(
        se.state(),
        EngineState::Locked,
        "denial must not mutate state"
    );
}

/// LatencyClock telemetry helper is monotonic and non-negative.
#[test]
fn latency_clock_measures_microseconds() {
    let clock = abide_harness::LatencyClock::start();
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert!(clock.elapsed_us() >= 1000);
}
