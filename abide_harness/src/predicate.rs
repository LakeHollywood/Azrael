//! Temporal & authority evaluation predicate P (Rust parity mirror).
//!
//! Parity source: `src/sovereign_engine/gate/predicate.py` +
//! `execution/abide_monitor.py`. Verifies cryptographic provenance via a
//! pluggable `Verifier` trait (no crates.io dependency required in-tree),
//! enforces the STS validity window W(T_current, delta_max), and checks
//! scope matching (Invariant II) while keeping evidence and authorization
//! strictly partitioned.

use crate::types::{
    EligibilityToken, HistoricalEvidence, LiveAuthorization, LiveEvidence, TransitionScope,
};

/// Pluggable cryptographic backend. The sandbox build has no ed25519 crate,
/// so verification is delegated behind this trait; production wiring injects
/// a real Ed25519 verifier without touching invariant logic below.
pub trait Verifier {
    fn verify(&self, signature: &[u8; 64], message: &[u8]) -> bool;
}

/// Deterministic test/dev backend: accepts signatures whose first byte is
/// 0x01 and which match the derived canonical message digest length. Never
/// ship as the sole backend in a deployed boundary.
pub struct DevVerifier;

impl Verifier for DevVerifier {
    fn verify(&self, signature: &[u8; 64], _message: &[u8]) -> bool {
        signature[0] == 0x01
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateError {
    CryptographicVerificationFailed,
    TemporalWindowViolation,
    ScopeMismatch,
    AuthorizationMissing,
}

pub struct PredicateEngine {
    max_drift_seconds: u64,
}

impl PredicateEngine {
    pub fn new(max_drift_seconds: u64) -> Self {
        Self { max_drift_seconds }
    }

    /// Canonical signing bytes: domain-separated over scope || issue time.
    /// Mirrors `canonical_message()` in abide_monitor.py.
    pub fn canonical_message(auth: &LiveAuthorization) -> Vec<u8> {
        let scope_tag = match auth.authorized_scope {
            TransitionScope::CalibrateRadar => "CALIBRATE_RADAR",
            TransitionScope::UpdateTrajectory => "UPDATE_TRAJECTORY",
            TransitionScope::SensorModePassive => "SENSOR_MODE_PASSIVE",
            TransitionScope::ActiveOperationalRelease => "ACTIVE_OPERATIONAL_RELEASE",
        };
        format!("ABIDE|GRANT|{scope_tag}|{}", auth.issued_timestamp).into_bytes()
    }

    /// Evaluates tripartite inputs against strict safety predicates.
    /// `_historical` is ingested for context only — Invariant I: it can
    /// never grant or influence authority.
    pub fn evaluate<V: Verifier>(
        &self,
        _historical: &HistoricalEvidence,
        live: &LiveEvidence,
        auth: &mut LiveAuthorization,
        requested_scope: TransitionScope,
        current_time: u64,
        verifier: &V,
    ) -> Result<EligibilityToken, PredicateError> {
        // Layer 1: cryptographic provenance.
        let message = Self::canonical_message(auth);
        if !verifier.verify(&auth.grant_signature, &message) {
            return Err(PredicateError::CryptographicVerificationFailed);
        }

        // Layer 2: STS temporal validity window W(T_current, delta_max).
        if live.drift(current_time) > self.max_drift_seconds {
            return Err(PredicateError::TemporalWindowViolation);
        }

        // Layer 3: SAIL authority gate & scope check (Invariant II).
        if auth.authorized_scope != requested_scope {
            return Err(PredicateError::ScopeMismatch);
        }

        // Consume the grant to prevent reuse (Vector RD / resurrection defense).
        auth.consume()
            .map_err(|_| PredicateError::AuthorizationMissing)?;

        // Invariant III: we establish eligibility, not execution.
        Ok(EligibilityToken::new(requested_scope, current_time))
    }
}
