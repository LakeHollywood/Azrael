//! Sovereign Engine structural type boundaries (Rust parity mirror).
//!
//! Parity source: `src/sovereign_engine/types/{evidence,authorization}.py`
//! and the SAIL-SPEC-2026 frozen invariants.
//!
//! * **Invariant I** — evidence content never carries authority. Historical
//!   and live evidence are distinct types with no shared conversion path, so
//!   a function demanding `LiveEvidence` can never be fed `HistoricalEvidence`.
//! * **Invariant II** — every grant is bound to exactly one target scope.
//! * **Single-use** — consumption state lives inside `LiveAuthorization`;
//!   resurrection attempts are rejected at the type boundary (`&mut self`).

use std::time::{Duration, Instant};

/// Target operational scope for state transitions (Invariant II enforcement).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransitionScope {
    CalibrateRadar,
    UpdateTrajectory,
    SensorModePassive,
    /// High-criticality state; requires physical unlock (see `engine.rs`).
    ActiveOperationalRelease,
}

/// Historical evidence container (persisted state, prior mission logs).
/// Invariant I: ingested for context only; grants no authority.
#[derive(Debug, Clone)]
pub struct HistoricalEvidence {
    pub payload_blob: Vec<u8>,
    pub timestamp: u64,
}

/// Live operational evidence container (active sensor streams, real-time
/// telemetry). Distinct type from `HistoricalEvidence` by construction.
#[derive(Debug, Clone)]
pub struct LiveEvidence {
    pub sensor_feed: Vec<u8>,
    pub timestamp: u64,
}

impl LiveEvidence {
    /// Absolute skew between this attestation and the STS clock reading.
    pub fn drift(&self, current_time: u64) -> u64 {
        self.timestamp.abs_diff(current_time)
    }
}

/// Cryptographic Live Authorization Grant bound strictly to a target scope.
#[derive(Debug, Clone)]
pub struct LiveAuthorization {
    pub grant_signature: [u8; 64],
    pub authorized_scope: TransitionScope,
    pub issued_timestamp: u64,
    consumed: bool,
}

impl LiveAuthorization {
    pub fn new(signature: [u8; 64], scope: TransitionScope, timestamp: u64) -> Self {
        Self {
            grant_signature: signature,
            authorized_scope: scope,
            issued_timestamp: timestamp,
            consumed: false,
        }
    }

    /// Enforces single-use token consumption mechanics (Vector RD defense).
    pub fn consume(&mut self) -> Result<(), &'static str> {
        if self.consumed {
            return Err("Token Resurrection Attempt: Authorization grant already consumed.");
        }
        self.consumed = true;
        Ok(())
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
}

/// Eligibility Token proving predicate satisfaction.
/// Invariant III: eligibility != execution — holding a token mutates nothing.
#[derive(Debug, Clone)]
pub struct EligibilityToken {
    target_scope: TransitionScope,
    epoch: u64,
}

impl EligibilityToken {
    pub(crate) fn new(scope: TransitionScope, epoch: u64) -> Self {
        Self {
            target_scope: scope,
            epoch,
        }
    }

    pub fn scope(&self) -> TransitionScope {
        self.target_scope
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Monotonic timing helper used by the telemetry layer (latency_us).
#[derive(Debug, Clone)]
pub struct LatencyClock(Instant);

impl LatencyClock {
    pub fn start() -> Self {
        Self(Instant::now())
    }

    /// Microseconds elapsed since `start()` (integer division, truncating).
    pub fn elapsed_us(&self) -> u64 {
        Duration::as_micros(&self.0.elapsed()) as u64
    }
}
