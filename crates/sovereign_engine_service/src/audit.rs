//! Tamper-evident, hash-chained audit log — the Rust counterpart of `audit_log.py`.
//!
//! Each record stores the hex digest of (previous_digest ++ canonical(self)).
//! Genesis uses a fixed zero prev-digest. Verification recomputes the chain and
//! fails on the first mismatch (fail-closed, like the Python ledger verifier).
//!
//! Hash: FNV-1a 64-bit over the canonical line. This is deliberately *not*
//! cryptographic; it gives deterministic chaining for tests. Swap in SHA-256
//! (e.g. via the `sha2` crate) before using this with real ledgers.

use crate::gate::GateDecision;
use crate::risk::RiskLevel;

const GENESIS: &str = "0000000000000000";

fn fnv1a_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in input.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// One immutable entry in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub stage: String,
    pub actor: String,
    pub message: String,
    /// Hex digest of every record before this one.
    pub prev_digest: String,
    /// Hex digest covering this record's content plus `prev_digest`.
    pub digest: String,
}

impl AuditRecord {
    /// Canonical serialization used for hashing. Fields are separated by \x1f
    /// (unit separator) so no field value can forge a boundary.
    fn canonical(&self) -> String {
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.seq, self.stage, self.actor, self.message
        )
    }

    fn compute_digest(&self) -> String {
        fnv1a_hex(&format!("{}{}", self.prev_digest, self.canonical()))
    }
}

#[derive(Debug, Default, Clone)]
pub struct AuditLog {
    pub(crate) records: Vec<AuditRecord>,
}

impl AuditLog {
    pub fn new() -> Self {
        AuditLog::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Append a record chained to the current tip. Returns the stored record.
    pub fn append(&mut self, stage: &str, actor: &str, message: String) -> AuditRecord {
        let prev_digest = self
            .records
            .last()
            .map(|r| r.digest.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        let rec = AuditRecord {
            seq: self.records.len() as u64,
            stage: stage.to_string(),
            actor: actor.to_string(),
            message,
            prev_digest,
            digest: String::new(),
        };
        let mut rec = rec;
        rec.digest = rec.compute_digest();
        self.records.push(rec.clone());
        rec
    }

    /// Convenience wrappers used by the pipeline stages.
    pub fn note_risk(&mut self, actor: &str, level: RiskLevel, score: f64) -> AuditRecord {
        self.append("risk", actor, format!("level={level:?} score={score:.4}"))
    }

    pub fn note_gate(&mut self, actor: &str, decision: &GateDecision) -> AuditRecord {
        self.append("gate", actor, format!("decision={decision:?}"))
    }

    /// Recompute the chain; Err(first_bad_seq) on any tampering or splice.
    pub fn verify(&self) -> Result<(), u64> {
        let mut prev = GENESIS.to_string();
        for (i, rec) in self.records.iter().enumerate() {
            if rec.seq != i as u64 {
                return Err(rec.seq);
            }
            if rec.prev_digest != prev {
                return Err(rec.seq);
            }
            if rec.compute_digest() != rec.digest {
                return Err(rec.seq);
            }
            prev = rec.digest.clone();
        }
        Ok(())
    }

    /// Simulate an attacker rewriting one record's message without re-hashing.
    /// Used by tests to prove `verify` catches tampering.
    #[doc(hidden)]
    pub fn tamper_with_for_tests(&mut self, seq: usize, new_message: &str) {
        if let Some(r) = self.records.get_mut(seq) {
            r.message = new_message.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_chain_verifies() {
        let mut log = AuditLog::new();
        log.append("parse", "agent", "hello".into());
        log.append("execute", "agent", "world".into());
        assert_eq!(log.verify(), Ok(()));
    }

    #[test]
    fn tamper_is_detected() {
        let mut log = AuditLog::new();
        log.append("parse", "agent", "ok".into());
        log.append("execute", "agent", "delete_prod".into());
        log.tamper_with_for_tests(1, "nothing_happened");
        assert_eq!(log.verify(), Err(1));
    }

    #[test]
    fn genesis_prev_digest_is_zero() {
        let mut log = AuditLog::new();
        let r = log.append("parse", "agent", "x".into());
        assert_eq!(r.prev_digest, GENESIS);
    }
}
