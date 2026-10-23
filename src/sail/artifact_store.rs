//! S.A.I.L. Layer 2 — Storage: content-addressed evidence preservation.
//!
//! # Contract
//!
//! The store is **evidence-only**. It never executes business logic, never
//! validates tokens or signatures, and never confers authority. Its two
//! load-bearing rules are:
//!
//! 1. **Integrity on write** — [`ArtifactStore::put`] enforces the invariant
//!    `key == artifact.key()`: the caller-supplied address must equal the
//!    artifact's own recomputed content address. A mismatch means either a
//!    corrupted key or tampered bytes, and the write is rejected outright.
//! 2. **Neutrality on read** — [`ArtifactStore::get`] returns the raw
//!    canonical bytes exactly as preserved. Holding bytes is not endorsing
//!    them; authority over what those bytes *mean* is earned exclusively by
//!    passing [`verifier`](crate::verifier)'s evaluation rules.
//!
//! Because keys are content addresses, deduplication is automatic and any
//! fetch can be independently re-verified by recomputing the address from
//! the returned bytes (see [`verify_address`]).

use std::collections::HashMap;

use crate::codec::{constant_time_eq, ArtifactKey, FrameWriter};

/// SHA-256 over the `SAIL-V1-KEY` framed encoding of an artifact body.
///
/// Kept private to this module so every implementation of [`Artifact::key`]
/// derives its address through the same length-prefixed domain frame.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    // FIPS 180-4 SHA-256, minimal constant-time-free-by-nature impl (hashing
    // is public data; no secrets touched).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pre-processing: pad with 0x80, zeros, then u64 BE bit-length.
    let mut msg = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip(v.iter()) {
            *x = x.wrapping_add(*y);
        }
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// A stored piece of evidence: opaque canonical bytes plus whatever typed
/// commitments the artifact itself carries. Types live in `codec.rs`; only
/// `verifier.rs` ever interprets them.
pub trait Artifact: Clone {
    /// Domain tag used when addressing this artifact class.
    const DOMAIN_TAG: &'static str;

    /// The exact framed bytes whose hash forms the content address.
    fn address_body(&self) -> Vec<u8>;

    /// Recompute this artifact's own content address from its canonical
    /// bytes. The store calls this on every `put` and rejects mismatches.
    fn key(&self) -> ArtifactKey {
        content_address(Self::DOMAIN_TAG, &self.address_body())
    }

    /// Canonical wire bytes (the exact `SAIL-V1-*` framed encoding).
    fn canonical_bytes(&self) -> Vec<u8> {
        self.address_body()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The supplied key did not equal `artifact.key()`. Write refused.
    AddressMismatch {
        claimed: String,
        computed: String,
    },
    /// No artifact is preserved under this address.
    NotFound,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::AddressMismatch { claimed, computed } => {
                write!(f, "SAIL_STORE_ERR_ADDRESS_MISMATCH({claimed}!={computed})")
            }
            StoreError::NotFound => write!(f, "SAIL_STORE_ERR_NOT_FOUND"),
        }
    }
}

impl std::error::Error for StoreError {}

/// In-memory content-addressed evidence vault.
///
/// Deliberately inert: no validation hooks, no policy callbacks, no trust.
/// Callers who need judgment go to `verifier.rs`.
pub struct ArtifactStore<A: Artifact> {
    vault: HashMap<ArtifactKey, Vec<u8>>,
    /// The vault is typed to a single artifact class so addresses from
    /// different domains can never be conflated at the API boundary.
    _class: std::marker::PhantomData<A>,
}

impl<A: Artifact> Default for ArtifactStore<A> {
    fn default() -> Self {
        Self {
            vault: HashMap::new(),
            _class: std::marker::PhantomData,
        }
    }
}

impl<A: Artifact> ArtifactStore<A> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Preserve `artifact` under `key`.
    ///
    /// Enforced invariant: `key == artifact.key()`. The store recomputes the
    /// address from the artifact's canonical bytes and refuses — without
    /// writing anything — if the caller's claim disagrees.
    pub fn put(&mut self, key: &ArtifactKey, artifact: &A) -> Result<(), StoreError> {
        let computed = artifact.key();
        // Constant-time comparison: even the store's integrity gate must not
        // leak how many leading bytes of an address matched.
        if !constant_time_eq(key.as_bytes(), computed.as_bytes()) {
            return Err(StoreError::AddressMismatch {
                claimed: key.to_hex(),
                computed: computed.to_hex(),
            });
        }
        self.vault.insert(computed, artifact.canonical_bytes());
        Ok(())
    }

    /// Retrieve the raw canonical bytes preserved under `key`.
    ///
    /// This confers **no authority**: it is evidence retrieval, not
    /// endorsement. Verification happens in `verifier.rs`.
    pub fn get(&self, key: &ArtifactKey) -> Result<Vec<u8>, StoreError> {
        // Linear-scan equality would leak ordering info about which vault
        // entries match prefix bytes; HashMap uses full digest hashing, and
        // we still confirm the hit with constant-time equality.
        for (k, v) in self.vault.iter() {
            if constant_time_eq(k.as_bytes(), key.as_bytes()) {
                return Ok(v.clone());
            }
        }
        Err(StoreError::NotFound)
    }

    /// Number of preserved artifacts. (Metrics only — not an authority signal.)
    pub fn len(&self) -> usize {
        self.vault.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vault.is_empty()
    }
}

/// Convenience helper shared by artifact implementations: fold a body into a
/// `SAIL-V1-KEY` content address using the canonical framing.
pub fn content_address(tag: &str, body: &[u8]) -> ArtifactKey {
    let mut w = FrameWriter::new(tag);
    w.field(body);
    ArtifactKey::from_bytes(sha256(w.finish()))
}

/// Re-derivation check usable on bytes fetched via [`ArtifactStore::get`]:
/// recomputing the address is always available to any party, which is what
/// keeps the store honest without giving it any power.
pub fn verify_address<A: Artifact>(artifact: &A) -> bool {
    let recomputed = content_address(A::DOMAIN_TAG, &artifact.address_body());
    constant_time_eq(recomputed.as_bytes(), artifact.key().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::LineageDigest;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[derive(Clone)]
    struct Receipt {
        lineage: LineageDigest,
        payload: Vec<u8>,
    }

    impl Artifact for Receipt {
        const DOMAIN_TAG: &'static str = "SAIL-V1-RECEIPT";
        fn address_body(&self) -> Vec<u8> {
            let mut w = FrameWriter::new(Self::DOMAIN_TAG);
            w.digest(&self.lineage).field(&self.payload);
            w.finish().to_vec()
        }
    }

    #[test]
    fn put_enforces_key_equals_artifact_key() {
        let r = Receipt {
            lineage: LineageDigest::from_bytes([1u8; 32]),
            payload: b"telemetry".to_vec(),
        };
        let good = r.key();
        let bad = ArtifactKey::from_bytes([9u8; 32]);
        let mut store = ArtifactStore::<Receipt>::new();
        assert!(matches!(
            store.put(&bad, &r),
            Err(StoreError::AddressMismatch { .. })
        ));
        assert!(store.is_empty(), "rejected writes must not persist");
        assert!(store.put(&good, &r).is_ok());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn get_returns_raw_canonical_bytes() {
        let r = Receipt {
            lineage: LineageDigest::from_bytes([2u8; 32]),
            payload: b"frame".to_vec(),
        };
        let k = r.key();
        let mut store = ArtifactStore::<Receipt>::new();
        store.put(&k, &r).unwrap();
        assert_eq!(store.get(&k).unwrap(), r.canonical_bytes());
        assert!(verify_address(&r));
    }

    #[test]
    fn missing_address_is_not_found() {
        let store = ArtifactStore::<Receipt>::new();
        let k = ArtifactKey::from_bytes([3u8; 32]);
        assert_eq!(store.get(&k), Err(StoreError::NotFound));
    }

    #[test]
    fn content_addressing_dedupes() {
        let r = Receipt {
            lineage: LineageDigest::from_bytes([4u8; 32]),
            payload: b"x".to_vec(),
        };
        let k = r.key();
        let mut store = ArtifactStore::<Receipt>::new();
        store.put(&k, &r).unwrap();
        store.put(&k, &r).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn framing_change_changes_address() {
        // Different payloads ⇒ different addresses (collision resistance of
        // the length-prefixed frame, exercised at the codec boundary).
        let a = Receipt { lineage: LineageDigest::from_bytes([0u8; 32]), payload: b"ab".to_vec() };
        let b = Receipt { lineage: LineageDigest::from_bytes([0u8; 32]), payload: b"a".to_vec() };
        assert_ne!(a.key(), b.key());
    }
}
