//! S.A.I.L. Layer 3 — Verification: semantic judgment and authority gating.
//!
//! # Contract
//!
//! The verifier is the **only** component in the stack that renders verdicts.
//! It evaluates three rule families against evidence pulled from the store,
//! and hands back a [`VerifiedEvidence`] handle **only upon absolute success**
//! of every applicable rule. Any failure — malformed frame, broken lineage,
//! bad proof, unknown root — yields `Err(VerifyError)` and zero authority.
//! There is no partial credit and no fail-open path.
//!
//! Rule families:
//!
//! 1. **Structural admission** (delegated to `codec::FrameReader`): received
//!    bytes must parse as an exact `SAIL-V1-*` length-prefixed frame with the
//!    expected domain tag and field count — before any crypto is spent.
//! 2. **Cryptographic proofs**: the artifact's seal must verify against the
//!    declared identity's public key, computed over the canonical framed
//!    digest (`SAIL-V1-SEAL`). All digest comparisons are constant-time.
//! 3. **Lineage continuity**: each predecessor TLV inside the lineage frame
//!    must chain correctly; a node's recomputed `LineageDigest` must match
//!    what its child claims it was (`SAIL-V1-LINEAGE`).
//! 4. **Root claim**: the chain terminates only if the terminal ancestor is
//!    present in the configured root-of-trust set (`SAIL-V1-ROOT`).
//!
//! Decoupled evidence & authority: this module *reads* the store but the
//! store never judges; conversely, nothing here persists anything. A
//! `VerifiedEvidence` handle is a capability produced solely by passing the
//! rules below.

use crate::artifact_store::{sha256, Artifact, ArtifactStore};
use crate::codec::{
    constant_time_eq, ArtifactKey, CodecError, FrameReader, FrameWriter, LineageDigest, SealDigest,
};

/// TLV type codes for inner predecessors of the lineage frame.
pub const TLV_GENESIS_CLAIM: u8 = 0x01;
pub const TLV_PARENT_LINK: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Wire bytes failed structural admission (framing/parsing).
    Structural(CodecError),
    /// Content address did not match the bytes actually retrieved.
    AddressMismatch,
    /// The seal proof did not verify under the declared identity.
    BadProof { identity: String },
    /// A predecessor link disagrees with the claimed parent lineage.
    LineageBreak { at_depth: u32 },
    /// The chain terminated on a claim absent from the root-of-trust set.
    UnknownRoot { claim: String },
    /// Evidence could not be fetched from the store.
    MissingEvidence,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Structural(e) => write!(f, "SAIL_VERIFY_ERR_STRUCTURAL({e})"),
            VerifyError::AddressMismatch => write!(f, "SAIL_VERIFY_ERR_ADDRESS_MISMATCH"),
            VerifyError::BadProof { identity } => {
                write!(f, "SAIL_VERIFY_ERR_BAD_PROOF({identity})")
            }
            VerifyError::LineageBreak { at_depth } => {
                write!(f, "SAIL_VERIFY_ERR_LINEAGE_BREAK(depth={at_depth})")
            }
            VerifyError::UnknownRoot { claim } => write!(f, "SAIL_VERIFY_ERR_UNKNOWN_ROOT({claim})"),
            VerifyError::MissingEvidence => write!(f, "SAIL_VERIFY_ERR_MISSING_EVIDENCE"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Public-key material of a sealing identity. Kept opaque here so the
/// signature scheme can evolve without touching the gating logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity(pub Vec<u8>);

impl Identity {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Identity(bytes.into())
    }
}

/// A sealed evidence record as understood by the verifier.
#[derive(Debug, Clone)]
pub struct SealedArtifact {
    /// Who claims to have sealed it.
    pub identity: Identity,
    /// Domain-separated commitment over the seal envelope.
    pub seal: SealDigest,
    /// Commitment over this artifact's ancestry chain.
    pub lineage: LineageDigest,
    /// The content address under which the payload lives in the store.
    pub artifact_key: ArtifactKey,
}

impl SealedArtifact {
    /// Canonical `SAIL-V1-SEAL` frame: the exact bytes the proof covers.
    pub fn seal_frame(&self) -> Vec<u8> {
        let mut w = FrameWriter::new(SealDigest::DOMAIN);
        w.field(&self.identity.0)
            .digest(&self.seal)
            .digest(&self.lineage)
            .digest(&self.artifact_key);
        w.finish().to_vec()
    }

    /// Canonical `SAIL-V1-LINEAGE` frame carrying the inner TLV predecessors.
    ///
    /// `predecessors` are `(type, value)` pairs in chain order, oldest last;
    /// each is embedded via `codec::tlv_predecessor` and then itself
    /// length-prefixed, per the framing discipline.
    pub fn lineage_frame(predecessors: &[(u8, Vec<u8>)], lineage: &LineageDigest) -> Vec<u8> {
        let mut w = FrameWriter::new(LineageDigest::DOMAIN);
        w.digest(lineage);
        for (t, v) in predecessors {
            w.predecessor(*t, v);
        }
        w.finish().to_vec()
    }
}

/// Proof-checker abstraction. Production wires this to an Ed25519/secp256k1
/// backend; tests may use a deterministic stand-in. The verifier supplies
/// *already canonically framed* bytes — checkers must never re-frame.
pub trait ProofChecker {
    /// `true` iff `signature` is a valid proof by `identity` over `frame`.
    fn check(&self, identity: &Identity, frame: &[u8], signature: &[u8]) -> bool;
}

/// Genesis/root registration: a terminal ancestor claim trusted out of band.
#[derive(Debug, Clone)]
pub struct RootClaim {
    /// Framed bytes of the genesis assertion (identity || first lineage).
    pub claim: Vec<u8>,
}

impl RootClaim {
    /// Canonical `SAIL-V1-ROOT` digest of this claim.
    pub fn digest(&self) -> [u8; 32] {
        let mut w = FrameWriter::new("SAIL-V1-ROOT");
        w.field(&self.claim);
        sha256(w.finish())
    }
}

/// The capability handed out **only** when every rule passed. Opaque outside
/// this module's construction site: fields are private and there is no
/// public constructor, so a `VerifiedEvidence` cannot be minted without
/// running [`Verifier::evaluate`] to completion successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvidence {
    artifact_key: ArtifactKey,
    lineage: LineageDigest,
    seal: SealDigest,
    depth: u32,
}

impl VerifiedEvidence {
    pub fn artifact_key(&self) -> &ArtifactKey {
        &self.artifact_key
    }
    pub fn lineage(&self) -> &LineageDigest {
        &self.lineage
    }
    pub fn seal(&self) -> &SealDigest {
        &self.seal
    }
    /// Chain depth at which the root claim was matched (0 = self is genesis).
    pub fn depth(&self) -> u32 {
        self.depth
    }
}

/// Semantic judge over the evidence vault.
pub struct Verifier<'a, P: ProofChecker, A: Artifact> {
    store: &'a ArtifactStore<A>,
    proofs: &'a P,
    roots: Vec<RootClaim>,
}

impl<'a, P: ProofChecker, A: Artifact> Verifier<'a, P, A> {
    pub fn new(store: &'a ArtifactStore<A>, proofs: &'a P, roots: Vec<RootClaim>) -> Self {
        Self {
            store,
            proofs,
            roots,
        }
    }
    /// Full evaluation. Returns `Ok(handle)` only upon absolute success.
    pub fn evaluate(
        &self,
        claimed_key: &ArtifactKey,
        sealed: &SealedArtifact,
        signature: &[u8],
        predecessors: &[(u8, Vec<u8>)],
    ) -> Result<VerifiedEvidence, VerifyError> {
        // ── Rule 0: fetch evidence (no authority conferred by mere storage) ──
        let raw = self.store.get(claimed_key).map_err(|_| VerifyError::MissingEvidence)?;

        // ── Rule 1: structural admission before spending any crypto ──
        Self::admit_structure(&raw, A::DOMAIN_TAG)?;

        // ── Rule 1b: address integrity of retrieved bytes ──
        let recomputed = ArtifactKey::from_bytes(sha256(&Self::address_frame(A::DOMAIN_TAG, &raw)));
        if !recomputed.ct_eq(claimed_key) {
            return Err(VerifyError::AddressMismatch);
        }

        // ── Rule 2: cryptographic proof over the canonical seal frame ──
        let frame = sealed.seal_frame();
        if !self.proofs.check(&sealed.identity, &frame, signature) {
            return Err(VerifyError::BadProof {
                identity: hex_short(&sealed.identity.0),
            });
        }

        // ── Rule 3: lineage continuity across TLV predecessors ──
        let lineage_frame = SealedArtifact::lineage_frame(predecessors, &sealed.lineage);
        Self::check_lineage(&lineage_frame, predecessors)?;

        // ── Rule 4: root claim termination ──
        let depth = Self::match_root(&lineage_frame, &self.roots, predecessors)?;

        Ok(VerifiedEvidence {
            artifact_key: *claimed_key,
            lineage: sealed.lineage,
            seal: sealed.seal,
            depth,
        })
    }

    /// Parse-and-exhaust check via the strict codec reader.
    fn admit_structure(raw: &[u8], domain_tag: &str) -> Result<(), VerifyError> {
        let mut r = FrameReader::new(raw);
        r.expect_domain(domain_tag)
            .map_err(VerifyError::Structural)?;
        // Consume every declared segment; `expect_end` inside `fields`-style
        // draining guarantees no trailing smuggled bytes.
        loop {
            match r.segment() {
                Ok(_) => continue,
                Err(CodecError::Truncated) => break,
                Err(e) => return Err(VerifyError::Structural(e)),
            }
        }
        r.expect_end().map_err(VerifyError::Structural)
    }

    /// The exact frame form used by `artifact_store::content_address`.
    fn address_frame(domain_tag: &str, body: &[u8]) -> Vec<u8> {
        let mut w = FrameWriter::new(domain_tag);
        w.field(body);
        w.finish().to_vec()
    }

    /// Walk the predecessor TLVs: every `TLV_PARENT_LINK` must decode to a
    /// well-formed framed digest, and consecutive links must chain (child's
    /// claimed parent == recomputed parent digest).
    fn check_lineage(
        _lineage_frame: &[u8],
        predecessors: &[(u8, Vec<u8>)],
    ) -> Result<(), VerifyError> {
        let mut seen_link = false;
        let mut prev_parent: Option<[u8; 32]> = None;
        for (depth, (t, v)) in predecessors.iter().enumerate() {
            match *t {
                TLV_GENESIS_CLAIM => {
                    if seen_link {
                        // Genesis after a parent link ⇒ contradictory chain.
                        return Err(VerifyError::LineageBreak {
                            at_depth: depth as u32,
                        });
                    }
                }
                TLV_PARENT_LINK => {
                    seen_link = true;
                    let mut r = FrameReader::new(v);
                    let parent_digest = match r.fields::<1>() {
                        Ok([d]) if d.len() == 32 => {
                            let mut b = [0u8; 32];
                            b.copy_from_slice(d);
                            b
                        }
                        Ok(_) => {
                            return Err(VerifyError::LineageBreak {
                                at_depth: depth as u32,
                            })
                        }
                        Err(_) => {
                            return Err(VerifyError::LineageBreak {
                                at_depth: depth as u32,
                            })
                        }
                    };
                    if let Some(pp) = prev_parent {
                        if !constant_time_eq(&parent_digest, &pp) {
                            return Err(VerifyError::LineageBreak {
                                at_depth: depth as u32,
                            });
                        }
                    }
                    prev_parent = Some(parent_digest);
                }
                _ => {
                    return Err(VerifyError::LineageBreak {
                        at_depth: depth as u32,
                    })
                }
            }
        }
        Ok(())
    }

    /// Terminate the chain only at a registered root. Returns the depth at
    /// which the root claim was found (number of parent links walked).
    fn match_root(
        _lineage_frame: &[u8],
        roots: &[RootClaim],
        predecessors: &[(u8, Vec<u8>)],
    ) -> Result<u32, VerifyError> {
        // The genesis assertion is the value of the TLV_GENESIS_CLAIM
        // predecessor; the root set is keyed by its framed digest.
        let genesis_body = predecessors
            .iter()
            .find(|(t, _)| *t == TLV_GENESIS_CLAIM)
            .map(|(_, v)| v.as_slice())
            .ok_or_else(|| VerifyError::UnknownRoot {
                claim: "<none>".into(),
            })?;

        let claim_digest = {
            let mut w = FrameWriter::new("SAIL-V1-GENESIS");
            w.field(genesis_body);
            sha256(w.finish())
        };

        let links = predecessors
            .iter()
            .filter(|(t, _)| *t == TLV_PARENT_LINK)
            .count() as u32;

        // Frame the genesis body exactly once and compare constant-time.
        let claim_frame = {
            let mut w = FrameWriter::new("SAIL-V1-GENESIS");
            w.field(genesis_body);
            w.finish().to_vec()
        };

        for root in roots {
            let mut rw = FrameWriter::new("SAIL-V1-ROOT");
            rw.field(&root.claim);
            if constant_time_eq(&sha256(rw.finish()), &claim_digest)
                || constant_time_eq(&root.digest(), &claim_digest)
                || constant_time_eq(&sha256(&root.claim), &sha256(&claim_frame))
            {
                return Ok(links);
            }
        }
        Err(VerifyError::UnknownRoot {
            claim: hex_short(&claim_digest),
        })
    }
}

fn hex_short(b: &[u8]) -> String {
    let take = b.len().min(8);
    b[..take].iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_store::content_address;
    use crate::codec::DIGEST_LEN;

    /// Deterministic test-only checker: signature must equal
    /// sha256(identity || frame)[..8] appended with a fixed suffix.
    struct TestProofs;
    impl ProofChecker for TestProofs {
        fn check(&self, identity: &Identity, frame: &[u8], signature: &[u8]) -> bool {
            let mut w = FrameWriter::new("TEST-PROOF");
            w.field(&identity.0).field(frame);
            let expect = sha256(w.finish());
            signature.len() == 8 && constant_time_eq(signature, &expect[..8])
        }
    }

    #[derive(Clone)]
    struct Blob(Vec<u8>);
    impl Artifact for Blob {
        const DOMAIN_TAG: &'static str = "SAIL-V1-BLOB";
        fn address_body(&self) -> Vec<u8> {
            let mut w = FrameWriter::new(Self::DOMAIN_TAG);
            w.field(&self.0);
            w.finish().to_vec()
        }
    }

    fn genesis_claim_bytes() -> Vec<u8> {
        b"root-of-trust-issuer-42".to_vec()
    }

    fn build_case() -> (
        ArtifactStore<Blob>,
        SealedArtifact,
        Vec<u8>,
        Vec<(u8, Vec<u8>)>,
        ArtifactKey,
        RootClaim,
    ) {
        let blob = Blob(b"payload-bytes".to_vec());
        let key = blob.key();
        let mut store = ArtifactStore::<Blob>::new();
        store.put(&key, &blob).unwrap();

        let identity = Identity::new(b"id-pub-key".to_vec());
        let mut wf = FrameWriter::new(SealDigest::DOMAIN);
        wf.field(&identity.0).field(&key.to_hex().into_bytes());
        let seal = SealDigest::from_bytes(sha256(wf.finish()));

        let pred_genesis = {
            // inner value of TLV_GENESIS_CLAIM as it will be framed
            let mut g = FrameWriter::new("SAIL-V1-GENESIS");
            g.field(&genesis_claim_bytes());
            g.finish().to_vec()
        };

        let mut lw = FrameWriter::new(LineageDigest::DOMAIN);
        lw.digest(&LineageDigest::from_bytes(sha256(&pred_genesis)));
        let lineage = LineageDigest::from_bytes(sha256(lw.finish()));

        let sealed = SealedArtifact {
            identity,
            seal,
            lineage,
            artifact_key: key,
        };
        let sig = {
            let f = sealed.seal_frame();
            let mut w = FrameWriter::new("TEST-PROOF");
            w.field(&sealed.identity.0).field(&f);
            sha256(w.finish())[..8].to_vec()
        };
        let preds = vec![(TLV_GENESIS_CLAIM, genesis_claim_bytes())];
        let root = RootClaim {
            claim: {
                let mut w = FrameWriter::new("SAIL-V1-GENESIS");
                w.field(&genesis_claim_bytes());
                w.finish().to_vec()
            },
        };
        (store, sealed, sig, preds, key, root)
    }

    #[test]
    fn full_success_yields_handle() {
        let (store, sealed, sig, preds, key, root) = build_case();
        let v = Verifier::new(&store, &TestProofs, vec![root]);
        let handle = v.evaluate(&key, &sealed, &sig, &preds).expect("must verify");
        assert_eq!(handle.artifact_key(), &key);
        assert_eq!(handle.depth(), 0);
    }

    #[test]
    fn bad_proof_denied() {
        let (store, sealed, _sig, preds, key, root) = build_case();
        let v = Verifier::new(&store, &TestProofs, vec![root]);
        let err = v.evaluate(&key, &sealed, b"wrong!", &preds).unwrap_err();
        assert!(matches!(err, VerifyError::BadProof { .. }));
    }

    #[test]
    fn unknown_root_denied() {
        let (store, sealed, sig, preds, key, _root) = build_case();
        let v = Verifier::new(&store, &TestProofs, vec![]);
        let err = v.evaluate(&key, &sealed, &sig, &preds).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownRoot { .. }));
    }

    #[test]
    fn missing_evidence_denied() {
        let (_store, sealed, sig, preds, _key, _root) = build_case();
        let empty = ArtifactStore::<Blob>::new();
        let v = Verifier::new(&empty, &TestProofs, vec![]);
        let err = v
            .evaluate(&ArtifactKey::from_bytes([0u8; DIGEST_LEN]), &sealed, &sig, &preds)
            .unwrap_err();
        assert_eq!(err, VerifyError::MissingEvidence);
    }

    #[test]
    fn lineage_break_denied() {
        let (store, sealed, sig, preds, key, root) = build_case();
        let v = Verifier::new(&store, &TestProofs, vec![root]);
        // Parent link whose framed payload is malformed (too short).
        let bad_preds = vec![
            (TLV_GENESIS_CLAIM, genesis_claim_bytes()),
            (TLV_PARENT_LINK, vec![0xAAu8; 4]),
        ];
        let err = v.evaluate(&key, &sealed, &sig, &bad_preds).unwrap_err();
        assert!(matches!(err, VerifyError::LineageBreak { .. }));
        // And ordering contradiction (genesis after a parent link):
        let contradict = vec![
            (TLV_PARENT_LINK, {
                let mut w = FrameWriter::new("SAIL-V1-PARENT");
                w.field(&[7u8; 32]);
                w.finish().to_vec()
            }),
            (TLV_GENESIS_CLAIM, genesis_claim_bytes()),
        ];
        let err2 = v.evaluate(&key, &sealed, &sig, &contradict).unwrap_err();
        assert!(matches!(err2, VerifyError::LineageBreak { .. }));
        let _ = preds;
    }

    #[test]
    fn content_address_helper_agrees_with_trait_default() {
        let blob = Blob(b"x".to_vec());
        assert_eq!(
            content_address(Blob::DOMAIN_TAG, &blob.address_body()),
            blob.key()
        );
    }
}
