//! S.A.I.L. Layer 1 — Serialization: deterministic wire formatting &
//! structural parsing (`SAIL-V1-*`).
//!
//! # Framing discipline
//!
//! Every domain-separated hash in this stack is computed over an explicit
//! **u64 big-endian length-prefixed frame**:
//!
//! ```text
//! len(tag) || tag || len(field_1) || field_1 || ... || len(field_n) || field_n
//! ```
//!
//! This "zero-ambiguity" framing eliminates the three classic digest
//! malleability classes:
//!
//! * **Stream realignment** — concatenating variable-length fields without
//!   lengths lets an attacker shift the boundary between two fields and land
//!   on the same byte stream. Length prefixes pin every field boundary.
//! * **NUL-padding attacks** — trailing/embedded zero bytes can no longer be
//!   smuggled into a field, because the declared length must match exactly.
//! * **Variable-length injection** — a field cannot impersonate the following
//!   field (or the domain tag), because each segment is consumed strictly by
//!   its declared length.
//!
//! The same framing is used for the inner **TLV predecessors** of composite
//! structures: each predecessor contributes `len(tlv) || tlv` to the parent
//! digest, where `tlv = type(1) || u64-len(value) || value`.
//!
//! # Typed digests
//!
//! [`LineageDigest`], [`SealDigest`] and [`ArtifactKey`] are strongly-typed
//! newtypes so cross-domain confusion (e.g. passing a receipt digest where a
//! lineage digest is required) is caught at compile time. All three compare
//! with **constant-time equality** and serde as strict lowercase hex strings.

use std::fmt;

use serde::de::{Error as DeError, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Version tag prefix for every framed structure produced by this codec.
pub const SAIL_V1_PREFIX: &str = "SAIL-V1";

/// Size of the SHA-256 digests carried by the typed newtypes below.
pub const DIGEST_LEN: usize = 32;

// ── Constant-time equality ──────────────────────────────────────────

/// Timing-safe comparison of two byte slices.
///
/// Runs in time independent of the position of the first differing byte:
/// every byte pair is always examined. A length mismatch short-circuits,
/// which is safe here because all typed consumers have fixed widths known to
/// the public anyway.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// ── Big-endian length-prefixed framing ──────────────────────────────

/// Append `len(segment)` (u64 BE) followed by the segment itself.
#[inline]
pub fn put_length_prefixed(dst: &mut Vec<u8>, segment: &[u8]) {
    dst.extend_from_slice(&(segment.len() as u64).to_be_bytes());
    dst.extend_from_slice(segment);
}

/// Build the canonical `len(tag) || tag` domain-separation header.
pub fn domain_frame(tag: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + tag.len());
    put_length_prefixed(&mut out, tag.as_bytes());
    out
}

/// Encode one inner TLV predecessor: `type(1) || u64be-len(value) || value`.
pub fn tlv_predecessor(tag_type: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + value.len());
    out.push(tag_type);
    put_length_prefixed(&mut out, value);
    out
}

/// Streaming frame builder for `len || tag || (len || field)*` frames.
#[derive(Debug, Clone)]
pub struct FrameWriter {
    buf: Vec<u8>,
}

impl FrameWriter {
    /// Start a frame with the given domain tag (e.g. `"SAIL-V1-LINEAGE"`).
    pub fn new(tag: &str) -> Self {
        Self {
            buf: domain_frame(tag),
        }
    }

    /// Append one length-prefixed field to the frame.
    pub fn field(&mut self, bytes: &[u8]) -> &mut Self {
        put_length_prefixed(&mut self.buf, bytes);
        self
    }

    /// Append a typed digest's raw bytes as one field.
    pub fn digest<D: DigestBytes>(&mut self, d: &D) -> &mut Self {
        self.field(d.as_digest_bytes())
    }

    /// Append an inner TLV predecessor, itself length-prefixed, so that
    /// predecessor streams can never realign against sibling fields.
    pub fn predecessor(&mut self, tag_type: u8, value: &[u8]) -> &mut Self {
        let tlv = tlv_predecessor(tag_type, value);
        self.field(&tlv)
    }

    /// The finished canonical frame bytes.
    pub fn finish(&self) -> &[u8] {
        &self.buf
    }
}

/// Strict parser for length-prefixed frames (used to re-validate received
/// wire bytes before any semantic evaluation happens in `verifier.rs`).
#[derive(Debug, Clone)]
pub struct FrameReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Frame ended while a length prefix or field body was expected.
    Truncated,
    /// A declared length exceeded the remaining frame bytes.
    LengthOverflow,
    /// Trailing bytes remain after the expected field count was consumed.
    TrailingBytes,
    /// The leading domain tag did not match the expected `SAIL-V1-*` tag.
    DomainMismatch { expected: String, found: String },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Truncated => write!(f, "SAIL_CODEC_ERR_TRUNCATED"),
            CodecError::LengthOverflow => write!(f, "SAIL_CODEC_ERR_LENGTH_OVERFLOW"),
            CodecError::TrailingBytes => write!(f, "SAIL_CODEC_ERR_TRAILING_BYTES"),
            CodecError::DomainMismatch { expected, found } => {
                write!(f, "SAIL_CODEC_ERR_DOMAIN_MISMATCH({expected}!={found})")
            }
        }
    }
}

impl std::error::Error for CodecError {}

impl<'a> FrameReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Read the next `u64` big-endian length prefix.
    fn read_u64(&mut self) -> Result<u64, CodecError> {
        let end = self.pos.checked_add(8).ok_or(CodecError::Truncated)?;
        let raw: [u8; 8] = self
            .buf
            .get(self.pos..end)
            .ok_or(CodecError::Truncated)?
            .try_into()
            .map_err(|_| CodecError::Truncated)?;
        self.pos = end;
        Ok(u64::from_be_bytes(raw))
    }

    /// Read one length-prefixed segment.
    pub fn segment(&mut self) -> Result<&'a [u8], CodecError> {
        let len = self.read_u64()? as usize;
        let end = self.pos.checked_add(len).ok_or(CodecError::LengthOverflow)?;
        let seg = self.buf.get(self.pos..end).ok_or(CodecError::Truncated)?;
        self.pos = end;
        Ok(seg)
    }

    /// Consume and validate the leading domain tag.
    pub fn expect_domain(&mut self, expected_tag: &str) -> Result<(), CodecError> {
        let got = self.segment()?;
        if constant_time_eq(got, expected_tag.as_bytes()) {
            Ok(())
        } else {
            Err(CodecError::DomainMismatch {
                expected: expected_tag.to_string(),
                found: String::from_utf8_lossy(got).into_owned(),
            })
        }
    }

    /// Parse exactly `n` fields, then require the frame to be exhausted.
    pub fn fields<const N: usize>(&mut self) -> Result<[&'a [u8]; N], CodecError> {
        let mut out: [&[u8]; N] = [&[]; N];
        for slot in out.iter_mut() {
            *slot = self.segment()?;
        }
        self.expect_end()?;
        Ok(out)
    }

    pub fn expect_end(&mut self) -> Result<(), CodecError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

// ── Hex helpers (strict lowercase) ──────────────────────────────────

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode *strict* lowercase hex: even length, `[0-9a-f]` only. Uppercase or
/// mixed-case input is rejected — canonical form is canonical form.
fn from_hex_strict(s: &str) -> Option<Vec<u8>> {
    let src = s.as_bytes();
    if src.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(src.len() / 2);
    for pair in src.chunks(2) {
        // Strict lowercase hex: digits `0-9` are valid, but uppercase `A-F`
        // must be rejected. `is_ascii_lowercase()` alone would wrongly reject
        // every numeric nibble, so gate on hexdigit-ness first and then reject
        // only ASCII uppercase letters.
        if !pair[0].is_ascii_hexdigit() || !pair[1].is_ascii_hexdigit() {
            return None;
        }
        if pair[0].is_ascii_uppercase() || pair[1].is_ascii_uppercase() {
            return None;
        }
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

// ── Typed digest newtypes ───────────────────────────────────────────

/// Shared accessor so generic frame code can consume any typed digest.
pub trait DigestBytes {
    fn as_digest_bytes(&self) -> &[u8; DIGEST_LEN];
}

macro_rules! digest_newtype {
    ($(#[$doc:meta])* $name:ident, $domain:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Eq)]
        pub struct $name([u8; DIGEST_LEN]);

        impl $name {
            /// Domain tag this newtype is bound to (compile-time pairing of
            /// type ↔ `SAIL-V1-*` namespace).
            pub const DOMAIN: &'static str = $domain;

            /// Construct from raw digest bytes.
            pub fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
                Self(bytes)
            }

            /// Raw canonical digest bytes.
            pub fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
                &self.0
            }

            /// Lowercase-hex rendering (canonical serde form).
            pub fn to_hex(&self) -> String {
                to_hex(&self.0)
            }

            /// Parse a strict lowercase hex string of exact digest width.
            pub fn from_hex(s: &str) -> Option<Self> {
                let raw = from_hex_strict(s)?;
                <[u8; DIGEST_LEN]>::try_from(raw).ok().map(Self)
            }

            /// Constant-time equality — see [`constant_time_eq`].
            #[inline]
            pub fn ct_eq(&self, other: &Self) -> bool {
                constant_time_eq(&self.0, &other.0)
            }
        }

        impl DigestBytes for $name {
            #[inline]
            fn as_digest_bytes(&self) -> &[u8; DIGEST_LEN] {
                &self.0
            }
        }

        // Manual `PartialEq` routed through the constant-time path so *every*
        // equality check on this type (tests, dedup, lookups) resists timing
        // analysis.
        impl PartialEq for $name {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other)
            }
        }

        impl std::hash::Hash for $name {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                state.write(&self.0);
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                write!(f, $domain)?;
                write!(f, ") ")?;
                let hex = self.to_hex();
                write!(f, "{}…", &hex[..16.min(hex.len())])
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> Visitor<'de> for V {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        write!(
                            f,
                            "a strict lowercase {}-char hex {}",
                            DIGEST_LEN * 2,
                            stringify!($name)
                        )
                    }
                    fn visit_str<E: DeError>(self, v: &str) -> Result<$name, E> {
                        $name::from_hex(v)
                            .ok_or_else(|| E::invalid_value(Unexpected::Str(v), &self))
                    }
                }
                d.deserialize_str(V)
            }
        }
    };
}

digest_newtype!(
    /// Commitment over an artifact's ancestry chain (`SAIL-V1-LINEAGE`).
    LineageDigest,
    "SAIL-V1-LINEAGE"
);

digest_newtype!(
    /// Commitment over a sealing signature envelope (`SAIL-V1-SEAL`).
    SealDigest,
    "SAIL-V1-SEAL"
);

digest_newtype!(
    /// Content-address key of a stored artifact (`SAIL-V1-KEY`).
    ArtifactKey,
    "SAIL-V1-KEY"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_is_realignment_proof() {
        // ("ab", "c") and ("a", "bc") MUST produce different frames.
        let mut w1 = FrameWriter::new("SAIL-V1-TEST");
        w1.field(b"ab").field(b"c");
        let mut w2 = FrameWriter::new("SAIL-V1-TEST");
        w2.field(b"a").field(b"bc");
        assert_ne!(w1.finish(), w2.finish());
    }

    #[test]
    fn nul_padding_changes_the_frame() {
        let mut w1 = FrameWriter::new("SAIL-V1-TEST");
        w1.field(b"x");
        let mut w2 = FrameWriter::new("SAIL-V1-TEST");
        w2.field(b"x\0");
        assert_ne!(w1.finish(), w2.finish());
    }

    #[test]
    fn roundtrip_parse() {
        let mut w = FrameWriter::new("SAIL-V1-TEST");
        w.field(b"one").field(b"two").predecessor(0x01, b"pred");
        let bytes = w.finish().to_vec();
        let mut r = FrameReader::new(&bytes);
        r.expect_domain("SAIL-V1-TEST").unwrap();
        let [a, b, c] = r.fields::<3>().unwrap();
        assert_eq!(a, b"one");
        assert_eq!(b, b"two");
        assert_eq!(c, &tlv_predecessor(0x01, b"pred")[..]);
    }

    #[test]
    fn domain_mismatch_rejected() {
        let mut w = FrameWriter::new("SAIL-V1-LINEAGE");
        w.field(b"x");
        let bytes = w.finish().to_vec();
        let mut r = FrameReader::new(&bytes);
        let err = r.expect_domain("SAIL-V1-SEAL").unwrap_err();
        assert!(matches!(err, CodecError::DomainMismatch { .. }));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut w = FrameWriter::new("SAIL-V1-TEST");
        w.field(b"a");
        let mut bytes = w.finish().to_vec();
        bytes.push(0);
        let mut r = FrameReader::new(&bytes);
        r.expect_domain("SAIL-V1-TEST").unwrap();
        let _f = r.segment().unwrap();
        assert_eq!(r.expect_end(), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn newtypes_are_cross_domain_safe_by_construction() {
        let lineage = LineageDigest::from_bytes([7u8; DIGEST_LEN]);
        let seal = SealDigest::from_bytes([7u8; DIGEST_LEN]);
        // The two share raw bytes but are distinct types — `lineage == seal`
        // does not compile. Only `.ct_eq` within a domain is legal.
        assert!(lineage.ct_eq(&LineageDigest::from_bytes([7u8; DIGEST_LEN])));
        let _ = seal;
    }

    #[test]
    fn hex_serde_roundtrip_and_strictness() {
        let k = ArtifactKey::from_bytes([0xab; DIGEST_LEN]);
        assert_eq!(k.to_hex(), "ab".repeat(32));
        assert_eq!(ArtifactKey::from_hex(&k.to_hex()).unwrap(), k);
        // Numeric nibbles (`0`-`9`) are valid strict-lowercase hex and must
        // decode — regression guard against rejecting decimal digits.
        let d = ArtifactKey::from_bytes([0x01, 0x9f, 0x2a, 0x77, 0x88, 0x64, 0x55, 0x10,
                                         0x00, 0x99, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                         0x77, 0x88, 0x99, 0x00, 0x1a, 0x2b, 0x3c, 0x4d,
                                         0x5e, 0x6f, 0x07, 0x08, 0x09, 0x0f, 0x0e, 0x0d]);
        assert_eq!(ArtifactKey::from_hex(&d.to_hex()).unwrap(), d);
        // Uppercase / odd-length hex must be rejected.
        assert!(ArtifactKey::from_hex(&k.to_hex().to_uppercase()).is_none());
        assert!(ArtifactKey::from_hex("abc").is_none());
        assert!(ArtifactKey::from_hex(&format!("{}A", "ab".repeat(31) + "a")).is_none());
    }
}
