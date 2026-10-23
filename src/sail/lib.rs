//! S.A.I.L. Architecture Stack — Rust crate root.
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │ Layer 3  verifier.rs        semantic judgment / authority     │
//! ├───────────────────────────────────────────────────────────────┤
//! │ Layer 2  artifact_store.rs  content-addressed evidence vault  │
//! ├───────────────────────────────────────────────────────────────┤
//! │ Layer 1  codec.rs           deterministic SAIL-V1-* framing   │
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! Core invariants enforced by this stack:
//!
//! * **Zero-ambiguity hashing** — every domain-separated hash is computed
//!   over `len || tag || len || field…` u64 big-endian length-prefixed
//!   frames (see [`codec`]), eliminating stream realignment, NUL-padding
//!   vulnerabilities, and variable-length injection attacks.
//! * **Compile-time domain safety** — [`codec::LineageDigest`],
//!   [`codec::SealDigest`] and [`codec::ArtifactKey`] are distinct newtypes;
//!   cross-domain confusion does not compile.
//! * **Strict side-channel defense** — all cryptographic comparison paths
//!   route through [`codec::constant_time_eq`].
//! * **Decoupled evidence & authority** — [`artifact_store`] only holds
//!   bytes; [`verifier`] alone confers authority, and only upon absolute
//!   success.

pub mod artifact_store;
pub mod codec;
pub mod verifier;
