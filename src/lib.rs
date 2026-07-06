#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Audit-oriented threshold ML-DSA-65 API boundary.
//!
//! This crate exposes protocol state, transcript, validation, and backend traits
//! for threshold ML-DSA-65 experiments. Simulation and raw provider surfaces are
//! explicit non-production paths; the P1 nonce-producer handoff profile expects
//! reviewed external capture material before promotion.

pub mod adapter;
pub mod aggregation;
pub mod backend;
pub mod collections;
pub mod crypto;
pub mod dkg;
pub mod errors;
pub mod low_level;
#[cfg(any(feature = "coordinator-assisted", feature = "raw-real-mldsa"))]
pub mod production;
pub mod protocol;
pub mod serialization;
pub mod transcript;
pub mod types;
pub mod utils;

pub use aggregation::{SignatureAggregator, SimulatedAggregator};
pub use backend::{Mldsa65Backend, SimulatedBackend};
pub use collections::{CommitmentSet, PartialShareSet, ValidatedDkgShares};
pub use dkg::{SimulatedDkg, ThresholdKeyGeneration};
pub use errors::ThresholdError;
pub use low_level::poly::{Poly, N, Q};
pub use protocol::{state, SigningSession, ThresholdSigner};
pub use transcript::{SigningTranscript, ThresholdSigningTranscript};
pub use types::{
    Challenge, Commitment, PartialSignatureShare, PrivateKeyShare, SessionId, ThresholdPublicKey,
    ThresholdSignature, ValidatorId, COMMITMENT_BYTES, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES, POLY_SEED_BYTES, SESSION_ID_BYTES,
};
