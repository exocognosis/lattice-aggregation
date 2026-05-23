#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Research-grade threshold ML-DSA-65 API boundary.
//!
//! This crate exposes protocol state, transcript, validation, and backend traits
//! for threshold ML-DSA-65 experiments. The default backend is a deterministic
//! simulation backend and does not produce real ML-DSA signatures.

pub mod adapter;
pub mod aggregation;
pub mod backend;
pub mod collections;
pub mod crypto;
pub mod dkg;
pub mod errors;
pub mod low_level;
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
#[cfg(feature = "hazmat-real-mldsa")]
pub use low_level::mldsa65;
pub use low_level::poly::{Poly, N, Q};
pub use protocol::{state, SigningSession, ThresholdSigner};
pub use transcript::{SigningTranscript, ThresholdSigningTranscript};
pub use types::{
    Challenge, Commitment, PartialSignatureShare, PrivateKeyShare, SessionId, ThresholdPublicKey,
    ThresholdSignature, ValidatorId, COMMITMENT_BYTES, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES, POLY_SEED_BYTES, SESSION_ID_BYTES,
};
