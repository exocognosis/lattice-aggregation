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

pub use aggregation::{aggregate_with_backend, SignatureAggregator, SimulatedAggregator};
pub use backend::no_reconstruction::{
    derive_committee8_fips_public_key_from_t_shares, Committee8FipsKeygenCapabilities,
    Committee8Session, DkgReady as Committee8DkgReady, NoReconstructionCapabilities,
    NoReconstructionError, NoReconstructionPrimitive, NonceCommitted as Committee8NonceCommitted,
    NonceReady as Committee8NonceReady, Uninitialized as Committee8Uninitialized,
    COMMITTEE8_MIN_DKG_DEALERS, COMMITTEE8_SIZE, COMMITTEE8_THRESHOLD,
};
#[cfg(feature = "raw-real-mldsa")]
pub use backend::{
    aggregate_algebraic_partials, aggregate_module_partials, challenge_scalar_from_digest,
    compute_z, emit_algebraic_partial_zi, emit_module_partial_zi, expand_s1_research,
    expand_y_research, keygen_from_seed, module_partial_round_trip, pack_z_encoding,
    sample_in_ball, self_contained_sign_with_module_z_shares, sign_internal_empty_ctx,
    sign_with_module_partial_z_evidence, split_module_vector_shamir, split_secret_poly_shamir,
    strict_distributed_sign_from_s1_y_partials, unpack_z_from_signature, AggregateWithRejection,
    AlgebraicAggregateZ, AlgebraicPartialStatus, AlgebraicPartialZi, BlockerStatus,
    ExpandedSecret65, FipsWireModulePartialPackage, FipsWireStatus, KeyDkgOutput, ModuleAggregateZ,
    ModulePartialZi, ModuleVecL, NonceDkgAttempt, PartialZiContribution, RealAggregator,
    RealCommitmentSecret, RealMldsa65Backend, RealMldsaConstruction, SelfContainedFipsStatus,
    SelfContainedSignPackage, StrictDistributedSignPackage, ThresholdAttemptPartials,
    ThresholdMldsaEngine, BETA, C_TILDE_BYTES, GAMMA1, H_ENCODED_BYTES, KEY_VSS_DOMAIN, MODULE_L,
    NONCE_DKG_DOMAIN, PARTIAL_ZI_DOMAIN, SEED_SHARE_DOMAIN_DEFAULT, TAU, Z_BOUND, Z_ENCODED_BYTES,
};
pub use backend::{Mldsa65Backend, SimulatedBackend};
pub use collections::{CommitmentSet, PartialShareSet, ValidatedDkgShares};
pub use dkg::{SimulatedDkg, ThresholdKeyGeneration};
pub use errors::ThresholdError;
pub use low_level::poly::{Poly, N, Q};
pub use protocol::{state, SessionBackend, SigningSession, ThresholdSigner};
pub use transcript::{SigningTranscript, ThresholdSigningTranscript};
pub use types::{
    Challenge, Commitment, PartialSignatureShare, PrivateKeyShare, SessionId, ThresholdPublicKey,
    ThresholdSignature, ValidatorId, COMMITMENT_BYTES, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES, POLY_SEED_BYTES, SESSION_ID_BYTES,
};
