//! Error types for threshold protocol validation.

use crate::types::ValidatorId;

/// Errors surfaced by the threshold ML-DSA API boundary.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum ThresholdError {
    /// Threshold or validator-set parameters are invalid.
    #[error("invalid threshold parameters: threshold={threshold}, total_nodes={total_nodes}")]
    InvalidThresholdParameters {
        /// Requested signing threshold.
        threshold: u16,
        /// Configured validator count.
        total_nodes: u16,
    },

    /// Validator ID is not in the configured validator set.
    #[error("unknown {validator}")]
    UnknownValidator {
        /// Validator that is not present in the configured set.
        validator: ValidatorId,
    },

    /// Validator ID appeared more than once.
    #[error("duplicate {validator}")]
    DuplicateValidator {
        /// Validator that appeared more than once.
        validator: ValidatorId,
    },

    /// Too few commitments were supplied.
    #[error("insufficient commitments: required {required}, received {received}")]
    InsufficientCommitments {
        /// Minimum number of commitments required.
        required: u16,
        /// Number of commitments received.
        received: usize,
    },

    /// Too few partial shares were supplied.
    #[error("insufficient partial shares: required {required}, received {received}")]
    InsufficientPartialShares {
        /// Minimum number of partial shares required.
        required: u16,
        /// Number of partial shares received.
        received: usize,
    },

    /// Commitment validation failed for an attributable validator.
    #[error("commitment verification failed for {validator}")]
    CommitmentVerificationFailed {
        /// Validator whose commitment failed verification.
        validator: ValidatorId,
    },

    /// Partial share validation failed for an attributable validator.
    #[error("partial share verification failed for {validator}")]
    PartialShareVerificationFailed {
        /// Validator whose partial share failed verification.
        validator: ValidatorId,
    },

    /// Local or aggregate rejection sampling checks failed.
    #[error("rejection sampling failed for {validator}")]
    RejectionSamplingFailed {
        /// Validator associated with the rejection sampling failure.
        validator: ValidatorId,
    },

    /// Transcript input does not match the current protocol session.
    #[error("transcript mismatch")]
    TranscriptMismatch,

    /// Versioned wire bytes could not be decoded.
    #[error("malformed serialization: {reason}")]
    MalformedSerialization {
        /// Static reason for the serialization failure.
        reason: &'static str,
    },

    /// Requested backend is not enabled or is blocked by safety gates.
    #[error("backend unavailable: {reason}")]
    BackendUnavailable {
        /// Static reason the backend is unavailable.
        reason: &'static str,
    },

    /// Production profile is blocked by policy gates.
    #[error("production policy blocked: {reason}")]
    ProductionPolicyBlocked {
        /// Static reason the policy gate blocked the operation.
        reason: &'static str,
    },

    /// Coordinator attestation failed.
    #[error("coordinator attestation failed: {reason}")]
    CoordinatorAttestationFailed {
        /// Static reason the attestation was rejected.
        reason: &'static str,
    },

    /// Preprocessed attempt was stale, reused, or unknown.
    #[error("invalid preprocessed attempt: {reason}")]
    InvalidPreprocessedAttempt {
        /// Static reason the attempt was rejected.
        reason: &'static str,
    },

    /// Standard ML-DSA verification rejected the signature.
    #[error("standard ML-DSA verification failed")]
    StandardVerificationFailed,
}
