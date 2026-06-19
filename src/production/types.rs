//! Typed production profile context wrappers.

use crate::{collections::set_from_validators, ThresholdError, ValidatorId};

/// Coordinator-assisted profile identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProtocolProfile(&'static [u8]);

impl ProtocolProfile {
    /// Profile label for the first coordinator-assisted ML-DSA-65 profile.
    pub fn coordinator_assisted_v1() -> Self {
        Self(b"mldsa65-coordinator-v1")
    }

    /// Return profile label bytes.
    pub fn as_bytes(&self) -> &'static [u8] {
        self.0
    }
}

/// Epoch identifier for a validator set and key epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EpochId(pub u64);

impl EpochId {
    /// Return big-endian bytes.
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// Threshold key identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct KeyId(pub [u8; 32]);

impl KeyId {
    /// Borrow the digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Single-use preprocessing attempt identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AttemptId(pub [u8; 32]);

impl AttemptId {
    /// Borrow the digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Digest of the canonical validator set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ValidatorSetDigest(pub [u8; 32]);

impl ValidatorSetDigest {
    /// Borrow the digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Digest of the DKG transcript or external share ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DkgTranscriptDigest(pub [u8; 32]);

impl DkgTranscriptDigest {
    /// Borrow the digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// ML-DSA message binding, such as `mu`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MessageBinding(pub [u8; 64]);

impl MessageBinding {
    /// Borrow the binding bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Canonical active signer set for one attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveSignerSet {
    validators: Vec<ValidatorId>,
}

impl ActiveSignerSet {
    /// Construct and canonicalize an active signer set.
    pub fn new(validators: Vec<ValidatorId>) -> Result<Self, ThresholdError> {
        let validators = set_from_validators(validators)?.into_iter().collect();
        Ok(Self { validators })
    }

    /// Borrow canonical validators.
    pub fn as_slice(&self) -> &[ValidatorId] {
        &self.validators
    }

    /// Number of active signers.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Return true when no active signers are present.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}
