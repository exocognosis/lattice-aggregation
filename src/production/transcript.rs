//! Production coordinator transcript binding.

use std::collections::BTreeMap;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{ThresholdError, ThresholdPublicKey, ValidatorId};

use super::types::{
    ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
    ProtocolProfile, ValidatorSetDigest,
};

/// Digest of a production commitment statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CommitmentDigest(pub [u8; 32]);

/// Fully bound production transcript input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionTranscriptInput {
    /// Protocol session ID.
    pub session_id: crate::SessionId,
    /// Validator/key epoch.
    pub epoch: EpochId,
    /// Threshold key ID.
    pub key_id: KeyId,
    /// Digest of canonical validator set.
    pub validator_set_digest: ValidatorSetDigest,
    /// DKG transcript or external share ceremony digest.
    pub dkg_transcript_digest: DkgTranscriptDigest,
    /// Active signer set for this attempt.
    pub active_signers: ActiveSignerSet,
    /// Signing threshold.
    pub threshold: u16,
    /// Threshold public key.
    pub public_key: ThresholdPublicKey,
    /// Original application message bytes supplied to standard ML-DSA verification.
    pub application_message: Vec<u8>,
    /// Transcript-internal ML-DSA message binding, such as `mu`.
    pub message_binding: MessageBinding,
    /// Single-use attempt ID.
    pub attempt_id: AttemptId,
    /// Digest of coordinator attestation quote.
    pub coordinator_attestation_digest: [u8; 32],
    /// Retry counter for this session.
    pub retry_counter: u32,
    /// Commitment digests by validator.
    pub commitment_digests: Vec<(ValidatorId, CommitmentDigest)>,
}

/// Bound production signing transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionSigningTranscript {
    input: ProductionTranscriptInput,
    challenge_digest: [u8; 32],
}

impl ProductionSigningTranscript {
    /// Construct a production transcript and derive its challenge digest.
    pub fn new(mut input: ProductionTranscriptInput) -> Result<Self, ThresholdError> {
        if input.threshold == 0 || input.threshold as usize > input.active_signers.len() {
            return Err(ThresholdError::InvalidThresholdParameters {
                threshold: input.threshold,
                total_nodes: input.active_signers.len() as u16,
            });
        }

        let mut commitments = BTreeMap::new();
        for (validator, digest) in input.commitment_digests.drain(..) {
            if !input.active_signers.as_slice().contains(&validator) {
                return Err(ThresholdError::TranscriptMismatch);
            }
            if commitments.insert(validator, digest).is_some() {
                return Err(ThresholdError::DuplicateValidator { validator });
            }
        }

        if commitments.len() < input.threshold as usize {
            return Err(ThresholdError::InsufficientCommitments {
                required: input.threshold,
                received: commitments.len(),
            });
        }

        input.commitment_digests = commitments.into_iter().collect();
        let challenge_digest = derive_challenge_digest(&input);
        Ok(Self {
            input,
            challenge_digest,
        })
    }

    /// Return the derived challenge digest.
    pub fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }

    /// Borrow transcript input.
    pub fn input(&self) -> &ProductionTranscriptInput {
        &self.input
    }
}

fn derive_challenge_digest(input: &ProductionTranscriptInput) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(ProtocolProfile::coordinator_assisted_v1().as_bytes());
    hasher.update(&1u16.to_be_bytes());
    hasher.update(&input.session_id);
    hasher.update(&input.epoch.to_be_bytes());
    hasher.update(input.key_id.as_bytes());
    hasher.update(input.validator_set_digest.as_bytes());
    hasher.update(input.dkg_transcript_digest.as_bytes());
    hasher.update(&(input.active_signers.len() as u16).to_be_bytes());
    for validator in input.active_signers.as_slice() {
        hasher.update(&validator.0.to_be_bytes());
    }
    hasher.update(&input.threshold.to_be_bytes());
    hasher.update(&input.public_key.0);
    hasher.update(&(input.application_message.len() as u64).to_be_bytes());
    hasher.update(&input.application_message);
    hasher.update(input.message_binding.as_bytes());
    hasher.update(input.attempt_id.as_bytes());
    hasher.update(&input.coordinator_attestation_digest);
    hasher.update(&input.retry_counter.to_be_bytes());
    hasher.update(&(input.commitment_digests.len() as u16).to_be_bytes());
    for (validator, digest) in &input.commitment_digests {
        hasher.update(&validator.0.to_be_bytes());
        hasher.update(&digest.0);
    }

    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}
