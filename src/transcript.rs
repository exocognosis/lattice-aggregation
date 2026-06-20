//! Canonical transcript construction for threshold signing.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    collections::{set_from_validators, CommitmentSet},
    errors::ThresholdError,
    types::{Challenge, SessionId, ThresholdPublicKey, ValidatorId},
};

const PROTOCOL_LABEL: &[u8] = b"lattice-aggregation/threshold-mldsa65";
const PROTOCOL_VERSION: u16 = 1;

/// Fully bound signing transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningTranscript {
    session_id: SessionId,
    threshold: u16,
    validator_set: Vec<ValidatorId>,
    public_key: ThresholdPublicKey,
    message: Vec<u8>,
    commitments: CommitmentSet,
    challenge: Challenge,
}

/// Aggregator-facing transcript alias.
pub type ThresholdSigningTranscript = SigningTranscript;

impl SigningTranscript {
    /// Construct a canonical transcript and derive its challenge.
    pub fn new(
        session_id: SessionId,
        threshold: u16,
        mut validator_set: Vec<ValidatorId>,
        public_key: ThresholdPublicKey,
        message: &[u8],
        commitments: CommitmentSet,
    ) -> Result<Self, ThresholdError> {
        let canonical_validator_set = set_from_validators(validator_set)?;

        if commitments.threshold() != threshold {
            return Err(ThresholdError::TranscriptMismatch);
        }
        if commitments.validators() != &canonical_validator_set {
            return Err(ThresholdError::TranscriptMismatch);
        }

        validator_set = canonical_validator_set.into_iter().collect();

        let challenge = derive_challenge(
            session_id,
            threshold,
            &validator_set,
            &public_key,
            message,
            &commitments,
        );

        Ok(Self {
            session_id,
            threshold,
            validator_set,
            public_key,
            message: message.to_vec(),
            commitments,
            challenge,
        })
    }

    /// Return the derived challenge.
    pub fn challenge(&self) -> Challenge {
        self.challenge
    }

    /// Return the threshold bound into the transcript.
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Return the message bound into the transcript.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Return the public key bound into the transcript.
    pub fn public_key(&self) -> &ThresholdPublicKey {
        &self.public_key
    }

    /// Return the validator set bound into the transcript.
    pub fn validator_set(&self) -> &[ValidatorId] {
        &self.validator_set
    }
}

fn derive_challenge(
    session_id: SessionId,
    threshold: u16,
    validator_set: &[ValidatorId],
    public_key: &ThresholdPublicKey,
    message: &[u8],
    commitments: &CommitmentSet,
) -> Challenge {
    let mut hasher = Shake256::default();
    hasher.update(PROTOCOL_LABEL);
    hasher.update(&PROTOCOL_VERSION.to_be_bytes());
    hasher.update(&session_id);
    hasher.update(&threshold.to_be_bytes());
    hasher.update(&(validator_set.len() as u16).to_be_bytes());
    for id in validator_set {
        hasher.update(&id.0.to_be_bytes());
    }
    hasher.update(&public_key.0);
    hasher.update(&(message.len() as u64).to_be_bytes());
    hasher.update(message);
    hasher.update(&(commitments.len() as u16).to_be_bytes());
    for (id, commitment) in commitments.iter() {
        hasher.update(&id.0.to_be_bytes());
        hasher.update(&commitment.0);
    }

    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    Challenge(out)
}
