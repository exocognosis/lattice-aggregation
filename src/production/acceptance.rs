//! Coordinator-assisted acceptance predicate conformance anchors.
//!
//! This module models digest-only evidence checks for future reviewed
//! LocalAccept and AggregateAccept predicates. It intentionally carries no raw
//! partial share bytes or secret signing material.

use std::collections::BTreeSet;

use sha3::{Digest, Sha3_256};

use crate::{ThresholdError, ThresholdSignature, ValidatorId};

use super::{
    provider::StandardMldsa65Provider,
    transcript::{CommitmentDigest, ProductionSigningTranscript},
};

/// Public digest evidence for a local accepted partial contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAcceptEvidence {
    /// Validator that produced the partial contribution.
    pub signer: ValidatorId,
    /// Commitment digest declared for the signer in the production transcript.
    pub commitment_digest: CommitmentDigest,
    /// Digest of the partial share, not the raw partial share bytes.
    pub partial_share_digest: [u8; 32],
    /// Digest of the local bounds proof, not the raw proof witness.
    pub local_bounds_proof_digest: [u8; 32],
}

/// Capability token proving a local partial contribution passed conformance checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedPartialContribution {
    signer: ValidatorId,
    commitment_digest: CommitmentDigest,
    challenge_digest: [u8; 32],
    partial_share_digest: [u8; 32],
    local_bounds_proof_digest: [u8; 32],
}

impl AcceptedPartialContribution {
    /// Return the accepted signer.
    pub const fn signer(self) -> ValidatorId {
        self.signer
    }

    /// Return the accepted commitment digest.
    pub const fn commitment_digest(self) -> CommitmentDigest {
        self.commitment_digest
    }

    /// Borrow the transcript challenge digest that minted this token.
    pub const fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }

    /// Borrow the accepted partial share digest.
    pub const fn partial_share_digest(&self) -> &[u8; 32] {
        &self.partial_share_digest
    }

    /// Borrow the accepted local bounds proof digest.
    pub const fn local_bounds_proof_digest(&self) -> &[u8; 32] {
        &self.local_bounds_proof_digest
    }
}

/// Local acceptance predicate scaffold.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalAccept;

impl LocalAccept {
    /// Accept digest-only local evidence after transcript membership checks pass.
    pub fn accept(
        transcript: &ProductionSigningTranscript,
        evidence: LocalAcceptEvidence,
    ) -> Result<AcceptedPartialContribution, ThresholdError> {
        let active_signers = transcript.input().active_signers.as_slice();
        if !active_signers.contains(&evidence.signer) {
            return Err(ThresholdError::UnknownValidator {
                validator: evidence.signer,
            });
        }

        let expected_commitment = transcript
            .input()
            .commitment_digests
            .iter()
            .find(|(validator, _)| *validator == evidence.signer)
            .map(|(_, digest)| *digest)
            .ok_or(ThresholdError::CommitmentVerificationFailed {
                validator: evidence.signer,
            })?;

        if expected_commitment != evidence.commitment_digest {
            return Err(ThresholdError::CommitmentVerificationFailed {
                validator: evidence.signer,
            });
        }

        if is_all_zero(&evidence.partial_share_digest) {
            return Err(ThresholdError::PartialShareVerificationFailed {
                validator: evidence.signer,
            });
        }

        if is_all_zero(&evidence.local_bounds_proof_digest) {
            return Err(ThresholdError::RejectionSamplingFailed {
                validator: evidence.signer,
            });
        }

        Ok(AcceptedPartialContribution {
            signer: evidence.signer,
            commitment_digest: evidence.commitment_digest,
            challenge_digest: *transcript.challenge_digest(),
            partial_share_digest: evidence.partial_share_digest,
            local_bounds_proof_digest: evidence.local_bounds_proof_digest,
        })
    }
}

/// Capability token proving standard ML-DSA verification passed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardVerifierEvidence {
    challenge_digest: [u8; 32],
    candidate_signature_digest: [u8; 32],
}

impl StandardVerifierEvidence {
    /// Verify a candidate signature using the transcript public key and original message.
    pub fn verify<P>(
        transcript: &ProductionSigningTranscript,
        candidate_signature: &ThresholdSignature,
    ) -> Result<Self, ThresholdError>
    where
        P: StandardMldsa65Provider,
    {
        let input = transcript.input();
        if !P::verify(
            &input.public_key,
            &input.application_message,
            candidate_signature,
        )? {
            return Err(ThresholdError::StandardVerificationFailed);
        }

        Ok(Self {
            challenge_digest: *transcript.challenge_digest(),
            candidate_signature_digest: digest_signature(candidate_signature),
        })
    }

    /// Borrow the verified transcript challenge digest.
    pub const fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }

    /// Borrow the verified candidate signature digest.
    pub const fn candidate_signature_digest(&self) -> &[u8; 32] {
        &self.candidate_signature_digest
    }
}

/// Public digest evidence for an aggregate accepted candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateAcceptEvidence {
    /// Digest of the aggregate response, not raw aggregate response bytes.
    pub aggregate_response_digest: [u8; 32],
    /// Digest of the hint-routing evidence.
    pub hint_digest: [u8; 32],
    /// Provider-minted standard ML-DSA verification token.
    pub standard_verifier: StandardVerifierEvidence,
}

/// Capability token proving an aggregate candidate passed conformance checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedAggregateCandidate {
    signers: Vec<ValidatorId>,
    aggregate_response_digest: [u8; 32],
    hint_digest: [u8; 32],
    challenge_digest: [u8; 32],
    candidate_signature_digest: [u8; 32],
}

/// Alias for callers that model the accepted aggregate as a contribution.
pub type AcceptedAggregateContribution = AcceptedAggregateCandidate;

impl AcceptedAggregateCandidate {
    /// Borrow the canonical accepted partial signer set.
    pub fn signers(&self) -> &[ValidatorId] {
        &self.signers
    }

    /// Borrow the accepted aggregate response digest.
    pub const fn aggregate_response_digest(&self) -> &[u8; 32] {
        &self.aggregate_response_digest
    }

    /// Borrow the accepted hint digest.
    pub const fn hint_digest(&self) -> &[u8; 32] {
        &self.hint_digest
    }

    /// Borrow the accepted challenge digest.
    pub const fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }

    /// Borrow the provider-verified candidate aggregate signature digest.
    pub const fn candidate_signature_digest(&self) -> &[u8; 32] {
        &self.candidate_signature_digest
    }
}

/// Aggregate acceptance predicate scaffold.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateAccept;

impl AggregateAccept {
    /// Accept digest-only aggregate evidence after threshold and transcript checks pass.
    pub fn accept(
        transcript: &ProductionSigningTranscript,
        partials: &[AcceptedPartialContribution],
        evidence: AggregateAcceptEvidence,
    ) -> Result<AcceptedAggregateCandidate, ThresholdError> {
        let threshold = transcript.input().threshold;
        if partials.len() < threshold as usize {
            return Err(ThresholdError::InsufficientPartialShares {
                required: threshold,
                received: partials.len(),
            });
        }

        let active_signers = transcript.input().active_signers.as_slice();
        let mut signers = BTreeSet::new();
        for partial in partials {
            let signer = partial.signer();
            if !signers.insert(signer) {
                return Err(ThresholdError::DuplicateValidator { validator: signer });
            }
            if !active_signers.contains(&signer) {
                return Err(ThresholdError::UnknownValidator { validator: signer });
            }

            let expected_commitment = transcript
                .input()
                .commitment_digests
                .iter()
                .find(|(validator, _)| *validator == signer)
                .map(|(_, digest)| *digest)
                .ok_or(ThresholdError::CommitmentVerificationFailed { validator: signer })?;
            if partial.commitment_digest() != expected_commitment {
                return Err(ThresholdError::CommitmentVerificationFailed { validator: signer });
            }

            if partial.challenge_digest() != transcript.challenge_digest() {
                return Err(ThresholdError::TranscriptMismatch);
            }
        }

        if is_all_zero(&evidence.aggregate_response_digest) {
            return Err(ThresholdError::MalformedSerialization {
                reason: "aggregate response digest is all zero",
            });
        }

        if is_all_zero(&evidence.hint_digest) {
            return Err(ThresholdError::InvalidHintRoute {
                reason: "hint digest is all zero",
            });
        }

        let challenge_digest = *evidence.standard_verifier.challenge_digest();
        if challenge_digest != *transcript.challenge_digest() {
            return Err(ThresholdError::TranscriptMismatch);
        }

        Ok(AcceptedAggregateCandidate {
            signers: signers.into_iter().collect(),
            aggregate_response_digest: evidence.aggregate_response_digest,
            hint_digest: evidence.hint_digest,
            challenge_digest,
            candidate_signature_digest: *evidence.standard_verifier.candidate_signature_digest(),
        })
    }
}

fn is_all_zero(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

fn digest_signature(signature: &ThresholdSignature) -> [u8; 32] {
    Sha3_256::digest(signature.0).into()
}
