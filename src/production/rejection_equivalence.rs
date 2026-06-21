//! Aggregate rejection-equivalence evidence gates.
//!
//! This module is a hazmat/conformance-only bridge. It separates digest-only
//! scaffold evidence from provider-verified aggregate recomputation evidence
//! without claiming that the current coordinator profile implements production
//! threshold ML-DSA rejection-distribution preservation.

use sha3::{Digest, Sha3_256};

use crate::{
    production::{
        acceptance::StandardVerifierEvidence, provider::StandardMldsa65Provider,
        transcript::ProductionSigningTranscript,
    },
    ThresholdError, ThresholdSignature,
};

/// Evidence strength for aggregate rejection-equivalence claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateRejectionEvidenceStrength {
    /// Digest-only scaffold evidence; useful for conformance plumbing only.
    ScaffoldOnly,
    /// Standard-verifier evidence plus public aggregate recomputation evidence.
    ProviderRecomputedBridge,
}

/// Public transcript of aggregate recomputation outputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateRecomputationTranscript {
    challenge_digest: [u8; 32],
    aggregate_response_digest: [u8; 32],
    hint_digest: [u8; 32],
    recomputed_signature_digest: [u8; 32],
}

impl AggregateRecomputationTranscript {
    /// Build public recomputation evidence from a bound transcript and aggregate outputs.
    pub fn from_public_outputs(
        transcript: &ProductionSigningTranscript,
        aggregate_response: &[u8],
        hint: &[u8],
        recomputed_signature: &ThresholdSignature,
    ) -> Result<Self, ThresholdError> {
        if aggregate_response.is_empty() {
            return Err(ThresholdError::MalformedSerialization {
                reason: "aggregate response recomputation bytes are empty",
            });
        }
        if hint.is_empty() {
            return Err(ThresholdError::InvalidHintRoute {
                reason: "hint recomputation bytes are empty",
            });
        }

        Ok(Self {
            challenge_digest: *transcript.challenge_digest(),
            aggregate_response_digest: digest_bytes(aggregate_response),
            hint_digest: digest_bytes(hint),
            recomputed_signature_digest: digest_signature(recomputed_signature),
        })
    }

    /// Borrow the recomputation transcript challenge digest.
    pub const fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }

    /// Borrow the recomputed aggregate-response digest.
    pub const fn aggregate_response_digest(&self) -> &[u8; 32] {
        &self.aggregate_response_digest
    }

    /// Borrow the recomputed hint digest.
    pub const fn hint_digest(&self) -> &[u8; 32] {
        &self.hint_digest
    }

    /// Borrow the digest of the recomputed aggregate signature.
    pub const fn recomputed_signature_digest(&self) -> &[u8; 32] {
        &self.recomputed_signature_digest
    }
}

/// Bounded evidence for aggregate rejection-equivalence checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateRejectionEquivalenceEvidence {
    strength: AggregateRejectionEvidenceStrength,
    challenge_digest: [u8; 32],
    aggregate_response_digest: [u8; 32],
    hint_digest: [u8; 32],
    candidate_signature_digest: [u8; 32],
    recomputed_signature_digest: Option<[u8; 32]>,
}

impl AggregateRejectionEquivalenceEvidence {
    /// Record digest-only scaffold evidence without satisfying the bridge gate.
    pub const fn scaffold_only(
        challenge_digest: [u8; 32],
        aggregate_response_digest: [u8; 32],
        hint_digest: [u8; 32],
        candidate_signature_digest: [u8; 32],
    ) -> Self {
        Self {
            strength: AggregateRejectionEvidenceStrength::ScaffoldOnly,
            challenge_digest,
            aggregate_response_digest,
            hint_digest,
            candidate_signature_digest,
            recomputed_signature_digest: None,
        }
    }

    /// Return the evidence strength.
    pub const fn strength(&self) -> AggregateRejectionEvidenceStrength {
        self.strength
    }

    /// Borrow the bound transcript challenge digest.
    pub const fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }

    /// Borrow the aggregate-response evidence digest.
    pub const fn aggregate_response_digest(&self) -> &[u8; 32] {
        &self.aggregate_response_digest
    }

    /// Borrow the hint evidence digest.
    pub const fn hint_digest(&self) -> &[u8; 32] {
        &self.hint_digest
    }

    /// Borrow the provider-verified candidate signature digest.
    pub const fn candidate_signature_digest(&self) -> &[u8; 32] {
        &self.candidate_signature_digest
    }

    /// Borrow the recomputed signature digest when recomputation evidence exists.
    pub const fn recomputed_signature_digest(&self) -> Option<&[u8; 32]> {
        self.recomputed_signature_digest.as_ref()
    }

    /// Return whether this evidence satisfies the provider/recomputation bridge gate.
    pub fn satisfies_equivalence_gate(&self) -> bool {
        self.strength == AggregateRejectionEvidenceStrength::ProviderRecomputedBridge
            && self.recomputed_signature_digest == Some(self.candidate_signature_digest)
    }
}

/// Gate that separates scaffold evidence from provider-backed bridge evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateRejectionEquivalenceGate;

impl AggregateRejectionEquivalenceGate {
    /// Require evidence that passed the standard-verifier and recomputation bridge.
    pub fn require_verified_bridge(
        evidence: &AggregateRejectionEquivalenceEvidence,
    ) -> Result<(), ThresholdError> {
        if evidence.satisfies_equivalence_gate() {
            return Ok(());
        }

        Err(ThresholdError::BackendUnavailable {
            reason: "aggregate rejection equivalence requires provider bridge and recomputation transcript",
        })
    }

    /// Verify a candidate through the standard provider and match recomputation evidence.
    pub fn verify_recomputed_bridge<P>(
        transcript: &ProductionSigningTranscript,
        candidate_signature: &ThresholdSignature,
        recomputation: &AggregateRecomputationTranscript,
    ) -> Result<AggregateRejectionEquivalenceEvidence, ThresholdError>
    where
        P: StandardMldsa65Provider,
    {
        if recomputation.challenge_digest() != transcript.challenge_digest() {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let verifier = StandardVerifierEvidence::verify::<P>(transcript, candidate_signature)?;
        let candidate_signature_digest = *verifier.candidate_signature_digest();

        if candidate_signature_digest != *recomputation.recomputed_signature_digest() {
            return Err(ThresholdError::StandardVerificationFailed);
        }

        Ok(AggregateRejectionEquivalenceEvidence {
            strength: AggregateRejectionEvidenceStrength::ProviderRecomputedBridge,
            challenge_digest: *verifier.challenge_digest(),
            aggregate_response_digest: *recomputation.aggregate_response_digest(),
            hint_digest: *recomputation.hint_digest(),
            candidate_signature_digest,
            recomputed_signature_digest: Some(*recomputation.recomputed_signature_digest()),
        })
    }
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

fn digest_signature(signature: &ThresholdSignature) -> [u8; 32] {
    digest_bytes(&signature.0)
}
