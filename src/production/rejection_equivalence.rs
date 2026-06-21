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

/// Artifact class for rejection-equivalence closure evidence digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateRejectionEvidenceKind {
    /// Digest-only placeholder evidence; useful for wiring but never closure-ready.
    ScaffoldOnly,
    /// Digest of selected-backend aggregate recomputation evidence.
    RealRecomputation,
    /// Digest of standard-verifier provider identity plus KAT evidence.
    StandardProviderKat,
    /// Digest of aggregate norm-bound evidence.
    NormBound,
    /// Digest of hint-bound evidence.
    HintBound,
    /// Digest of challenge-bound evidence.
    ChallengeBound,
    /// Digest binding the closure package to the production transcript.
    TranscriptBinding,
    /// Digest of negative/provider-mismatch test corpus evidence.
    NegativeTestCorpus,
    /// Digest of external review or audit evidence.
    ExternalReview,
}

/// Classified digest carried by a rejection-equivalence closure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateRejectionEvidenceDigest {
    kind: AggregateRejectionEvidenceKind,
    digest: [u8; 32],
}

impl AggregateRejectionEvidenceDigest {
    /// Record scaffold-only evidence that cannot satisfy closure requirements.
    pub const fn scaffold_only(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::ScaffoldOnly,
            digest,
        }
    }

    /// Record selected-backend aggregate recomputation evidence.
    pub const fn real_recomputation(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::RealRecomputation,
            digest,
        }
    }

    /// Record standard verifier provider identity and KAT evidence.
    pub const fn standard_provider_kat(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::StandardProviderKat,
            digest,
        }
    }

    /// Record aggregate norm-bound evidence.
    pub const fn norm_bound(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::NormBound,
            digest,
        }
    }

    /// Record hint-bound evidence.
    pub const fn hint_bound(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::HintBound,
            digest,
        }
    }

    /// Record challenge-bound evidence.
    pub const fn challenge_bound(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::ChallengeBound,
            digest,
        }
    }

    /// Record transcript-binding evidence.
    pub const fn transcript_binding(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::TranscriptBinding,
            digest,
        }
    }

    /// Record negative test corpus evidence.
    pub const fn negative_test_corpus(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::NegativeTestCorpus,
            digest,
        }
    }

    /// Record external review evidence.
    pub const fn external_review(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::ExternalReview,
            digest,
        }
    }

    /// Return the artifact class.
    pub const fn kind(self) -> AggregateRejectionEvidenceKind {
        self.kind
    }

    /// Borrow the classified digest bytes.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Explicit boundary carried by a rejection-equivalence closure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateRejectionConformanceBoundary {
    /// Scaffold-only package; never closure-ready.
    ScaffoldOnly,
    /// Candidate closure package for selected-backend proof review.
    ClosureCandidate,
}

/// Status exposed by an accepted closure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateRejectionClosureStatus {
    /// All closure-framework evidence gates are present and classified correctly.
    ClosureReady,
}

/// Submitted rejection-equivalence closure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateRejectionClosurePackage {
    /// Explicit conformance boundary for the package.
    pub boundary: AggregateRejectionConformanceBoundary,
    /// Digest of real aggregate recomputation evidence.
    pub real_recomputation_evidence: Option<AggregateRejectionEvidenceDigest>,
    /// Digest of standard verifier provider identity and KAT evidence.
    pub standard_provider_kat_evidence: Option<AggregateRejectionEvidenceDigest>,
    /// Digest of aggregate norm-bound evidence.
    pub norm_bound_evidence: Option<AggregateRejectionEvidenceDigest>,
    /// Digest of hint-bound evidence.
    pub hint_bound_evidence: Option<AggregateRejectionEvidenceDigest>,
    /// Digest of challenge-bound evidence.
    pub challenge_bound_evidence: Option<AggregateRejectionEvidenceDigest>,
    /// Digest of transcript-binding evidence.
    pub transcript_binding_evidence: Option<AggregateRejectionEvidenceDigest>,
    /// Digest of negative/provider-mismatch test corpus evidence.
    pub negative_test_corpus_evidence: Option<AggregateRejectionEvidenceDigest>,
    /// Digest of external review or audit evidence.
    pub external_review_evidence: Option<AggregateRejectionEvidenceDigest>,
}

impl AggregateRejectionClosurePackage {
    /// Construct a submitted closure package.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        boundary: AggregateRejectionConformanceBoundary,
        real_recomputation_evidence: Option<AggregateRejectionEvidenceDigest>,
        standard_provider_kat_evidence: Option<AggregateRejectionEvidenceDigest>,
        norm_bound_evidence: Option<AggregateRejectionEvidenceDigest>,
        hint_bound_evidence: Option<AggregateRejectionEvidenceDigest>,
        challenge_bound_evidence: Option<AggregateRejectionEvidenceDigest>,
        transcript_binding_evidence: Option<AggregateRejectionEvidenceDigest>,
        negative_test_corpus_evidence: Option<AggregateRejectionEvidenceDigest>,
        external_review_evidence: Option<AggregateRejectionEvidenceDigest>,
    ) -> Self {
        Self {
            boundary,
            real_recomputation_evidence,
            standard_provider_kat_evidence,
            norm_bound_evidence,
            hint_bound_evidence,
            challenge_bound_evidence,
            transcript_binding_evidence,
            negative_test_corpus_evidence,
            external_review_evidence,
        }
    }
}

/// Accepted rejection-equivalence closure-framework certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateRejectionClosureCertificate {
    boundary: AggregateRejectionConformanceBoundary,
    real_recomputation_evidence_digest: [u8; 32],
    standard_provider_kat_evidence_digest: [u8; 32],
    norm_bound_evidence_digest: [u8; 32],
    hint_bound_evidence_digest: [u8; 32],
    challenge_bound_evidence_digest: [u8; 32],
    transcript_binding_evidence_digest: [u8; 32],
    negative_test_corpus_digest: [u8; 32],
    external_review_digest: [u8; 32],
}

impl AggregateRejectionClosureCertificate {
    /// Return the closure-framework status.
    pub const fn status(self) -> AggregateRejectionClosureStatus {
        AggregateRejectionClosureStatus::ClosureReady
    }

    /// Return the accepted conformance boundary.
    pub const fn boundary(self) -> AggregateRejectionConformanceBoundary {
        self.boundary
    }

    /// Borrow the real recomputation evidence digest.
    pub const fn real_recomputation_evidence_digest(&self) -> &[u8; 32] {
        &self.real_recomputation_evidence_digest
    }

    /// Borrow the standard provider/KAT evidence digest.
    pub const fn standard_provider_kat_evidence_digest(&self) -> &[u8; 32] {
        &self.standard_provider_kat_evidence_digest
    }

    /// Borrow the norm-bound evidence digest.
    pub const fn norm_bound_evidence_digest(&self) -> &[u8; 32] {
        &self.norm_bound_evidence_digest
    }

    /// Borrow the hint-bound evidence digest.
    pub const fn hint_bound_evidence_digest(&self) -> &[u8; 32] {
        &self.hint_bound_evidence_digest
    }

    /// Borrow the challenge-bound evidence digest.
    pub const fn challenge_bound_evidence_digest(&self) -> &[u8; 32] {
        &self.challenge_bound_evidence_digest
    }

    /// Borrow the transcript-binding evidence digest.
    pub const fn transcript_binding_evidence_digest(&self) -> &[u8; 32] {
        &self.transcript_binding_evidence_digest
    }

    /// Borrow the negative test corpus digest.
    pub const fn negative_test_corpus_digest(&self) -> &[u8; 32] {
        &self.negative_test_corpus_digest
    }

    /// Borrow the external review digest.
    pub const fn external_review_digest(&self) -> &[u8; 32] {
        &self.external_review_digest
    }

    /// This certificate is a closure-framework gate, not a production verifier.
    pub const fn claims_production_verifier(self) -> bool {
        false
    }
}

/// Result of assessing a rejection-equivalence closure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateRejectionClosureAssessment {
    /// No package or required evidence digest was supplied.
    Missing {
        /// Static reason for the missing-evidence assessment.
        reason: &'static str,
    },
    /// A supplied package failed deterministic validation.
    Invalid {
        /// Static reason for the invalid-evidence assessment.
        reason: &'static str,
    },
    /// The package has all closure-framework evidence and is ready for proof review.
    ClosureReady(AggregateRejectionClosureCertificate),
}

impl AggregateRejectionClosureAssessment {
    /// Return true when the package is closure-ready.
    pub const fn is_closure_ready(self) -> bool {
        matches!(self, Self::ClosureReady(_))
    }

    /// Borrow the closure certificate when present.
    pub const fn closure_certificate(&self) -> Option<&AggregateRejectionClosureCertificate> {
        match self {
            Self::ClosureReady(certificate) => Some(certificate),
            Self::Missing { .. } | Self::Invalid { .. } => None,
        }
    }
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

/// Assess whether a submitted package is ready for rejection-equivalence proof closure.
pub fn assess_rejection_equivalence_closure(
    package: Option<AggregateRejectionClosurePackage>,
) -> AggregateRejectionClosureAssessment {
    let Some(package) = package else {
        return AggregateRejectionClosureAssessment::Missing {
            reason: "missing aggregate rejection equivalence closure package",
        };
    };

    if package.boundary != AggregateRejectionConformanceBoundary::ClosureCandidate {
        return AggregateRejectionClosureAssessment::Invalid {
            reason: "closure package must use the closure-candidate conformance boundary",
        };
    }

    let real_recomputation_evidence_digest = match require_closure_digest(
        package.real_recomputation_evidence,
        AggregateRejectionEvidenceKind::RealRecomputation,
        "missing real aggregate recomputation evidence digest",
        "real aggregate recomputation evidence must not be scaffold-only",
        "real aggregate recomputation evidence has wrong artifact kind",
        "real aggregate recomputation evidence digest is all zero",
    ) {
        Ok(digest) => digest,
        Err(assessment) => return assessment,
    };
    let standard_provider_kat_evidence_digest = match require_closure_digest(
        package.standard_provider_kat_evidence,
        AggregateRejectionEvidenceKind::StandardProviderKat,
        "missing standard verifier provider KAT evidence digest",
        "standard verifier provider KAT evidence must not be scaffold-only",
        "standard verifier provider KAT evidence has wrong artifact kind",
        "standard verifier provider KAT digest is all zero",
    ) {
        Ok(digest) => digest,
        Err(assessment) => return assessment,
    };
    let norm_bound_evidence_digest = match require_closure_digest(
        package.norm_bound_evidence,
        AggregateRejectionEvidenceKind::NormBound,
        "missing norm bound evidence digest",
        "norm bound evidence must not be scaffold-only",
        "norm bound evidence has wrong artifact kind",
        "norm bound evidence digest is all zero",
    ) {
        Ok(digest) => digest,
        Err(assessment) => return assessment,
    };
    let hint_bound_evidence_digest = match require_closure_digest(
        package.hint_bound_evidence,
        AggregateRejectionEvidenceKind::HintBound,
        "missing hint bound evidence digest",
        "hint bound evidence must not be scaffold-only",
        "hint bound evidence has wrong artifact kind",
        "hint bound evidence digest is all zero",
    ) {
        Ok(digest) => digest,
        Err(assessment) => return assessment,
    };
    let challenge_bound_evidence_digest = match require_closure_digest(
        package.challenge_bound_evidence,
        AggregateRejectionEvidenceKind::ChallengeBound,
        "missing challenge bound evidence digest",
        "challenge bound evidence must not be scaffold-only",
        "challenge bound evidence has wrong artifact kind",
        "challenge bound evidence digest is all zero",
    ) {
        Ok(digest) => digest,
        Err(assessment) => return assessment,
    };
    let transcript_binding_evidence_digest = match require_closure_digest(
        package.transcript_binding_evidence,
        AggregateRejectionEvidenceKind::TranscriptBinding,
        "missing transcript binding evidence digest",
        "transcript binding evidence must not be scaffold-only",
        "transcript binding evidence has wrong artifact kind",
        "transcript binding evidence digest is all zero",
    ) {
        Ok(digest) => digest,
        Err(assessment) => return assessment,
    };
    let negative_test_corpus_digest = match require_closure_digest(
        package.negative_test_corpus_evidence,
        AggregateRejectionEvidenceKind::NegativeTestCorpus,
        "missing negative test corpus digest",
        "negative test corpus evidence must not be scaffold-only",
        "negative test corpus evidence has wrong artifact kind",
        "negative test corpus digest is all zero",
    ) {
        Ok(digest) => digest,
        Err(assessment) => return assessment,
    };
    let external_review_digest = match require_closure_digest(
        package.external_review_evidence,
        AggregateRejectionEvidenceKind::ExternalReview,
        "missing external review digest",
        "external review evidence must not be scaffold-only",
        "external review evidence has wrong artifact kind",
        "external review digest is all zero",
    ) {
        Ok(digest) => digest,
        Err(assessment) => return assessment,
    };

    AggregateRejectionClosureAssessment::ClosureReady(AggregateRejectionClosureCertificate {
        boundary: package.boundary,
        real_recomputation_evidence_digest,
        standard_provider_kat_evidence_digest,
        norm_bound_evidence_digest,
        hint_bound_evidence_digest,
        challenge_bound_evidence_digest,
        transcript_binding_evidence_digest,
        negative_test_corpus_digest,
        external_review_digest,
    })
}

fn require_closure_digest(
    evidence: Option<AggregateRejectionEvidenceDigest>,
    expected_kind: AggregateRejectionEvidenceKind,
    missing_reason: &'static str,
    scaffold_reason: &'static str,
    wrong_kind_reason: &'static str,
    zero_reason: &'static str,
) -> Result<[u8; 32], AggregateRejectionClosureAssessment> {
    let Some(evidence) = evidence else {
        return Err(AggregateRejectionClosureAssessment::Missing {
            reason: missing_reason,
        });
    };

    if evidence.kind() == AggregateRejectionEvidenceKind::ScaffoldOnly {
        return Err(AggregateRejectionClosureAssessment::Invalid {
            reason: scaffold_reason,
        });
    }
    if evidence.kind() != expected_kind {
        return Err(AggregateRejectionClosureAssessment::Invalid {
            reason: wrong_kind_reason,
        });
    }
    if is_all_zero(evidence.digest()) {
        return Err(AggregateRejectionClosureAssessment::Invalid {
            reason: zero_reason,
        });
    }

    Ok(*evidence.digest())
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

fn digest_signature(signature: &ThresholdSignature) -> [u8; 32] {
    digest_bytes(&signature.0)
}

fn is_all_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
