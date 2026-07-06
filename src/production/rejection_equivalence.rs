//! Aggregate rejection-equivalence evidence gates.
//!
//! This module is a hazmat/conformance-only bridge. It separates digest-only
//! scaffold evidence from provider-verified aggregate recomputation evidence
//! without claiming that the current coordinator profile implements production
//! threshold ML-DSA rejection-distribution preservation.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{
    production::{
        acceptance::{AcceptedAggregateCandidate, StandardVerifierEvidence},
        provider::StandardMldsa65Provider,
        selected_backend::SelectedProductionBackendProfile,
        transcript::ProductionSigningTranscript,
    },
    ThresholdError, ThresholdPublicKey, ThresholdSignature, ValidatorId, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES,
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
    /// Digest of standard-verifier bridge evidence for the recomputed aggregate.
    StandardVerifierBridge,
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

    /// Record standard-verifier bridge evidence for the recomputed aggregate.
    pub const fn standard_verifier_bridge(digest: [u8; 32]) -> Self {
        Self {
            kind: AggregateRejectionEvidenceKind::StandardVerifierBridge,
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
    /// Digest of standard-verifier bridge evidence for the recomputed aggregate.
    pub standard_verifier_bridge_evidence: Option<AggregateRejectionEvidenceDigest>,
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
        standard_verifier_bridge_evidence: Option<AggregateRejectionEvidenceDigest>,
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
            standard_verifier_bridge_evidence,
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
    standard_verifier_bridge_evidence_digest: [u8; 32],
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

    /// Borrow the standard-verifier bridge evidence digest.
    pub const fn standard_verifier_bridge_evidence_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_bridge_evidence_digest
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

/// Source class for ML-DSA-65 provider KAT evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcvpFips204EvidenceSource {
    /// Non-ACVP smoke evidence; useful for provider plumbing only.
    NonAcvpSmokeOnly,
    /// NIST ACVP-Server FIPS204 sample vector evidence.
    NistAcvpServerFips204,
    /// CAVP/ACVTS production validation certificate evidence.
    CavpCertificate,
}

impl AcvpFips204EvidenceSource {
    /// Return true when the source can satisfy the ACVP/FIPS204 artifact gate.
    pub const fn is_acvp_fips204_backed(self) -> bool {
        match self {
            Self::NonAcvpSmokeOnly => false,
            Self::NistAcvpServerFips204 | Self::CavpCertificate => true,
        }
    }

    /// Return true only for a production CAVP/ACVTS validation certificate source.
    pub const fn claims_fips_validation(self) -> bool {
        match self {
            Self::CavpCertificate => true,
            Self::NonAcvpSmokeOnly | Self::NistAcvpServerFips204 => false,
        }
    }
}

/// Provider identity and KAT evidence for the selected ML-DSA-65 provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mldsa65ProviderKatEvidence {
    source: AcvpFips204EvidenceSource,
    provider_kat_evidence_digest: [u8; 32],
    acvp_vector_set_digest: [u8; 32],
    provider_identity_digest: [u8; 32],
    reviewed: bool,
}

impl Mldsa65ProviderKatEvidence {
    /// Construct provider KAT evidence for a P1 artifact package.
    pub const fn new(
        source: AcvpFips204EvidenceSource,
        provider_kat_evidence_digest: [u8; 32],
        acvp_vector_set_digest: [u8; 32],
        provider_identity_digest: [u8; 32],
        reviewed: bool,
    ) -> Self {
        Self {
            source,
            provider_kat_evidence_digest,
            acvp_vector_set_digest,
            provider_identity_digest,
            reviewed,
        }
    }

    /// Return the KAT evidence source class.
    pub const fn source(self) -> AcvpFips204EvidenceSource {
        self.source
    }

    /// Borrow the digest tied to the aggregate closure package.
    pub const fn provider_kat_evidence_digest(&self) -> &[u8; 32] {
        &self.provider_kat_evidence_digest
    }

    /// Borrow the digest of the ACVP/FIPS204 vector set or validation transcript.
    pub const fn acvp_vector_set_digest(&self) -> &[u8; 32] {
        &self.acvp_vector_set_digest
    }

    /// Borrow the digest of the provider identity, build, and toolchain record.
    pub const fn provider_identity_digest(&self) -> &[u8; 32] {
        &self.provider_identity_digest
    }

    /// Return whether the evidence has a named review signoff.
    pub const fn reviewed(self) -> bool {
        self.reviewed
    }
}

/// Typed Criterion 2 proof-slot artifact classes for P1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum P1Criterion2ProofSlotArtifactKind {
    /// Full KAT or validation package evidence beyond the bounded fixture set.
    FullKatValidation = 0,
    /// Rejection-distribution review evidence for accepted P1 outputs.
    RejectionDistributionReview = 1,
    /// Norm-bound proof artifact evidence.
    NormBound = 2,
    /// Hint-bound proof artifact evidence.
    HintBound = 3,
    /// Challenge-bound proof artifact evidence.
    ChallengeBound = 4,
    /// Transcript-binding proof artifact evidence.
    TranscriptBinding = 5,
    /// Theorem-linkage artifact evidence.
    TheoremLinkage = 6,
    /// External proof/audit review evidence.
    ExternalReview = 7,
    /// Predecessor threshold-output certificate digest evidence.
    ThresholdOutputCertificate = 8,
    /// Predecessor real recomputation evidence digest.
    RealRecomputationEvidence = 9,
    /// Reviewed distributed nonce-producer artifact evidence.
    DistributedNonceProducer = 10,
}

impl P1Criterion2ProofSlotArtifactKind {
    const fn tag(self) -> u8 {
        self as u8
    }
}

/// A reviewed, typed artifact for one unclosed Criterion 2 proof slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1Criterion2ProofSlotArtifact {
    /// Criterion 2 proof-slot class.
    pub kind: P1Criterion2ProofSlotArtifactKind,
    /// Selected backend profile the slot is bound to.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Digest binding the selected backend profile.
    pub selected_profile_binding_digest: [u8; 32],
    /// Digest of the accepted threshold-output certificate.
    pub threshold_output_certificate_digest: [u8; 32],
    /// Digest binding the slot to the production signing transcript.
    pub transcript_binding_digest: [u8; 32],
    /// Digest of the source evidence for this proof slot.
    pub source_evidence_digest: [u8; 32],
    /// Digest of the review evidence for this proof slot.
    pub review_evidence_digest: [u8; 32],
    /// Domain-separated digest of this typed slot artifact.
    pub artifact_digest: [u8; 32],
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    /// Whether this slot artifact has a named review signoff.
    pub reviewed: bool,
}

impl P1Criterion2ProofSlotArtifact {
    /// Return the artifact class.
    pub const fn kind(self) -> P1Criterion2ProofSlotArtifactKind {
        self.kind
    }

    /// Borrow the artifact digest committed by the slot package.
    pub const fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }

    /// Return whether this slot has a named review signoff.
    pub const fn reviewed(self) -> bool {
        self.reviewed
    }
}

/// Bundle of typed Criterion 2 artifacts used by the P1 proof-closure gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1Criterion2ProofSlotArtifacts {
    /// Full KAT or validation package proof-slot artifact.
    pub full_kat_validation_artifact: P1Criterion2ProofSlotArtifact,
    /// Rejection-distribution review proof-slot artifact.
    pub rejection_distribution_review_artifact: P1Criterion2ProofSlotArtifact,
    /// Norm-bound proof-slot artifact.
    pub norm_bound_artifact: P1Criterion2ProofSlotArtifact,
    /// Hint-bound proof-slot artifact.
    pub hint_bound_artifact: P1Criterion2ProofSlotArtifact,
    /// Challenge-bound proof-slot artifact.
    pub challenge_bound_artifact: P1Criterion2ProofSlotArtifact,
    /// Transcript-binding proof-slot artifact.
    pub transcript_binding_artifact: P1Criterion2ProofSlotArtifact,
    /// Theorem-linkage proof-slot artifact.
    pub theorem_linkage_artifact: P1Criterion2ProofSlotArtifact,
    /// External proof/audit review proof-slot artifact.
    pub external_review_artifact: P1Criterion2ProofSlotArtifact,
    /// Threshold-output certificate predecessor proof-slot artifact.
    pub threshold_output_certificate_artifact: P1Criterion2ProofSlotArtifact,
    /// Real recomputation evidence predecessor proof-slot artifact.
    pub real_recomputation_evidence_artifact: P1Criterion2ProofSlotArtifact,
    /// Distributed nonce-producer proof-slot artifact.
    pub distributed_nonce_producer_artifact: P1Criterion2ProofSlotArtifact,
}

impl P1Criterion2ProofSlotArtifacts {
    /// Construct a typed Criterion 2 proof-slot bundle.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        full_kat_validation_artifact: P1Criterion2ProofSlotArtifact,
        rejection_distribution_review_artifact: P1Criterion2ProofSlotArtifact,
        norm_bound_artifact: P1Criterion2ProofSlotArtifact,
        hint_bound_artifact: P1Criterion2ProofSlotArtifact,
        challenge_bound_artifact: P1Criterion2ProofSlotArtifact,
        transcript_binding_artifact: P1Criterion2ProofSlotArtifact,
        theorem_linkage_artifact: P1Criterion2ProofSlotArtifact,
        external_review_artifact: P1Criterion2ProofSlotArtifact,
        threshold_output_certificate_artifact: P1Criterion2ProofSlotArtifact,
        real_recomputation_evidence_artifact: P1Criterion2ProofSlotArtifact,
        distributed_nonce_producer_artifact: P1Criterion2ProofSlotArtifact,
    ) -> Self {
        Self {
            full_kat_validation_artifact,
            rejection_distribution_review_artifact,
            norm_bound_artifact,
            hint_bound_artifact,
            challenge_bound_artifact,
            transcript_binding_artifact,
            theorem_linkage_artifact,
            external_review_artifact,
            threshold_output_certificate_artifact,
            real_recomputation_evidence_artifact,
            distributed_nonce_producer_artifact,
        }
    }
}

/// Source digests and review metadata used to derive the typed Criterion 2
/// proof-slot bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1Criterion2ProofSlotArtifactSources {
    /// Source digest for the full KAT or validation package slot.
    pub full_kat_validation_source_digest: [u8; 32],
    /// Source digest for the rejection-distribution review slot.
    pub rejection_distribution_review_source_digest: [u8; 32],
    /// Source digest for the distributed nonce-producer slot.
    pub distributed_nonce_producer_source_digest: [u8; 32],
    /// Source digest for the theorem-linkage slot.
    pub theorem_linkage_source_digest: [u8; 32],
    /// Claim boundary assigned to every derived proof-slot artifact.
    pub claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    /// Review bit assigned to every derived proof-slot artifact.
    pub reviewed: bool,
}

impl P1Criterion2ProofSlotArtifactSources {
    /// Construct the source bundle for Criterion 2 proof-slot derivation.
    pub const fn new(
        full_kat_validation_source_digest: [u8; 32],
        rejection_distribution_review_source_digest: [u8; 32],
        distributed_nonce_producer_source_digest: [u8; 32],
        theorem_linkage_source_digest: [u8; 32],
        claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
        reviewed: bool,
    ) -> Self {
        Self {
            full_kat_validation_source_digest,
            rejection_distribution_review_source_digest,
            distributed_nonce_producer_source_digest,
            theorem_linkage_source_digest,
            claim_boundary,
            reviewed,
        }
    }
}

/// Reviewed P1 rejection-equivalence proof artifact digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1RejectionProofArtifacts {
    selected_profile_binding_digest: [u8; 32],
    real_recomputation_evidence_digest: [u8; 32],
    standard_verifier_bridge_evidence_digest: [u8; 32],
    standard_verifier_bridge_fixture_package_digest: [u8; 32],
    norm_bound_evidence_digest: [u8; 32],
    hint_bound_evidence_digest: [u8; 32],
    challenge_bound_evidence_digest: [u8; 32],
    transcript_binding_evidence_digest: [u8; 32],
    negative_test_corpus_digest: [u8; 32],
    external_review_digest: [u8; 32],
    reviewed: bool,
}

impl P1RejectionProofArtifacts {
    /// Construct the proof artifact digest bundle required by the P1 gate.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        selected_profile_binding_digest: [u8; 32],
        real_recomputation_evidence_digest: [u8; 32],
        standard_verifier_bridge_evidence_digest: [u8; 32],
        standard_verifier_bridge_fixture_package_digest: [u8; 32],
        norm_bound_evidence_digest: [u8; 32],
        hint_bound_evidence_digest: [u8; 32],
        challenge_bound_evidence_digest: [u8; 32],
        transcript_binding_evidence_digest: [u8; 32],
        negative_test_corpus_digest: [u8; 32],
        external_review_digest: [u8; 32],
        reviewed: bool,
    ) -> Self {
        Self {
            selected_profile_binding_digest,
            real_recomputation_evidence_digest,
            standard_verifier_bridge_evidence_digest,
            standard_verifier_bridge_fixture_package_digest,
            norm_bound_evidence_digest,
            hint_bound_evidence_digest,
            challenge_bound_evidence_digest,
            transcript_binding_evidence_digest,
            negative_test_corpus_digest,
            external_review_digest,
            reviewed,
        }
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        &self.selected_profile_binding_digest
    }

    /// Borrow the real aggregate recomputation artifact digest.
    pub const fn real_recomputation_evidence_digest(&self) -> &[u8; 32] {
        &self.real_recomputation_evidence_digest
    }

    /// Borrow the standard-verifier bridge artifact digest.
    pub const fn standard_verifier_bridge_evidence_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_bridge_evidence_digest
    }

    /// Borrow the raw standard-verifier bridge fixture/package digest.
    pub const fn standard_verifier_bridge_fixture_package_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_bridge_fixture_package_digest
    }

    /// Borrow the norm-bound proof artifact digest.
    pub const fn norm_bound_evidence_digest(&self) -> &[u8; 32] {
        &self.norm_bound_evidence_digest
    }

    /// Borrow the hint-bound proof artifact digest.
    pub const fn hint_bound_evidence_digest(&self) -> &[u8; 32] {
        &self.hint_bound_evidence_digest
    }

    /// Borrow the challenge-bound proof artifact digest.
    pub const fn challenge_bound_evidence_digest(&self) -> &[u8; 32] {
        &self.challenge_bound_evidence_digest
    }

    /// Borrow the transcript-binding proof artifact digest.
    pub const fn transcript_binding_evidence_digest(&self) -> &[u8; 32] {
        &self.transcript_binding_evidence_digest
    }

    /// Borrow the negative corpus artifact digest.
    pub const fn negative_test_corpus_digest(&self) -> &[u8; 32] {
        &self.negative_test_corpus_digest
    }

    /// Borrow the external review artifact digest.
    pub const fn external_review_digest(&self) -> &[u8; 32] {
        &self.external_review_digest
    }

    /// Return whether the proof artifacts have a named review signoff.
    pub const fn reviewed(self) -> bool {
        self.reviewed
    }
}

/// Submitted P1 aggregate recomputation closure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1AggregateRecomputationClosurePackage {
    /// Selected backend profile this package claims to close against.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Underlying aggregate rejection-equivalence closure package.
    pub rejection_closure_package: AggregateRejectionClosurePackage,
    /// Provider identity and ACVP/FIPS204 KAT evidence.
    pub provider_kat_evidence: Mldsa65ProviderKatEvidence,
    /// Reviewed proof artifact digests for the P1 rejection-equivalence gate.
    pub proof_artifacts: P1RejectionProofArtifacts,
}

impl P1AggregateRecomputationClosurePackage {
    /// Construct a submitted P1 aggregate recomputation closure package.
    pub const fn new(
        selected_profile: SelectedProductionBackendProfile,
        rejection_closure_package: AggregateRejectionClosurePackage,
        provider_kat_evidence: Mldsa65ProviderKatEvidence,
        proof_artifacts: P1RejectionProofArtifacts,
    ) -> Self {
        Self {
            selected_profile,
            rejection_closure_package,
            provider_kat_evidence,
            proof_artifacts,
        }
    }
}

/// Accepted P1 aggregate recomputation artifact-gate certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1AggregateRecomputationClosureCertificate {
    selected_profile: SelectedProductionBackendProfile,
    closure_certificate: AggregateRejectionClosureCertificate,
    provider_kat_evidence: Mldsa65ProviderKatEvidence,
    proof_artifacts: P1RejectionProofArtifacts,
}

impl P1AggregateRecomputationClosureCertificate {
    /// Return the selected P1 backend profile bound to the certificate.
    pub const fn selected_profile(self) -> SelectedProductionBackendProfile {
        self.selected_profile
    }

    /// Return the provider KAT source bound to the certificate.
    pub const fn provider_kat_source(self) -> AcvpFips204EvidenceSource {
        self.provider_kat_evidence.source()
    }

    /// Borrow the provider KAT evidence digest.
    pub const fn provider_kat_evidence_digest(&self) -> &[u8; 32] {
        self.provider_kat_evidence.provider_kat_evidence_digest()
    }

    /// Borrow the ACVP/FIPS204 vector-set or validation-transcript digest.
    pub const fn acvp_vector_set_digest(&self) -> &[u8; 32] {
        self.provider_kat_evidence.acvp_vector_set_digest()
    }

    /// Borrow the provider identity/build/toolchain digest.
    pub const fn provider_identity_digest(&self) -> &[u8; 32] {
        self.provider_kat_evidence.provider_identity_digest()
    }

    /// Borrow the real recomputation evidence digest.
    pub const fn real_recomputation_evidence_digest(&self) -> &[u8; 32] {
        self.closure_certificate
            .real_recomputation_evidence_digest()
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        self.proof_artifacts.selected_profile_binding_digest()
    }

    /// Borrow the standard-verifier bridge evidence digest.
    pub const fn standard_verifier_bridge_evidence_digest(&self) -> &[u8; 32] {
        self.closure_certificate
            .standard_verifier_bridge_evidence_digest()
    }

    /// Borrow the raw standard-verifier bridge fixture/package digest.
    pub const fn standard_verifier_bridge_fixture_package_digest(&self) -> &[u8; 32] {
        self.proof_artifacts
            .standard_verifier_bridge_fixture_package_digest()
    }

    /// Return true only when the source is a production CAVP/ACVTS certificate.
    pub const fn claims_fips_validation(self) -> bool {
        self.provider_kat_evidence.source().claims_fips_validation()
    }

    /// Return true only after the selected profile itself is production approved.
    pub const fn claims_production_approval(self) -> bool {
        self.selected_profile.production_approved()
    }

    /// Artifact readiness does not claim deployed standard-verifier compatibility.
    pub const fn claims_standard_verifier_compatibility(self) -> bool {
        false
    }

    /// This certificate gates artifacts; it does not replace cryptographic review.
    pub const fn claims_completed_cryptographic_proof(self) -> bool {
        false
    }
}

/// Submitted selected-backend aggregate-output artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1SelectedBackendAggregateArtifactPackage {
    /// Selected backend profile this aggregate artifact claims to bind.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Digest binding the selected backend profile.
    pub selected_profile_binding_digest: [u8; 32],
    /// Provider KAT evidence digest bound to the recomputation gate.
    pub provider_kat_evidence_digest: [u8; 32],
    /// Standard-verifier bridge evidence digest bound to the recomputation gate.
    pub standard_verifier_bridge_evidence_digest: [u8; 32],
    /// Real aggregate recomputation evidence digest bound to the recomputation gate.
    pub real_recomputation_evidence_digest: [u8; 32],
    /// Digest binding this aggregate artifact to the production signing transcript.
    pub transcript_binding_digest: [u8; 32],
    /// Digest binding the accepted aggregate signer set.
    pub signer_set_digest: [u8; 32],
    /// Digest binding the single-use attempt ID and retry domain.
    pub attempt_binding_digest: [u8; 32],
    /// Accepted aggregate-response digest from `AggregateAccept`.
    pub aggregate_response_digest: [u8; 32],
    /// Accepted hint digest from `AggregateAccept`.
    pub hint_digest: [u8; 32],
    /// Provider-verified accepted aggregate signature digest.
    pub accepted_signature_digest: [u8; 32],
    /// Whether this artifact package has a named review signoff.
    pub reviewed: bool,
}

impl P1SelectedBackendAggregateArtifactPackage {
    /// Construct a selected-backend aggregate-output artifact package.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        selected_profile: SelectedProductionBackendProfile,
        selected_profile_binding_digest: [u8; 32],
        provider_kat_evidence_digest: [u8; 32],
        standard_verifier_bridge_evidence_digest: [u8; 32],
        real_recomputation_evidence_digest: [u8; 32],
        transcript_binding_digest: [u8; 32],
        signer_set_digest: [u8; 32],
        attempt_binding_digest: [u8; 32],
        aggregate_response_digest: [u8; 32],
        hint_digest: [u8; 32],
        accepted_signature_digest: [u8; 32],
        reviewed: bool,
    ) -> Self {
        Self {
            selected_profile,
            selected_profile_binding_digest,
            provider_kat_evidence_digest,
            standard_verifier_bridge_evidence_digest,
            real_recomputation_evidence_digest,
            transcript_binding_digest,
            signer_set_digest,
            attempt_binding_digest,
            aggregate_response_digest,
            hint_digest,
            accepted_signature_digest,
            reviewed,
        }
    }
}

/// Accepted selected-backend aggregate-output artifact-gate certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1SelectedBackendAggregateArtifactCertificate {
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: [u8; 32],
    provider_kat_evidence_digest: [u8; 32],
    standard_verifier_bridge_evidence_digest: [u8; 32],
    real_recomputation_evidence_digest: [u8; 32],
    transcript_binding_digest: [u8; 32],
    signer_set_digest: [u8; 32],
    attempt_binding_digest: [u8; 32],
    aggregate_response_digest: [u8; 32],
    hint_digest: [u8; 32],
    accepted_signature_digest: [u8; 32],
}

impl P1SelectedBackendAggregateArtifactCertificate {
    /// Return the selected backend profile bound to the artifact.
    pub const fn selected_profile(self) -> SelectedProductionBackendProfile {
        self.selected_profile
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        &self.selected_profile_binding_digest
    }

    /// Borrow the provider KAT evidence digest.
    pub const fn provider_kat_evidence_digest(&self) -> &[u8; 32] {
        &self.provider_kat_evidence_digest
    }

    /// Borrow the standard-verifier bridge evidence digest.
    pub const fn standard_verifier_bridge_evidence_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_bridge_evidence_digest
    }

    /// Borrow the real recomputation evidence digest.
    pub const fn real_recomputation_evidence_digest(&self) -> &[u8; 32] {
        &self.real_recomputation_evidence_digest
    }

    /// Borrow the transcript binding digest.
    pub const fn transcript_binding_digest(&self) -> &[u8; 32] {
        &self.transcript_binding_digest
    }

    /// Borrow the signer-set binding digest.
    pub const fn signer_set_digest(&self) -> &[u8; 32] {
        &self.signer_set_digest
    }

    /// Borrow the attempt binding digest.
    pub const fn attempt_binding_digest(&self) -> &[u8; 32] {
        &self.attempt_binding_digest
    }

    /// Borrow the accepted aggregate-response digest.
    pub const fn aggregate_response_digest(&self) -> &[u8; 32] {
        &self.aggregate_response_digest
    }

    /// Borrow the accepted hint digest.
    pub const fn hint_digest(&self) -> &[u8; 32] {
        &self.hint_digest
    }

    /// Borrow the accepted aggregate signature digest.
    pub const fn accepted_signature_digest(&self) -> &[u8; 32] {
        &self.accepted_signature_digest
    }

    /// Artifact readiness does not claim a deployed production backend.
    pub const fn claims_selected_backend_production(self) -> bool {
        false
    }

    /// Artifact readiness does not claim completed standard-verifier compatibility proof.
    pub const fn claims_standard_verifier_compatibility(self) -> bool {
        false
    }

    /// This certificate gates artifacts; it does not replace cryptographic proof.
    pub const fn claims_completed_cryptographic_proof(self) -> bool {
        false
    }
}

/// Claim boundary carried by Batch 3 threshold-output artifact evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P1ThresholdOutputClaimBoundary {
    /// The artifact is present for conformance and proof review only.
    ProofReviewOnly,
    /// Forbidden boundary used to reject packages that try to claim production readiness.
    ProductionClaim,
}

/// Digest-only pointer to selected-backend threshold-output attempt evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1ThresholdOutputEvidenceSource {
    source_digest: [u8; 32],
    source_package_digest: [u8; 32],
    reviewed: bool,
}

impl P1ThresholdOutputEvidenceSource {
    /// Record a reviewed selected-backend candidate output source digest.
    ///
    /// The digest identifies the external or generated artifact bundle for a
    /// threshold-output attempt. It does not by itself prove threshold ML-DSA
    /// security, standard-verifier compatibility, or distribution preservation.
    pub const fn selected_backend_candidate(
        source_digest: [u8; 32],
        source_package_digest: [u8; 32],
        reviewed: bool,
    ) -> Self {
        Self {
            source_digest,
            source_package_digest,
            reviewed,
        }
    }

    /// Borrow the selected-backend threshold-output source digest.
    pub const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    /// Borrow the digest of the reviewed source package bytes.
    pub const fn source_package_digest(&self) -> &[u8; 32] {
        &self.source_package_digest
    }

    /// Return whether the source digest has named review signoff.
    pub const fn reviewed(self) -> bool {
        self.reviewed
    }
}

/// Submitted Batch 3 selected-backend threshold-output artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1SelectedBackendThresholdOutputArtifactPackage {
    /// Selected backend profile this threshold-output artifact claims to bind.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Digest binding the selected backend profile.
    pub selected_profile_binding_digest: [u8; 32],
    /// Digest of the predecessor selected-backend aggregate artifact certificate.
    pub aggregate_artifact_digest: [u8; 32],
    /// Provider KAT evidence digest inherited from the aggregate certificate.
    pub provider_kat_evidence_digest: [u8; 32],
    /// Reviewed threshold-output attempt source evidence.
    pub threshold_output_source: P1ThresholdOutputEvidenceSource,
    /// Digest of the reviewed threshold-output attempt source.
    pub threshold_output_source_digest: [u8; 32],
    /// Digest binding the threshold-output artifact to the production transcript.
    pub transcript_binding_digest: [u8; 32],
    /// Digest binding the accepted aggregate signer set.
    pub signer_set_digest: [u8; 32],
    /// Digest binding the single-use attempt ID and retry domain.
    pub attempt_binding_digest: [u8; 32],
    /// Accepted aggregate-response digest from `AggregateAccept`.
    pub aggregate_response_digest: [u8; 32],
    /// Accepted hint digest from `AggregateAccept`.
    pub hint_digest: [u8; 32],
    /// Provider-verified accepted aggregate signature digest.
    pub accepted_signature_digest: [u8; 32],
    /// Standard-verifier bridge evidence digest inherited from the aggregate certificate.
    pub standard_verifier_bridge_evidence_digest: [u8; 32],
    /// Real recomputation evidence digest inherited from the aggregate certificate.
    pub real_recomputation_evidence_digest: [u8; 32],
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1ThresholdOutputClaimBoundary,
    /// Whether this artifact package has a named review signoff.
    pub reviewed: bool,
}

/// Accepted Batch 3 selected-backend threshold-output artifact certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1SelectedBackendThresholdOutputArtifactCertificate {
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: [u8; 32],
    aggregate_artifact_digest: [u8; 32],
    provider_kat_evidence_digest: [u8; 32],
    threshold_output_source_digest: [u8; 32],
    threshold_output_source_package_digest: [u8; 32],
    transcript_binding_digest: [u8; 32],
    signer_set_digest: [u8; 32],
    attempt_binding_digest: [u8; 32],
    aggregate_response_digest: [u8; 32],
    hint_digest: [u8; 32],
    accepted_signature_digest: [u8; 32],
    standard_verifier_bridge_evidence_digest: [u8; 32],
    real_recomputation_evidence_digest: [u8; 32],
    claim_boundary: P1ThresholdOutputClaimBoundary,
}

impl P1SelectedBackendThresholdOutputArtifactCertificate {
    /// Return the selected backend profile bound to the threshold-output artifact.
    pub const fn selected_profile(self) -> SelectedProductionBackendProfile {
        self.selected_profile
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        &self.selected_profile_binding_digest
    }

    /// Borrow the predecessor aggregate artifact certificate digest.
    pub const fn aggregate_artifact_digest(&self) -> &[u8; 32] {
        &self.aggregate_artifact_digest
    }

    /// Borrow the provider KAT evidence digest inherited from the aggregate certificate.
    pub const fn provider_kat_evidence_digest(&self) -> &[u8; 32] {
        &self.provider_kat_evidence_digest
    }

    /// Borrow the reviewed threshold-output source digest.
    pub const fn threshold_output_source_digest(&self) -> &[u8; 32] {
        &self.threshold_output_source_digest
    }

    /// Borrow the digest of the reviewed threshold-output source package bytes.
    pub const fn threshold_output_source_package_digest(&self) -> &[u8; 32] {
        &self.threshold_output_source_package_digest
    }

    /// Borrow the transcript binding digest.
    pub const fn transcript_binding_digest(&self) -> &[u8; 32] {
        &self.transcript_binding_digest
    }

    /// Borrow the signer-set binding digest.
    pub const fn signer_set_digest(&self) -> &[u8; 32] {
        &self.signer_set_digest
    }

    /// Borrow the attempt binding digest.
    pub const fn attempt_binding_digest(&self) -> &[u8; 32] {
        &self.attempt_binding_digest
    }

    /// Borrow the accepted aggregate-response digest.
    pub const fn aggregate_response_digest(&self) -> &[u8; 32] {
        &self.aggregate_response_digest
    }

    /// Borrow the accepted hint digest.
    pub const fn hint_digest(&self) -> &[u8; 32] {
        &self.hint_digest
    }

    /// Borrow the accepted aggregate signature digest.
    pub const fn accepted_signature_digest(&self) -> &[u8; 32] {
        &self.accepted_signature_digest
    }

    /// Borrow the standard-verifier bridge evidence digest.
    pub const fn standard_verifier_bridge_evidence_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_bridge_evidence_digest
    }

    /// Borrow the real recomputation evidence digest.
    pub const fn real_recomputation_evidence_digest(&self) -> &[u8; 32] {
        &self.real_recomputation_evidence_digest
    }

    /// Return the explicit non-production claim boundary.
    pub const fn claim_boundary(self) -> P1ThresholdOutputClaimBoundary {
        self.claim_boundary
    }

    /// This gate still does not claim a real threshold signer is implemented.
    pub const fn claims_real_threshold_signer(self) -> bool {
        false
    }

    /// Artifact readiness does not claim a deployed production backend.
    pub const fn claims_selected_backend_production(self) -> bool {
        false
    }

    /// Artifact readiness does not claim completed standard-verifier compatibility proof.
    pub const fn claims_standard_verifier_compatibility(self) -> bool {
        false
    }

    /// This certificate gates artifacts; it does not replace cryptographic proof.
    pub const fn claims_completed_cryptographic_proof(self) -> bool {
        false
    }
}

/// Claim boundary carried by Batch 4 proof-closure artifact evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P1SelectedBackendProofClosureClaimBoundary {
    /// The artifact is present for conformance and proof review only.
    ProofReviewOnly,
    /// Forbidden boundary used to reject packages that try to claim production readiness.
    ProductionClaim,
}

/// Claim boundary carried by a P1 standard-verifier compatibility artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P1StandardVerifierCompatibilityClaimBoundary {
    /// The artifact is present for conformance and proof review only.
    ProofReviewOnly,
    /// Forbidden boundary used to reject packages that try to claim production readiness.
    ProductionClaim,
}

/// Standard verifier result bound into a compatibility artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P1StandardVerifierCompatibilityResult {
    /// The selected provider accepted `MLDSA65.Verify(pk, m, sigma)`.
    Accept,
    /// Forbidden result for a compatibility artifact.
    Reject,
}

/// Submitted P1 standard-verifier compatibility artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1StandardVerifierCompatibilityArtifactPackage {
    /// Selected backend profile this compatibility artifact binds.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Digest binding the selected backend profile.
    pub selected_profile_binding_digest: [u8; 32],
    /// Digest of this compatibility artifact payload.
    pub artifact_digest: [u8; 32],
    /// Digest of the predecessor threshold-output certificate.
    pub threshold_output_certificate_digest: [u8; 32],
    /// Provider KAT evidence digest inherited from the threshold-output certificate.
    pub provider_kat_evidence_digest: [u8; 32],
    /// Provider identity, build, and version digest for the standard verifier.
    pub provider_identity_digest: [u8; 32],
    /// Digest of the public ML-DSA-65 verification key `pk`.
    pub public_key_digest: [u8; 32],
    /// Digest of the original application message `m`.
    pub message_digest: [u8; 32],
    /// Digest binding this artifact to the production signing transcript.
    pub transcript_binding_digest: [u8; 32],
    /// Digest binding the accepted aggregate signer set.
    pub signer_set_digest: [u8; 32],
    /// Digest binding the single-use attempt ID and retry domain.
    pub attempt_binding_digest: [u8; 32],
    /// Accepted aggregate-response digest from `AggregateAccept`.
    pub aggregate_response_digest: [u8; 32],
    /// Accepted hint digest from `AggregateAccept`.
    pub hint_digest: [u8; 32],
    /// Provider-verified accepted signature digest for `sigma`.
    pub accepted_signature_digest: [u8; 32],
    /// Standard-verifier bridge evidence digest inherited from the threshold certificate.
    pub standard_verifier_bridge_evidence_digest: [u8; 32],
    /// Real recomputation evidence digest inherited from the threshold certificate.
    pub real_recomputation_evidence_digest: [u8; 32],
    /// Provider verifier result bound to the payload.
    pub verifier_result: P1StandardVerifierCompatibilityResult,
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1StandardVerifierCompatibilityClaimBoundary,
    /// Whether this artifact package has a named review signoff.
    pub reviewed: bool,
}

/// Accepted P1 standard-verifier compatibility artifact certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1StandardVerifierCompatibilityArtifactCertificate {
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: [u8; 32],
    artifact_digest: [u8; 32],
    threshold_output_certificate_digest: [u8; 32],
    provider_kat_evidence_digest: [u8; 32],
    provider_identity_digest: [u8; 32],
    public_key_digest: [u8; 32],
    message_digest: [u8; 32],
    transcript_binding_digest: [u8; 32],
    signer_set_digest: [u8; 32],
    attempt_binding_digest: [u8; 32],
    aggregate_response_digest: [u8; 32],
    hint_digest: [u8; 32],
    accepted_signature_digest: [u8; 32],
    standard_verifier_bridge_evidence_digest: [u8; 32],
    real_recomputation_evidence_digest: [u8; 32],
    verifier_result: P1StandardVerifierCompatibilityResult,
    claim_boundary: P1StandardVerifierCompatibilityClaimBoundary,
}

impl P1StandardVerifierCompatibilityArtifactCertificate {
    /// Return the selected backend profile bound to the compatibility artifact.
    pub const fn selected_profile(self) -> SelectedProductionBackendProfile {
        self.selected_profile
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        &self.selected_profile_binding_digest
    }

    /// Borrow the compatibility artifact payload digest.
    pub const fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }

    /// Borrow the predecessor threshold-output certificate digest.
    pub const fn threshold_output_certificate_digest(&self) -> &[u8; 32] {
        &self.threshold_output_certificate_digest
    }

    /// Borrow the provider KAT evidence digest.
    pub const fn provider_kat_evidence_digest(&self) -> &[u8; 32] {
        &self.provider_kat_evidence_digest
    }

    /// Borrow the provider identity/build/version digest.
    pub const fn provider_identity_digest(&self) -> &[u8; 32] {
        &self.provider_identity_digest
    }

    /// Borrow the public key digest for `pk`.
    pub const fn public_key_digest(&self) -> &[u8; 32] {
        &self.public_key_digest
    }

    /// Borrow the message digest for `m`.
    pub const fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }

    /// Borrow the transcript binding digest.
    pub const fn transcript_binding_digest(&self) -> &[u8; 32] {
        &self.transcript_binding_digest
    }

    /// Borrow the signer-set binding digest.
    pub const fn signer_set_digest(&self) -> &[u8; 32] {
        &self.signer_set_digest
    }

    /// Borrow the attempt binding digest.
    pub const fn attempt_binding_digest(&self) -> &[u8; 32] {
        &self.attempt_binding_digest
    }

    /// Borrow the accepted aggregate-response digest.
    pub const fn aggregate_response_digest(&self) -> &[u8; 32] {
        &self.aggregate_response_digest
    }

    /// Borrow the accepted hint digest.
    pub const fn hint_digest(&self) -> &[u8; 32] {
        &self.hint_digest
    }

    /// Borrow the accepted signature digest for `sigma`.
    pub const fn accepted_signature_digest(&self) -> &[u8; 32] {
        &self.accepted_signature_digest
    }

    /// Borrow the standard-verifier bridge evidence digest.
    pub const fn standard_verifier_bridge_evidence_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_bridge_evidence_digest
    }

    /// Borrow the real recomputation evidence digest.
    pub const fn real_recomputation_evidence_digest(&self) -> &[u8; 32] {
        &self.real_recomputation_evidence_digest
    }

    /// Return the provider verifier result bound into the artifact.
    pub const fn verifier_result(self) -> P1StandardVerifierCompatibilityResult {
        self.verifier_result
    }

    /// Return the explicit non-production claim boundary.
    pub const fn claim_boundary(self) -> P1StandardVerifierCompatibilityClaimBoundary {
        self.claim_boundary
    }

    /// Artifact readiness does not claim selected-backend proof closure.
    pub const fn claims_selected_backend_proof_closure(self) -> bool {
        false
    }

    /// Artifact readiness does not claim completed standard-verifier compatibility proof.
    pub const fn claims_standard_verifier_compatibility(self) -> bool {
        false
    }

    /// Artifact readiness does not claim rejection-distribution preservation.
    pub const fn claims_rejection_distribution_preservation(self) -> bool {
        false
    }

    /// Artifact readiness does not claim CAVP/ACVTS validation.
    pub const fn claims_cavp_acvts_validation(self) -> bool {
        false
    }

    /// Artifact readiness does not claim FIPS validation.
    pub const fn claims_fips_validation(self) -> bool {
        false
    }

    /// This certificate gates artifacts; it does not replace cryptographic proof.
    pub const fn claims_completed_cryptographic_proof(self) -> bool {
        false
    }
}

/// Evidence class for the P1 distributed nonce-producer artifact gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P1DistributedNonceProducerEvidence {
    /// Current hazmat PRF-output oracle; always fail-closed for this gate.
    HazmatPrfOutputOracle,
    /// Centralized expanded-secret-key nonce helper; always fail-closed.
    CentralizedExpandedSecretKeyHelper,
    /// Checked fixture harness evidence; useful for shape checks only.
    FixtureHarness,
    /// Ordinary single-key ML-DSA provider output; not threshold nonce provenance.
    StandardProviderSingleKey,
    /// Reviewed P1 Shamir nonce-DKG producer under the TEE/HSM coordinator profile.
    ReviewedP1ShamirNonceDkgTee,
}

impl P1DistributedNonceProducerEvidence {
    const fn tag(self) -> u8 {
        match self {
            Self::HazmatPrfOutputOracle => 0,
            Self::CentralizedExpandedSecretKeyHelper => 1,
            Self::FixtureHarness => 2,
            Self::StandardProviderSingleKey => 3,
            Self::ReviewedP1ShamirNonceDkgTee => 4,
        }
    }
}

/// Claim boundary for the P1 distributed nonce-producer artifact gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P1DistributedNonceProducerClaimBoundary {
    /// The artifact is present for conformance and proof review only.
    ProofReviewOnly,
    /// Forbidden boundary used to reject production or theorem-closure claims.
    ProductionClaim,
}

impl P1DistributedNonceProducerClaimBoundary {
    const fn tag(self) -> u8 {
        match self {
            Self::ProofReviewOnly => 0,
            Self::ProductionClaim => 1,
        }
    }
}

/// Backend-generated ML-DSA-65 distributed nonce-producer artifact material.
///
/// This is the byte-material handoff for a reviewed external P1 nonce producer.
/// It is converted into `P1DistributedNonceProducerArtifactPackage` by hashing
/// each material class with domain separation and binding the result to the
/// predecessor threshold-output and standard-verifier compatibility
/// certificates. Supplying this material does not implement threshold signing
/// inside this crate and does not close Criterion 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mldsa65DistributedNonceProducerArtifact<'a> {
    /// Reviewed source/reference package bytes for the nonce producer.
    pub source_reference: &'a [u8],
    /// Reviewed backend implementation bytes or implementation attestation.
    pub backend_implementation: &'a [u8],
    /// Coordinator TEE/HSM attestation evidence bytes.
    pub coordinator_attestation: &'a [u8],
    /// Shamir nonce-DKG transcript bytes.
    pub shamir_nonce_dkg_transcript: &'a [u8],
    /// Pairwise mask seed commitment bytes.
    pub pairwise_mask_seed_commitments: &'a [u8],
    /// Nonce-share commitment bytes.
    pub nonce_share_commitments: &'a [u8],
    /// Abort-accountability evidence bytes.
    pub abort_accountability: &'a [u8],
    /// External proof-review signoff bytes.
    pub external_review: &'a [u8],
    /// Explicit non-production claim boundary for the derived package.
    pub claim_boundary: P1DistributedNonceProducerClaimBoundary,
    /// Whether the external material has named review signoff.
    pub reviewed: bool,
}

/// Repo-generated request binding that a canonical nonce-producer capture must echo.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1DistributedNonceProducerRequestDigestBinding<'a> {
    /// Name of the request manifest answered by the capture.
    pub name: &'a str,
    /// SHA-256 digest of the canonical request JSON.
    pub request_sha256: [u8; 32],
}

/// Byte length for one imported ML-DSA-65 distributed nonce PRF output share.
pub const MLDSA65_DISTRIBUTED_NONCE_PRF_OUTPUT_SHARE_BYTES: usize = 32;

const MLDSA65_DISTRIBUTED_NONCE_PRF_SHARE_COMMITMENT_DOMAIN: &[u8] =
    b"lattice-aggregation:p1:distributed-nonce-prf-output-share-commitment:v1";
const MLDSA65_DISTRIBUTED_NONCE_PRF_MASKING_CONTRIBUTION_DOMAIN: &[u8] =
    b"lattice-aggregation:p1:distributed-nonce-prf-masking-contribution:v1";

/// Imported output share from a reviewed ML-DSA-65 distributed nonce PRF producer.
///
/// This type is the repo-side handoff boundary for externally generated P1
/// nonce material. It binds one producer-supplied output share to the request
/// digest and validator identity; it does not generate nonce material inside
/// this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mldsa65DistributedNoncePrfOutputShare {
    validator: ValidatorId,
    request_sha256: [u8; 32],
    share_index: u16,
    output_share: [u8; MLDSA65_DISTRIBUTED_NONCE_PRF_OUTPUT_SHARE_BYTES],
    commitment_digest: [u8; 32],
}

impl Mldsa65DistributedNoncePrfOutputShare {
    /// Construct a request-bound imported nonce PRF output share.
    pub const fn new(
        validator: ValidatorId,
        request_sha256: [u8; 32],
        share_index: u16,
        output_share: [u8; MLDSA65_DISTRIBUTED_NONCE_PRF_OUTPUT_SHARE_BYTES],
        commitment_digest: [u8; 32],
    ) -> Self {
        Self {
            validator,
            request_sha256,
            share_index,
            output_share,
            commitment_digest,
        }
    }

    /// Return the validator associated with this imported share.
    pub const fn validator(self) -> ValidatorId {
        self.validator
    }

    /// Return the canonical request SHA-256 digest this share answers.
    pub const fn request_sha256(self) -> [u8; 32] {
        self.request_sha256
    }

    /// Return the canonical share index from the producer output stream.
    pub const fn share_index(self) -> u16 {
        self.share_index
    }

    /// Return the imported nonce PRF output share bytes.
    pub const fn output_share(self) -> [u8; MLDSA65_DISTRIBUTED_NONCE_PRF_OUTPUT_SHARE_BYTES] {
        self.output_share
    }

    /// Return the request-bound commitment digest for this imported share.
    pub const fn commitment_digest(self) -> [u8; 32] {
        self.commitment_digest
    }
}

/// Split externally emitted ML-DSA-65 distributed nonce PRF output into shares.
///
/// The input buffer must already be emitted by a reviewed P1 backend capture:
/// one 32-byte output share per validator, ordered identically to
/// `validators`. This function only normalizes those bytes into request-bound
/// evidence objects for later import and masking-contribution derivation.
pub fn split_mldsa65_distributed_nonce_prf_output(
    request_sha256: [u8; 32],
    producer_output: &[u8],
    validators: &[ValidatorId],
) -> Result<Vec<Mldsa65DistributedNoncePrfOutputShare>, ThresholdError> {
    if validators.is_empty() {
        return Err(ThresholdError::InvalidThresholdParameters {
            threshold: 0,
            total_nodes: 0,
        });
    }
    let expected_len = validators
        .len()
        .checked_mul(MLDSA65_DISTRIBUTED_NONCE_PRF_OUTPUT_SHARE_BYTES)
        .ok_or(ThresholdError::MalformedSerialization {
            reason: "P1 distributed nonce PRF output share length overflow",
        })?;
    if producer_output.len() != expected_len {
        return Err(ThresholdError::MalformedSerialization {
            reason: "P1 distributed nonce PRF output length does not match validator set",
        });
    }

    let mut seen_validators = std::collections::BTreeSet::new();
    let mut shares = Vec::with_capacity(validators.len());
    for (offset, (validator, chunk)) in validators
        .iter()
        .copied()
        .zip(producer_output.chunks_exact(MLDSA65_DISTRIBUTED_NONCE_PRF_OUTPUT_SHARE_BYTES))
        .enumerate()
    {
        if !seen_validators.insert(validator.0) {
            return Err(ThresholdError::DuplicateValidator { validator });
        }
        let share_index =
            u16::try_from(offset).map_err(|_| ThresholdError::InvalidThresholdParameters {
                threshold: u16::MAX,
                total_nodes: u16::MAX,
            })?;
        let mut output_share = [0u8; MLDSA65_DISTRIBUTED_NONCE_PRF_OUTPUT_SHARE_BYTES];
        output_share.copy_from_slice(chunk);
        let commitment_digest = mldsa65_distributed_nonce_prf_share_commitment_digest(
            request_sha256,
            validator,
            share_index,
            &output_share,
        );
        shares.push(Mldsa65DistributedNoncePrfOutputShare::new(
            validator,
            request_sha256,
            share_index,
            output_share,
            commitment_digest,
        ));
    }
    Ok(shares)
}

/// Derive the request-bound masking contribution from an imported nonce PRF share.
///
/// This conversion binds the reviewed backend output share to the request,
/// validator, share index, and commitment digest. It is intentionally separate
/// from nonce generation so the admissible route remains an external backend
/// capture followed by repo-side import checks.
pub fn derive_mldsa65_distributed_nonce_prf_masking_contribution_from_share(
    nonce_share: &Mldsa65DistributedNoncePrfOutputShare,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(MLDSA65_DISTRIBUTED_NONCE_PRF_MASKING_CONTRIBUTION_DOMAIN);
    hasher.update(nonce_share.request_sha256);
    hasher.update(nonce_share.validator.0.to_be_bytes());
    hasher.update(nonce_share.share_index.to_be_bytes());
    hasher.update(nonce_share.output_share);
    hasher.update(nonce_share.commitment_digest);
    hasher.finalize().into()
}

fn mldsa65_distributed_nonce_prf_share_commitment_digest(
    request_sha256: [u8; 32],
    validator: ValidatorId,
    share_index: u16,
    output_share: &[u8; MLDSA65_DISTRIBUTED_NONCE_PRF_OUTPUT_SHARE_BYTES],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(MLDSA65_DISTRIBUTED_NONCE_PRF_SHARE_COMMITMENT_DOMAIN);
    hasher.update(request_sha256);
    hasher.update(validator.0.to_be_bytes());
    hasher.update(share_index.to_be_bytes());
    hasher.update(output_share);
    hasher.finalize().into()
}

/// Canonical JSON schema tag for P1 distributed nonce-producer captures.
pub const P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_SCHEMA: &str =
    "lattice-aggregation:p1-distributed-nonce-producer-capture:v1";
/// Canonical JSON schema tag for P1 distributed nonce-producer requests.
pub const P1_DISTRIBUTED_NONCE_PRODUCER_REQUEST_SCHEMA: &str =
    "lattice-aggregation:p1-distributed-nonce-producer-request:v1";
/// Evidence class for actual externally generated distributed nonce-producer captures.
pub const P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_EXTERNAL_EVIDENCE: &str =
    "p1_shamir_nonce_dkg_tee_external_capture";
const P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_CLAIM_BOUNDARY: &str =
    "conformance/proof-review evidence only";
const P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_SELECTED_PROFILE: &str =
    "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1";

/// Canonical external capture envelope for P1 distributed nonce-producer artifacts.
///
/// The capture schema is the future backend-to-proof-gate handoff for reviewed
/// nonce-DKG/PRF producer material. It carries source, implementation,
/// attestation, transcript, commitment, abort-accountability, predecessor, and
/// expected digest bindings. Importing this evidence does not close Criterion 2.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct P1DistributedNonceProducerCapture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    producer_evidence: String,
    note: String,
    #[serde(default)]
    request: Option<P1DistributedNonceProducerCaptureRequestBinding>,
    #[serde(default)]
    predecessors: Option<P1DistributedNonceProducerCapturePredecessors>,
    capture: P1DistributedNonceProducerCapturePayload,
    #[serde(default)]
    expected: Option<P1DistributedNonceProducerCaptureExpectedDigests>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1DistributedNonceProducerCaptureRequestBinding {
    schema: String,
    name: String,
    request_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1DistributedNonceProducerCapturePredecessors {
    selected_profile_binding_digest_hex: String,
    threshold_output_certificate_digest_hex: String,
    standard_verifier_compatibility_artifact_digest_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1DistributedNonceProducerCapturePayload {
    source_reference: P1DistributedNonceProducerCaptureBytes,
    backend_implementation: P1DistributedNonceProducerCaptureBytes,
    coordinator_attestation: P1DistributedNonceProducerCaptureBytes,
    shamir_nonce_dkg_transcript: P1DistributedNonceProducerCaptureBytes,
    pairwise_mask_seed_commitments: P1DistributedNonceProducerCaptureBytes,
    nonce_share_commitments: P1DistributedNonceProducerCaptureBytes,
    abort_accountability: P1DistributedNonceProducerCaptureBytes,
    external_review: P1DistributedNonceProducerCaptureBytes,
    reviewed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1DistributedNonceProducerCaptureBytes {
    encoding: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1DistributedNonceProducerCaptureExpectedDigests {
    source_reference_digest_hex: String,
    backend_implementation_digest_hex: String,
    coordinator_attestation_digest_hex: String,
    shamir_nonce_dkg_transcript_digest_hex: String,
    pairwise_mask_seed_commitment_digest_hex: String,
    nonce_share_commitment_digest_hex: String,
    abort_accountability_digest_hex: String,
    external_review_digest_hex: String,
    distributed_nonce_producer_artifact_digest_hex: String,
}

/// Owned nonce-producer material decoded from a canonical capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P1OwnedMldsa65DistributedNonceProducerArtifact {
    /// Reviewed source/reference package bytes for the nonce producer.
    pub source_reference: Vec<u8>,
    /// Reviewed backend implementation bytes or implementation attestation.
    pub backend_implementation: Vec<u8>,
    /// Coordinator TEE/HSM attestation evidence bytes.
    pub coordinator_attestation: Vec<u8>,
    /// Shamir nonce-DKG transcript bytes.
    pub shamir_nonce_dkg_transcript: Vec<u8>,
    /// Pairwise mask seed commitment bytes.
    pub pairwise_mask_seed_commitments: Vec<u8>,
    /// Nonce-share commitment bytes.
    pub nonce_share_commitments: Vec<u8>,
    /// Abort-accountability evidence bytes.
    pub abort_accountability: Vec<u8>,
    /// External proof-review signoff bytes.
    pub external_review: Vec<u8>,
    /// Explicit non-production claim boundary for the derived package.
    pub claim_boundary: P1DistributedNonceProducerClaimBoundary,
    /// Whether the external material has named review signoff.
    pub reviewed: bool,
}

impl P1OwnedMldsa65DistributedNonceProducerArtifact {
    /// Borrow this owned material as the existing nonce-producer adapter input.
    pub fn as_nonce_producer_artifact(&self) -> Mldsa65DistributedNonceProducerArtifact<'_> {
        Mldsa65DistributedNonceProducerArtifact {
            source_reference: &self.source_reference,
            backend_implementation: &self.backend_implementation,
            coordinator_attestation: &self.coordinator_attestation,
            shamir_nonce_dkg_transcript: &self.shamir_nonce_dkg_transcript,
            pairwise_mask_seed_commitments: &self.pairwise_mask_seed_commitments,
            nonce_share_commitments: &self.nonce_share_commitments,
            abort_accountability: &self.abort_accountability,
            external_review: &self.external_review,
            claim_boundary: self.claim_boundary,
            reviewed: self.reviewed,
        }
    }
}

impl P1DistributedNonceProducerCapture {
    /// Decode a canonical P1 distributed nonce-producer capture from JSON.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, ThresholdError> {
        serde_json::from_slice(bytes).map_err(|_| ThresholdError::MalformedSerialization {
            reason: "P1 distributed nonce-producer capture JSON is malformed",
        })
    }

    /// Encode this capture as stable pretty JSON for artifact handoff.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ThresholdError> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| {
            ThresholdError::MalformedSerialization {
                reason: "P1 distributed nonce-producer capture JSON could not be encoded",
            }
        })?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Return the capture name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the capture schema tag.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Return the capture producer evidence class.
    pub fn producer_evidence(&self) -> &str {
        &self.producer_evidence
    }

    /// Return the capture note.
    pub fn note(&self) -> &str {
        &self.note
    }

    /// Return the nonce-producer request name carried by the capture.
    pub fn request_name(&self) -> Option<&str> {
        self.request.as_ref().map(|request| request.name.as_str())
    }

    /// Return the nonce-producer request SHA-256 hex binding if present.
    pub fn request_sha256_hex(&self) -> Option<&str> {
        self.request
            .as_ref()
            .map(|request| request.request_sha256.as_str())
    }

    /// Decode the capture into owned nonce-producer material.
    pub fn to_nonce_producer_material(
        &self,
    ) -> Result<P1OwnedMldsa65DistributedNonceProducerArtifact, ThresholdError> {
        self.validate_capture_header()?;
        if self.producer_evidence != P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_EXTERNAL_EVIDENCE {
            return Err(ThresholdError::BackendUnavailable {
                reason: "P1 distributed nonce-producer capture requires actual P1 Shamir nonce-DKG/TEE producer evidence",
            });
        }

        Ok(P1OwnedMldsa65DistributedNonceProducerArtifact {
            source_reference: self.capture.source_reference.decode()?,
            backend_implementation: self.capture.backend_implementation.decode()?,
            coordinator_attestation: self.capture.coordinator_attestation.decode()?,
            shamir_nonce_dkg_transcript: self.capture.shamir_nonce_dkg_transcript.decode()?,
            pairwise_mask_seed_commitments: self.capture.pairwise_mask_seed_commitments.decode()?,
            nonce_share_commitments: self.capture.nonce_share_commitments.decode()?,
            abort_accountability: self.capture.abort_accountability.decode()?,
            external_review: self.capture.external_review.decode()?,
            claim_boundary: P1DistributedNonceProducerClaimBoundary::ProofReviewOnly,
            reviewed: self.capture.reviewed,
        })
    }

    fn validate_capture_header(&self) -> Result<(), ThresholdError> {
        if self.schema != P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_SCHEMA {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 distributed nonce-producer capture schema mismatch",
            });
        }
        if self.claim_boundary != P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_CLAIM_BOUNDARY {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 distributed nonce-producer capture must remain proof-review-only",
            });
        }
        if self.selected_profile != P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_SELECTED_PROFILE {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 distributed nonce-producer capture selected profile mismatch",
            });
        }
        self.validated_request_binding()?;
        Ok(())
    }

    fn validated_request_binding(&self) -> Result<(&str, [u8; 32]), ThresholdError> {
        let Some(request) = &self.request else {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 distributed nonce-producer capture requires request digest binding",
            });
        };
        if request.schema != P1_DISTRIBUTED_NONCE_PRODUCER_REQUEST_SCHEMA
            || request.name.trim().is_empty()
        {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 distributed nonce-producer capture requires request digest binding",
            });
        }
        let request_sha256 = decode_hex_array::<32>(
            &request.request_sha256,
            "P1 distributed nonce-producer capture request SHA-256 hex is malformed",
        )?;
        if is_all_zero(&request_sha256) {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 distributed nonce-producer capture requires request digest binding",
            });
        }
        Ok((request.name.as_str(), request_sha256))
    }

    fn validate_expected_request_binding(
        &self,
        request_binding: P1DistributedNonceProducerRequestDigestBinding<'_>,
    ) -> Result<(), ThresholdError> {
        if request_binding.name.trim().is_empty() || is_all_zero(&request_binding.request_sha256) {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 distributed nonce-producer capture requires request digest binding",
            });
        }
        let (capture_name, capture_sha256) = self.validated_request_binding()?;
        if capture_name != request_binding.name || capture_sha256 != request_binding.request_sha256
        {
            return Err(ThresholdError::TranscriptMismatch);
        }
        Ok(())
    }

    fn validate_predecessors(
        &self,
        threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
        compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    ) -> Result<(), ThresholdError> {
        let Some(predecessors) = &self.predecessors else {
            return Err(ThresholdError::MalformedSerialization {
                reason:
                    "P1 distributed nonce-producer capture requires predecessor certificate digests",
            });
        };

        let selected_profile_binding_digest = decode_hex_array::<32>(
            &predecessors.selected_profile_binding_digest_hex,
            "P1 distributed nonce-producer capture selected profile binding digest hex is malformed",
        )?;
        if selected_profile_binding_digest
            != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
                .profile_binding_digest()
            || &selected_profile_binding_digest
                != threshold_certificate.selected_profile_binding_digest()
            || &selected_profile_binding_digest
                != compatibility_certificate.selected_profile_binding_digest()
        {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let threshold_output_certificate_digest = decode_hex_array::<32>(
            &predecessors.threshold_output_certificate_digest_hex,
            "P1 distributed nonce-producer capture threshold-output certificate digest hex is malformed",
        )?;
        if threshold_output_certificate_digest
            != derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate)
        {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let standard_verifier_compatibility_artifact_digest = decode_hex_array::<32>(
            &predecessors.standard_verifier_compatibility_artifact_digest_hex,
            "P1 distributed nonce-producer capture compatibility artifact digest hex is malformed",
        )?;
        if standard_verifier_compatibility_artifact_digest
            != derive_p1_standard_verifier_compatibility_artifact_digest(compatibility_certificate)
        {
            return Err(ThresholdError::TranscriptMismatch);
        }

        Ok(())
    }

    fn validate_expected_digests(
        &self,
        package: &P1DistributedNonceProducerArtifactPackage,
    ) -> Result<(), ThresholdError> {
        let Some(expected) = &self.expected else {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 distributed nonce-producer capture requires expected package digests",
            });
        };

        for (actual, expected_hex, reason) in [
            (
                &package.source_reference_digest,
                expected.source_reference_digest_hex.as_str(),
                "P1 distributed nonce-producer capture expected source reference digest mismatch",
            ),
            (
                &package.backend_implementation_digest,
                expected.backend_implementation_digest_hex.as_str(),
                "P1 distributed nonce-producer capture expected implementation digest mismatch",
            ),
            (
                &package.coordinator_attestation_digest,
                expected.coordinator_attestation_digest_hex.as_str(),
                "P1 distributed nonce-producer capture expected coordinator attestation digest mismatch",
            ),
            (
                &package.shamir_nonce_dkg_transcript_digest,
                expected.shamir_nonce_dkg_transcript_digest_hex.as_str(),
                "P1 distributed nonce-producer capture expected Shamir nonce-DKG transcript digest mismatch",
            ),
            (
                &package.pairwise_mask_seed_commitment_digest,
                expected.pairwise_mask_seed_commitment_digest_hex.as_str(),
                "P1 distributed nonce-producer capture expected pairwise mask seed commitment digest mismatch",
            ),
            (
                &package.nonce_share_commitment_digest,
                expected.nonce_share_commitment_digest_hex.as_str(),
                "P1 distributed nonce-producer capture expected nonce-share commitment digest mismatch",
            ),
            (
                &package.abort_accountability_digest,
                expected.abort_accountability_digest_hex.as_str(),
                "P1 distributed nonce-producer capture expected abort-accountability digest mismatch",
            ),
            (
                &package.external_review_digest,
                expected.external_review_digest_hex.as_str(),
                "P1 distributed nonce-producer capture expected external review digest mismatch",
            ),
            (
                &package.distributed_nonce_producer_artifact_digest,
                expected
                    .distributed_nonce_producer_artifact_digest_hex
                    .as_str(),
                "P1 distributed nonce-producer capture expected artifact digest mismatch",
            ),
        ] {
            let expected_digest = decode_hex_array::<32>(
                expected_hex,
                "P1 distributed nonce-producer capture expected digest hex is malformed",
            )?;
            if actual != &expected_digest {
                return Err(ThresholdError::TranscriptMismatch);
            }
            if is_all_zero(actual) {
                return Err(ThresholdError::MalformedSerialization { reason });
            }
        }

        Ok(())
    }
}

impl P1DistributedNonceProducerCaptureBytes {
    fn decode(&self) -> Result<Vec<u8>, ThresholdError> {
        match self.encoding.as_str() {
            "utf8" => Ok(self.value.as_bytes().to_vec()),
            "hex" => decode_hex_vec(
                &self.value,
                "P1 distributed nonce-producer capture byte hex is malformed",
            ),
            _ => Err(ThresholdError::MalformedSerialization {
                reason: "unsupported P1 distributed nonce-producer capture byte encoding",
            }),
        }
    }
}

/// Submitted P1 distributed nonce-producer artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1DistributedNonceProducerArtifactPackage {
    /// Selected backend profile this producer artifact binds.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Digest binding the selected backend profile.
    pub selected_profile_binding_digest: [u8; 32],
    /// Producer evidence class used by this artifact.
    pub producer_evidence: P1DistributedNonceProducerEvidence,
    /// Digest of the reviewed source/reference material.
    pub source_reference_digest: [u8; 32],
    /// Digest of the reviewed backend implementation material.
    pub backend_implementation_digest: [u8; 32],
    /// Digest of the coordinator attestation or HSM/TEE identity evidence.
    pub coordinator_attestation_digest: [u8; 32],
    /// Digest of the Shamir nonce-DKG transcript.
    pub shamir_nonce_dkg_transcript_digest: [u8; 32],
    /// Digest binding the active signer set.
    pub active_set_digest: [u8; 32],
    /// Digest of pairwise mask seed commitments.
    pub pairwise_mask_seed_commitment_digest: [u8; 32],
    /// Digest of nonce-share commitments.
    pub nonce_share_commitment_digest: [u8; 32],
    /// Digest binding the signing attempt and retry domain.
    pub attempt_binding_digest: [u8; 32],
    /// Digest of abort-accountability evidence.
    pub abort_accountability_digest: [u8; 32],
    /// Digest of the standard-verifier bridge evidence bound to this output.
    pub standard_verifier_bridge_digest: [u8; 32],
    /// Digest of external review evidence.
    pub external_review_digest: [u8; 32],
    /// Digest of this distributed nonce-producer artifact payload.
    pub distributed_nonce_producer_artifact_digest: [u8; 32],
    /// Digest of the predecessor threshold-output certificate.
    pub threshold_output_certificate_digest: [u8; 32],
    /// Digest of the predecessor standard-verifier compatibility artifact.
    pub standard_verifier_compatibility_artifact_digest: [u8; 32],
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1DistributedNonceProducerClaimBoundary,
    /// Whether this artifact package has a named review signoff.
    pub reviewed: bool,
}

/// Accepted P1 distributed nonce-producer artifact certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1DistributedNonceProducerArtifactCertificate {
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: [u8; 32],
    source_reference_digest: [u8; 32],
    backend_implementation_digest: [u8; 32],
    coordinator_attestation_digest: [u8; 32],
    shamir_nonce_dkg_transcript_digest: [u8; 32],
    active_set_digest: [u8; 32],
    pairwise_mask_seed_commitment_digest: [u8; 32],
    nonce_share_commitment_digest: [u8; 32],
    attempt_binding_digest: [u8; 32],
    abort_accountability_digest: [u8; 32],
    standard_verifier_bridge_digest: [u8; 32],
    external_review_digest: [u8; 32],
    distributed_nonce_producer_artifact_digest: [u8; 32],
    threshold_output_certificate_digest: [u8; 32],
    standard_verifier_compatibility_artifact_digest: [u8; 32],
    claim_boundary: P1DistributedNonceProducerClaimBoundary,
}

impl P1DistributedNonceProducerArtifactCertificate {
    /// Return the selected backend profile bound to the producer artifact.
    pub const fn selected_profile(self) -> SelectedProductionBackendProfile {
        self.selected_profile
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        &self.selected_profile_binding_digest
    }

    /// Borrow the source/reference digest.
    pub const fn source_reference_digest(&self) -> &[u8; 32] {
        &self.source_reference_digest
    }

    /// Borrow the backend implementation digest.
    pub const fn backend_implementation_digest(&self) -> &[u8; 32] {
        &self.backend_implementation_digest
    }

    /// Borrow the coordinator attestation digest.
    pub const fn coordinator_attestation_digest(&self) -> &[u8; 32] {
        &self.coordinator_attestation_digest
    }

    /// Borrow the Shamir nonce-DKG transcript digest.
    pub const fn shamir_nonce_dkg_transcript_digest(&self) -> &[u8; 32] {
        &self.shamir_nonce_dkg_transcript_digest
    }

    /// Borrow the active signer-set digest.
    pub const fn active_set_digest(&self) -> &[u8; 32] {
        &self.active_set_digest
    }

    /// Borrow the pairwise mask seed commitment digest.
    pub const fn pairwise_mask_seed_commitment_digest(&self) -> &[u8; 32] {
        &self.pairwise_mask_seed_commitment_digest
    }

    /// Borrow the nonce-share commitment digest.
    pub const fn nonce_share_commitment_digest(&self) -> &[u8; 32] {
        &self.nonce_share_commitment_digest
    }

    /// Borrow the attempt binding digest.
    pub const fn attempt_binding_digest(&self) -> &[u8; 32] {
        &self.attempt_binding_digest
    }

    /// Borrow the abort-accountability digest.
    pub const fn abort_accountability_digest(&self) -> &[u8; 32] {
        &self.abort_accountability_digest
    }

    /// Borrow the standard-verifier bridge digest.
    pub const fn standard_verifier_bridge_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_bridge_digest
    }

    /// Borrow the external review digest.
    pub const fn external_review_digest(&self) -> &[u8; 32] {
        &self.external_review_digest
    }

    /// Borrow the distributed nonce-producer artifact digest.
    pub const fn distributed_nonce_producer_artifact_digest(&self) -> &[u8; 32] {
        &self.distributed_nonce_producer_artifact_digest
    }

    /// Borrow the predecessor threshold-output certificate digest.
    pub const fn threshold_output_certificate_digest(&self) -> &[u8; 32] {
        &self.threshold_output_certificate_digest
    }

    /// Borrow the predecessor standard-verifier compatibility artifact digest.
    pub const fn standard_verifier_compatibility_artifact_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_compatibility_artifact_digest
    }

    /// Return the explicit non-production claim boundary.
    pub const fn claim_boundary(self) -> P1DistributedNonceProducerClaimBoundary {
        self.claim_boundary
    }

    /// Artifact readiness does not claim theorem closure.
    pub const fn claims_theorem_closure(self) -> bool {
        false
    }

    /// Artifact readiness does not claim selected-backend proof closure.
    pub const fn claims_selected_backend_proof_closure(self) -> bool {
        false
    }

    /// Artifact readiness does not claim production threshold ML-DSA security.
    pub const fn claims_production_threshold_mldsa_security(self) -> bool {
        false
    }

    /// Artifact readiness does not claim rejection-distribution preservation.
    pub const fn claims_rejection_distribution_preservation(self) -> bool {
        false
    }

    /// Artifact readiness does not claim completed standard-verifier compatibility.
    pub const fn claims_standard_verifier_compatibility_complete(self) -> bool {
        false
    }
}

/// Backend evidence class for the 10,000-validator real-threshold verifier contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P1RealThresholdVerifierClosureBackendEvidence {
    /// Deterministic simulation evidence; always fail-closed for this contract.
    SimulatedDeterministic,
    /// Ordinary single-key ML-DSA standard-provider output; not threshold provenance.
    StandardProviderSingleKey,
    /// Checked fixture harness evidence; useful for ingestion-shape checks only.
    FixtureHarness,
    /// Evidence from a real threshold ML-DSA backend implementation.
    RealThresholdMldsa,
}

/// Claim boundary for the 10,000-validator real-threshold verifier contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P1RealThresholdVerifierClosureClaimBoundary {
    /// The artifact is present for conformance and proof review only.
    ProofReviewOnly,
    /// Forbidden boundary used to reject production or theorem-closure claims.
    ProductionClaim,
}

/// Submitted real-threshold backend emission artifact package for P1.
///
/// This package is the ingestion surface for future real threshold backend
/// output. It binds a reviewed backend emission artifact to the predecessor
/// threshold-output and standard-verifier compatibility certificates without
/// claiming that this repository implements the backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1RealThresholdBackendEmissionArtifactPackage {
    /// Selected backend profile this emission package binds.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Digest binding the selected backend profile.
    pub selected_profile_binding_digest: [u8; 32],
    /// Number of validators in the closure target.
    pub validator_count: u32,
    /// Threshold required for the closure target.
    pub threshold: u32,
    /// Emitted aggregate signature byte length.
    pub aggregate_signature_len: usize,
    /// Backend evidence class used by the emission artifact.
    pub backend_evidence: P1RealThresholdVerifierClosureBackendEvidence,
    /// Digest of reviewed real-threshold backend evidence.
    pub backend_evidence_digest: [u8; 32],
    /// Digest of the external source package emitted by the backend.
    pub backend_source_package_digest: [u8; 32],
    /// Digest identifying the backend implementation/build under review.
    pub backend_implementation_digest: [u8; 32],
    /// Digest binding the backend signing transcript and participant set.
    pub backend_transcript_digest: [u8; 32],
    /// Digest of this emission artifact payload.
    pub artifact_digest: [u8; 32],
    /// Digest of the predecessor threshold-output certificate.
    pub threshold_output_certificate_digest: [u8; 32],
    /// Digest of the standard-verifier compatibility artifact.
    pub standard_verifier_compatibility_artifact_digest: [u8; 32],
    /// Digest of the public ML-DSA-65 verification key `pk`.
    pub public_key_digest: [u8; 32],
    /// Digest of the original application message `m`.
    pub message_digest: [u8; 32],
    /// Digest binding this artifact to the production signing transcript.
    pub transcript_binding_digest: [u8; 32],
    /// Digest binding the accepted aggregate signer set.
    pub signer_set_digest: [u8; 32],
    /// Digest binding the single-use attempt ID and retry domain.
    pub attempt_binding_digest: [u8; 32],
    /// Provider-verified accepted signature digest for `sigma`.
    pub accepted_signature_digest: [u8; 32],
    /// Standard verifier result for `MLDSA65.Verify(pk, m, sigma)`.
    pub verifier_result: P1StandardVerifierCompatibilityResult,
    /// Whether the same verifier rejected a mutated message.
    pub mutated_message_rejected: bool,
    /// Whether the same verifier rejected a mutated public key.
    pub mutated_public_key_rejected: bool,
    /// Whether the same verifier rejected a mutated signature.
    pub mutated_signature_rejected: bool,
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1RealThresholdVerifierClosureClaimBoundary,
    /// Whether this artifact package has a named review signoff.
    pub reviewed: bool,
}

/// Backend-generated material submitted to the P1 real-threshold emission gate.
///
/// This is an import boundary for an external threshold backend. It carries the
/// backend provenance bytes and verifier tuple that must already match the
/// predecessor threshold-output and standard-verifier compatibility
/// certificates. Constructing this value does not implement a threshold backend
/// and does not bypass the artifact assessment gate.
#[derive(Clone, Copy, Debug)]
pub struct P1RealThresholdBackendEmissionOutput<'a> {
    /// Reviewed backend source package bytes or canonical manifest bytes.
    pub backend_source_package: &'a [u8],
    /// Reviewed backend implementation/build identity bytes.
    pub backend_implementation: &'a [u8],
    /// Reviewed backend signing transcript bytes.
    pub backend_transcript: &'a [u8],
    /// Standard ML-DSA-65 public verification key emitted by the backend.
    pub public_key: &'a ThresholdPublicKey,
    /// Original application message verified by the standard verifier.
    pub message: &'a [u8],
    /// Accepted aggregate signature emitted by the backend.
    pub aggregate_signature: &'a ThresholdSignature,
    /// Whether the standard verifier rejected the same signature over a mutated message.
    pub mutated_message_rejected: bool,
    /// Whether the standard verifier rejected the same signature under a mutated public key.
    pub mutated_public_key_rejected: bool,
    /// Whether the standard verifier rejected a mutated signature over the same tuple.
    pub mutated_signature_rejected: bool,
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1RealThresholdVerifierClosureClaimBoundary,
    /// Whether this backend emission output has named review signoff.
    pub reviewed: bool,
}

/// Repo-generated request binding that a canonical backend capture must echo.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1RealThresholdBackendEmissionRequestDigestBinding<'a> {
    /// Name of the request manifest answered by the capture.
    pub name: &'a str,
    /// SHA-256 digest of the canonical request JSON.
    pub request_sha256: [u8; 32],
}

/// Canonical JSON schema tag for P1 real-threshold backend emission captures.
pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA: &str =
    "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1";
/// Canonical JSON schema tag for P1 real-threshold backend emission requests.
pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_REQUEST_SCHEMA: &str =
    "lattice-aggregation:p1-real-threshold-backend-emission-request:v1";
/// Evidence class for actual externally generated real-threshold captures.
pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_EXTERNAL_EVIDENCE: &str =
    "real_threshold_mldsa_external_capture";
/// Evidence class for the checked schema fixture that must remain blocked.
pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA_FIXTURE_EVIDENCE: &str =
    "real_threshold_mldsa_capture_schema_fixture";
/// Gate label for the actual backend capture runner.
pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_ACTUAL_CAPTURE_RUNNER_GATE: &str =
    "p1_real_threshold_backend_actual_capture_runner_gate";
const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_CLAIM_BOUNDARY: &str =
    "conformance/proof-review evidence only";
const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SELECTED_PROFILE: &str =
    "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1";

/// Canonical external capture envelope for P1 real-threshold backend emissions.
///
/// The capture schema is the future backend-to-proof-gate handoff format. It
/// can carry backend provenance bytes, the accepted standard-verifier tuple,
/// predecessor digest bindings, and expected package digests. It is not itself
/// proof closure; conversion still feeds the existing provider-verified adapter
/// and the assessment gate must accept the derived package.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct P1RealThresholdBackendEmissionCapture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    backend_evidence: String,
    note: String,
    #[serde(default)]
    request: Option<P1RealThresholdBackendEmissionCaptureRequestBinding>,
    #[serde(default)]
    predecessors: Option<P1RealThresholdBackendEmissionCapturePredecessors>,
    capture: P1RealThresholdBackendEmissionCapturePayload,
    #[serde(default)]
    expected: Option<P1RealThresholdBackendEmissionCaptureExpectedDigests>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1RealThresholdBackendEmissionCaptureRequestBinding {
    schema: String,
    name: String,
    request_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1RealThresholdBackendEmissionCapturePredecessors {
    selected_profile_binding_digest_hex: String,
    threshold_output_certificate_digest_hex: String,
    standard_verifier_compatibility_artifact_digest_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1RealThresholdBackendEmissionCapturePayload {
    validator_count: u32,
    threshold: u32,
    aggregate_signature_len: usize,
    public_key_hex: String,
    message: P1RealThresholdBackendEmissionCaptureBytes,
    aggregate_signature_hex: String,
    backend_source_package: P1RealThresholdBackendEmissionCaptureBytes,
    backend_implementation: P1RealThresholdBackendEmissionCaptureBytes,
    backend_transcript: P1RealThresholdBackendEmissionCaptureBytes,
    mutated_message_rejected: bool,
    mutated_public_key_rejected: bool,
    mutated_signature_rejected: bool,
    reviewed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1RealThresholdBackendEmissionCaptureBytes {
    encoding: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct P1RealThresholdBackendEmissionCaptureExpectedDigests {
    backend_evidence_digest_hex: String,
    backend_source_package_digest_hex: String,
    backend_implementation_digest_hex: String,
    backend_transcript_digest_hex: String,
    artifact_digest_hex: String,
    public_key_digest_hex: String,
    message_digest_hex: String,
    accepted_signature_digest_hex: String,
}

/// Owned backend-output material decoded from a canonical capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P1OwnedRealThresholdBackendEmissionOutput {
    /// Reviewed backend source package bytes or canonical manifest bytes.
    pub backend_source_package: Vec<u8>,
    /// Reviewed backend implementation/build identity bytes.
    pub backend_implementation: Vec<u8>,
    /// Reviewed backend signing transcript bytes.
    pub backend_transcript: Vec<u8>,
    /// Standard ML-DSA-65 public verification key emitted by the backend.
    pub public_key: ThresholdPublicKey,
    /// Original application message verified by the standard verifier.
    pub message: Vec<u8>,
    /// Accepted aggregate signature emitted by the backend.
    pub aggregate_signature: ThresholdSignature,
    /// Whether the standard verifier rejected the same signature over a mutated message.
    pub mutated_message_rejected: bool,
    /// Whether the standard verifier rejected the same signature under a mutated public key.
    pub mutated_public_key_rejected: bool,
    /// Whether the standard verifier rejected a mutated signature over the same tuple.
    pub mutated_signature_rejected: bool,
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1RealThresholdVerifierClosureClaimBoundary,
    /// Whether this backend emission output has named review signoff.
    pub reviewed: bool,
}

impl P1OwnedRealThresholdBackendEmissionOutput {
    /// Borrow this owned material as the existing backend-emission adapter input.
    pub fn as_backend_output(&self) -> P1RealThresholdBackendEmissionOutput<'_> {
        P1RealThresholdBackendEmissionOutput {
            backend_source_package: &self.backend_source_package,
            backend_implementation: &self.backend_implementation,
            backend_transcript: &self.backend_transcript,
            public_key: &self.public_key,
            message: &self.message,
            aggregate_signature: &self.aggregate_signature,
            mutated_message_rejected: self.mutated_message_rejected,
            mutated_public_key_rejected: self.mutated_public_key_rejected,
            mutated_signature_rejected: self.mutated_signature_rejected,
            claim_boundary: self.claim_boundary,
            reviewed: self.reviewed,
        }
    }
}

impl P1RealThresholdBackendEmissionCapture {
    /// Decode a canonical P1 real-threshold backend emission capture from JSON.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, ThresholdError> {
        serde_json::from_slice(bytes).map_err(|_| ThresholdError::MalformedSerialization {
            reason: "P1 real-threshold backend emission capture JSON is malformed",
        })
    }

    /// Encode this capture as stable pretty JSON for artifact handoff.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ThresholdError> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| {
            ThresholdError::MalformedSerialization {
                reason: "P1 real-threshold backend emission capture JSON could not be encoded",
            }
        })?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Return the capture name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the capture schema tag.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Return the capture backend evidence class.
    pub fn backend_evidence(&self) -> &str {
        &self.backend_evidence
    }

    /// Return the capture note.
    pub fn note(&self) -> &str {
        &self.note
    }

    /// Return the backend emission request name if the capture carries one.
    pub fn request_name(&self) -> Option<&str> {
        self.request.as_ref().map(|request| request.name.as_str())
    }

    /// Return the backend emission request SHA-256 hex binding if present.
    pub fn request_sha256_hex(&self) -> Option<&str> {
        self.request
            .as_ref()
            .map(|request| request.request_sha256.as_str())
    }

    /// Return the validator count carried by the capture target.
    pub const fn validator_count(&self) -> u32 {
        self.capture.validator_count
    }

    /// Return the threshold carried by the capture target.
    pub const fn threshold(&self) -> u32 {
        self.capture.threshold
    }

    /// Return the aggregate signature length carried by the capture target.
    pub const fn aggregate_signature_len(&self) -> usize {
        self.capture.aggregate_signature_len
    }

    /// Decode the capture into owned backend-output material.
    ///
    /// This method intentionally blocks schema fixtures and all non-external
    /// evidence before decoding tuple material, so checked fixture envelopes can
    /// live in the repository without becoming accepted backend evidence.
    pub fn to_backend_output_material(
        &self,
    ) -> Result<P1OwnedRealThresholdBackendEmissionOutput, ThresholdError> {
        self.validate_capture_header()?;
        if self.backend_evidence != P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_EXTERNAL_EVIDENCE {
            return Err(ThresholdError::BackendUnavailable {
                reason: "P1 real-threshold backend emission capture requires actual real threshold ML-DSA backend evidence",
            });
        }
        if self.capture.validator_count != 10_000 || self.capture.threshold != 6_667 {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 real-threshold backend emission capture must bind 10,000 validators with threshold 6,667",
            });
        }
        if self.capture.aggregate_signature_len != MLDSA65_SIGNATURE_BYTES {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 real-threshold backend emission capture aggregate signature must be 3,309 bytes",
            });
        }

        let public_key = decode_hex_array::<MLDSA65_PUBLICKEY_BYTES>(
            &self.capture.public_key_hex,
            "P1 real-threshold backend emission capture public key hex is malformed",
        )?;
        let aggregate_signature = decode_hex_array::<MLDSA65_SIGNATURE_BYTES>(
            &self.capture.aggregate_signature_hex,
            "P1 real-threshold backend emission capture aggregate signature hex is malformed",
        )?;

        Ok(P1OwnedRealThresholdBackendEmissionOutput {
            backend_source_package: self.capture.backend_source_package.decode()?,
            backend_implementation: self.capture.backend_implementation.decode()?,
            backend_transcript: self.capture.backend_transcript.decode()?,
            public_key: ThresholdPublicKey(public_key),
            message: self.capture.message.decode()?,
            aggregate_signature: ThresholdSignature(aggregate_signature),
            mutated_message_rejected: self.capture.mutated_message_rejected,
            mutated_public_key_rejected: self.capture.mutated_public_key_rejected,
            mutated_signature_rejected: self.capture.mutated_signature_rejected,
            claim_boundary: P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
            reviewed: self.capture.reviewed,
        })
    }

    fn validate_capture_header(&self) -> Result<(), ThresholdError> {
        if self.schema != P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 real-threshold backend emission capture schema mismatch",
            });
        }
        if self.claim_boundary != P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_CLAIM_BOUNDARY {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 real-threshold backend emission capture must remain proof-review-only",
            });
        }
        if self.selected_profile != P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SELECTED_PROFILE {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 real-threshold backend emission capture selected profile mismatch",
            });
        }
        self.validate_request_binding()?;
        Ok(())
    }

    fn validate_request_binding(&self) -> Result<(), ThresholdError> {
        let Some(request) = &self.request else {
            return Err(ThresholdError::MalformedSerialization {
                reason:
                    "P1 real-threshold backend emission capture requires request digest binding",
            });
        };
        if request.schema != P1_REAL_THRESHOLD_BACKEND_EMISSION_REQUEST_SCHEMA
            || request.name.trim().is_empty()
        {
            return Err(ThresholdError::MalformedSerialization {
                reason:
                    "P1 real-threshold backend emission capture requires request digest binding",
            });
        }
        let request_sha256 = decode_hex_array::<32>(
            &request.request_sha256,
            "P1 real-threshold backend emission capture request SHA-256 hex is malformed",
        )?;
        if is_all_zero(&request_sha256) {
            return Err(ThresholdError::MalformedSerialization {
                reason:
                    "P1 real-threshold backend emission capture requires request digest binding",
            });
        }
        Ok(())
    }

    fn validate_predecessors(
        &self,
        threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
        compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    ) -> Result<(), ThresholdError> {
        let Some(predecessors) = &self.predecessors else {
            return Err(ThresholdError::MalformedSerialization {
                reason: "P1 real-threshold backend emission capture requires predecessor certificate digests",
            });
        };

        let selected_profile_binding_digest = decode_hex_array::<32>(
            &predecessors.selected_profile_binding_digest_hex,
            "P1 real-threshold backend emission capture selected profile binding digest hex is malformed",
        )?;
        if selected_profile_binding_digest
            != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
                .profile_binding_digest()
            || &selected_profile_binding_digest
                != threshold_certificate.selected_profile_binding_digest()
            || &selected_profile_binding_digest
                != compatibility_certificate.selected_profile_binding_digest()
        {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let threshold_output_certificate_digest = decode_hex_array::<32>(
            &predecessors.threshold_output_certificate_digest_hex,
            "P1 real-threshold backend emission capture threshold-output certificate digest hex is malformed",
        )?;
        if threshold_output_certificate_digest
            != derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate)
        {
            return Err(ThresholdError::TranscriptMismatch);
        }

        let standard_verifier_compatibility_artifact_digest = decode_hex_array::<32>(
            &predecessors.standard_verifier_compatibility_artifact_digest_hex,
            "P1 real-threshold backend emission capture compatibility artifact digest hex is malformed",
        )?;
        if standard_verifier_compatibility_artifact_digest
            != derive_p1_standard_verifier_compatibility_artifact_digest(compatibility_certificate)
        {
            return Err(ThresholdError::TranscriptMismatch);
        }

        Ok(())
    }

    fn validate_expected_digests(
        &self,
        package: &P1RealThresholdBackendEmissionArtifactPackage,
    ) -> Result<(), ThresholdError> {
        let Some(expected) = &self.expected else {
            return Err(ThresholdError::MalformedSerialization {
                reason:
                    "P1 real-threshold backend emission capture requires expected package digests",
            });
        };

        for (actual, expected_hex, reason) in [
            (
                &package.backend_evidence_digest,
                expected.backend_evidence_digest_hex.as_str(),
                "P1 real-threshold backend emission capture expected backend evidence digest mismatch",
            ),
            (
                &package.backend_source_package_digest,
                expected.backend_source_package_digest_hex.as_str(),
                "P1 real-threshold backend emission capture expected source package digest mismatch",
            ),
            (
                &package.backend_implementation_digest,
                expected.backend_implementation_digest_hex.as_str(),
                "P1 real-threshold backend emission capture expected implementation digest mismatch",
            ),
            (
                &package.backend_transcript_digest,
                expected.backend_transcript_digest_hex.as_str(),
                "P1 real-threshold backend emission capture expected transcript digest mismatch",
            ),
            (
                &package.artifact_digest,
                expected.artifact_digest_hex.as_str(),
                "P1 real-threshold backend emission capture expected artifact digest mismatch",
            ),
            (
                &package.public_key_digest,
                expected.public_key_digest_hex.as_str(),
                "P1 real-threshold backend emission capture expected public key digest mismatch",
            ),
            (
                &package.message_digest,
                expected.message_digest_hex.as_str(),
                "P1 real-threshold backend emission capture expected message digest mismatch",
            ),
            (
                &package.accepted_signature_digest,
                expected.accepted_signature_digest_hex.as_str(),
                "P1 real-threshold backend emission capture expected accepted signature digest mismatch",
            ),
        ] {
            let expected_digest = decode_hex_array::<32>(
                expected_hex,
                "P1 real-threshold backend emission capture expected digest hex is malformed",
            )?;
            if actual != &expected_digest {
                return Err(ThresholdError::TranscriptMismatch);
            }
            if is_all_zero(actual) {
                return Err(ThresholdError::MalformedSerialization { reason });
            }
        }

        Ok(())
    }
}

impl P1RealThresholdBackendEmissionCaptureBytes {
    fn hex(bytes: &[u8]) -> Self {
        Self {
            encoding: "hex".to_owned(),
            value: encode_hex(bytes),
        }
    }

    fn decode(&self) -> Result<Vec<u8>, ThresholdError> {
        match self.encoding.as_str() {
            "utf8" => Ok(self.value.as_bytes().to_vec()),
            "hex" => decode_hex_vec(
                &self.value,
                "P1 real-threshold backend emission capture byte hex is malformed",
            ),
            _ => Err(ThresholdError::MalformedSerialization {
                reason: "unsupported P1 real-threshold backend emission capture byte encoding",
            }),
        }
    }
}

/// Accepted real-threshold backend emission artifact certificate for P1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1RealThresholdBackendEmissionArtifactCertificate {
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: [u8; 32],
    validator_count: u32,
    threshold: u32,
    aggregate_signature_len: usize,
    backend_evidence_digest: [u8; 32],
    backend_source_package_digest: [u8; 32],
    backend_implementation_digest: [u8; 32],
    backend_transcript_digest: [u8; 32],
    artifact_digest: [u8; 32],
    threshold_output_certificate_digest: [u8; 32],
    standard_verifier_compatibility_artifact_digest: [u8; 32],
    public_key_digest: [u8; 32],
    message_digest: [u8; 32],
    transcript_binding_digest: [u8; 32],
    signer_set_digest: [u8; 32],
    attempt_binding_digest: [u8; 32],
    accepted_signature_digest: [u8; 32],
    verifier_result: P1StandardVerifierCompatibilityResult,
    mutated_message_rejected: bool,
    mutated_public_key_rejected: bool,
    mutated_signature_rejected: bool,
    claim_boundary: P1RealThresholdVerifierClosureClaimBoundary,
}

impl P1RealThresholdBackendEmissionArtifactCertificate {
    /// Return the selected backend profile bound to the backend emission artifact.
    pub const fn selected_profile(self) -> SelectedProductionBackendProfile {
        self.selected_profile
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        &self.selected_profile_binding_digest
    }

    /// Return the validator count bound to the artifact.
    pub const fn validator_count(self) -> u32 {
        self.validator_count
    }

    /// Return the threshold bound to the artifact.
    pub const fn threshold(self) -> u32 {
        self.threshold
    }

    /// Return the aggregate signature length bound to the artifact.
    pub const fn aggregate_signature_len(self) -> usize {
        self.aggregate_signature_len
    }

    /// Borrow the reviewed real-threshold backend evidence digest.
    pub const fn backend_evidence_digest(&self) -> &[u8; 32] {
        &self.backend_evidence_digest
    }

    /// Borrow the external backend source package digest.
    pub const fn backend_source_package_digest(&self) -> &[u8; 32] {
        &self.backend_source_package_digest
    }

    /// Borrow the backend implementation digest.
    pub const fn backend_implementation_digest(&self) -> &[u8; 32] {
        &self.backend_implementation_digest
    }

    /// Borrow the backend transcript digest.
    pub const fn backend_transcript_digest(&self) -> &[u8; 32] {
        &self.backend_transcript_digest
    }

    /// Borrow the emission artifact payload digest.
    pub const fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }

    /// Borrow the predecessor threshold-output certificate digest.
    pub const fn threshold_output_certificate_digest(&self) -> &[u8; 32] {
        &self.threshold_output_certificate_digest
    }

    /// Borrow the standard-verifier compatibility artifact digest.
    pub const fn standard_verifier_compatibility_artifact_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_compatibility_artifact_digest
    }

    /// Borrow the public key digest.
    pub const fn public_key_digest(&self) -> &[u8; 32] {
        &self.public_key_digest
    }

    /// Borrow the message digest.
    pub const fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }

    /// Borrow the transcript binding digest.
    pub const fn transcript_binding_digest(&self) -> &[u8; 32] {
        &self.transcript_binding_digest
    }

    /// Borrow the signer-set digest.
    pub const fn signer_set_digest(&self) -> &[u8; 32] {
        &self.signer_set_digest
    }

    /// Borrow the attempt binding digest.
    pub const fn attempt_binding_digest(&self) -> &[u8; 32] {
        &self.attempt_binding_digest
    }

    /// Borrow the accepted signature digest.
    pub const fn accepted_signature_digest(&self) -> &[u8; 32] {
        &self.accepted_signature_digest
    }

    /// Return the verifier result bound to the artifact.
    pub const fn verifier_result(self) -> P1StandardVerifierCompatibilityResult {
        self.verifier_result
    }

    /// Return true when all mutation rejection checks are present.
    pub const fn mutation_rejection_corpus_complete(self) -> bool {
        self.mutated_message_rejected
            && self.mutated_public_key_rejected
            && self.mutated_signature_rejected
    }

    /// Return the explicit non-production claim boundary.
    pub const fn claim_boundary(self) -> P1RealThresholdVerifierClosureClaimBoundary {
        self.claim_boundary
    }

    /// Convert the accepted emission artifact into the stricter verifier closure contract package.
    pub const fn to_verifier_closure_package(self) -> P1RealThresholdVerifierClosurePackage {
        P1RealThresholdVerifierClosurePackage {
            selected_profile: self.selected_profile,
            selected_profile_binding_digest: self.selected_profile_binding_digest,
            validator_count: self.validator_count,
            threshold: self.threshold,
            aggregate_signature_len: self.aggregate_signature_len,
            backend_evidence: P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa,
            backend_evidence_digest: self.backend_evidence_digest,
            threshold_output_certificate_digest: self.threshold_output_certificate_digest,
            standard_verifier_compatibility_artifact_digest: self
                .standard_verifier_compatibility_artifact_digest,
            verifier_result: self.verifier_result,
            mutated_message_rejected: self.mutated_message_rejected,
            mutated_public_key_rejected: self.mutated_public_key_rejected,
            mutated_signature_rejected: self.mutated_signature_rejected,
            claim_boundary: self.claim_boundary,
            reviewed: true,
        }
    }

    /// Artifact readiness does not claim this repo has implemented the backend.
    pub const fn claims_real_threshold_backend_implemented(self) -> bool {
        false
    }

    /// Artifact readiness does not claim production threshold ML-DSA security.
    pub const fn claims_production_threshold_mldsa_security(self) -> bool {
        false
    }

    /// Artifact readiness does not claim CAVP/ACVTS validation.
    pub const fn claims_cavp_acvts_validation(self) -> bool {
        false
    }

    /// Artifact readiness does not claim FIPS validation.
    pub const fn claims_fips_validation(self) -> bool {
        false
    }

    /// This certificate gates backend emission evidence; it does not close the theorem.
    pub const fn claims_completed_cryptographic_proof(self) -> bool {
        false
    }
}

/// Submitted 10,000-validator real-threshold verifier closure contract package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1RealThresholdVerifierClosurePackage {
    /// Selected backend profile this contract package binds.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Digest binding the selected backend profile.
    pub selected_profile_binding_digest: [u8; 32],
    /// Number of validators in the closure target.
    pub validator_count: u32,
    /// Threshold required for the closure target.
    pub threshold: u32,
    /// Emitted aggregate signature byte length.
    pub aggregate_signature_len: usize,
    /// Backend evidence class used by the package.
    pub backend_evidence: P1RealThresholdVerifierClosureBackendEvidence,
    /// Digest of reviewed real-threshold backend evidence.
    pub backend_evidence_digest: [u8; 32],
    /// Digest of the predecessor threshold-output certificate.
    pub threshold_output_certificate_digest: [u8; 32],
    /// Digest of the standard-verifier compatibility artifact.
    pub standard_verifier_compatibility_artifact_digest: [u8; 32],
    /// Standard verifier result for `MLDSA65.Verify(pk, m, sigma)`.
    pub verifier_result: P1StandardVerifierCompatibilityResult,
    /// Whether the same verifier rejected a mutated message.
    pub mutated_message_rejected: bool,
    /// Whether the same verifier rejected a mutated public key.
    pub mutated_public_key_rejected: bool,
    /// Whether the same verifier rejected a mutated signature.
    pub mutated_signature_rejected: bool,
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1RealThresholdVerifierClosureClaimBoundary,
    /// Whether this contract package has a named review signoff.
    pub reviewed: bool,
}

/// Accepted 10,000-validator real-threshold verifier contract certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1RealThresholdVerifierClosureCertificate {
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: [u8; 32],
    validator_count: u32,
    threshold: u32,
    aggregate_signature_len: usize,
    backend_evidence_digest: [u8; 32],
    threshold_output_certificate_digest: [u8; 32],
    standard_verifier_compatibility_artifact_digest: [u8; 32],
    verifier_result: P1StandardVerifierCompatibilityResult,
    mutated_message_rejected: bool,
    mutated_public_key_rejected: bool,
    mutated_signature_rejected: bool,
    claim_boundary: P1RealThresholdVerifierClosureClaimBoundary,
}

impl P1RealThresholdVerifierClosureCertificate {
    /// Return the selected backend profile bound to the verifier contract.
    pub const fn selected_profile(self) -> SelectedProductionBackendProfile {
        self.selected_profile
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        &self.selected_profile_binding_digest
    }

    /// Return the validator count bound to the contract.
    pub const fn validator_count(self) -> u32 {
        self.validator_count
    }

    /// Return the threshold bound to the contract.
    pub const fn threshold(self) -> u32 {
        self.threshold
    }

    /// Return the aggregate signature length bound to the contract.
    pub const fn aggregate_signature_len(self) -> usize {
        self.aggregate_signature_len
    }

    /// Borrow the reviewed real-threshold backend evidence digest.
    pub const fn backend_evidence_digest(&self) -> &[u8; 32] {
        &self.backend_evidence_digest
    }

    /// Borrow the predecessor threshold-output certificate digest.
    pub const fn threshold_output_certificate_digest(&self) -> &[u8; 32] {
        &self.threshold_output_certificate_digest
    }

    /// Borrow the standard-verifier compatibility artifact digest.
    pub const fn standard_verifier_compatibility_artifact_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_compatibility_artifact_digest
    }

    /// Return the verifier result bound to the contract.
    pub const fn verifier_result(self) -> P1StandardVerifierCompatibilityResult {
        self.verifier_result
    }

    /// Return true when all mutation rejection checks are present.
    pub const fn mutation_rejection_corpus_complete(self) -> bool {
        self.mutated_message_rejected
            && self.mutated_public_key_rejected
            && self.mutated_signature_rejected
    }

    /// Return the explicit non-production claim boundary.
    pub const fn claim_boundary(self) -> P1RealThresholdVerifierClosureClaimBoundary {
        self.claim_boundary
    }

    /// Contract readiness does not claim production threshold ML-DSA security.
    pub const fn claims_production_threshold_mldsa_security(self) -> bool {
        false
    }

    /// Contract readiness does not claim CAVP/ACVTS validation.
    pub const fn claims_cavp_acvts_validation(self) -> bool {
        false
    }

    /// Contract readiness does not claim FIPS validation.
    pub const fn claims_fips_validation(self) -> bool {
        false
    }

    /// This certificate gates a reviewed tuple; it does not close the theorem.
    pub const fn claims_completed_cryptographic_proof(self) -> bool {
        false
    }
}

/// Submitted Batch 4 selected-backend proof-closure artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1SelectedBackendProofClosureArtifactPackage {
    /// Selected backend profile this proof-closure artifact claims to bind.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Digest binding the selected backend profile.
    pub selected_profile_binding_digest: [u8; 32],
    /// Digest of the predecessor selected-backend threshold-output certificate.
    pub threshold_output_certificate_digest: [u8; 32],
    /// Digest of the predecessor selected-backend aggregate artifact certificate.
    pub aggregate_artifact_digest: [u8; 32],
    /// Reviewed threshold-output source digest inherited from the predecessor certificate.
    pub threshold_output_source_digest: [u8; 32],
    /// Reviewed threshold-output source-package digest inherited from the predecessor certificate.
    pub threshold_output_source_package_digest: [u8; 32],
    /// Provider KAT evidence digest inherited from the predecessor certificate.
    pub provider_kat_evidence_digest: [u8; 32],
    /// Standard-verifier bridge evidence digest inherited from the predecessor certificate.
    pub standard_verifier_bridge_evidence_digest: [u8; 32],
    /// Real recomputation evidence digest inherited from the predecessor certificate.
    pub real_recomputation_evidence_digest: [u8; 32],
    /// Distributed nonce-producer artifact digest for the selected producer path.
    pub distributed_nonce_producer_artifact_digest: [u8; 32],
    /// Digest binding this package to the production signing transcript.
    pub transcript_binding_digest: [u8; 32],
    /// Digest binding the accepted aggregate signer set.
    pub signer_set_digest: [u8; 32],
    /// Digest binding the single-use attempt ID and retry domain.
    pub attempt_binding_digest: [u8; 32],
    /// Accepted aggregate-response digest from `AggregateAccept`.
    pub aggregate_response_digest: [u8; 32],
    /// Accepted hint digest from `AggregateAccept`.
    pub hint_digest: [u8; 32],
    /// Provider-verified accepted aggregate signature digest.
    pub accepted_signature_digest: [u8; 32],
    /// Reviewed proof artifact digests linked to this selected-backend output.
    pub proof_artifacts: P1RejectionProofArtifacts,
    /// Typed Criterion 2 proof-slot artifacts linked to this selected-backend output.
    pub proof_slot_artifacts: P1Criterion2ProofSlotArtifacts,
    /// Digest of full KAT or validation artifacts beyond the bounded fixture set.
    pub full_kat_validation_artifact_digest: [u8; 32],
    /// Digest of rejection-distribution review artifacts for this selected backend.
    pub rejection_distribution_review_digest: [u8; 32],
    /// Digest of standard-verifier compatibility review artifacts.
    pub standard_verifier_compatibility_artifact_digest: [u8; 32],
    /// Assessed standard-verifier compatibility artifact certificate.
    pub standard_verifier_compatibility_artifact:
        P1StandardVerifierCompatibilityArtifactCertificate,
    /// Digest linking implementation evidence to the theorem/proof obligation package.
    pub theorem_linkage_artifact_digest: [u8; 32],
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    /// Whether this artifact package has a named review signoff.
    pub reviewed: bool,
}

/// Accepted Batch 4 selected-backend proof-closure artifact-gate certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1SelectedBackendProofClosureArtifactCertificate {
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: [u8; 32],
    threshold_output_certificate_digest: [u8; 32],
    aggregate_artifact_digest: [u8; 32],
    threshold_output_source_digest: [u8; 32],
    threshold_output_source_package_digest: [u8; 32],
    provider_kat_evidence_digest: [u8; 32],
    standard_verifier_bridge_evidence_digest: [u8; 32],
    real_recomputation_evidence_digest: [u8; 32],
    transcript_binding_digest: [u8; 32],
    signer_set_digest: [u8; 32],
    attempt_binding_digest: [u8; 32],
    aggregate_response_digest: [u8; 32],
    hint_digest: [u8; 32],
    accepted_signature_digest: [u8; 32],
    proof_artifacts: P1RejectionProofArtifacts,
    full_kat_validation_artifact_digest: [u8; 32],
    rejection_distribution_review_digest: [u8; 32],
    threshold_output_certificate_artifact_digest: [u8; 32],
    real_recomputation_evidence_artifact_digest: [u8; 32],
    distributed_nonce_producer_artifact_digest: [u8; 32],
    standard_verifier_compatibility_artifact_digest: [u8; 32],
    theorem_linkage_artifact_digest: [u8; 32],
    claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
}

impl P1SelectedBackendProofClosureArtifactCertificate {
    /// Return the selected backend profile bound to the proof-closure artifact.
    pub const fn selected_profile(self) -> SelectedProductionBackendProfile {
        self.selected_profile
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        &self.selected_profile_binding_digest
    }

    /// Borrow the predecessor threshold-output certificate digest.
    pub const fn threshold_output_certificate_digest(&self) -> &[u8; 32] {
        &self.threshold_output_certificate_digest
    }

    /// Borrow the predecessor aggregate artifact certificate digest.
    pub const fn aggregate_artifact_digest(&self) -> &[u8; 32] {
        &self.aggregate_artifact_digest
    }

    /// Borrow the reviewed threshold-output source digest.
    pub const fn threshold_output_source_digest(&self) -> &[u8; 32] {
        &self.threshold_output_source_digest
    }

    /// Borrow the reviewed threshold-output source-package digest.
    pub const fn threshold_output_source_package_digest(&self) -> &[u8; 32] {
        &self.threshold_output_source_package_digest
    }

    /// Borrow the provider KAT evidence digest.
    pub const fn provider_kat_evidence_digest(&self) -> &[u8; 32] {
        &self.provider_kat_evidence_digest
    }

    /// Borrow the standard-verifier bridge evidence digest.
    pub const fn standard_verifier_bridge_evidence_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_bridge_evidence_digest
    }

    /// Borrow the real recomputation evidence digest.
    pub const fn real_recomputation_evidence_digest(&self) -> &[u8; 32] {
        &self.real_recomputation_evidence_digest
    }

    /// Borrow the transcript binding digest.
    pub const fn transcript_binding_digest(&self) -> &[u8; 32] {
        &self.transcript_binding_digest
    }

    /// Borrow the signer-set binding digest.
    pub const fn signer_set_digest(&self) -> &[u8; 32] {
        &self.signer_set_digest
    }

    /// Borrow the attempt binding digest.
    pub const fn attempt_binding_digest(&self) -> &[u8; 32] {
        &self.attempt_binding_digest
    }

    /// Borrow the accepted aggregate-response digest.
    pub const fn aggregate_response_digest(&self) -> &[u8; 32] {
        &self.aggregate_response_digest
    }

    /// Borrow the accepted hint digest.
    pub const fn hint_digest(&self) -> &[u8; 32] {
        &self.hint_digest
    }

    /// Borrow the accepted aggregate signature digest.
    pub const fn accepted_signature_digest(&self) -> &[u8; 32] {
        &self.accepted_signature_digest
    }

    /// Borrow the full KAT/validation artifact digest.
    pub const fn full_kat_validation_artifact_digest(&self) -> &[u8; 32] {
        &self.full_kat_validation_artifact_digest
    }

    /// Borrow the rejection-distribution review digest.
    pub const fn rejection_distribution_review_digest(&self) -> &[u8; 32] {
        &self.rejection_distribution_review_digest
    }

    /// Borrow the typed threshold-output certificate predecessor artifact digest.
    pub const fn threshold_output_certificate_artifact_digest(&self) -> &[u8; 32] {
        &self.threshold_output_certificate_artifact_digest
    }

    /// Borrow the typed real recomputation predecessor artifact digest.
    pub const fn real_recomputation_evidence_artifact_digest(&self) -> &[u8; 32] {
        &self.real_recomputation_evidence_artifact_digest
    }

    /// Borrow the typed distributed nonce-producer artifact digest.
    pub const fn distributed_nonce_producer_artifact_digest(&self) -> &[u8; 32] {
        &self.distributed_nonce_producer_artifact_digest
    }

    /// Borrow the standard-verifier compatibility artifact digest.
    pub const fn standard_verifier_compatibility_artifact_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_compatibility_artifact_digest
    }

    /// Borrow the theorem-linkage artifact digest.
    pub const fn theorem_linkage_artifact_digest(&self) -> &[u8; 32] {
        &self.theorem_linkage_artifact_digest
    }

    /// Return the explicit non-production claim boundary.
    pub const fn claim_boundary(self) -> P1SelectedBackendProofClosureClaimBoundary {
        self.claim_boundary
    }

    /// This gate still does not claim a real threshold signer is implemented.
    pub const fn claims_real_threshold_signer(self) -> bool {
        false
    }

    /// Artifact readiness does not claim a deployed production backend.
    pub const fn claims_selected_backend_production(self) -> bool {
        false
    }

    /// Artifact readiness does not claim selected-backend proof closure.
    pub const fn claims_selected_backend_proof_closure(self) -> bool {
        false
    }

    /// Artifact readiness does not claim completed standard-verifier compatibility proof.
    pub const fn claims_standard_verifier_compatibility(self) -> bool {
        false
    }

    /// Artifact readiness does not claim rejection-distribution preservation.
    pub const fn claims_rejection_distribution_preservation(self) -> bool {
        false
    }

    /// Artifact readiness does not claim CAVP/ACVTS validation.
    pub const fn claims_cavp_acvts_validation(self) -> bool {
        false
    }

    /// Artifact readiness does not claim FIPS validation.
    pub const fn claims_fips_validation(self) -> bool {
        false
    }

    /// This certificate gates artifacts; it does not replace cryptographic proof.
    pub const fn claims_completed_cryptographic_proof(self) -> bool {
        false
    }
}

/// Submitted Batch 7 external-backend cryptographic closure-candidate package.
///
/// This is a wrapper over actual distributed nonce-producer evidence, real
/// threshold backend emission evidence, standard-verifier compatibility
/// evidence, and a rejection-distribution comparison artifact. Readiness here
/// means the artifact bundle is coherent enough for proof review; it is not
/// theorem closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1ExternalBackendCryptographicClosureCandidatePackage {
    /// Selected backend profile this closure-candidate package claims to bind.
    pub selected_profile: SelectedProductionBackendProfile,
    /// Digest binding the selected backend profile.
    pub selected_profile_binding_digest: [u8; 32],
    /// Digest of the predecessor selected-backend threshold-output certificate.
    pub threshold_output_certificate_digest: [u8; 32],
    /// Digest of the accepted distributed nonce-producer artifact.
    pub distributed_nonce_producer_artifact_digest: [u8; 32],
    /// Accepted distributed nonce-producer artifact certificate.
    pub distributed_nonce_producer_artifact: P1DistributedNonceProducerArtifactCertificate,
    /// Digest of the accepted real-threshold backend emission artifact.
    pub real_threshold_backend_emission_artifact_digest: [u8; 32],
    /// Accepted real-threshold backend emission artifact certificate.
    pub real_threshold_backend_emission_artifact: P1RealThresholdBackendEmissionArtifactCertificate,
    /// Digest of the standard-verifier compatibility artifact.
    pub standard_verifier_compatibility_artifact_digest: [u8; 32],
    /// Accepted standard-verifier compatibility artifact certificate.
    pub standard_verifier_compatibility_artifact:
        P1StandardVerifierCompatibilityArtifactCertificate,
    /// Digest of the rejection-distribution comparison artifact.
    pub rejection_distribution_comparison_digest: [u8; 32],
    /// Typed rejection-distribution comparison artifact.
    pub rejection_distribution_comparison_artifact: P1Criterion2ProofSlotArtifact,
    /// Digest of the full Batch 7 candidate package.
    pub candidate_artifact_digest: [u8; 32],
    /// Explicit non-production claim boundary.
    pub claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    /// Whether this candidate package has a named review signoff.
    pub reviewed: bool,
}

/// Accepted Batch 7 external-backend cryptographic closure-candidate certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1ExternalBackendCryptographicClosureCandidateCertificate {
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: [u8; 32],
    threshold_output_certificate_digest: [u8; 32],
    distributed_nonce_producer_artifact_digest: [u8; 32],
    real_threshold_backend_emission_artifact_digest: [u8; 32],
    standard_verifier_compatibility_artifact_digest: [u8; 32],
    rejection_distribution_comparison_digest: [u8; 32],
    candidate_artifact_digest: [u8; 32],
    claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
}

impl P1ExternalBackendCryptographicClosureCandidateCertificate {
    /// Return the selected backend profile bound to the candidate artifact.
    pub const fn selected_profile(self) -> SelectedProductionBackendProfile {
        self.selected_profile
    }

    /// Borrow the selected profile binding digest.
    pub const fn selected_profile_binding_digest(&self) -> &[u8; 32] {
        &self.selected_profile_binding_digest
    }

    /// Borrow the predecessor threshold-output certificate digest.
    pub const fn threshold_output_certificate_digest(&self) -> &[u8; 32] {
        &self.threshold_output_certificate_digest
    }

    /// Borrow the distributed nonce-producer artifact digest.
    pub const fn distributed_nonce_producer_artifact_digest(&self) -> &[u8; 32] {
        &self.distributed_nonce_producer_artifact_digest
    }

    /// Borrow the real-threshold backend emission artifact digest.
    pub const fn real_threshold_backend_emission_artifact_digest(&self) -> &[u8; 32] {
        &self.real_threshold_backend_emission_artifact_digest
    }

    /// Borrow the standard-verifier compatibility artifact digest.
    pub const fn standard_verifier_compatibility_artifact_digest(&self) -> &[u8; 32] {
        &self.standard_verifier_compatibility_artifact_digest
    }

    /// Borrow the rejection-distribution comparison artifact digest.
    pub const fn rejection_distribution_comparison_digest(&self) -> &[u8; 32] {
        &self.rejection_distribution_comparison_digest
    }

    /// Borrow the full candidate artifact digest.
    pub const fn candidate_artifact_digest(&self) -> &[u8; 32] {
        &self.candidate_artifact_digest
    }

    /// Return the explicit non-production claim boundary.
    pub const fn claim_boundary(self) -> P1SelectedBackendProofClosureClaimBoundary {
        self.claim_boundary
    }

    /// Candidate readiness does not mark Criterion 2 as met.
    pub const fn claims_criterion2_met(self) -> bool {
        false
    }

    /// Candidate readiness does not claim selected-backend proof closure.
    pub const fn claims_selected_backend_proof_closure(self) -> bool {
        false
    }

    /// Candidate readiness does not claim completed standard-verifier compatibility proof.
    pub const fn claims_standard_verifier_compatibility(self) -> bool {
        false
    }

    /// Candidate readiness does not claim rejection-distribution preservation.
    pub const fn claims_rejection_distribution_preservation(self) -> bool {
        false
    }

    /// Candidate readiness does not claim production threshold ML-DSA security.
    pub const fn claims_production_threshold_mldsa_security(self) -> bool {
        false
    }

    /// Candidate readiness does not claim CAVP/ACVTS validation.
    pub const fn claims_cavp_acvts_validation(self) -> bool {
        false
    }

    /// Candidate readiness does not claim FIPS validation.
    pub const fn claims_fips_validation(self) -> bool {
        false
    }

    /// Candidate readiness does not claim theorem closure.
    pub const fn claims_theorem_closure(self) -> bool {
        false
    }

    /// This certificate gates artifacts; it does not replace cryptographic proof.
    pub const fn claims_completed_cryptographic_proof(self) -> bool {
        false
    }
}

/// Result of assessing a selected-backend threshold-output artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum P1SelectedBackendThresholdOutputArtifactAssessment {
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
    /// The threshold-output artifact is ready for proof review.
    ArtifactReady(P1SelectedBackendThresholdOutputArtifactCertificate),
}

impl P1SelectedBackendThresholdOutputArtifactAssessment {
    /// Return true when the selected-backend threshold-output artifact is ready for proof review.
    pub const fn is_artifact_ready(self) -> bool {
        matches!(self, Self::ArtifactReady(_))
    }

    /// Borrow the threshold-output artifact certificate when present.
    pub const fn threshold_output_certificate(
        &self,
    ) -> Option<&P1SelectedBackendThresholdOutputArtifactCertificate> {
        match self {
            Self::ArtifactReady(certificate) => Some(certificate),
            Self::Missing { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Result of assessing a selected-backend proof-closure artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum P1SelectedBackendProofClosureArtifactAssessment {
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
    /// The proof-closure artifact package is ready for proof review.
    ArtifactReady(P1SelectedBackendProofClosureArtifactCertificate),
}

impl P1SelectedBackendProofClosureArtifactAssessment {
    /// Return true when the proof-closure artifact is ready for proof review.
    pub const fn is_artifact_ready(self) -> bool {
        matches!(self, Self::ArtifactReady(_))
    }

    /// Borrow the proof-closure artifact certificate when present.
    pub const fn proof_closure_certificate(
        &self,
    ) -> Option<&P1SelectedBackendProofClosureArtifactCertificate> {
        match self {
            Self::ArtifactReady(certificate) => Some(certificate),
            Self::Missing { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Result of assessing a Batch 7 external-backend cryptographic closure candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum P1ExternalBackendCryptographicClosureCandidateAssessment {
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
    /// The external-backend candidate package is ready for proof review.
    CandidateReady(P1ExternalBackendCryptographicClosureCandidateCertificate),
}

impl P1ExternalBackendCryptographicClosureCandidateAssessment {
    /// Return true when the candidate artifact is ready for proof review.
    pub const fn is_candidate_ready(self) -> bool {
        matches!(self, Self::CandidateReady(_))
    }

    /// Borrow the closure-candidate certificate when present.
    pub const fn closure_candidate_certificate(
        &self,
    ) -> Option<&P1ExternalBackendCryptographicClosureCandidateCertificate> {
        match self {
            Self::CandidateReady(certificate) => Some(certificate),
            Self::Missing { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Result of assessing a P1 standard-verifier compatibility artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum P1StandardVerifierCompatibilityArtifactAssessment {
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
    /// The compatibility artifact is ready for proof review.
    ArtifactReady(P1StandardVerifierCompatibilityArtifactCertificate),
}

impl P1StandardVerifierCompatibilityArtifactAssessment {
    /// Return true when the compatibility artifact is ready for proof review.
    pub const fn is_artifact_ready(self) -> bool {
        matches!(self, Self::ArtifactReady(_))
    }

    /// Borrow the compatibility artifact certificate when present.
    pub const fn standard_verifier_compatibility_certificate(
        &self,
    ) -> Option<&P1StandardVerifierCompatibilityArtifactCertificate> {
        match self {
            Self::ArtifactReady(certificate) => Some(certificate),
            Self::Missing { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Result of assessing a real-threshold backend emission artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum P1RealThresholdBackendEmissionArtifactAssessment {
    /// The artifact has no real-threshold backend evidence and must fail closed.
    BlockedFailClosed {
        /// Static reason for the fail-closed assessment.
        reason: &'static str,
    },
    /// A supplied package failed deterministic validation.
    Invalid {
        /// Static reason for the invalid-evidence assessment.
        reason: &'static str,
    },
    /// The backend emission artifact is ready for proof review.
    ArtifactReady(P1RealThresholdBackendEmissionArtifactCertificate),
}

impl P1RealThresholdBackendEmissionArtifactAssessment {
    /// Return true when the backend emission artifact is ready for proof review.
    pub const fn is_artifact_ready(self) -> bool {
        matches!(self, Self::ArtifactReady(_))
    }

    /// Borrow the backend emission artifact certificate when present.
    pub const fn backend_emission_certificate(
        &self,
    ) -> Option<&P1RealThresholdBackendEmissionArtifactCertificate> {
        match self {
            Self::ArtifactReady(certificate) => Some(certificate),
            Self::BlockedFailClosed { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Result of assessing a P1 distributed nonce-producer artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum P1DistributedNonceProducerArtifactAssessment {
    /// The artifact has no reviewed distributed nonce-producer evidence and must fail closed.
    BlockedFailClosed {
        /// Static reason for the fail-closed assessment.
        reason: &'static str,
    },
    /// A supplied package failed deterministic validation.
    Invalid {
        /// Static reason for the invalid-evidence assessment.
        reason: &'static str,
    },
    /// The distributed nonce-producer artifact is ready for proof review.
    ArtifactReady(P1DistributedNonceProducerArtifactCertificate),
}

impl P1DistributedNonceProducerArtifactAssessment {
    /// Return true when the distributed nonce-producer artifact is ready for proof review.
    pub const fn is_artifact_ready(self) -> bool {
        matches!(self, Self::ArtifactReady(_))
    }

    /// Borrow the distributed nonce-producer artifact certificate when present.
    pub const fn distributed_nonce_producer_certificate(
        &self,
    ) -> Option<&P1DistributedNonceProducerArtifactCertificate> {
        match self {
            Self::ArtifactReady(certificate) => Some(certificate),
            Self::BlockedFailClosed { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Result of assessing the 10,000-validator real-threshold verifier contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum P1RealThresholdVerifierClosureAssessment {
    /// The contract has no real-threshold backend evidence and must fail closed.
    BlockedFailClosed {
        /// Static reason for the fail-closed assessment.
        reason: &'static str,
    },
    /// A supplied package failed deterministic validation.
    Invalid {
        /// Static reason for the invalid-evidence assessment.
        reason: &'static str,
    },
    /// The verifier contract tuple is ready for proof review.
    ClosureReady(P1RealThresholdVerifierClosureCertificate),
}

impl P1RealThresholdVerifierClosureAssessment {
    /// Return true when the verifier contract tuple is ready for proof review.
    pub const fn is_closure_ready(self) -> bool {
        matches!(self, Self::ClosureReady(_))
    }

    /// Borrow the verifier contract certificate when present.
    pub const fn closure_certificate(&self) -> Option<&P1RealThresholdVerifierClosureCertificate> {
        match self {
            Self::ClosureReady(certificate) => Some(certificate),
            Self::BlockedFailClosed { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Result of assessing a selected-backend aggregate-output artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum P1SelectedBackendAggregateArtifactAssessment {
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
    /// The selected-backend aggregate artifact is ready for proof review.
    ArtifactReady(P1SelectedBackendAggregateArtifactCertificate),
}

impl P1SelectedBackendAggregateArtifactAssessment {
    /// Return true when the selected-backend aggregate artifact is ready for proof review.
    pub const fn is_artifact_ready(self) -> bool {
        matches!(self, Self::ArtifactReady(_))
    }

    /// Borrow the artifact certificate when present.
    pub const fn artifact_certificate(
        &self,
    ) -> Option<&P1SelectedBackendAggregateArtifactCertificate> {
        match self {
            Self::ArtifactReady(certificate) => Some(certificate),
            Self::Missing { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Result of assessing a P1 aggregate recomputation artifact package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum P1AggregateRecomputationAssessment {
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
    /// The package has all P1 artifact-gate evidence and is ready for proof review.
    ArtifactReady(P1AggregateRecomputationClosureCertificate),
}

impl P1AggregateRecomputationAssessment {
    /// Return true when the P1 artifact package is ready for proof review.
    pub const fn is_artifact_ready(self) -> bool {
        matches!(self, Self::ArtifactReady(_))
    }

    /// Borrow the P1 artifact certificate when present.
    pub const fn closure_certificate(&self) -> Option<&P1AggregateRecomputationClosureCertificate> {
        match self {
            Self::ArtifactReady(certificate) => Some(certificate),
            Self::Missing { .. } | Self::Invalid { .. } => None,
        }
    }
}

/// Result of assessing a rejection-equivalence closure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
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

/// Derive the digest used to bind a P1 standard-verifier bridge evidence package.
///
/// The digest is an artifact identifier for reviewed conformance evidence. It
/// requires provider/recomputation bridge evidence that already passed
/// `AggregateRejectionEquivalenceGate`, but it does not claim production
/// threshold recomputation, FIPS validation, or completed standard-verifier
/// compatibility proof.
pub fn derive_standard_verifier_bridge_evidence_digest(
    selected_profile_binding_digest: &[u8; 32],
    provider_kat_evidence_digest: &[u8; 32],
    evidence: &AggregateRejectionEquivalenceEvidence,
) -> Result<[u8; 32], ThresholdError> {
    AggregateRejectionEquivalenceGate::require_verified_bridge(evidence)?;
    let recomputed_signature_digest =
        evidence
            .recomputed_signature_digest()
            .ok_or(ThresholdError::BackendUnavailable {
                reason: "standard verifier bridge evidence is missing recomputed signature digest",
            })?;

    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-standard-verifier-bridge-evidence:v1");
    hasher.update(selected_profile_binding_digest);
    hasher.update(provider_kat_evidence_digest);
    hasher.update(evidence.challenge_digest());
    hasher.update(evidence.aggregate_response_digest());
    hasher.update(evidence.hint_digest());
    hasher.update(evidence.candidate_signature_digest());
    hasher.update(recomputed_signature_digest);
    Ok(hasher.finalize().into())
}

/// Derive the digest binding a selected-backend aggregate artifact to a transcript.
pub fn derive_p1_selected_backend_transcript_binding_digest(
    transcript: &ProductionSigningTranscript,
) -> [u8; 32] {
    let input = transcript.input();
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-selected-backend-transcript-binding:v1");
    hasher.update(transcript.challenge_digest());
    hasher.update(input.session_id);
    hasher.update(input.key_id.as_bytes());
    hasher.update(input.validator_set_digest.as_bytes());
    hasher.update(input.dkg_transcript_digest.as_bytes());
    hasher.update(input.threshold.to_be_bytes());
    hasher.update(input.public_key.0);
    hasher.update((input.application_message.len() as u64).to_be_bytes());
    hasher.update(&input.application_message);
    hasher.update(input.message_binding.as_bytes());
    hasher.update(input.coordinator_attestation_digest);
    hasher.finalize().into()
}

/// Derive the digest binding a selected-backend aggregate artifact to signers.
pub fn derive_p1_selected_backend_signer_set_digest(signers: &[ValidatorId]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-selected-backend-signer-set:v1");
    hasher.update((signers.len() as u16).to_be_bytes());
    for signer in signers {
        hasher.update(signer.0.to_be_bytes());
    }
    hasher.finalize().into()
}

/// Derive the digest binding a selected-backend aggregate artifact to an attempt.
pub fn derive_p1_selected_backend_attempt_binding_digest(
    transcript: &ProductionSigningTranscript,
) -> [u8; 32] {
    let input = transcript.input();
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-selected-backend-attempt-binding:v1");
    hasher.update(transcript.challenge_digest());
    hasher.update(input.session_id);
    hasher.update(input.attempt_id.as_bytes());
    hasher.update(input.retry_counter.to_be_bytes());
    hasher.finalize().into()
}

/// Derive the digest binding a selected-backend aggregate artifact certificate.
pub fn derive_p1_selected_backend_aggregate_certificate_digest(
    certificate: &P1SelectedBackendAggregateArtifactCertificate,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-selected-backend-aggregate-certificate:v1");
    hasher.update(certificate.selected_profile().profile_binding_digest());
    hasher.update(certificate.selected_profile_binding_digest());
    hasher.update(certificate.provider_kat_evidence_digest());
    hasher.update(certificate.standard_verifier_bridge_evidence_digest());
    hasher.update(certificate.real_recomputation_evidence_digest());
    hasher.update(certificate.transcript_binding_digest());
    hasher.update(certificate.signer_set_digest());
    hasher.update(certificate.attempt_binding_digest());
    hasher.update(certificate.aggregate_response_digest());
    hasher.update(certificate.hint_digest());
    hasher.update(certificate.accepted_signature_digest());
    hasher.finalize().into()
}

/// Derive the digest binding a Batch 3 threshold-output artifact certificate.
pub fn derive_p1_selected_backend_threshold_output_certificate_digest(
    certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-selected-backend-threshold-output-certificate:v1");
    hasher.update(certificate.selected_profile().profile_binding_digest());
    hasher.update(certificate.selected_profile_binding_digest());
    hasher.update(certificate.aggregate_artifact_digest());
    hasher.update(certificate.provider_kat_evidence_digest());
    hasher.update(certificate.threshold_output_source_digest());
    hasher.update(certificate.threshold_output_source_package_digest());
    hasher.update(certificate.transcript_binding_digest());
    hasher.update(certificate.signer_set_digest());
    hasher.update(certificate.attempt_binding_digest());
    hasher.update(certificate.aggregate_response_digest());
    hasher.update(certificate.hint_digest());
    hasher.update(certificate.accepted_signature_digest());
    hasher.update(certificate.standard_verifier_bridge_evidence_digest());
    hasher.update(certificate.real_recomputation_evidence_digest());
    match certificate.claim_boundary() {
        P1ThresholdOutputClaimBoundary::ProofReviewOnly => hasher.update([0]),
        P1ThresholdOutputClaimBoundary::ProductionClaim => hasher.update([1]),
    }
    hasher.finalize().into()
}

/// Derive the digest binding one typed Criterion 2 proof-slot artifact.
///
/// This is proof-review evidence only. A valid digest records that the slot was
/// checked against the accepted threshold-output certificate and a named review
/// artifact; it does not promote Criterion 2 by itself.
pub fn derive_p1_criterion2_proof_slot_artifact_digest(
    artifact: &P1Criterion2ProofSlotArtifact,
) -> [u8; 32] {
    derive_p1_criterion2_proof_slot_artifact_digest_from_fields(
        artifact.kind,
        artifact.selected_profile,
        &artifact.selected_profile_binding_digest,
        &artifact.threshold_output_certificate_digest,
        &artifact.transcript_binding_digest,
        &artifact.source_evidence_digest,
        &artifact.review_evidence_digest,
        artifact.claim_boundary,
        artifact.reviewed,
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_p1_criterion2_proof_slot_artifact_digest_from_fields(
    kind: P1Criterion2ProofSlotArtifactKind,
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: &[u8; 32],
    threshold_output_certificate_digest: &[u8; 32],
    transcript_binding_digest: &[u8; 32],
    source_evidence_digest: &[u8; 32],
    review_evidence_digest: &[u8; 32],
    claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    reviewed: bool,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-criterion2-proof-slot-artifact:v1");
    hasher.update([kind.tag()]);
    hasher.update(selected_profile.profile_binding_digest());
    hasher.update(selected_profile_binding_digest);
    hasher.update(threshold_output_certificate_digest);
    hasher.update(transcript_binding_digest);
    hasher.update(source_evidence_digest);
    hasher.update(review_evidence_digest);
    match claim_boundary {
        P1SelectedBackendProofClosureClaimBoundary::ProofReviewOnly => hasher.update([0]),
        P1SelectedBackendProofClosureClaimBoundary::ProductionClaim => hasher.update([1]),
    }
    hasher.update([u8::from(reviewed)]);
    hasher.finalize().into()
}

/// Derive one typed Criterion 2 proof-slot artifact package.
pub fn derive_p1_criterion2_proof_slot_artifact(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    kind: P1Criterion2ProofSlotArtifactKind,
    source_evidence_digest: [u8; 32],
    review_evidence_digest: [u8; 32],
    claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    reviewed: bool,
) -> P1Criterion2ProofSlotArtifact {
    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    let artifact_digest = derive_p1_criterion2_proof_slot_artifact_digest_from_fields(
        kind,
        threshold_certificate.selected_profile(),
        threshold_certificate.selected_profile_binding_digest(),
        &threshold_output_certificate_digest,
        threshold_certificate.transcript_binding_digest(),
        &source_evidence_digest,
        &review_evidence_digest,
        claim_boundary,
        reviewed,
    );

    P1Criterion2ProofSlotArtifact {
        kind,
        selected_profile: threshold_certificate.selected_profile(),
        selected_profile_binding_digest: *threshold_certificate.selected_profile_binding_digest(),
        threshold_output_certificate_digest,
        transcript_binding_digest: *threshold_certificate.transcript_binding_digest(),
        source_evidence_digest,
        review_evidence_digest,
        artifact_digest,
        claim_boundary,
        reviewed,
    }
}

/// Derive the typed Criterion 2 proof-slot bundle used by the P1 proof gate.
pub fn derive_p1_criterion2_proof_slot_artifacts(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    proof_artifacts: &P1RejectionProofArtifacts,
    sources: P1Criterion2ProofSlotArtifactSources,
) -> P1Criterion2ProofSlotArtifacts {
    let external_review_digest = *proof_artifacts.external_review_digest();
    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    P1Criterion2ProofSlotArtifacts::new(
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::FullKatValidation,
            sources.full_kat_validation_source_digest,
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::RejectionDistributionReview,
            sources.rejection_distribution_review_source_digest,
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::NormBound,
            *proof_artifacts.norm_bound_evidence_digest(),
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::HintBound,
            *proof_artifacts.hint_bound_evidence_digest(),
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::ChallengeBound,
            *proof_artifacts.challenge_bound_evidence_digest(),
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::TranscriptBinding,
            *proof_artifacts.transcript_binding_evidence_digest(),
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::TheoremLinkage,
            sources.theorem_linkage_source_digest,
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::ExternalReview,
            external_review_digest,
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::ThresholdOutputCertificate,
            threshold_output_certificate_digest,
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::RealRecomputationEvidence,
            *proof_artifacts.real_recomputation_evidence_digest(),
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::DistributedNonceProducer,
            sources.distributed_nonce_producer_source_digest,
            external_review_digest,
            sources.claim_boundary,
            sources.reviewed,
        ),
    )
}

/// Derive the digest of reviewed Batch 3 threshold-output source package bytes.
pub fn derive_p1_selected_backend_threshold_output_source_package_digest(
    source_package_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-selected-backend-threshold-output-source-package:v1");
    hasher.update((source_package_bytes.len() as u64).to_be_bytes());
    hasher.update(source_package_bytes);
    hasher.finalize().into()
}

/// Derive the digest binding a Batch 3 threshold-output source package digest.
///
/// The source digest commits to the public selected-backend aggregate evidence
/// and a reviewed source-package digest. It is an artifact identifier for proof
/// review and drift detection; it is not a threshold ML-DSA security proof or a
/// standard-verifier compatibility proof.
pub fn derive_p1_selected_backend_threshold_output_source_digest_from_package_digest(
    transcript: &ProductionSigningTranscript,
    accepted_aggregate: &AcceptedAggregateCandidate,
    recomputation: &AggregateRecomputationTranscript,
    source_package_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-selected-backend-threshold-output-source:v1");
    hasher.update(transcript.challenge_digest());
    hasher.update(derive_p1_selected_backend_transcript_binding_digest(
        transcript,
    ));
    hasher.update(derive_p1_selected_backend_signer_set_digest(
        accepted_aggregate.signers(),
    ));
    hasher.update(derive_p1_selected_backend_attempt_binding_digest(
        transcript,
    ));
    hasher.update(accepted_aggregate.aggregate_response_digest());
    hasher.update(accepted_aggregate.hint_digest());
    hasher.update(accepted_aggregate.candidate_signature_digest());
    hasher.update(recomputation.challenge_digest());
    hasher.update(recomputation.aggregate_response_digest());
    hasher.update(recomputation.hint_digest());
    hasher.update(recomputation.recomputed_signature_digest());
    hasher.update(source_package_digest);
    hasher.finalize().into()
}

/// Derive the digest binding a Batch 3 threshold-output source package.
pub fn derive_p1_selected_backend_threshold_output_source_digest(
    transcript: &ProductionSigningTranscript,
    accepted_aggregate: &AcceptedAggregateCandidate,
    recomputation: &AggregateRecomputationTranscript,
    source_package_bytes: &[u8],
) -> [u8; 32] {
    let source_package_digest =
        derive_p1_selected_backend_threshold_output_source_package_digest(source_package_bytes);
    derive_p1_selected_backend_threshold_output_source_digest_from_package_digest(
        transcript,
        accepted_aggregate,
        recomputation,
        &source_package_digest,
    )
}

/// Derive the digest binding P1 real aggregate recomputation evidence.
///
/// The digest commits only to public recomputation outputs and transcript
/// challenge material. It is a release-gate artifact identifier, not a proof
/// that threshold ML-DSA recomputation is secure or distribution preserving.
pub fn derive_p1_real_recomputation_evidence_digest(
    recomputation: &AggregateRecomputationTranscript,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-real-aggregate-recomputation-evidence:v1");
    hasher.update(recomputation.challenge_digest());
    hasher.update(recomputation.aggregate_response_digest());
    hasher.update(recomputation.hint_digest());
    hasher.update(recomputation.recomputed_signature_digest());
    hasher.finalize().into()
}

/// Derive the digest binding a standard-verifier compatibility artifact.
///
/// This digest commits to the selected provider accepting `MLDSA65.Verify(pk,
/// m, sigma)` for the public key, application message, and accepted aggregate
/// signature bound by the threshold-output certificate. It remains
/// conformance/proof-review evidence only.
pub fn derive_p1_standard_verifier_compatibility_artifact_digest(
    certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
) -> [u8; 32] {
    derive_p1_standard_verifier_compatibility_artifact_digest_from_fields(
        certificate.selected_profile(),
        certificate.selected_profile_binding_digest(),
        certificate.threshold_output_certificate_digest(),
        certificate.provider_kat_evidence_digest(),
        certificate.provider_identity_digest(),
        certificate.public_key_digest(),
        certificate.message_digest(),
        certificate.transcript_binding_digest(),
        certificate.signer_set_digest(),
        certificate.attempt_binding_digest(),
        certificate.aggregate_response_digest(),
        certificate.hint_digest(),
        certificate.accepted_signature_digest(),
        certificate.standard_verifier_bridge_evidence_digest(),
        certificate.real_recomputation_evidence_digest(),
        certificate.verifier_result(),
        certificate.claim_boundary(),
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_p1_standard_verifier_compatibility_artifact_digest_from_fields(
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: &[u8; 32],
    threshold_output_certificate_digest: &[u8; 32],
    provider_kat_evidence_digest: &[u8; 32],
    provider_identity_digest: &[u8; 32],
    public_key_digest: &[u8; 32],
    message_digest: &[u8; 32],
    transcript_binding_digest: &[u8; 32],
    signer_set_digest: &[u8; 32],
    attempt_binding_digest: &[u8; 32],
    aggregate_response_digest: &[u8; 32],
    hint_digest: &[u8; 32],
    accepted_signature_digest: &[u8; 32],
    standard_verifier_bridge_evidence_digest: &[u8; 32],
    real_recomputation_evidence_digest: &[u8; 32],
    verifier_result: P1StandardVerifierCompatibilityResult,
    claim_boundary: P1StandardVerifierCompatibilityClaimBoundary,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-standard-verifier-compatibility-artifact:v1");
    hasher.update(selected_profile.profile_binding_digest());
    hasher.update(selected_profile_binding_digest);
    hasher.update(threshold_output_certificate_digest);
    hasher.update(provider_kat_evidence_digest);
    hasher.update(provider_identity_digest);
    hasher.update(public_key_digest);
    hasher.update(message_digest);
    hasher.update(transcript_binding_digest);
    hasher.update(signer_set_digest);
    hasher.update(attempt_binding_digest);
    hasher.update(aggregate_response_digest);
    hasher.update(hint_digest);
    hasher.update(accepted_signature_digest);
    hasher.update(standard_verifier_bridge_evidence_digest);
    hasher.update(real_recomputation_evidence_digest);
    match verifier_result {
        P1StandardVerifierCompatibilityResult::Accept => hasher.update([0]),
        P1StandardVerifierCompatibilityResult::Reject => hasher.update([1]),
    }
    match claim_boundary {
        P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly => hasher.update([0]),
        P1StandardVerifierCompatibilityClaimBoundary::ProductionClaim => hasher.update([1]),
    }
    hasher.finalize().into()
}

/// Derive a Batch 3 selected-backend threshold-output artifact package.
///
/// This constructor binds a reviewed threshold-output source digest to the
/// predecessor selected-backend aggregate artifact certificate and the public
/// acceptance/recomputation transcript. The returned package is still
/// conformance/proof-review evidence only.
pub fn derive_p1_selected_backend_threshold_output_artifact_package(
    transcript: &ProductionSigningTranscript,
    accepted_aggregate: &AcceptedAggregateCandidate,
    recomputation: &AggregateRecomputationTranscript,
    aggregate_certificate: &P1SelectedBackendAggregateArtifactCertificate,
    threshold_output_source: P1ThresholdOutputEvidenceSource,
    claim_boundary: P1ThresholdOutputClaimBoundary,
    reviewed: bool,
) -> Result<P1SelectedBackendThresholdOutputArtifactPackage, ThresholdError> {
    if accepted_aggregate.challenge_digest() != transcript.challenge_digest()
        || recomputation.challenge_digest() != transcript.challenge_digest()
    {
        return Err(ThresholdError::TranscriptMismatch);
    }
    if accepted_aggregate.aggregate_response_digest() != recomputation.aggregate_response_digest()
        || accepted_aggregate.hint_digest() != recomputation.hint_digest()
        || accepted_aggregate.candidate_signature_digest()
            != recomputation.recomputed_signature_digest()
    {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    Ok(P1SelectedBackendThresholdOutputArtifactPackage {
        selected_profile: aggregate_certificate.selected_profile(),
        selected_profile_binding_digest: *aggregate_certificate.selected_profile_binding_digest(),
        aggregate_artifact_digest: derive_p1_selected_backend_aggregate_certificate_digest(
            aggregate_certificate,
        ),
        provider_kat_evidence_digest: *aggregate_certificate.provider_kat_evidence_digest(),
        threshold_output_source,
        threshold_output_source_digest: *threshold_output_source.source_digest(),
        transcript_binding_digest: derive_p1_selected_backend_transcript_binding_digest(transcript),
        signer_set_digest: derive_p1_selected_backend_signer_set_digest(
            accepted_aggregate.signers(),
        ),
        attempt_binding_digest: derive_p1_selected_backend_attempt_binding_digest(transcript),
        aggregate_response_digest: *accepted_aggregate.aggregate_response_digest(),
        hint_digest: *accepted_aggregate.hint_digest(),
        accepted_signature_digest: *accepted_aggregate.candidate_signature_digest(),
        standard_verifier_bridge_evidence_digest: *aggregate_certificate
            .standard_verifier_bridge_evidence_digest(),
        real_recomputation_evidence_digest: *aggregate_certificate
            .real_recomputation_evidence_digest(),
        claim_boundary,
        reviewed,
    })
}

/// Derive a P1 standard-verifier compatibility artifact package.
///
/// The package binds the threshold-output certificate to a provider acceptance
/// of the transcript public key, original application message, and accepted
/// aggregate signature. It does not claim FIPS validation, production threshold
/// ML-DSA security, rejection-distribution preservation, or completed proof
/// closure.
pub fn derive_p1_standard_verifier_compatibility_artifact_package<P>(
    transcript: &ProductionSigningTranscript,
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    candidate_signature: &ThresholdSignature,
    claim_boundary: P1StandardVerifierCompatibilityClaimBoundary,
    reviewed: bool,
) -> Result<P1StandardVerifierCompatibilityArtifactPackage, ThresholdError>
where
    P: StandardMldsa65Provider,
{
    let verifier = StandardVerifierEvidence::verify::<P>(transcript, candidate_signature)?;
    if verifier.challenge_digest() != transcript.challenge_digest() {
        return Err(ThresholdError::TranscriptMismatch);
    }
    if verifier.candidate_signature_digest() != threshold_certificate.accepted_signature_digest() {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    let public_key_digest = digest_bytes(&transcript.input().public_key.0);
    let message_digest = digest_bytes(&transcript.input().application_message);
    let provider_identity_digest = P::provider_identity_digest();
    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    let artifact_digest = derive_p1_standard_verifier_compatibility_artifact_digest_from_fields(
        threshold_certificate.selected_profile(),
        threshold_certificate.selected_profile_binding_digest(),
        &threshold_output_certificate_digest,
        threshold_certificate.provider_kat_evidence_digest(),
        &provider_identity_digest,
        &public_key_digest,
        &message_digest,
        threshold_certificate.transcript_binding_digest(),
        threshold_certificate.signer_set_digest(),
        threshold_certificate.attempt_binding_digest(),
        threshold_certificate.aggregate_response_digest(),
        threshold_certificate.hint_digest(),
        threshold_certificate.accepted_signature_digest(),
        threshold_certificate.standard_verifier_bridge_evidence_digest(),
        threshold_certificate.real_recomputation_evidence_digest(),
        P1StandardVerifierCompatibilityResult::Accept,
        claim_boundary,
    );

    Ok(P1StandardVerifierCompatibilityArtifactPackage {
        selected_profile: threshold_certificate.selected_profile(),
        selected_profile_binding_digest: *threshold_certificate.selected_profile_binding_digest(),
        artifact_digest,
        threshold_output_certificate_digest,
        provider_kat_evidence_digest: *threshold_certificate.provider_kat_evidence_digest(),
        provider_identity_digest,
        public_key_digest,
        message_digest,
        transcript_binding_digest: *threshold_certificate.transcript_binding_digest(),
        signer_set_digest: *threshold_certificate.signer_set_digest(),
        attempt_binding_digest: *threshold_certificate.attempt_binding_digest(),
        aggregate_response_digest: *threshold_certificate.aggregate_response_digest(),
        hint_digest: *threshold_certificate.hint_digest(),
        accepted_signature_digest: *threshold_certificate.accepted_signature_digest(),
        standard_verifier_bridge_evidence_digest: *threshold_certificate
            .standard_verifier_bridge_evidence_digest(),
        real_recomputation_evidence_digest: *threshold_certificate
            .real_recomputation_evidence_digest(),
        verifier_result: P1StandardVerifierCompatibilityResult::Accept,
        claim_boundary,
        reviewed,
    })
}

/// Derive the digest binding a reviewed P1 distributed nonce-producer artifact.
pub fn derive_p1_distributed_nonce_producer_artifact_digest(
    certificate: &P1DistributedNonceProducerArtifactCertificate,
) -> [u8; 32] {
    derive_p1_distributed_nonce_producer_artifact_digest_from_fields(
        certificate.selected_profile(),
        certificate.selected_profile_binding_digest(),
        P1DistributedNonceProducerEvidence::ReviewedP1ShamirNonceDkgTee,
        certificate.source_reference_digest(),
        certificate.backend_implementation_digest(),
        certificate.coordinator_attestation_digest(),
        certificate.shamir_nonce_dkg_transcript_digest(),
        certificate.active_set_digest(),
        certificate.pairwise_mask_seed_commitment_digest(),
        certificate.nonce_share_commitment_digest(),
        certificate.attempt_binding_digest(),
        certificate.abort_accountability_digest(),
        certificate.standard_verifier_bridge_digest(),
        certificate.external_review_digest(),
        certificate.threshold_output_certificate_digest(),
        certificate.standard_verifier_compatibility_artifact_digest(),
        certificate.claim_boundary(),
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_p1_distributed_nonce_producer_artifact_digest_from_fields(
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: &[u8; 32],
    producer_evidence: P1DistributedNonceProducerEvidence,
    source_reference_digest: &[u8; 32],
    backend_implementation_digest: &[u8; 32],
    coordinator_attestation_digest: &[u8; 32],
    shamir_nonce_dkg_transcript_digest: &[u8; 32],
    active_set_digest: &[u8; 32],
    pairwise_mask_seed_commitment_digest: &[u8; 32],
    nonce_share_commitment_digest: &[u8; 32],
    attempt_binding_digest: &[u8; 32],
    abort_accountability_digest: &[u8; 32],
    standard_verifier_bridge_digest: &[u8; 32],
    external_review_digest: &[u8; 32],
    threshold_output_certificate_digest: &[u8; 32],
    standard_verifier_compatibility_artifact_digest: &[u8; 32],
    claim_boundary: P1DistributedNonceProducerClaimBoundary,
    reviewed: bool,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-distributed-nonce-producer-artifact:v1");
    hasher.update(selected_profile.profile_binding_digest());
    hasher.update(selected_profile_binding_digest);
    hasher.update([producer_evidence.tag()]);
    hasher.update(source_reference_digest);
    hasher.update(backend_implementation_digest);
    hasher.update(coordinator_attestation_digest);
    hasher.update(shamir_nonce_dkg_transcript_digest);
    hasher.update(active_set_digest);
    hasher.update(pairwise_mask_seed_commitment_digest);
    hasher.update(nonce_share_commitment_digest);
    hasher.update(attempt_binding_digest);
    hasher.update(abort_accountability_digest);
    hasher.update(standard_verifier_bridge_digest);
    hasher.update(external_review_digest);
    hasher.update(threshold_output_certificate_digest);
    hasher.update(standard_verifier_compatibility_artifact_digest);
    hasher.update([claim_boundary.tag()]);
    hasher.update([u8::from(reviewed)]);
    hasher.finalize().into()
}

/// Derive a P1 distributed nonce-producer artifact package.
///
/// The package is the import boundary for a future reviewed P1 Shamir
/// nonce-DKG producer. It binds the producer evidence to the predecessor
/// threshold-output and standard-verifier compatibility certificates and
/// remains conformance/proof-review evidence only.
#[allow(clippy::too_many_arguments)]
pub fn derive_p1_distributed_nonce_producer_artifact_package(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    producer_evidence: P1DistributedNonceProducerEvidence,
    source_reference_digest: [u8; 32],
    backend_implementation_digest: [u8; 32],
    coordinator_attestation_digest: [u8; 32],
    shamir_nonce_dkg_transcript_digest: [u8; 32],
    pairwise_mask_seed_commitment_digest: [u8; 32],
    nonce_share_commitment_digest: [u8; 32],
    abort_accountability_digest: [u8; 32],
    external_review_digest: [u8; 32],
    claim_boundary: P1DistributedNonceProducerClaimBoundary,
    reviewed: bool,
) -> P1DistributedNonceProducerArtifactPackage {
    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    let standard_verifier_compatibility_artifact_digest =
        derive_p1_standard_verifier_compatibility_artifact_digest(compatibility_certificate);
    let distributed_nonce_producer_artifact_digest =
        derive_p1_distributed_nonce_producer_artifact_digest_from_fields(
            threshold_certificate.selected_profile(),
            threshold_certificate.selected_profile_binding_digest(),
            producer_evidence,
            &source_reference_digest,
            &backend_implementation_digest,
            &coordinator_attestation_digest,
            &shamir_nonce_dkg_transcript_digest,
            threshold_certificate.signer_set_digest(),
            &pairwise_mask_seed_commitment_digest,
            &nonce_share_commitment_digest,
            threshold_certificate.attempt_binding_digest(),
            &abort_accountability_digest,
            threshold_certificate.standard_verifier_bridge_evidence_digest(),
            &external_review_digest,
            &threshold_output_certificate_digest,
            &standard_verifier_compatibility_artifact_digest,
            claim_boundary,
            reviewed,
        );

    P1DistributedNonceProducerArtifactPackage {
        selected_profile: threshold_certificate.selected_profile(),
        selected_profile_binding_digest: *threshold_certificate.selected_profile_binding_digest(),
        producer_evidence,
        source_reference_digest,
        backend_implementation_digest,
        coordinator_attestation_digest,
        shamir_nonce_dkg_transcript_digest,
        active_set_digest: *threshold_certificate.signer_set_digest(),
        pairwise_mask_seed_commitment_digest,
        nonce_share_commitment_digest,
        attempt_binding_digest: *threshold_certificate.attempt_binding_digest(),
        abort_accountability_digest,
        standard_verifier_bridge_digest: *threshold_certificate
            .standard_verifier_bridge_evidence_digest(),
        external_review_digest,
        distributed_nonce_producer_artifact_digest,
        threshold_output_certificate_digest,
        standard_verifier_compatibility_artifact_digest,
        claim_boundary,
        reviewed,
    }
}

/// Derive a P1 distributed nonce-producer package from backend-emitted bytes.
///
/// This is the backend-side bridge for the existing nonce-producer gate. It
/// hashes actual submitted material classes, binds them to predecessor
/// certificates, and marks the evidence as reviewed P1 Shamir nonce-DKG/TEE
/// provenance. It does not evaluate nonce sampling, does not prove rejection
/// distribution preservation, and does not implement a threshold backend.
pub fn derive_p1_distributed_nonce_producer_artifact_package_from_backend_output(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    output: Mldsa65DistributedNonceProducerArtifact<'_>,
) -> Result<P1DistributedNonceProducerArtifactPackage, ThresholdError> {
    for (bytes, reason) in [
        (
            output.source_reference,
            "P1 distributed nonce producer source reference material is empty",
        ),
        (
            output.backend_implementation,
            "P1 distributed nonce producer backend implementation material is empty",
        ),
        (
            output.coordinator_attestation,
            "P1 distributed nonce producer coordinator attestation material is empty",
        ),
        (
            output.shamir_nonce_dkg_transcript,
            "P1 distributed nonce producer Shamir nonce-DKG transcript material is empty",
        ),
        (
            output.pairwise_mask_seed_commitments,
            "P1 distributed nonce producer pairwise mask seed commitment material is empty",
        ),
        (
            output.nonce_share_commitments,
            "P1 distributed nonce producer nonce-share commitment material is empty",
        ),
        (
            output.abort_accountability,
            "P1 distributed nonce producer abort-accountability material is empty",
        ),
        (
            output.external_review,
            "P1 distributed nonce producer external review material is empty",
        ),
    ] {
        if bytes.is_empty() {
            return Err(ThresholdError::MalformedSerialization { reason });
        }
    }

    Ok(derive_p1_distributed_nonce_producer_artifact_package(
        threshold_certificate,
        compatibility_certificate,
        P1DistributedNonceProducerEvidence::ReviewedP1ShamirNonceDkgTee,
        digest_domain_separated_bytes(
            b"lattice-aggregation:p1-distributed-nonce-producer-source-reference:v1",
            output.source_reference,
        ),
        digest_domain_separated_bytes(
            b"lattice-aggregation:p1-distributed-nonce-producer-backend-implementation:v1",
            output.backend_implementation,
        ),
        digest_domain_separated_bytes(
            b"lattice-aggregation:p1-distributed-nonce-producer-coordinator-attestation:v1",
            output.coordinator_attestation,
        ),
        digest_domain_separated_bytes(
            b"lattice-aggregation:p1-distributed-nonce-producer-shamir-nonce-dkg-transcript:v1",
            output.shamir_nonce_dkg_transcript,
        ),
        digest_domain_separated_bytes(
            b"lattice-aggregation:p1-distributed-nonce-producer-pairwise-mask-seed-commitments:v1",
            output.pairwise_mask_seed_commitments,
        ),
        digest_domain_separated_bytes(
            b"lattice-aggregation:p1-distributed-nonce-producer-nonce-share-commitments:v1",
            output.nonce_share_commitments,
        ),
        digest_domain_separated_bytes(
            b"lattice-aggregation:p1-distributed-nonce-producer-abort-accountability:v1",
            output.abort_accountability,
        ),
        digest_domain_separated_bytes(
            b"lattice-aggregation:p1-distributed-nonce-producer-external-review:v1",
            output.external_review,
        ),
        output.claim_boundary,
        output.reviewed,
    ))
}

/// Derive a P1 distributed nonce-producer artifact package from capture JSON.
///
/// This is the canonical handoff from externally generated nonce-producer
/// captures into the existing artifact gate. It rejects stale predecessor
/// bindings and compares the derived package against the capture's expected
/// digest inventory. The resulting package is still proof-review evidence only.
pub fn derive_p1_distributed_nonce_producer_artifact_package_from_capture(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    request_binding: P1DistributedNonceProducerRequestDigestBinding<'_>,
    capture: &P1DistributedNonceProducerCapture,
) -> Result<P1DistributedNonceProducerArtifactPackage, ThresholdError> {
    capture.validate_expected_request_binding(request_binding)?;
    let output = capture.to_nonce_producer_material()?;
    capture.validate_predecessors(threshold_certificate, compatibility_certificate)?;
    let package = derive_p1_distributed_nonce_producer_artifact_package_from_backend_output(
        threshold_certificate,
        compatibility_certificate,
        output.as_nonce_producer_artifact(),
    )?;
    capture.validate_expected_digests(&package)?;
    Ok(package)
}

/// Derive the digest binding a real-threshold backend emission artifact.
///
/// This digest commits to external backend provenance and the verifier-accepted
/// tuple already bound by the predecessor certificates. It remains
/// conformance/proof-review evidence only.
pub fn derive_p1_real_threshold_backend_emission_artifact_digest(
    certificate: &P1RealThresholdBackendEmissionArtifactCertificate,
) -> [u8; 32] {
    derive_p1_real_threshold_backend_emission_artifact_digest_from_fields(
        certificate.selected_profile(),
        certificate.selected_profile_binding_digest(),
        certificate.validator_count(),
        certificate.threshold(),
        certificate.aggregate_signature_len(),
        P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa,
        certificate.backend_evidence_digest(),
        certificate.backend_source_package_digest(),
        certificate.backend_implementation_digest(),
        certificate.backend_transcript_digest(),
        certificate.threshold_output_certificate_digest(),
        certificate.standard_verifier_compatibility_artifact_digest(),
        certificate.public_key_digest(),
        certificate.message_digest(),
        certificate.transcript_binding_digest(),
        certificate.signer_set_digest(),
        certificate.attempt_binding_digest(),
        certificate.accepted_signature_digest(),
        certificate.verifier_result(),
        certificate.mutated_message_rejected,
        certificate.mutated_public_key_rejected,
        certificate.mutated_signature_rejected,
        certificate.claim_boundary(),
    )
}

/// Derive the source-package digest for backend-generated real-threshold material.
pub fn derive_p1_real_threshold_backend_source_package_digest(bytes: &[u8]) -> [u8; 32] {
    digest_domain_separated_bytes(
        b"lattice-aggregation:p1-real-threshold-backend-source-package:v1",
        bytes,
    )
}

/// Derive the implementation/build digest for backend-generated real-threshold material.
pub fn derive_p1_real_threshold_backend_implementation_digest(bytes: &[u8]) -> [u8; 32] {
    digest_domain_separated_bytes(
        b"lattice-aggregation:p1-real-threshold-backend-implementation:v1",
        bytes,
    )
}

/// Derive the transcript digest for backend-generated real-threshold material.
pub fn derive_p1_real_threshold_backend_transcript_digest(bytes: &[u8]) -> [u8; 32] {
    digest_domain_separated_bytes(
        b"lattice-aggregation:p1-real-threshold-backend-transcript:v1",
        bytes,
    )
}

/// Derive the evidence digest for backend-generated real-threshold material.
///
/// This digest commits to the backend provenance digests plus the verifier
/// tuple and mutation-rejection corpus. It is an evidence binding only; the
/// assessment gate still rejects missing review, bad boundaries, tuple drift,
/// and non-threshold evidence classes.
pub fn derive_p1_real_threshold_backend_emission_evidence_digest(
    output: &P1RealThresholdBackendEmissionOutput<'_>,
) -> [u8; 32] {
    let source_digest =
        derive_p1_real_threshold_backend_source_package_digest(output.backend_source_package);
    let implementation_digest =
        derive_p1_real_threshold_backend_implementation_digest(output.backend_implementation);
    let transcript_digest =
        derive_p1_real_threshold_backend_transcript_digest(output.backend_transcript);

    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-real-threshold-backend-emission-evidence:v1");
    hasher.update(source_digest);
    hasher.update(implementation_digest);
    hasher.update(transcript_digest);
    hasher.update(digest_bytes(&output.public_key.0));
    hasher.update(digest_bytes(output.message));
    hasher.update(digest_signature(output.aggregate_signature));
    hasher.update([u8::from(output.mutated_message_rejected)]);
    hasher.update([u8::from(output.mutated_public_key_rejected)]);
    hasher.update([u8::from(output.mutated_signature_rejected)]);
    hasher.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn derive_p1_real_threshold_backend_emission_artifact_digest_from_fields(
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: &[u8; 32],
    validator_count: u32,
    threshold: u32,
    aggregate_signature_len: usize,
    backend_evidence: P1RealThresholdVerifierClosureBackendEvidence,
    backend_evidence_digest: &[u8; 32],
    backend_source_package_digest: &[u8; 32],
    backend_implementation_digest: &[u8; 32],
    backend_transcript_digest: &[u8; 32],
    threshold_output_certificate_digest: &[u8; 32],
    standard_verifier_compatibility_artifact_digest: &[u8; 32],
    public_key_digest: &[u8; 32],
    message_digest: &[u8; 32],
    transcript_binding_digest: &[u8; 32],
    signer_set_digest: &[u8; 32],
    attempt_binding_digest: &[u8; 32],
    accepted_signature_digest: &[u8; 32],
    verifier_result: P1StandardVerifierCompatibilityResult,
    mutated_message_rejected: bool,
    mutated_public_key_rejected: bool,
    mutated_signature_rejected: bool,
    claim_boundary: P1RealThresholdVerifierClosureClaimBoundary,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-real-threshold-backend-emission-artifact:v1");
    hasher.update(selected_profile.profile_binding_digest());
    hasher.update(selected_profile_binding_digest);
    hasher.update(validator_count.to_be_bytes());
    hasher.update(threshold.to_be_bytes());
    hasher.update((aggregate_signature_len as u64).to_be_bytes());
    match backend_evidence {
        P1RealThresholdVerifierClosureBackendEvidence::SimulatedDeterministic => hasher.update([0]),
        P1RealThresholdVerifierClosureBackendEvidence::StandardProviderSingleKey => {
            hasher.update([1])
        }
        P1RealThresholdVerifierClosureBackendEvidence::FixtureHarness => hasher.update([2]),
        P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa => hasher.update([3]),
    }
    hasher.update(backend_evidence_digest);
    hasher.update(backend_source_package_digest);
    hasher.update(backend_implementation_digest);
    hasher.update(backend_transcript_digest);
    hasher.update(threshold_output_certificate_digest);
    hasher.update(standard_verifier_compatibility_artifact_digest);
    hasher.update(public_key_digest);
    hasher.update(message_digest);
    hasher.update(transcript_binding_digest);
    hasher.update(signer_set_digest);
    hasher.update(attempt_binding_digest);
    hasher.update(accepted_signature_digest);
    match verifier_result {
        P1StandardVerifierCompatibilityResult::Accept => hasher.update([0]),
        P1StandardVerifierCompatibilityResult::Reject => hasher.update([1]),
    }
    hasher.update([u8::from(mutated_message_rejected)]);
    hasher.update([u8::from(mutated_public_key_rejected)]);
    hasher.update([u8::from(mutated_signature_rejected)]);
    match claim_boundary {
        P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly => hasher.update([0]),
        P1RealThresholdVerifierClosureClaimBoundary::ProductionClaim => hasher.update([1]),
    }
    hasher.finalize().into()
}

/// Derive the digest binding a Batch 7 external-backend closure candidate.
///
/// This digest commits to actual distributed nonce-producer evidence, real
/// threshold backend emission evidence, standard-verifier acceptance evidence,
/// and rejection-distribution comparison evidence. It remains a proof-review
/// candidate binding and does not claim theorem closure.
pub fn derive_p1_external_backend_cryptographic_closure_candidate_digest(
    certificate: &P1ExternalBackendCryptographicClosureCandidateCertificate,
) -> [u8; 32] {
    derive_p1_external_backend_cryptographic_closure_candidate_digest_from_fields(
        certificate.selected_profile(),
        certificate.selected_profile_binding_digest(),
        certificate.threshold_output_certificate_digest(),
        certificate.distributed_nonce_producer_artifact_digest(),
        certificate.real_threshold_backend_emission_artifact_digest(),
        certificate.standard_verifier_compatibility_artifact_digest(),
        certificate.rejection_distribution_comparison_digest(),
        certificate.claim_boundary(),
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_p1_external_backend_cryptographic_closure_candidate_digest_from_fields(
    selected_profile: SelectedProductionBackendProfile,
    selected_profile_binding_digest: &[u8; 32],
    threshold_output_certificate_digest: &[u8; 32],
    distributed_nonce_producer_artifact_digest: &[u8; 32],
    real_threshold_backend_emission_artifact_digest: &[u8; 32],
    standard_verifier_compatibility_artifact_digest: &[u8; 32],
    rejection_distribution_comparison_digest: &[u8; 32],
    claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    reviewed: bool,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1");
    hasher.update(selected_profile.profile_binding_digest());
    hasher.update(selected_profile_binding_digest);
    hasher.update(threshold_output_certificate_digest);
    hasher.update(distributed_nonce_producer_artifact_digest);
    hasher.update(real_threshold_backend_emission_artifact_digest);
    hasher.update(standard_verifier_compatibility_artifact_digest);
    hasher.update(rejection_distribution_comparison_digest);
    match claim_boundary {
        P1SelectedBackendProofClosureClaimBoundary::ProofReviewOnly => hasher.update([0]),
        P1SelectedBackendProofClosureClaimBoundary::ProductionClaim => hasher.update([1]),
    }
    hasher.update([u8::from(reviewed)]);
    hasher.finalize().into()
}

/// Derive a P1 real-threshold backend emission package from backend output material.
///
/// This constructor is the intended import adapter for actual backend-generated
/// evidence. It binds the external backend material to predecessor
/// threshold-output and standard-verifier compatibility certificates, sets the
/// evidence class to `RealThresholdMldsa`, and leaves final readiness to
/// `assess_p1_real_threshold_backend_emission_artifact`.
pub fn derive_p1_real_threshold_backend_emission_artifact_package_from_backend_output(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    output: P1RealThresholdBackendEmissionOutput<'_>,
) -> Result<P1RealThresholdBackendEmissionArtifactPackage, ThresholdError> {
    let public_key_digest = digest_bytes(&output.public_key.0);
    let message_digest = digest_bytes(output.message);
    let accepted_signature_digest = digest_signature(output.aggregate_signature);
    if public_key_digest != *compatibility_certificate.public_key_digest()
        || message_digest != *compatibility_certificate.message_digest()
        || accepted_signature_digest != *threshold_certificate.accepted_signature_digest()
        || accepted_signature_digest != *compatibility_certificate.accepted_signature_digest()
    {
        return Err(ThresholdError::TranscriptMismatch);
    }

    Ok(derive_p1_real_threshold_backend_emission_artifact_package(
        threshold_certificate,
        compatibility_certificate,
        P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa,
        derive_p1_real_threshold_backend_emission_evidence_digest(&output),
        derive_p1_real_threshold_backend_source_package_digest(output.backend_source_package),
        derive_p1_real_threshold_backend_implementation_digest(output.backend_implementation),
        derive_p1_real_threshold_backend_transcript_digest(output.backend_transcript),
        output.mutated_message_rejected,
        output.mutated_public_key_rejected,
        output.mutated_signature_rejected,
        output.claim_boundary,
        output.reviewed,
    ))
}

/// Derive a P1 real-threshold backend emission package after standard verification.
///
/// This is the preferred adapter for actual backend-generated emissions when a
/// standard ML-DSA provider is available. It proves only that the submitted
/// tuple is accepted by the provider boundary and matches predecessor
/// certificates; it still does not implement an in-repo threshold backend.
pub fn derive_p1_verified_real_threshold_backend_emission_artifact_package<P>(
    transcript: &ProductionSigningTranscript,
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    output: P1RealThresholdBackendEmissionOutput<'_>,
) -> Result<P1RealThresholdBackendEmissionArtifactPackage, ThresholdError>
where
    P: StandardMldsa65Provider,
{
    if output.public_key != &transcript.input().public_key
        || output.message != transcript.input().application_message.as_slice()
    {
        return Err(ThresholdError::TranscriptMismatch);
    }

    let verifier = StandardVerifierEvidence::verify::<P>(transcript, output.aggregate_signature)?;
    if verifier.candidate_signature_digest() != &digest_signature(output.aggregate_signature)
        || verifier.candidate_signature_digest()
            != threshold_certificate.accepted_signature_digest()
        || verifier.candidate_signature_digest()
            != compatibility_certificate.accepted_signature_digest()
    {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    derive_p1_real_threshold_backend_emission_artifact_package_from_backend_output(
        threshold_certificate,
        compatibility_certificate,
        output,
    )
}

/// Emit canonical capture JSON material for an artifact-ready backend package.
///
/// This is the in-process capture runner seam for an external threshold
/// backend. It does not derive real-threshold provenance from raw tuple bytes:
/// callers must first supply a package that the real-threshold backend emission
/// assessment gate accepts as artifact-ready. The function cross-checks that
/// package against the bytes being packaged, and only then emits a canonical
/// capture envelope that can be re-imported by
/// `derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture`.
/// It does not implement threshold signing and does not close Criterion 2.
pub fn derive_p1_verified_real_threshold_backend_emission_capture(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    name: &str,
    request_binding: P1RealThresholdBackendEmissionRequestDigestBinding<'_>,
    note: &str,
    output: P1RealThresholdBackendEmissionOutput<'_>,
    package: P1RealThresholdBackendEmissionArtifactPackage,
) -> Result<P1RealThresholdBackendEmissionCapture, ThresholdError> {
    if name.trim().is_empty() {
        return Err(ThresholdError::MalformedSerialization {
            reason: "P1 real-threshold backend emission capture name is required",
        });
    }
    if note.trim().is_empty() {
        return Err(ThresholdError::MalformedSerialization {
            reason: "P1 real-threshold backend emission capture note is required",
        });
    }
    if request_binding.name.trim().is_empty() || is_all_zero(&request_binding.request_sha256) {
        return Err(ThresholdError::MalformedSerialization {
            reason: "P1 real-threshold backend emission capture requires request digest binding",
        });
    }

    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        threshold_certificate,
        compatibility_certificate,
        Some(package),
    );
    if !assessment.is_artifact_ready() {
        return Err(ThresholdError::BackendUnavailable {
            reason: "P1 real-threshold backend capture runner requires artifact-ready external backend evidence",
        });
    }
    if package.backend_evidence != P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa
        || package.backend_evidence_digest
            != derive_p1_real_threshold_backend_emission_evidence_digest(&output)
        || package.backend_source_package_digest
            != derive_p1_real_threshold_backend_source_package_digest(output.backend_source_package)
        || package.backend_implementation_digest
            != derive_p1_real_threshold_backend_implementation_digest(output.backend_implementation)
        || package.backend_transcript_digest
            != derive_p1_real_threshold_backend_transcript_digest(output.backend_transcript)
        || package.public_key_digest != digest_bytes(&output.public_key.0)
        || package.message_digest != digest_bytes(output.message)
        || package.accepted_signature_digest != digest_signature(output.aggregate_signature)
        || package.mutated_message_rejected != output.mutated_message_rejected
        || package.mutated_public_key_rejected != output.mutated_public_key_rejected
        || package.mutated_signature_rejected != output.mutated_signature_rejected
        || package.claim_boundary != output.claim_boundary
        || package.reviewed != output.reviewed
    {
        return Err(ThresholdError::TranscriptMismatch);
    }

    Ok(P1RealThresholdBackendEmissionCapture {
        name: name.to_owned(),
        schema: P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA.to_owned(),
        claim_boundary: P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_CLAIM_BOUNDARY.to_owned(),
        selected_profile: P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SELECTED_PROFILE.to_owned(),
        backend_evidence: P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_EXTERNAL_EVIDENCE.to_owned(),
        note: note.to_owned(),
        request: Some(P1RealThresholdBackendEmissionCaptureRequestBinding {
            schema: P1_REAL_THRESHOLD_BACKEND_EMISSION_REQUEST_SCHEMA.to_owned(),
            name: request_binding.name.to_owned(),
            request_sha256: encode_hex(&request_binding.request_sha256),
        }),
        predecessors: Some(P1RealThresholdBackendEmissionCapturePredecessors {
            selected_profile_binding_digest_hex: encode_hex(
                &SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
                    .profile_binding_digest(),
            ),
            threshold_output_certificate_digest_hex: encode_hex(
                &derive_p1_selected_backend_threshold_output_certificate_digest(
                    threshold_certificate,
                ),
            ),
            standard_verifier_compatibility_artifact_digest_hex: encode_hex(
                &derive_p1_standard_verifier_compatibility_artifact_digest(
                    compatibility_certificate,
                ),
            ),
        }),
        capture: P1RealThresholdBackendEmissionCapturePayload {
            validator_count: 10_000,
            threshold: 6_667,
            aggregate_signature_len: MLDSA65_SIGNATURE_BYTES,
            public_key_hex: encode_hex(&output.public_key.0),
            message: P1RealThresholdBackendEmissionCaptureBytes::hex(output.message),
            aggregate_signature_hex: encode_hex(&output.aggregate_signature.0),
            backend_source_package: P1RealThresholdBackendEmissionCaptureBytes::hex(
                output.backend_source_package,
            ),
            backend_implementation: P1RealThresholdBackendEmissionCaptureBytes::hex(
                output.backend_implementation,
            ),
            backend_transcript: P1RealThresholdBackendEmissionCaptureBytes::hex(
                output.backend_transcript,
            ),
            mutated_message_rejected: output.mutated_message_rejected,
            mutated_public_key_rejected: output.mutated_public_key_rejected,
            mutated_signature_rejected: output.mutated_signature_rejected,
            reviewed: output.reviewed,
        },
        expected: Some(P1RealThresholdBackendEmissionCaptureExpectedDigests {
            backend_evidence_digest_hex: encode_hex(&package.backend_evidence_digest),
            backend_source_package_digest_hex: encode_hex(&package.backend_source_package_digest),
            backend_implementation_digest_hex: encode_hex(&package.backend_implementation_digest),
            backend_transcript_digest_hex: encode_hex(&package.backend_transcript_digest),
            artifact_digest_hex: encode_hex(&package.artifact_digest),
            public_key_digest_hex: encode_hex(&package.public_key_digest),
            message_digest_hex: encode_hex(&package.message_digest),
            accepted_signature_digest_hex: encode_hex(&package.accepted_signature_digest),
        }),
    })
}

/// Derive a verified P1 real-threshold backend emission package from capture JSON.
///
/// This is the canonical handoff from externally generated backend-emission
/// captures into the existing verifier gate. It rejects stale predecessor
/// bindings, derives the package with a standard ML-DSA provider, and compares
/// the derived package against the capture's expected digest inventory.
pub fn derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture<P>(
    transcript: &ProductionSigningTranscript,
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    capture: &P1RealThresholdBackendEmissionCapture,
) -> Result<P1RealThresholdBackendEmissionArtifactPackage, ThresholdError>
where
    P: StandardMldsa65Provider,
{
    let output = capture.to_backend_output_material()?;
    capture.validate_predecessors(threshold_certificate, compatibility_certificate)?;
    let package = derive_p1_verified_real_threshold_backend_emission_artifact_package::<P>(
        transcript,
        threshold_certificate,
        compatibility_certificate,
        output.as_backend_output(),
    )?;
    capture.validate_expected_digests(&package)?;
    Ok(package)
}

/// Derive a P1 real-threshold backend emission artifact package.
///
/// The returned package ingests external backend-emission provenance and binds it
/// to the already reviewed threshold-output and standard-verifier compatibility
/// certificates. It does not implement a real threshold backend.
#[allow(clippy::too_many_arguments)]
pub fn derive_p1_real_threshold_backend_emission_artifact_package(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    backend_evidence: P1RealThresholdVerifierClosureBackendEvidence,
    backend_evidence_digest: [u8; 32],
    backend_source_package_digest: [u8; 32],
    backend_implementation_digest: [u8; 32],
    backend_transcript_digest: [u8; 32],
    mutated_message_rejected: bool,
    mutated_public_key_rejected: bool,
    mutated_signature_rejected: bool,
    claim_boundary: P1RealThresholdVerifierClosureClaimBoundary,
    reviewed: bool,
) -> P1RealThresholdBackendEmissionArtifactPackage {
    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    let standard_verifier_compatibility_artifact_digest =
        derive_p1_standard_verifier_compatibility_artifact_digest(compatibility_certificate);
    let artifact_digest = derive_p1_real_threshold_backend_emission_artifact_digest_from_fields(
        threshold_certificate.selected_profile(),
        threshold_certificate.selected_profile_binding_digest(),
        10_000,
        6_667,
        MLDSA65_SIGNATURE_BYTES,
        backend_evidence,
        &backend_evidence_digest,
        &backend_source_package_digest,
        &backend_implementation_digest,
        &backend_transcript_digest,
        &threshold_output_certificate_digest,
        &standard_verifier_compatibility_artifact_digest,
        compatibility_certificate.public_key_digest(),
        compatibility_certificate.message_digest(),
        threshold_certificate.transcript_binding_digest(),
        threshold_certificate.signer_set_digest(),
        threshold_certificate.attempt_binding_digest(),
        threshold_certificate.accepted_signature_digest(),
        compatibility_certificate.verifier_result(),
        mutated_message_rejected,
        mutated_public_key_rejected,
        mutated_signature_rejected,
        claim_boundary,
    );

    P1RealThresholdBackendEmissionArtifactPackage {
        selected_profile: threshold_certificate.selected_profile(),
        selected_profile_binding_digest: *threshold_certificate.selected_profile_binding_digest(),
        validator_count: 10_000,
        threshold: 6_667,
        aggregate_signature_len: MLDSA65_SIGNATURE_BYTES,
        backend_evidence,
        backend_evidence_digest,
        backend_source_package_digest,
        backend_implementation_digest,
        backend_transcript_digest,
        artifact_digest,
        threshold_output_certificate_digest,
        standard_verifier_compatibility_artifact_digest,
        public_key_digest: *compatibility_certificate.public_key_digest(),
        message_digest: *compatibility_certificate.message_digest(),
        transcript_binding_digest: *threshold_certificate.transcript_binding_digest(),
        signer_set_digest: *threshold_certificate.signer_set_digest(),
        attempt_binding_digest: *threshold_certificate.attempt_binding_digest(),
        accepted_signature_digest: *threshold_certificate.accepted_signature_digest(),
        verifier_result: compatibility_certificate.verifier_result(),
        mutated_message_rejected,
        mutated_public_key_rejected,
        mutated_signature_rejected,
        claim_boundary,
        reviewed,
    }
}

/// Derive a Batch 4 selected-backend proof-closure artifact package.
///
/// The returned package binds the accepted threshold-output artifact
/// certificate to reviewed proof, validation, distribution-review, standard
/// verifier, and theorem-linkage artifact digests. It remains
/// conformance/proof-review evidence only.
#[allow(clippy::too_many_arguments)]
pub fn derive_p1_selected_backend_proof_closure_artifact_package(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    provider_kat_evidence_digest: [u8; 32],
    proof_artifacts: P1RejectionProofArtifacts,
    proof_slot_artifacts: P1Criterion2ProofSlotArtifacts,
    standard_verifier_compatibility_artifact: &P1StandardVerifierCompatibilityArtifactCertificate,
    claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    reviewed: bool,
) -> P1SelectedBackendProofClosureArtifactPackage {
    P1SelectedBackendProofClosureArtifactPackage {
        selected_profile: threshold_certificate.selected_profile(),
        selected_profile_binding_digest: *threshold_certificate.selected_profile_binding_digest(),
        threshold_output_certificate_digest:
            derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate),
        aggregate_artifact_digest: *threshold_certificate.aggregate_artifact_digest(),
        threshold_output_source_digest: *threshold_certificate.threshold_output_source_digest(),
        threshold_output_source_package_digest: *threshold_certificate
            .threshold_output_source_package_digest(),
        provider_kat_evidence_digest,
        standard_verifier_bridge_evidence_digest: *threshold_certificate
            .standard_verifier_bridge_evidence_digest(),
        real_recomputation_evidence_digest: *threshold_certificate
            .real_recomputation_evidence_digest(),
        distributed_nonce_producer_artifact_digest: proof_slot_artifacts
            .distributed_nonce_producer_artifact
            .source_evidence_digest,
        transcript_binding_digest: *threshold_certificate.transcript_binding_digest(),
        signer_set_digest: *threshold_certificate.signer_set_digest(),
        attempt_binding_digest: *threshold_certificate.attempt_binding_digest(),
        aggregate_response_digest: *threshold_certificate.aggregate_response_digest(),
        hint_digest: *threshold_certificate.hint_digest(),
        accepted_signature_digest: *threshold_certificate.accepted_signature_digest(),
        proof_artifacts,
        proof_slot_artifacts,
        full_kat_validation_artifact_digest: *proof_slot_artifacts
            .full_kat_validation_artifact
            .artifact_digest(),
        rejection_distribution_review_digest: *proof_slot_artifacts
            .rejection_distribution_review_artifact
            .artifact_digest(),
        standard_verifier_compatibility_artifact_digest:
            derive_p1_standard_verifier_compatibility_artifact_digest(
                standard_verifier_compatibility_artifact,
            ),
        standard_verifier_compatibility_artifact: *standard_verifier_compatibility_artifact,
        theorem_linkage_artifact_digest: *proof_slot_artifacts
            .theorem_linkage_artifact
            .artifact_digest(),
        claim_boundary,
        reviewed,
    }
}

/// Derive a Batch 7 external-backend cryptographic closure-candidate package.
///
/// The returned package composes accepted child certificates for the actual
/// distributed nonce-producer path, real threshold backend emission path,
/// standard verifier compatibility path, and rejection-distribution comparison
/// slot. It remains conformance/proof-review evidence only.
pub fn derive_p1_external_backend_cryptographic_closure_candidate_package(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    distributed_nonce_producer_artifact: &P1DistributedNonceProducerArtifactCertificate,
    real_threshold_backend_emission_artifact: &P1RealThresholdBackendEmissionArtifactCertificate,
    standard_verifier_compatibility_artifact: &P1StandardVerifierCompatibilityArtifactCertificate,
    rejection_distribution_comparison_artifact: P1Criterion2ProofSlotArtifact,
    claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    reviewed: bool,
) -> P1ExternalBackendCryptographicClosureCandidatePackage {
    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    let distributed_nonce_producer_artifact_digest =
        derive_p1_distributed_nonce_producer_artifact_digest(distributed_nonce_producer_artifact);
    let real_threshold_backend_emission_artifact_digest =
        derive_p1_real_threshold_backend_emission_artifact_digest(
            real_threshold_backend_emission_artifact,
        );
    let standard_verifier_compatibility_artifact_digest =
        derive_p1_standard_verifier_compatibility_artifact_digest(
            standard_verifier_compatibility_artifact,
        );
    let rejection_distribution_comparison_digest =
        *rejection_distribution_comparison_artifact.artifact_digest();
    let candidate_artifact_digest =
        derive_p1_external_backend_cryptographic_closure_candidate_digest_from_fields(
            threshold_certificate.selected_profile(),
            threshold_certificate.selected_profile_binding_digest(),
            &threshold_output_certificate_digest,
            &distributed_nonce_producer_artifact_digest,
            &real_threshold_backend_emission_artifact_digest,
            &standard_verifier_compatibility_artifact_digest,
            &rejection_distribution_comparison_digest,
            claim_boundary,
            reviewed,
        );

    P1ExternalBackendCryptographicClosureCandidatePackage {
        selected_profile: threshold_certificate.selected_profile(),
        selected_profile_binding_digest: *threshold_certificate.selected_profile_binding_digest(),
        threshold_output_certificate_digest,
        distributed_nonce_producer_artifact_digest,
        distributed_nonce_producer_artifact: *distributed_nonce_producer_artifact,
        real_threshold_backend_emission_artifact_digest,
        real_threshold_backend_emission_artifact: *real_threshold_backend_emission_artifact,
        standard_verifier_compatibility_artifact_digest,
        standard_verifier_compatibility_artifact: *standard_verifier_compatibility_artifact,
        rejection_distribution_comparison_digest,
        rejection_distribution_comparison_artifact,
        candidate_artifact_digest,
        claim_boundary,
        reviewed,
    }
}

/// Derive a selected-backend aggregate-output artifact package from live
/// accepted aggregate, recomputation, and provider-verification evidence.
///
/// This constructor is intentionally stricter than `P1SelectedBackendAggregateArtifactPackage::new`:
/// it verifies the candidate signature with the selected provider boundary,
/// requires public recomputation to match the accepted aggregate token, derives
/// the bridge digest from that evidence, and requires the supplied P1
/// recomputation certificate to bind the same recomputation and bridge digests.
/// The returned package is still proof-review evidence only; it does not claim
/// production threshold ML-DSA security, FIPS validation, or completed
/// standard-verifier compatibility proof.
pub fn derive_p1_selected_backend_aggregate_artifact_package<P>(
    transcript: &ProductionSigningTranscript,
    accepted_aggregate: &AcceptedAggregateCandidate,
    recomputation: &AggregateRecomputationTranscript,
    recomputation_certificate: &P1AggregateRecomputationClosureCertificate,
    candidate_signature: &ThresholdSignature,
    reviewed: bool,
) -> Result<P1SelectedBackendAggregateArtifactPackage, ThresholdError>
where
    P: StandardMldsa65Provider,
{
    if accepted_aggregate.challenge_digest() != transcript.challenge_digest()
        || recomputation.challenge_digest() != transcript.challenge_digest()
    {
        return Err(ThresholdError::TranscriptMismatch);
    }
    if accepted_aggregate.aggregate_response_digest() != recomputation.aggregate_response_digest()
        || accepted_aggregate.hint_digest() != recomputation.hint_digest()
        || accepted_aggregate.candidate_signature_digest()
            != recomputation.recomputed_signature_digest()
    {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    let bridge_evidence = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<P>(
        transcript,
        candidate_signature,
        recomputation,
    )?;
    if bridge_evidence.aggregate_response_digest() != accepted_aggregate.aggregate_response_digest()
        || bridge_evidence.hint_digest() != accepted_aggregate.hint_digest()
        || bridge_evidence.candidate_signature_digest()
            != accepted_aggregate.candidate_signature_digest()
    {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    let selected_profile_binding_digest =
        *recomputation_certificate.selected_profile_binding_digest();
    let provider_kat_evidence_digest = *recomputation_certificate.provider_kat_evidence_digest();
    let real_recomputation_evidence_digest =
        derive_p1_real_recomputation_evidence_digest(recomputation);
    if &real_recomputation_evidence_digest
        != recomputation_certificate.real_recomputation_evidence_digest()
    {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    let standard_verifier_bridge_evidence_digest = derive_standard_verifier_bridge_evidence_digest(
        &selected_profile_binding_digest,
        &provider_kat_evidence_digest,
        &bridge_evidence,
    )?;
    if &standard_verifier_bridge_evidence_digest
        != recomputation_certificate.standard_verifier_bridge_evidence_digest()
    {
        return Err(ThresholdError::StandardVerificationFailed);
    }

    Ok(P1SelectedBackendAggregateArtifactPackage::new(
        recomputation_certificate.selected_profile(),
        selected_profile_binding_digest,
        provider_kat_evidence_digest,
        standard_verifier_bridge_evidence_digest,
        real_recomputation_evidence_digest,
        derive_p1_selected_backend_transcript_binding_digest(transcript),
        derive_p1_selected_backend_signer_set_digest(accepted_aggregate.signers()),
        derive_p1_selected_backend_attempt_binding_digest(transcript),
        *accepted_aggregate.aggregate_response_digest(),
        *accepted_aggregate.hint_digest(),
        *accepted_aggregate.candidate_signature_digest(),
        reviewed,
    ))
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
    let standard_verifier_bridge_evidence_digest = match require_closure_digest(
        package.standard_verifier_bridge_evidence,
        AggregateRejectionEvidenceKind::StandardVerifierBridge,
        "missing standard verifier bridge evidence digest",
        "standard verifier bridge evidence must not be scaffold-only",
        "standard verifier bridge evidence has wrong artifact kind",
        "standard verifier bridge evidence digest is all zero",
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
        standard_verifier_bridge_evidence_digest,
        norm_bound_evidence_digest,
        hint_bound_evidence_digest,
        challenge_bound_evidence_digest,
        transcript_binding_evidence_digest,
        negative_test_corpus_digest,
        external_review_digest,
    })
}

/// Assess whether the selected P1 backend has aggregate recomputation, KAT, and
/// proof artifacts wired tightly enough for proof review.
pub fn assess_p1_aggregate_recomputation_closure(
    package: Option<P1AggregateRecomputationClosurePackage>,
) -> P1AggregateRecomputationAssessment {
    let Some(package) = package else {
        return P1AggregateRecomputationAssessment::Missing {
            reason: "missing P1 aggregate recomputation closure package",
        };
    };

    if package.selected_profile
        != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 aggregate recomputation package must bind the selected ML-DSA-65 coordinator-assisted profile",
        };
    }

    if !package
        .provider_kat_evidence
        .source()
        .is_acvp_fips204_backed()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 provider KAT evidence must be ACVP/FIPS204-backed, not smoke-only",
        };
    }
    if !package.provider_kat_evidence.reviewed() {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 provider KAT evidence must be reviewed before artifact closure",
        };
    }
    if is_all_zero(package.provider_kat_evidence.provider_kat_evidence_digest()) {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 provider KAT evidence digest is all zero",
        };
    }
    if is_all_zero(package.provider_kat_evidence.acvp_vector_set_digest()) {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 ACVP/FIPS204 vector-set digest is all zero",
        };
    }
    if is_all_zero(package.provider_kat_evidence.provider_identity_digest()) {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 provider identity digest is all zero",
        };
    }

    if !package.proof_artifacts.reviewed() {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 proof artifacts must be reviewed before artifact closure",
        };
    }
    if *package.proof_artifacts.selected_profile_binding_digest()
        != package.selected_profile.profile_binding_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 selected profile binding digest does not match selected profile",
        };
    }
    if is_all_zero(
        package
            .proof_artifacts
            .standard_verifier_bridge_fixture_package_digest(),
    ) {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 standard verifier bridge fixture package digest is all zero",
        };
    }

    let closure_certificate =
        match assess_rejection_equivalence_closure(Some(package.rejection_closure_package)) {
            AggregateRejectionClosureAssessment::ClosureReady(certificate) => certificate,
            AggregateRejectionClosureAssessment::Missing { reason } => {
                return P1AggregateRecomputationAssessment::Missing { reason };
            }
            AggregateRejectionClosureAssessment::Invalid { reason } => {
                return P1AggregateRecomputationAssessment::Invalid { reason };
            }
        };

    if closure_certificate.standard_provider_kat_evidence_digest()
        != package.provider_kat_evidence.provider_kat_evidence_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 provider KAT evidence digest does not match closure package",
        };
    }
    if closure_certificate.real_recomputation_evidence_digest()
        != package.proof_artifacts.real_recomputation_evidence_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 real recomputation evidence digest does not match closure package",
        };
    }
    if closure_certificate.standard_verifier_bridge_evidence_digest()
        != package
            .proof_artifacts
            .standard_verifier_bridge_evidence_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 standard verifier bridge evidence digest does not match closure package",
        };
    }
    if closure_certificate.norm_bound_evidence_digest()
        != package.proof_artifacts.norm_bound_evidence_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 norm-bound evidence digest does not match closure package",
        };
    }
    if closure_certificate.hint_bound_evidence_digest()
        != package.proof_artifacts.hint_bound_evidence_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 hint-bound evidence digest does not match closure package",
        };
    }
    if closure_certificate.challenge_bound_evidence_digest()
        != package.proof_artifacts.challenge_bound_evidence_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 challenge-bound evidence digest does not match closure package",
        };
    }
    if closure_certificate.transcript_binding_evidence_digest()
        != package.proof_artifacts.transcript_binding_evidence_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 transcript-binding evidence digest does not match closure package",
        };
    }
    if closure_certificate.negative_test_corpus_digest()
        != package.proof_artifacts.negative_test_corpus_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 negative test corpus digest does not match closure package",
        };
    }
    if closure_certificate.external_review_digest()
        != package.proof_artifacts.external_review_digest()
    {
        return P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 external review digest does not match closure package",
        };
    }

    P1AggregateRecomputationAssessment::ArtifactReady(P1AggregateRecomputationClosureCertificate {
        selected_profile: package.selected_profile,
        closure_certificate,
        provider_kat_evidence: package.provider_kat_evidence,
        proof_artifacts: package.proof_artifacts,
    })
}

/// Assess whether selected-backend aggregate acceptance is bound to recomputation evidence.
pub fn assess_p1_selected_backend_aggregate_artifact(
    transcript: &ProductionSigningTranscript,
    accepted_aggregate: &AcceptedAggregateCandidate,
    recomputation: &AggregateRecomputationTranscript,
    recomputation_certificate: &P1AggregateRecomputationClosureCertificate,
    package: Option<P1SelectedBackendAggregateArtifactPackage>,
) -> P1SelectedBackendAggregateArtifactAssessment {
    let Some(package) = package else {
        return P1SelectedBackendAggregateArtifactAssessment::Missing {
            reason: "missing P1 selected-backend aggregate artifact package",
        };
    };

    if !package.reviewed {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason:
                "P1 selected-backend aggregate artifact must be reviewed before artifact closure",
        };
    }
    if package.selected_profile
        != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate artifact must bind the selected ML-DSA-65 coordinator-assisted profile",
        };
    }
    if package.selected_profile != recomputation_certificate.selected_profile() {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason:
                "P1 selected-backend aggregate profile does not match recomputation certificate",
        };
    }

    for (digest, reason) in [
        (
            &package.selected_profile_binding_digest,
            "P1 selected-backend aggregate profile binding digest is all zero",
        ),
        (
            &package.provider_kat_evidence_digest,
            "P1 selected-backend aggregate provider KAT digest is all zero",
        ),
        (
            &package.standard_verifier_bridge_evidence_digest,
            "P1 selected-backend aggregate bridge digest is all zero",
        ),
        (
            &package.real_recomputation_evidence_digest,
            "P1 selected-backend aggregate recomputation digest is all zero",
        ),
        (
            &package.transcript_binding_digest,
            "P1 selected-backend aggregate transcript binding digest is all zero",
        ),
        (
            &package.signer_set_digest,
            "P1 selected-backend aggregate signer-set digest is all zero",
        ),
        (
            &package.attempt_binding_digest,
            "P1 selected-backend aggregate attempt binding digest is all zero",
        ),
        (
            &package.aggregate_response_digest,
            "P1 selected-backend aggregate response digest is all zero",
        ),
        (
            &package.hint_digest,
            "P1 selected-backend aggregate hint digest is all zero",
        ),
        (
            &package.accepted_signature_digest,
            "P1 selected-backend aggregate signature digest is all zero",
        ),
    ] {
        if is_all_zero(digest) {
            return P1SelectedBackendAggregateArtifactAssessment::Invalid { reason };
        }
    }

    if package.selected_profile_binding_digest != package.selected_profile.profile_binding_digest()
    {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate profile binding digest does not match selected profile",
        };
    }
    if &package.selected_profile_binding_digest
        != recomputation_certificate.selected_profile_binding_digest()
    {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate profile binding digest does not match recomputation certificate",
        };
    }
    if &package.provider_kat_evidence_digest
        != recomputation_certificate.provider_kat_evidence_digest()
    {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate provider KAT digest does not match recomputation certificate",
        };
    }
    if &package.real_recomputation_evidence_digest
        != recomputation_certificate.real_recomputation_evidence_digest()
    {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate recomputation digest does not match recomputation certificate",
        };
    }
    if &package.standard_verifier_bridge_evidence_digest
        != recomputation_certificate.standard_verifier_bridge_evidence_digest()
    {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate bridge digest does not match recomputation certificate",
        };
    }

    if accepted_aggregate.challenge_digest() != transcript.challenge_digest() {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 accepted aggregate transcript binding does not match production transcript",
        };
    }
    if recomputation.challenge_digest() != transcript.challenge_digest() {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 aggregate recomputation transcript does not match production transcript",
        };
    }
    if accepted_aggregate.aggregate_response_digest() != recomputation.aggregate_response_digest() {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 accepted aggregate response digest does not match recomputation transcript",
        };
    }
    if accepted_aggregate.hint_digest() != recomputation.hint_digest() {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 accepted aggregate hint digest does not match recomputation transcript",
        };
    }
    if accepted_aggregate.candidate_signature_digest()
        != recomputation.recomputed_signature_digest()
    {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason:
                "P1 accepted aggregate signature digest does not match recomputation transcript",
        };
    }

    let transcript_binding_digest =
        derive_p1_selected_backend_transcript_binding_digest(transcript);
    if package.transcript_binding_digest != transcript_binding_digest {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate transcript binding digest does not match production transcript",
        };
    }
    let signer_set_digest =
        derive_p1_selected_backend_signer_set_digest(accepted_aggregate.signers());
    if package.signer_set_digest != signer_set_digest {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason:
                "P1 selected-backend aggregate signer-set digest does not match accepted aggregate",
        };
    }
    let attempt_binding_digest = derive_p1_selected_backend_attempt_binding_digest(transcript);
    if package.attempt_binding_digest != attempt_binding_digest {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate attempt binding digest does not match production transcript",
        };
    }
    if package.aggregate_response_digest != *accepted_aggregate.aggregate_response_digest() {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason:
                "P1 selected-backend aggregate response digest does not match accepted aggregate",
        };
    }
    if package.hint_digest != *accepted_aggregate.hint_digest() {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate hint digest does not match accepted aggregate",
        };
    }
    if package.accepted_signature_digest != *accepted_aggregate.candidate_signature_digest() {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason:
                "P1 selected-backend aggregate signature digest does not match accepted aggregate",
        };
    }

    let bridge_evidence = AggregateRejectionEquivalenceEvidence {
        strength: AggregateRejectionEvidenceStrength::ProviderRecomputedBridge,
        challenge_digest: *accepted_aggregate.challenge_digest(),
        aggregate_response_digest: *accepted_aggregate.aggregate_response_digest(),
        hint_digest: *accepted_aggregate.hint_digest(),
        candidate_signature_digest: *accepted_aggregate.candidate_signature_digest(),
        recomputed_signature_digest: Some(*recomputation.recomputed_signature_digest()),
    };
    let bound_bridge_digest = match derive_standard_verifier_bridge_evidence_digest(
        &package.selected_profile_binding_digest,
        &package.provider_kat_evidence_digest,
        &bridge_evidence,
    ) {
        Ok(digest) => digest,
        Err(_) => {
            return P1SelectedBackendAggregateArtifactAssessment::Invalid {
                reason: "P1 selected-backend aggregate bridge evidence is not provider/recomputation bound",
            };
        }
    };
    if package.standard_verifier_bridge_evidence_digest != bound_bridge_digest {
        return P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate bridge digest does not match accepted aggregate and recomputation evidence",
        };
    }

    P1SelectedBackendAggregateArtifactAssessment::ArtifactReady(
        P1SelectedBackendAggregateArtifactCertificate {
            selected_profile: package.selected_profile,
            selected_profile_binding_digest: package.selected_profile_binding_digest,
            provider_kat_evidence_digest: package.provider_kat_evidence_digest,
            standard_verifier_bridge_evidence_digest: package
                .standard_verifier_bridge_evidence_digest,
            real_recomputation_evidence_digest: package.real_recomputation_evidence_digest,
            transcript_binding_digest,
            signer_set_digest,
            attempt_binding_digest,
            aggregate_response_digest: package.aggregate_response_digest,
            hint_digest: package.hint_digest,
            accepted_signature_digest: package.accepted_signature_digest,
        },
    )
}

/// Assess whether selected-backend threshold-output evidence is bound to the
/// predecessor aggregate artifact certificate and public recomputation outputs.
pub fn assess_p1_selected_backend_threshold_output_artifact(
    transcript: &ProductionSigningTranscript,
    accepted_aggregate: &AcceptedAggregateCandidate,
    recomputation: &AggregateRecomputationTranscript,
    aggregate_certificate: &P1SelectedBackendAggregateArtifactCertificate,
    package: Option<P1SelectedBackendThresholdOutputArtifactPackage>,
) -> P1SelectedBackendThresholdOutputArtifactAssessment {
    let Some(package) = package else {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Missing {
            reason: "missing P1 selected-backend threshold-output artifact package",
        };
    };

    if !package.reviewed {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason:
                "P1 selected-backend threshold-output artifact must be reviewed before artifact closure",
        };
    }
    if !package.threshold_output_source.reviewed() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output source evidence must be reviewed",
        };
    }
    if package.claim_boundary != P1ThresholdOutputClaimBoundary::ProofReviewOnly {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output artifact must remain proof-review-only",
        };
    }
    if package.selected_profile
        != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output artifact must bind the selected ML-DSA-65 coordinator-assisted profile",
        };
    }
    if package.selected_profile != aggregate_certificate.selected_profile() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output selected profile does not match aggregate certificate",
        };
    }

    for (digest, reason) in [
        (
            &package.selected_profile_binding_digest,
            "P1 threshold-output profile binding digest is all zero",
        ),
        (
            &package.aggregate_artifact_digest,
            "P1 threshold-output aggregate artifact digest is all zero",
        ),
        (
            &package.provider_kat_evidence_digest,
            "P1 threshold-output provider KAT digest is all zero",
        ),
        (
            &package.threshold_output_source_digest,
            "P1 threshold-output source digest is all zero",
        ),
        (
            &package.transcript_binding_digest,
            "P1 threshold-output transcript binding digest is all zero",
        ),
        (
            &package.signer_set_digest,
            "P1 threshold-output signer-set digest is all zero",
        ),
        (
            &package.attempt_binding_digest,
            "P1 threshold-output attempt binding digest is all zero",
        ),
        (
            &package.aggregate_response_digest,
            "P1 threshold-output aggregate response digest is all zero",
        ),
        (
            &package.hint_digest,
            "P1 threshold-output hint digest is all zero",
        ),
        (
            &package.accepted_signature_digest,
            "P1 threshold-output accepted signature digest is all zero",
        ),
        (
            &package.standard_verifier_bridge_evidence_digest,
            "P1 threshold-output bridge digest is all zero",
        ),
        (
            &package.real_recomputation_evidence_digest,
            "P1 threshold-output recomputation digest is all zero",
        ),
    ] {
        if is_all_zero(digest) {
            return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid { reason };
        }
    }

    if package.selected_profile_binding_digest != package.selected_profile.profile_binding_digest()
    {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output profile binding digest does not match selected profile",
        };
    }
    if &package.selected_profile_binding_digest
        != aggregate_certificate.selected_profile_binding_digest()
    {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason:
                "P1 threshold-output profile binding digest does not match aggregate certificate",
        };
    }

    let aggregate_artifact_digest =
        derive_p1_selected_backend_aggregate_certificate_digest(aggregate_certificate);
    if package.aggregate_artifact_digest != aggregate_artifact_digest {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason:
                "P1 threshold-output aggregate artifact digest does not match aggregate certificate",
        };
    }
    if &package.provider_kat_evidence_digest != aggregate_certificate.provider_kat_evidence_digest()
    {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output provider KAT digest does not match aggregate certificate",
        };
    }
    if accepted_aggregate.challenge_digest() != transcript.challenge_digest() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output accepted aggregate does not match production transcript",
        };
    }
    if recomputation.challenge_digest() != transcript.challenge_digest() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output recomputation does not match production transcript",
        };
    }
    if accepted_aggregate.aggregate_response_digest() != recomputation.aggregate_response_digest() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output accepted aggregate response does not match recomputation",
        };
    }
    if accepted_aggregate.hint_digest() != recomputation.hint_digest() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output accepted hint does not match recomputation",
        };
    }
    if accepted_aggregate.candidate_signature_digest()
        != recomputation.recomputed_signature_digest()
    {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output accepted signature does not match recomputation",
        };
    }

    let transcript_binding_digest =
        derive_p1_selected_backend_transcript_binding_digest(transcript);
    if package.transcript_binding_digest != transcript_binding_digest {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason:
                "P1 threshold-output transcript binding digest does not match production transcript",
        };
    }
    let signer_set_digest =
        derive_p1_selected_backend_signer_set_digest(accepted_aggregate.signers());
    if package.signer_set_digest != signer_set_digest {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output signer-set digest does not match accepted aggregate",
        };
    }
    let attempt_binding_digest = derive_p1_selected_backend_attempt_binding_digest(transcript);
    if package.attempt_binding_digest != attempt_binding_digest {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason:
                "P1 threshold-output attempt binding digest does not match production transcript",
        };
    }
    if package.aggregate_response_digest != *accepted_aggregate.aggregate_response_digest() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason:
                "P1 threshold-output aggregate response digest does not match accepted aggregate",
        };
    }
    if package.hint_digest != *accepted_aggregate.hint_digest() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output hint digest does not match accepted aggregate",
        };
    }
    if package.accepted_signature_digest != *accepted_aggregate.candidate_signature_digest() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output signature digest does not match accepted aggregate",
        };
    }
    if &package.standard_verifier_bridge_evidence_digest
        != aggregate_certificate.standard_verifier_bridge_evidence_digest()
    {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output bridge digest does not match aggregate certificate",
        };
    }
    if &package.real_recomputation_evidence_digest
        != aggregate_certificate.real_recomputation_evidence_digest()
    {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output recomputation digest does not match aggregate certificate",
        };
    }

    let expected_source_digest =
        derive_p1_selected_backend_threshold_output_source_digest_from_package_digest(
            transcript,
            accepted_aggregate,
            recomputation,
            package.threshold_output_source.source_package_digest(),
        );
    if package.threshold_output_source_digest != expected_source_digest {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output source digest does not match selected-backend aggregate evidence",
        };
    }
    if package.threshold_output_source_digest != *package.threshold_output_source.source_digest() {
        return P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output source digest does not match reviewed source evidence",
        };
    }

    P1SelectedBackendThresholdOutputArtifactAssessment::ArtifactReady(
        P1SelectedBackendThresholdOutputArtifactCertificate {
            selected_profile: package.selected_profile,
            selected_profile_binding_digest: package.selected_profile_binding_digest,
            aggregate_artifact_digest: package.aggregate_artifact_digest,
            provider_kat_evidence_digest: package.provider_kat_evidence_digest,
            threshold_output_source_digest: package.threshold_output_source_digest,
            threshold_output_source_package_digest: *package
                .threshold_output_source
                .source_package_digest(),
            transcript_binding_digest,
            signer_set_digest,
            attempt_binding_digest,
            aggregate_response_digest: package.aggregate_response_digest,
            hint_digest: package.hint_digest,
            accepted_signature_digest: package.accepted_signature_digest,
            standard_verifier_bridge_evidence_digest: package
                .standard_verifier_bridge_evidence_digest,
            real_recomputation_evidence_digest: package.real_recomputation_evidence_digest,
            claim_boundary: package.claim_boundary,
        },
    )
}

/// Assess whether a P1 standard-verifier compatibility artifact is bound to
/// the threshold-output certificate, transcript public key/message, accepted
/// signature, provider identity, bridge evidence, and recomputation evidence.
pub fn assess_p1_standard_verifier_compatibility_artifact(
    transcript: &ProductionSigningTranscript,
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    package: Option<P1StandardVerifierCompatibilityArtifactPackage>,
) -> P1StandardVerifierCompatibilityArtifactAssessment {
    let Some(package) = package else {
        return P1StandardVerifierCompatibilityArtifactAssessment::Missing {
            reason: "missing P1 standard-verifier compatibility artifact package",
        };
    };

    if !package.reviewed {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility artifact must be reviewed",
        };
    }
    if package.claim_boundary != P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility artifact must remain proof-review-only",
        };
    }
    if threshold_certificate.claim_boundary() != P1ThresholdOutputClaimBoundary::ProofReviewOnly {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility threshold-output certificate must remain proof-review-only",
        };
    }
    if package.verifier_result != P1StandardVerifierCompatibilityResult::Accept {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason:
                "P1 standard-verifier compatibility artifact must bind an accepted verifier result",
        };
    }
    if package.selected_profile
        != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility artifact must bind the selected ML-DSA-65 coordinator-assisted profile",
        };
    }
    if package.selected_profile != threshold_certificate.selected_profile() {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility selected profile does not match threshold-output certificate",
        };
    }

    for (digest, reason) in [
        (
            &package.selected_profile_binding_digest,
            "P1 standard-verifier compatibility profile binding digest is all zero",
        ),
        (
            &package.artifact_digest,
            "P1 standard-verifier compatibility artifact digest is all zero",
        ),
        (
            &package.threshold_output_certificate_digest,
            "P1 standard-verifier compatibility threshold-output certificate digest is all zero",
        ),
        (
            &package.provider_kat_evidence_digest,
            "P1 standard-verifier compatibility provider KAT digest is all zero",
        ),
        (
            &package.provider_identity_digest,
            "P1 standard-verifier compatibility provider identity digest is all zero",
        ),
        (
            &package.public_key_digest,
            "P1 standard-verifier compatibility public key digest is all zero",
        ),
        (
            &package.message_digest,
            "P1 standard-verifier compatibility message digest is all zero",
        ),
        (
            &package.transcript_binding_digest,
            "P1 standard-verifier compatibility transcript binding digest is all zero",
        ),
        (
            &package.signer_set_digest,
            "P1 standard-verifier compatibility signer-set digest is all zero",
        ),
        (
            &package.attempt_binding_digest,
            "P1 standard-verifier compatibility attempt binding digest is all zero",
        ),
        (
            &package.aggregate_response_digest,
            "P1 standard-verifier compatibility aggregate response digest is all zero",
        ),
        (
            &package.hint_digest,
            "P1 standard-verifier compatibility hint digest is all zero",
        ),
        (
            &package.accepted_signature_digest,
            "P1 standard-verifier compatibility accepted signature digest is all zero",
        ),
        (
            &package.standard_verifier_bridge_evidence_digest,
            "P1 standard-verifier compatibility bridge digest is all zero",
        ),
        (
            &package.real_recomputation_evidence_digest,
            "P1 standard-verifier compatibility recomputation digest is all zero",
        ),
    ] {
        if is_all_zero(digest) {
            return P1StandardVerifierCompatibilityArtifactAssessment::Invalid { reason };
        }
    }

    if package.selected_profile_binding_digest != package.selected_profile.profile_binding_digest()
    {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason:
                "P1 standard-verifier compatibility profile binding digest does not match selected profile",
        };
    }
    if &package.selected_profile_binding_digest
        != threshold_certificate.selected_profile_binding_digest()
    {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility profile binding digest does not match threshold-output certificate",
        };
    }

    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    if package.threshold_output_certificate_digest != threshold_output_certificate_digest {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility threshold-output certificate digest does not match certificate",
        };
    }
    if &package.provider_kat_evidence_digest != threshold_certificate.provider_kat_evidence_digest()
    {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility provider KAT digest does not match threshold-output certificate",
        };
    }
    if package.public_key_digest != digest_bytes(&transcript.input().public_key.0) {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason:
                "P1 standard-verifier compatibility public key digest does not match transcript",
        };
    }
    if package.message_digest != digest_bytes(&transcript.input().application_message) {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility message digest does not match transcript",
        };
    }
    if &package.transcript_binding_digest != threshold_certificate.transcript_binding_digest() {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility transcript binding digest does not match threshold-output certificate",
        };
    }
    if package.transcript_binding_digest
        != derive_p1_selected_backend_transcript_binding_digest(transcript)
    {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility transcript binding digest does not match transcript",
        };
    }
    if &package.signer_set_digest != threshold_certificate.signer_set_digest() {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility signer-set digest does not match threshold-output certificate",
        };
    }
    if &package.attempt_binding_digest != threshold_certificate.attempt_binding_digest() {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility attempt binding digest does not match threshold-output certificate",
        };
    }
    if &package.aggregate_response_digest != threshold_certificate.aggregate_response_digest() {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility aggregate response digest does not match threshold-output certificate",
        };
    }
    if &package.hint_digest != threshold_certificate.hint_digest() {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility hint digest does not match threshold-output certificate",
        };
    }
    if &package.accepted_signature_digest != threshold_certificate.accepted_signature_digest() {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility accepted signature digest does not match threshold-output certificate",
        };
    }
    if &package.standard_verifier_bridge_evidence_digest
        != threshold_certificate.standard_verifier_bridge_evidence_digest()
    {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility bridge digest does not match threshold-output certificate",
        };
    }
    if &package.real_recomputation_evidence_digest
        != threshold_certificate.real_recomputation_evidence_digest()
    {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility recomputation digest does not match threshold-output certificate",
        };
    }

    let expected_artifact_digest =
        derive_p1_standard_verifier_compatibility_artifact_digest_from_fields(
            package.selected_profile,
            &package.selected_profile_binding_digest,
            &package.threshold_output_certificate_digest,
            &package.provider_kat_evidence_digest,
            &package.provider_identity_digest,
            &package.public_key_digest,
            &package.message_digest,
            &package.transcript_binding_digest,
            &package.signer_set_digest,
            &package.attempt_binding_digest,
            &package.aggregate_response_digest,
            &package.hint_digest,
            &package.accepted_signature_digest,
            &package.standard_verifier_bridge_evidence_digest,
            &package.real_recomputation_evidence_digest,
            package.verifier_result,
            package.claim_boundary,
        );
    if package.artifact_digest != expected_artifact_digest {
        return P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason:
                "P1 standard-verifier compatibility artifact digest does not match verifier payload",
        };
    }

    P1StandardVerifierCompatibilityArtifactAssessment::ArtifactReady(
        P1StandardVerifierCompatibilityArtifactCertificate {
            selected_profile: package.selected_profile,
            selected_profile_binding_digest: package.selected_profile_binding_digest,
            artifact_digest: package.artifact_digest,
            threshold_output_certificate_digest: package.threshold_output_certificate_digest,
            provider_kat_evidence_digest: package.provider_kat_evidence_digest,
            provider_identity_digest: package.provider_identity_digest,
            public_key_digest: package.public_key_digest,
            message_digest: package.message_digest,
            transcript_binding_digest: package.transcript_binding_digest,
            signer_set_digest: package.signer_set_digest,
            attempt_binding_digest: package.attempt_binding_digest,
            aggregate_response_digest: package.aggregate_response_digest,
            hint_digest: package.hint_digest,
            accepted_signature_digest: package.accepted_signature_digest,
            standard_verifier_bridge_evidence_digest: package
                .standard_verifier_bridge_evidence_digest,
            real_recomputation_evidence_digest: package.real_recomputation_evidence_digest,
            verifier_result: package.verifier_result,
            claim_boundary: package.claim_boundary,
        },
    )
}

/// Assess whether external P1 distributed nonce-producer evidence satisfies the artifact gate.
pub fn assess_p1_distributed_nonce_producer_artifact(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    package: Option<P1DistributedNonceProducerArtifactPackage>,
) -> P1DistributedNonceProducerArtifactAssessment {
    let Some(package) = package else {
        return P1DistributedNonceProducerArtifactAssessment::BlockedFailClosed {
            reason: "missing P1 distributed nonce-producer artifact package",
        };
    };

    match package.producer_evidence {
        P1DistributedNonceProducerEvidence::HazmatPrfOutputOracle => {
            return P1DistributedNonceProducerArtifactAssessment::BlockedFailClosed {
                reason: "P1 distributed nonce producer requires reviewed Shamir nonce-DKG evidence, not the hazmat PRF-output oracle",
            };
        }
        P1DistributedNonceProducerEvidence::CentralizedExpandedSecretKeyHelper => {
            return P1DistributedNonceProducerArtifactAssessment::BlockedFailClosed {
                reason: "P1 distributed nonce producer requires distributed nonce-DKG evidence, not centralized expanded-secret-key nonce output",
            };
        }
        P1DistributedNonceProducerEvidence::FixtureHarness => {
            return P1DistributedNonceProducerArtifactAssessment::BlockedFailClosed {
                reason: "P1 distributed nonce producer requires actual reviewed producer evidence, not a fixture harness",
            };
        }
        P1DistributedNonceProducerEvidence::StandardProviderSingleKey => {
            return P1DistributedNonceProducerArtifactAssessment::Invalid {
                reason: "P1 distributed nonce producer requires threshold nonce provenance, not ordinary single-key standard-provider output",
            };
        }
        P1DistributedNonceProducerEvidence::ReviewedP1ShamirNonceDkgTee => {}
    }
    if !package.reviewed {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer artifact must be reviewed",
        };
    }
    if package.claim_boundary != P1DistributedNonceProducerClaimBoundary::ProofReviewOnly {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer artifact must remain proof-review-only",
        };
    }
    if threshold_certificate.claim_boundary() != P1ThresholdOutputClaimBoundary::ProofReviewOnly {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer threshold-output certificate must remain proof-review-only",
        };
    }
    if compatibility_certificate.claim_boundary()
        != P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer compatibility certificate must remain proof-review-only",
        };
    }
    if package.selected_profile
        != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer must bind the selected ML-DSA-65 coordinator-assisted profile",
        };
    }
    if package.selected_profile != threshold_certificate.selected_profile()
        || package.selected_profile != compatibility_certificate.selected_profile()
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer selected profile does not match predecessor certificates",
        };
    }
    if package.selected_profile_binding_digest != package.selected_profile.profile_binding_digest()
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer profile binding digest does not match selected profile",
        };
    }
    if &package.selected_profile_binding_digest
        != threshold_certificate.selected_profile_binding_digest()
        || &package.selected_profile_binding_digest
            != compatibility_certificate.selected_profile_binding_digest()
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer profile binding digest does not match predecessor certificates",
        };
    }

    for (digest, reason) in [
        (
            &package.selected_profile_binding_digest,
            "P1 distributed nonce producer profile binding digest is all zero",
        ),
        (
            &package.source_reference_digest,
            "P1 distributed nonce producer source reference digest is all zero",
        ),
        (
            &package.backend_implementation_digest,
            "P1 distributed nonce producer backend implementation digest is all zero",
        ),
        (
            &package.coordinator_attestation_digest,
            "P1 distributed nonce producer coordinator attestation digest is all zero",
        ),
        (
            &package.shamir_nonce_dkg_transcript_digest,
            "P1 distributed nonce producer Shamir nonce-DKG transcript digest is all zero",
        ),
        (
            &package.active_set_digest,
            "P1 distributed nonce producer active set digest is all zero",
        ),
        (
            &package.pairwise_mask_seed_commitment_digest,
            "P1 distributed nonce producer pairwise mask seed commitment digest is all zero",
        ),
        (
            &package.nonce_share_commitment_digest,
            "P1 distributed nonce producer nonce-share commitment digest is all zero",
        ),
        (
            &package.attempt_binding_digest,
            "P1 distributed nonce producer attempt binding digest is all zero",
        ),
        (
            &package.abort_accountability_digest,
            "P1 distributed nonce producer abort-accountability digest is all zero",
        ),
        (
            &package.standard_verifier_bridge_digest,
            "P1 distributed nonce producer standard-verifier bridge digest is all zero",
        ),
        (
            &package.external_review_digest,
            "P1 distributed nonce producer external review digest is all zero",
        ),
        (
            &package.distributed_nonce_producer_artifact_digest,
            "P1 distributed nonce producer artifact digest is all zero",
        ),
        (
            &package.threshold_output_certificate_digest,
            "P1 distributed nonce producer threshold-output certificate digest is all zero",
        ),
        (
            &package.standard_verifier_compatibility_artifact_digest,
            "P1 distributed nonce producer compatibility artifact digest is all zero",
        ),
    ] {
        if is_all_zero(digest) {
            return P1DistributedNonceProducerArtifactAssessment::Invalid { reason };
        }
    }

    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    if package.threshold_output_certificate_digest != threshold_output_certificate_digest {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer threshold-output digest does not match predecessor certificate",
        };
    }
    if compatibility_certificate.threshold_output_certificate_digest()
        != &threshold_output_certificate_digest
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer compatibility certificate does not bind threshold-output certificate",
        };
    }
    let standard_verifier_compatibility_artifact_digest =
        derive_p1_standard_verifier_compatibility_artifact_digest(compatibility_certificate);
    if package.standard_verifier_compatibility_artifact_digest
        != standard_verifier_compatibility_artifact_digest
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer compatibility artifact digest does not match certificate",
        };
    }
    if package.active_set_digest != *threshold_certificate.signer_set_digest()
        || package.active_set_digest != *compatibility_certificate.signer_set_digest()
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer active set digest does not match predecessor certificates",
        };
    }
    if package.attempt_binding_digest != *threshold_certificate.attempt_binding_digest()
        || package.attempt_binding_digest != *compatibility_certificate.attempt_binding_digest()
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer attempt binding digest does not match predecessor certificates",
        };
    }
    if package.standard_verifier_bridge_digest
        != *threshold_certificate.standard_verifier_bridge_evidence_digest()
        || package.standard_verifier_bridge_digest
            != *compatibility_certificate.standard_verifier_bridge_evidence_digest()
    {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer standard-verifier bridge digest does not match predecessor certificates",
        };
    }

    let expected_artifact_digest = derive_p1_distributed_nonce_producer_artifact_digest_from_fields(
        package.selected_profile,
        &package.selected_profile_binding_digest,
        package.producer_evidence,
        &package.source_reference_digest,
        &package.backend_implementation_digest,
        &package.coordinator_attestation_digest,
        &package.shamir_nonce_dkg_transcript_digest,
        &package.active_set_digest,
        &package.pairwise_mask_seed_commitment_digest,
        &package.nonce_share_commitment_digest,
        &package.attempt_binding_digest,
        &package.abort_accountability_digest,
        &package.standard_verifier_bridge_digest,
        &package.external_review_digest,
        &package.threshold_output_certificate_digest,
        &package.standard_verifier_compatibility_artifact_digest,
        package.claim_boundary,
        package.reviewed,
    );
    if package.distributed_nonce_producer_artifact_digest != expected_artifact_digest {
        return P1DistributedNonceProducerArtifactAssessment::Invalid {
            reason: "P1 distributed nonce producer artifact digest does not match payload",
        };
    }

    P1DistributedNonceProducerArtifactAssessment::ArtifactReady(
        P1DistributedNonceProducerArtifactCertificate {
            selected_profile: package.selected_profile,
            selected_profile_binding_digest: package.selected_profile_binding_digest,
            source_reference_digest: package.source_reference_digest,
            backend_implementation_digest: package.backend_implementation_digest,
            coordinator_attestation_digest: package.coordinator_attestation_digest,
            shamir_nonce_dkg_transcript_digest: package.shamir_nonce_dkg_transcript_digest,
            active_set_digest: package.active_set_digest,
            pairwise_mask_seed_commitment_digest: package.pairwise_mask_seed_commitment_digest,
            nonce_share_commitment_digest: package.nonce_share_commitment_digest,
            attempt_binding_digest: package.attempt_binding_digest,
            abort_accountability_digest: package.abort_accountability_digest,
            standard_verifier_bridge_digest: package.standard_verifier_bridge_digest,
            external_review_digest: package.external_review_digest,
            distributed_nonce_producer_artifact_digest: package
                .distributed_nonce_producer_artifact_digest,
            threshold_output_certificate_digest: package.threshold_output_certificate_digest,
            standard_verifier_compatibility_artifact_digest: package
                .standard_verifier_compatibility_artifact_digest,
            claim_boundary: package.claim_boundary,
        },
    )
}

/// Assess whether external P1 backend emission evidence can feed the verifier closure contract.
pub fn assess_p1_real_threshold_backend_emission_artifact(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    package: Option<P1RealThresholdBackendEmissionArtifactPackage>,
) -> P1RealThresholdBackendEmissionArtifactAssessment {
    let Some(package) = package else {
        return P1RealThresholdBackendEmissionArtifactAssessment::BlockedFailClosed {
            reason: "missing P1 real-threshold backend emission artifact package",
        };
    };

    match package.backend_evidence {
        P1RealThresholdVerifierClosureBackendEvidence::SimulatedDeterministic => {
            return P1RealThresholdBackendEmissionArtifactAssessment::BlockedFailClosed {
                reason: "P1 real-threshold backend emission requires real threshold ML-DSA backend evidence, not deterministic simulation",
            };
        }
        P1RealThresholdVerifierClosureBackendEvidence::StandardProviderSingleKey => {
            return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
                reason: "P1 real-threshold backend emission requires threshold backend provenance, not ordinary single-key standard-provider output",
            };
        }
        P1RealThresholdVerifierClosureBackendEvidence::FixtureHarness => {
            return P1RealThresholdBackendEmissionArtifactAssessment::BlockedFailClosed {
                reason: "P1 real-threshold backend emission requires actual real threshold ML-DSA backend evidence, not the checked fixture harness",
            };
        }
        P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa => {}
    }
    if !package.reviewed {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission artifact must be reviewed",
        };
    }
    if package.claim_boundary != P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission artifact must remain proof-review-only",
        };
    }
    if threshold_certificate.claim_boundary() != P1ThresholdOutputClaimBoundary::ProofReviewOnly {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason:
                "P1 real-threshold backend emission threshold-output certificate must remain proof-review-only",
        };
    }
    if compatibility_certificate.claim_boundary()
        != P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason:
                "P1 real-threshold backend emission compatibility certificate must remain proof-review-only",
        };
    }
    if package.selected_profile
        != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission must bind the selected ML-DSA-65 coordinator-assisted profile",
        };
    }
    if package.selected_profile != threshold_certificate.selected_profile()
        || package.selected_profile != compatibility_certificate.selected_profile()
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission selected profile does not match predecessor certificates",
        };
    }
    if package.selected_profile_binding_digest != package.selected_profile.profile_binding_digest()
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission profile binding digest does not match selected profile",
        };
    }
    if &package.selected_profile_binding_digest
        != threshold_certificate.selected_profile_binding_digest()
        || &package.selected_profile_binding_digest
            != compatibility_certificate.selected_profile_binding_digest()
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission profile binding digest does not match predecessor certificates",
        };
    }
    if package.validator_count != 10_000 || package.threshold != 6_667 {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason:
                "P1 real-threshold backend emission must bind 10,000 validators with threshold 6,667",
        };
    }
    if package.aggregate_signature_len != MLDSA65_SIGNATURE_BYTES {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission aggregate signature must be 3,309 bytes",
        };
    }
    if package.verifier_result != P1StandardVerifierCompatibilityResult::Accept {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason:
                "P1 real-threshold backend emission must bind an accepted standard verifier result",
        };
    }
    if package.verifier_result != compatibility_certificate.verifier_result() {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission verifier result does not match compatibility certificate",
        };
    }
    if !(package.mutated_message_rejected
        && package.mutated_public_key_rejected
        && package.mutated_signature_rejected)
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission requires mutated message, public key, and signature rejection evidence",
        };
    }

    for (digest, reason) in [
        (
            &package.selected_profile_binding_digest,
            "P1 real-threshold backend emission profile binding digest is all zero",
        ),
        (
            &package.backend_evidence_digest,
            "P1 real-threshold backend emission backend evidence digest is all zero",
        ),
        (
            &package.backend_source_package_digest,
            "P1 real-threshold backend emission source package digest is all zero",
        ),
        (
            &package.backend_implementation_digest,
            "P1 real-threshold backend emission implementation digest is all zero",
        ),
        (
            &package.backend_transcript_digest,
            "P1 real-threshold backend emission transcript digest is all zero",
        ),
        (
            &package.artifact_digest,
            "P1 real-threshold backend emission artifact digest is all zero",
        ),
        (
            &package.threshold_output_certificate_digest,
            "P1 real-threshold backend emission threshold-output certificate digest is all zero",
        ),
        (
            &package.standard_verifier_compatibility_artifact_digest,
            "P1 real-threshold backend emission compatibility artifact digest is all zero",
        ),
        (
            &package.public_key_digest,
            "P1 real-threshold backend emission public key digest is all zero",
        ),
        (
            &package.message_digest,
            "P1 real-threshold backend emission message digest is all zero",
        ),
        (
            &package.transcript_binding_digest,
            "P1 real-threshold backend emission transcript binding digest is all zero",
        ),
        (
            &package.signer_set_digest,
            "P1 real-threshold backend emission signer-set digest is all zero",
        ),
        (
            &package.attempt_binding_digest,
            "P1 real-threshold backend emission attempt binding digest is all zero",
        ),
        (
            &package.accepted_signature_digest,
            "P1 real-threshold backend emission accepted signature digest is all zero",
        ),
    ] {
        if is_all_zero(digest) {
            return P1RealThresholdBackendEmissionArtifactAssessment::Invalid { reason };
        }
    }

    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    if package.threshold_output_certificate_digest != threshold_output_certificate_digest {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission threshold-output digest does not match predecessor certificate",
        };
    }
    if compatibility_certificate.threshold_output_certificate_digest()
        != &threshold_output_certificate_digest
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission compatibility certificate does not bind threshold-output certificate",
        };
    }
    let compatibility_artifact_digest =
        derive_p1_standard_verifier_compatibility_artifact_digest(compatibility_certificate);
    if package.standard_verifier_compatibility_artifact_digest != compatibility_artifact_digest {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission compatibility artifact digest does not match certificate",
        };
    }
    if package.public_key_digest != *compatibility_certificate.public_key_digest() {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission public key digest does not match compatibility certificate",
        };
    }
    if package.message_digest != *compatibility_certificate.message_digest() {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission message digest does not match compatibility certificate",
        };
    }
    if package.transcript_binding_digest != *threshold_certificate.transcript_binding_digest()
        || package.transcript_binding_digest
            != *compatibility_certificate.transcript_binding_digest()
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission transcript binding digest does not match predecessor certificates",
        };
    }
    if package.signer_set_digest != *threshold_certificate.signer_set_digest()
        || package.signer_set_digest != *compatibility_certificate.signer_set_digest()
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission signer-set digest does not match predecessor certificates",
        };
    }
    if package.attempt_binding_digest != *threshold_certificate.attempt_binding_digest()
        || package.attempt_binding_digest != *compatibility_certificate.attempt_binding_digest()
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission attempt binding digest does not match predecessor certificates",
        };
    }
    if package.accepted_signature_digest != *threshold_certificate.accepted_signature_digest()
        || package.accepted_signature_digest
            != *compatibility_certificate.accepted_signature_digest()
    {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission accepted signature digest does not match predecessor certificates",
        };
    }

    let expected_artifact_digest =
        derive_p1_real_threshold_backend_emission_artifact_digest_from_fields(
            package.selected_profile,
            &package.selected_profile_binding_digest,
            package.validator_count,
            package.threshold,
            package.aggregate_signature_len,
            package.backend_evidence,
            &package.backend_evidence_digest,
            &package.backend_source_package_digest,
            &package.backend_implementation_digest,
            &package.backend_transcript_digest,
            &package.threshold_output_certificate_digest,
            &package.standard_verifier_compatibility_artifact_digest,
            &package.public_key_digest,
            &package.message_digest,
            &package.transcript_binding_digest,
            &package.signer_set_digest,
            &package.attempt_binding_digest,
            &package.accepted_signature_digest,
            package.verifier_result,
            package.mutated_message_rejected,
            package.mutated_public_key_rejected,
            package.mutated_signature_rejected,
            package.claim_boundary,
        );
    if package.artifact_digest != expected_artifact_digest {
        return P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission artifact digest does not match payload",
        };
    }

    P1RealThresholdBackendEmissionArtifactAssessment::ArtifactReady(
        P1RealThresholdBackendEmissionArtifactCertificate {
            selected_profile: package.selected_profile,
            selected_profile_binding_digest: package.selected_profile_binding_digest,
            validator_count: package.validator_count,
            threshold: package.threshold,
            aggregate_signature_len: package.aggregate_signature_len,
            backend_evidence_digest: package.backend_evidence_digest,
            backend_source_package_digest: package.backend_source_package_digest,
            backend_implementation_digest: package.backend_implementation_digest,
            backend_transcript_digest: package.backend_transcript_digest,
            artifact_digest: package.artifact_digest,
            threshold_output_certificate_digest: package.threshold_output_certificate_digest,
            standard_verifier_compatibility_artifact_digest: package
                .standard_verifier_compatibility_artifact_digest,
            public_key_digest: package.public_key_digest,
            message_digest: package.message_digest,
            transcript_binding_digest: package.transcript_binding_digest,
            signer_set_digest: package.signer_set_digest,
            attempt_binding_digest: package.attempt_binding_digest,
            accepted_signature_digest: package.accepted_signature_digest,
            verifier_result: package.verifier_result,
            mutated_message_rejected: package.mutated_message_rejected,
            mutated_public_key_rejected: package.mutated_public_key_rejected,
            mutated_signature_rejected: package.mutated_signature_rejected,
            claim_boundary: package.claim_boundary,
        },
    )
}

/// Assess whether a 10,000-validator selected-backend output satisfies the
/// future real-threshold standard-verifier closure contract.
pub fn assess_p1_real_threshold_verifier_closure_contract(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
    package: Option<P1RealThresholdVerifierClosurePackage>,
) -> P1RealThresholdVerifierClosureAssessment {
    let Some(package) = package else {
        return P1RealThresholdVerifierClosureAssessment::BlockedFailClosed {
            reason: "missing P1 real-threshold verifier closure package",
        };
    };

    match package.backend_evidence {
        P1RealThresholdVerifierClosureBackendEvidence::SimulatedDeterministic => {
            return P1RealThresholdVerifierClosureAssessment::BlockedFailClosed {
                reason: "P1 real-threshold verifier closure requires real threshold ML-DSA backend evidence, not deterministic simulation",
            };
        }
        P1RealThresholdVerifierClosureBackendEvidence::StandardProviderSingleKey => {
            return P1RealThresholdVerifierClosureAssessment::Invalid {
                reason: "P1 real-threshold verifier closure requires threshold backend provenance, not ordinary single-key standard-provider output",
            };
        }
        P1RealThresholdVerifierClosureBackendEvidence::FixtureHarness => {
            return P1RealThresholdVerifierClosureAssessment::BlockedFailClosed {
                reason: "P1 real-threshold verifier closure requires actual real threshold ML-DSA backend evidence, not the checked fixture harness",
            };
        }
        P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa => {}
    }
    if !package.reviewed {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure package must be reviewed",
        };
    }
    if package.claim_boundary != P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure package must remain proof-review-only",
        };
    }
    if threshold_certificate.claim_boundary() != P1ThresholdOutputClaimBoundary::ProofReviewOnly {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason:
                "P1 real-threshold verifier closure threshold-output certificate must remain proof-review-only",
        };
    }
    if compatibility_certificate.claim_boundary()
        != P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly
    {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason:
                "P1 real-threshold verifier closure compatibility certificate must remain proof-review-only",
        };
    }
    if package.selected_profile
        != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure must bind the selected ML-DSA-65 coordinator-assisted profile",
        };
    }
    if package.selected_profile != threshold_certificate.selected_profile()
        || package.selected_profile != compatibility_certificate.selected_profile()
    {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure selected profile does not match predecessor certificates",
        };
    }
    if package.selected_profile_binding_digest != package.selected_profile.profile_binding_digest()
    {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure profile binding digest does not match selected profile",
        };
    }
    if &package.selected_profile_binding_digest
        != threshold_certificate.selected_profile_binding_digest()
        || &package.selected_profile_binding_digest
            != compatibility_certificate.selected_profile_binding_digest()
    {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure profile binding digest does not match predecessor certificates",
        };
    }
    if package.validator_count != 10_000 || package.threshold != 6_667 {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason:
                "P1 real-threshold verifier closure must bind 10,000 validators with threshold 6,667",
        };
    }
    if package.aggregate_signature_len != MLDSA65_SIGNATURE_BYTES {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure aggregate signature must be 3,309 bytes",
        };
    }
    if package.verifier_result != P1StandardVerifierCompatibilityResult::Accept {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason:
                "P1 real-threshold verifier closure must bind an accepted standard verifier result",
        };
    }
    if package.verifier_result != compatibility_certificate.verifier_result() {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason:
                "P1 real-threshold verifier closure verifier result does not match compatibility certificate",
        };
    }
    if !(package.mutated_message_rejected
        && package.mutated_public_key_rejected
        && package.mutated_signature_rejected)
    {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure requires mutated message, public key, and signature rejection evidence",
        };
    }

    for (digest, reason) in [
        (
            &package.selected_profile_binding_digest,
            "P1 real-threshold verifier closure profile binding digest is all zero",
        ),
        (
            &package.backend_evidence_digest,
            "P1 real-threshold verifier closure backend evidence digest is all zero",
        ),
        (
            &package.threshold_output_certificate_digest,
            "P1 real-threshold verifier closure threshold-output certificate digest is all zero",
        ),
        (
            &package.standard_verifier_compatibility_artifact_digest,
            "P1 real-threshold verifier closure compatibility artifact digest is all zero",
        ),
    ] {
        if is_all_zero(digest) {
            return P1RealThresholdVerifierClosureAssessment::Invalid { reason };
        }
    }

    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    if package.threshold_output_certificate_digest != threshold_output_certificate_digest {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure threshold-output certificate digest does not match certificate",
        };
    }
    if compatibility_certificate.threshold_output_certificate_digest()
        != &threshold_output_certificate_digest
    {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure compatibility certificate does not bind threshold-output certificate",
        };
    }
    let compatibility_artifact_digest =
        derive_p1_standard_verifier_compatibility_artifact_digest(compatibility_certificate);
    if package.standard_verifier_compatibility_artifact_digest != compatibility_artifact_digest {
        return P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure compatibility artifact digest does not match certificate",
        };
    }

    P1RealThresholdVerifierClosureAssessment::ClosureReady(
        P1RealThresholdVerifierClosureCertificate {
            selected_profile: package.selected_profile,
            selected_profile_binding_digest: package.selected_profile_binding_digest,
            validator_count: package.validator_count,
            threshold: package.threshold,
            aggregate_signature_len: package.aggregate_signature_len,
            backend_evidence_digest: package.backend_evidence_digest,
            threshold_output_certificate_digest: package.threshold_output_certificate_digest,
            standard_verifier_compatibility_artifact_digest: package
                .standard_verifier_compatibility_artifact_digest,
            verifier_result: package.verifier_result,
            mutated_message_rejected: package.mutated_message_rejected,
            mutated_public_key_rejected: package.mutated_public_key_rejected,
            mutated_signature_rejected: package.mutated_signature_rejected,
            claim_boundary: package.claim_boundary,
        },
    )
}

fn validate_p1_criterion2_proof_slot_artifact(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    artifact: &P1Criterion2ProofSlotArtifact,
    expected_kind: P1Criterion2ProofSlotArtifactKind,
    expected_source_evidence_digest: &[u8; 32],
    expected_review_evidence_digest: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if artifact.kind != expected_kind {
        return Err("P1 proof-closure Criterion 2 slot artifact kind mismatch");
    }
    if !artifact.reviewed() {
        return Err("P1 proof-closure Criterion 2 slot artifact must be reviewed");
    }
    if artifact.claim_boundary != P1SelectedBackendProofClosureClaimBoundary::ProofReviewOnly {
        return Err("P1 proof-closure Criterion 2 slot artifact must remain proof-review-only");
    }
    if artifact.selected_profile != threshold_certificate.selected_profile() {
        return Err(
            "P1 proof-closure Criterion 2 slot artifact selected profile does not match threshold-output certificate",
        );
    }
    if &artifact.selected_profile_binding_digest
        != threshold_certificate.selected_profile_binding_digest()
    {
        return Err(
            "P1 proof-closure Criterion 2 slot artifact profile binding does not match threshold-output certificate",
        );
    }
    if artifact.threshold_output_certificate_digest
        != derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate)
    {
        return Err(
            "P1 proof-closure Criterion 2 slot artifact threshold-output certificate digest does not match certificate",
        );
    }
    if &artifact.transcript_binding_digest != threshold_certificate.transcript_binding_digest() {
        return Err(
            "P1 proof-closure Criterion 2 slot artifact transcript binding does not match threshold-output certificate",
        );
    }
    if is_all_zero(&artifact.source_evidence_digest) {
        return Err("P1 proof-closure Criterion 2 slot artifact source digest is all zero");
    }
    if is_all_zero(&artifact.review_evidence_digest) {
        return Err("P1 proof-closure Criterion 2 slot artifact review digest is all zero");
    }
    if &artifact.source_evidence_digest != expected_source_evidence_digest {
        return Err("P1 proof-closure Criterion 2 slot artifact source digest does not match expected proof evidence");
    }
    if &artifact.review_evidence_digest != expected_review_evidence_digest {
        return Err("P1 proof-closure Criterion 2 slot artifact review digest does not match expected external review evidence");
    }
    if is_all_zero(&artifact.artifact_digest) {
        return Err("P1 proof-closure Criterion 2 slot artifact digest is all zero");
    }
    if artifact.artifact_digest != derive_p1_criterion2_proof_slot_artifact_digest(artifact) {
        return Err("P1 proof-closure Criterion 2 slot artifact digest does not match payload");
    }

    Ok(artifact.artifact_digest)
}

/// Assess whether selected-backend proof-closure artifact evidence is bound to
/// the accepted threshold-output certificate and remains proof-review-only.
pub fn assess_p1_selected_backend_proof_closure_artifact(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    package: Option<P1SelectedBackendProofClosureArtifactPackage>,
) -> P1SelectedBackendProofClosureArtifactAssessment {
    let Some(package) = package else {
        return P1SelectedBackendProofClosureArtifactAssessment::Missing {
            reason: "missing P1 selected-backend proof-closure artifact package",
        };
    };

    if !package.reviewed {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 selected-backend proof-closure artifact must be reviewed before artifact closure",
        };
    }
    if !package.proof_artifacts.reviewed() {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure proof artifacts must be reviewed",
        };
    }
    if package.claim_boundary != P1SelectedBackendProofClosureClaimBoundary::ProofReviewOnly {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure artifact must remain proof-review-only",
        };
    }
    if threshold_certificate.claim_boundary() != P1ThresholdOutputClaimBoundary::ProofReviewOnly {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure threshold-output certificate must remain proof-review-only",
        };
    }
    if package.selected_profile
        != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure artifact must bind the selected ML-DSA-65 coordinator-assisted profile",
        };
    }
    if package.selected_profile != threshold_certificate.selected_profile() {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure selected profile does not match threshold-output certificate",
        };
    }

    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    let slot_artifacts = package.proof_slot_artifacts;
    let expected_review_evidence_digest = package.proof_artifacts.external_review_digest();
    let full_kat_validation_artifact_digest = match validate_p1_criterion2_proof_slot_artifact(
        threshold_certificate,
        &slot_artifacts.full_kat_validation_artifact,
        P1Criterion2ProofSlotArtifactKind::FullKatValidation,
        &slot_artifacts
            .full_kat_validation_artifact
            .source_evidence_digest,
        expected_review_evidence_digest,
    ) {
        Ok(digest) => digest,
        Err(reason) => return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason },
    };
    let rejection_distribution_review_digest = match validate_p1_criterion2_proof_slot_artifact(
        threshold_certificate,
        &slot_artifacts.rejection_distribution_review_artifact,
        P1Criterion2ProofSlotArtifactKind::RejectionDistributionReview,
        &slot_artifacts
            .rejection_distribution_review_artifact
            .source_evidence_digest,
        expected_review_evidence_digest,
    ) {
        Ok(digest) => digest,
        Err(reason) => return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason },
    };
    let norm_bound_artifact_digest = match validate_p1_criterion2_proof_slot_artifact(
        threshold_certificate,
        &slot_artifacts.norm_bound_artifact,
        P1Criterion2ProofSlotArtifactKind::NormBound,
        package.proof_artifacts.norm_bound_evidence_digest(),
        expected_review_evidence_digest,
    ) {
        Ok(digest) => digest,
        Err(reason) => return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason },
    };
    let hint_bound_artifact_digest = match validate_p1_criterion2_proof_slot_artifact(
        threshold_certificate,
        &slot_artifacts.hint_bound_artifact,
        P1Criterion2ProofSlotArtifactKind::HintBound,
        package.proof_artifacts.hint_bound_evidence_digest(),
        expected_review_evidence_digest,
    ) {
        Ok(digest) => digest,
        Err(reason) => return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason },
    };
    let challenge_bound_artifact_digest = match validate_p1_criterion2_proof_slot_artifact(
        threshold_certificate,
        &slot_artifacts.challenge_bound_artifact,
        P1Criterion2ProofSlotArtifactKind::ChallengeBound,
        package.proof_artifacts.challenge_bound_evidence_digest(),
        expected_review_evidence_digest,
    ) {
        Ok(digest) => digest,
        Err(reason) => return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason },
    };
    let transcript_binding_artifact_digest = match validate_p1_criterion2_proof_slot_artifact(
        threshold_certificate,
        &slot_artifacts.transcript_binding_artifact,
        P1Criterion2ProofSlotArtifactKind::TranscriptBinding,
        package.proof_artifacts.transcript_binding_evidence_digest(),
        expected_review_evidence_digest,
    ) {
        Ok(digest) => digest,
        Err(reason) => return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason },
    };
    let theorem_linkage_artifact_digest = match validate_p1_criterion2_proof_slot_artifact(
        threshold_certificate,
        &slot_artifacts.theorem_linkage_artifact,
        P1Criterion2ProofSlotArtifactKind::TheoremLinkage,
        &slot_artifacts
            .theorem_linkage_artifact
            .source_evidence_digest,
        expected_review_evidence_digest,
    ) {
        Ok(digest) => digest,
        Err(reason) => return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason },
    };
    let external_review_artifact_digest = match validate_p1_criterion2_proof_slot_artifact(
        threshold_certificate,
        &slot_artifacts.external_review_artifact,
        P1Criterion2ProofSlotArtifactKind::ExternalReview,
        expected_review_evidence_digest,
        expected_review_evidence_digest,
    ) {
        Ok(digest) => digest,
        Err(reason) => return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason },
    };
    let threshold_output_certificate_artifact_digest =
        match validate_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            &slot_artifacts.threshold_output_certificate_artifact,
            P1Criterion2ProofSlotArtifactKind::ThresholdOutputCertificate,
            &threshold_output_certificate_digest,
            expected_review_evidence_digest,
        ) {
            Ok(digest) => digest,
            Err(reason) => {
                return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason };
            }
        };
    let real_recomputation_evidence_artifact_digest =
        match validate_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            &slot_artifacts.real_recomputation_evidence_artifact,
            P1Criterion2ProofSlotArtifactKind::RealRecomputationEvidence,
            package.proof_artifacts.real_recomputation_evidence_digest(),
            expected_review_evidence_digest,
        ) {
            Ok(digest) => digest,
            Err(reason) => {
                return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason };
            }
        };
    let distributed_nonce_producer_slot_artifact_digest =
        match validate_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            &slot_artifacts.distributed_nonce_producer_artifact,
            P1Criterion2ProofSlotArtifactKind::DistributedNonceProducer,
            &package.distributed_nonce_producer_artifact_digest,
            expected_review_evidence_digest,
        ) {
            Ok(digest) => digest,
            Err(reason) => {
                return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason };
            }
        };

    for (digest, reason) in [
        (
            &package.selected_profile_binding_digest,
            "P1 proof-closure profile binding digest is all zero",
        ),
        (
            &package.threshold_output_certificate_digest,
            "P1 proof-closure threshold-output certificate digest is all zero",
        ),
        (
            &package.aggregate_artifact_digest,
            "P1 proof-closure aggregate artifact digest is all zero",
        ),
        (
            &package.threshold_output_source_digest,
            "P1 proof-closure threshold-output source digest is all zero",
        ),
        (
            &package.threshold_output_source_package_digest,
            "P1 proof-closure threshold-output source-package digest is all zero",
        ),
        (
            &package.provider_kat_evidence_digest,
            "P1 proof-closure provider KAT digest is all zero",
        ),
        (
            &package.standard_verifier_bridge_evidence_digest,
            "P1 proof-closure bridge digest is all zero",
        ),
        (
            &package.real_recomputation_evidence_digest,
            "P1 proof-closure recomputation digest is all zero",
        ),
        (
            &package.transcript_binding_digest,
            "P1 proof-closure transcript binding digest is all zero",
        ),
        (
            &package.signer_set_digest,
            "P1 proof-closure signer-set digest is all zero",
        ),
        (
            &package.attempt_binding_digest,
            "P1 proof-closure attempt binding digest is all zero",
        ),
        (
            &package.aggregate_response_digest,
            "P1 proof-closure aggregate response digest is all zero",
        ),
        (
            &package.hint_digest,
            "P1 proof-closure hint digest is all zero",
        ),
        (
            &package.accepted_signature_digest,
            "P1 proof-closure accepted signature digest is all zero",
        ),
        (
            package.proof_artifacts.selected_profile_binding_digest(),
            "P1 proof-closure proof-artifact profile binding digest is all zero",
        ),
        (
            package.proof_artifacts.real_recomputation_evidence_digest(),
            "P1 proof-closure proof-artifact recomputation digest is all zero",
        ),
        (
            package
                .proof_artifacts
                .standard_verifier_bridge_evidence_digest(),
            "P1 proof-closure proof-artifact bridge digest is all zero",
        ),
        (
            package
                .proof_artifacts
                .standard_verifier_bridge_fixture_package_digest(),
            "P1 proof-closure bridge fixture package digest is all zero",
        ),
        (
            package.proof_artifacts.norm_bound_evidence_digest(),
            "P1 proof-closure norm-bound artifact digest is all zero",
        ),
        (
            package.proof_artifacts.hint_bound_evidence_digest(),
            "P1 proof-closure hint-bound artifact digest is all zero",
        ),
        (
            package.proof_artifacts.challenge_bound_evidence_digest(),
            "P1 proof-closure challenge-bound artifact digest is all zero",
        ),
        (
            package.proof_artifacts.transcript_binding_evidence_digest(),
            "P1 proof-closure proof-artifact transcript-binding digest is all zero",
        ),
        (
            package.proof_artifacts.negative_test_corpus_digest(),
            "P1 proof-closure negative corpus digest is all zero",
        ),
        (
            package.proof_artifacts.external_review_digest(),
            "P1 proof-closure external review digest is all zero",
        ),
        (
            &package.full_kat_validation_artifact_digest,
            "P1 proof-closure full KAT/validation artifact digest is all zero",
        ),
        (
            &package.rejection_distribution_review_digest,
            "P1 proof-closure rejection-distribution review digest is all zero",
        ),
        (
            &package.standard_verifier_compatibility_artifact_digest,
            "P1 proof-closure standard-verifier compatibility artifact digest is all zero",
        ),
        (
            &package.distributed_nonce_producer_artifact_digest,
            "P1 proof-closure distributed nonce-producer artifact digest is all zero",
        ),
        (
            &package.theorem_linkage_artifact_digest,
            "P1 proof-closure theorem-linkage artifact digest is all zero",
        ),
    ] {
        if is_all_zero(digest) {
            return P1SelectedBackendProofClosureArtifactAssessment::Invalid { reason };
        }
    }

    if package.selected_profile_binding_digest != package.selected_profile.profile_binding_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure profile binding digest does not match selected profile",
        };
    }
    if &package.selected_profile_binding_digest
        != threshold_certificate.selected_profile_binding_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure profile binding digest does not match threshold-output certificate",
        };
    }
    if package.proof_artifacts.selected_profile_binding_digest()
        != threshold_certificate.selected_profile_binding_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure proof-artifact profile binding digest does not match threshold-output certificate",
        };
    }

    if package.threshold_output_certificate_digest != threshold_output_certificate_digest {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure threshold-output certificate digest does not match certificate",
        };
    }
    if &package.aggregate_artifact_digest != threshold_certificate.aggregate_artifact_digest() {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure aggregate artifact digest does not match threshold-output certificate",
        };
    }
    if &package.threshold_output_source_digest
        != threshold_certificate.threshold_output_source_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure threshold-output source digest does not match threshold-output certificate",
        };
    }
    if &package.threshold_output_source_package_digest
        != threshold_certificate.threshold_output_source_package_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure threshold-output source-package digest does not match threshold-output certificate",
        };
    }
    if &package.provider_kat_evidence_digest != threshold_certificate.provider_kat_evidence_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure provider KAT digest does not match threshold-output certificate",
        };
    }
    if &package.standard_verifier_bridge_evidence_digest
        != threshold_certificate.standard_verifier_bridge_evidence_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure bridge digest does not match threshold-output certificate",
        };
    }
    if &package.real_recomputation_evidence_digest
        != threshold_certificate.real_recomputation_evidence_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure recomputation digest does not match threshold-output certificate",
        };
    }
    if package.proof_artifacts.real_recomputation_evidence_digest()
        != threshold_certificate.real_recomputation_evidence_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure proof-artifact recomputation digest does not match threshold-output certificate",
        };
    }
    if package
        .proof_artifacts
        .standard_verifier_bridge_evidence_digest()
        != threshold_certificate.standard_verifier_bridge_evidence_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure proof-artifact bridge digest does not match threshold-output certificate",
        };
    }
    if package.proof_artifacts.transcript_binding_evidence_digest()
        != threshold_certificate.transcript_binding_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure proof-artifact transcript binding digest does not match threshold-output certificate",
        };
    }
    if package.full_kat_validation_artifact_digest != full_kat_validation_artifact_digest {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure full KAT/validation artifact digest does not match typed Criterion 2 slot artifact",
        };
    }
    if package.rejection_distribution_review_digest != rejection_distribution_review_digest {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure rejection-distribution review digest does not match typed Criterion 2 slot artifact",
        };
    }
    if package.proof_artifacts.norm_bound_evidence_digest()
        != &slot_artifacts.norm_bound_artifact.source_evidence_digest
        || package.proof_artifacts.hint_bound_evidence_digest()
            != &slot_artifacts.hint_bound_artifact.source_evidence_digest
        || package.proof_artifacts.challenge_bound_evidence_digest()
            != &slot_artifacts
                .challenge_bound_artifact
                .source_evidence_digest
        || package.proof_artifacts.transcript_binding_evidence_digest()
            != &slot_artifacts
                .transcript_binding_artifact
                .source_evidence_digest
        || package.proof_artifacts.external_review_digest()
            != &slot_artifacts
                .external_review_artifact
                .source_evidence_digest
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure proof artifact source digest does not match typed Criterion 2 slot artifact",
        };
    }
    if norm_bound_artifact_digest == hint_bound_artifact_digest
        || norm_bound_artifact_digest == challenge_bound_artifact_digest
        || transcript_binding_artifact_digest == external_review_artifact_digest
        || threshold_output_certificate_artifact_digest
            == real_recomputation_evidence_artifact_digest
        || threshold_output_certificate_artifact_digest
            == distributed_nonce_producer_slot_artifact_digest
        || real_recomputation_evidence_artifact_digest
            == distributed_nonce_producer_slot_artifact_digest
        || threshold_output_certificate_artifact_digest == external_review_artifact_digest
        || real_recomputation_evidence_artifact_digest == external_review_artifact_digest
        || distributed_nonce_producer_slot_artifact_digest == external_review_artifact_digest
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifacts must be domain-separated",
        };
    }
    if package.theorem_linkage_artifact_digest != theorem_linkage_artifact_digest {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure theorem-linkage artifact digest does not match typed Criterion 2 slot artifact",
        };
    }
    if &package.transcript_binding_digest != threshold_certificate.transcript_binding_digest() {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure transcript binding digest does not match threshold-output certificate",
        };
    }
    if &package.signer_set_digest != threshold_certificate.signer_set_digest() {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure signer-set digest does not match threshold-output certificate",
        };
    }
    if &package.attempt_binding_digest != threshold_certificate.attempt_binding_digest() {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure attempt binding digest does not match threshold-output certificate",
        };
    }
    if &package.aggregate_response_digest != threshold_certificate.aggregate_response_digest() {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure aggregate response digest does not match threshold-output certificate",
        };
    }
    if &package.hint_digest != threshold_certificate.hint_digest() {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure hint digest does not match threshold-output certificate",
        };
    }
    if &package.accepted_signature_digest != threshold_certificate.accepted_signature_digest() {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure signature digest does not match threshold-output certificate",
        };
    }
    let compatibility_artifact_digest = derive_p1_standard_verifier_compatibility_artifact_digest(
        &package.standard_verifier_compatibility_artifact,
    );
    if package.standard_verifier_compatibility_artifact_digest != compatibility_artifact_digest {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure standard-verifier compatibility artifact digest does not match compatibility certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .claim_boundary()
        != P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility artifact must remain proof-review-only",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .threshold_output_certificate_digest()
        != &threshold_output_certificate_digest
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility threshold-output certificate digest does not match certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .provider_kat_evidence_digest()
        != threshold_certificate.provider_kat_evidence_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility provider KAT digest does not match threshold-output certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .standard_verifier_bridge_evidence_digest()
        != threshold_certificate.standard_verifier_bridge_evidence_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility bridge digest does not match threshold-output certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .real_recomputation_evidence_digest()
        != threshold_certificate.real_recomputation_evidence_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility recomputation digest does not match threshold-output certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .transcript_binding_digest()
        != threshold_certificate.transcript_binding_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility transcript binding digest does not match threshold-output certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .signer_set_digest()
        != threshold_certificate.signer_set_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility signer-set digest does not match threshold-output certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .attempt_binding_digest()
        != threshold_certificate.attempt_binding_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility attempt binding digest does not match threshold-output certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .aggregate_response_digest()
        != threshold_certificate.aggregate_response_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility aggregate response digest does not match threshold-output certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .hint_digest()
        != threshold_certificate.hint_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility hint digest does not match threshold-output certificate",
        };
    }
    if package
        .standard_verifier_compatibility_artifact
        .accepted_signature_digest()
        != threshold_certificate.accepted_signature_digest()
    {
        return P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure compatibility signature digest does not match threshold-output certificate",
        };
    }

    P1SelectedBackendProofClosureArtifactAssessment::ArtifactReady(
        P1SelectedBackendProofClosureArtifactCertificate {
            selected_profile: package.selected_profile,
            selected_profile_binding_digest: package.selected_profile_binding_digest,
            threshold_output_certificate_digest: package.threshold_output_certificate_digest,
            aggregate_artifact_digest: package.aggregate_artifact_digest,
            threshold_output_source_digest: package.threshold_output_source_digest,
            threshold_output_source_package_digest: package.threshold_output_source_package_digest,
            provider_kat_evidence_digest: package.provider_kat_evidence_digest,
            standard_verifier_bridge_evidence_digest: package
                .standard_verifier_bridge_evidence_digest,
            real_recomputation_evidence_digest: package.real_recomputation_evidence_digest,
            distributed_nonce_producer_artifact_digest: package
                .distributed_nonce_producer_artifact_digest,
            transcript_binding_digest: package.transcript_binding_digest,
            signer_set_digest: package.signer_set_digest,
            attempt_binding_digest: package.attempt_binding_digest,
            aggregate_response_digest: package.aggregate_response_digest,
            hint_digest: package.hint_digest,
            accepted_signature_digest: package.accepted_signature_digest,
            proof_artifacts: package.proof_artifacts,
            full_kat_validation_artifact_digest: package.full_kat_validation_artifact_digest,
            rejection_distribution_review_digest: package.rejection_distribution_review_digest,
            threshold_output_certificate_artifact_digest,
            real_recomputation_evidence_artifact_digest,
            standard_verifier_compatibility_artifact_digest: package
                .standard_verifier_compatibility_artifact_digest,
            theorem_linkage_artifact_digest: package.theorem_linkage_artifact_digest,
            claim_boundary: package.claim_boundary,
        },
    )
}

/// Assess whether a Batch 7 external-backend closure candidate binds the real
/// backend handoff artifacts tightly enough for proof review.
pub fn assess_p1_external_backend_cryptographic_closure_candidate(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    package: Option<P1ExternalBackendCryptographicClosureCandidatePackage>,
) -> P1ExternalBackendCryptographicClosureCandidateAssessment {
    let Some(package) = package else {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Missing {
            reason: "missing P1 external backend cryptographic closure candidate package",
        };
    };

    if !package.reviewed {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate must be reviewed",
        };
    }
    if package.claim_boundary != P1SelectedBackendProofClosureClaimBoundary::ProofReviewOnly {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate must remain proof-review-only",
        };
    }
    if threshold_certificate.claim_boundary() != P1ThresholdOutputClaimBoundary::ProofReviewOnly {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason:
                "P1 external backend closure candidate threshold-output certificate must remain proof-review-only",
        };
    }
    if package.selected_profile
        != SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate must bind the selected ML-DSA-65 coordinator-assisted profile",
        };
    }
    if package.selected_profile != threshold_certificate.selected_profile() {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate selected profile does not match threshold-output certificate",
        };
    }

    let rejection_distribution_comparison_digest = match validate_p1_criterion2_proof_slot_artifact(
        threshold_certificate,
        &package.rejection_distribution_comparison_artifact,
        P1Criterion2ProofSlotArtifactKind::RejectionDistributionReview,
        &package
            .rejection_distribution_comparison_artifact
            .source_evidence_digest,
        &package
            .rejection_distribution_comparison_artifact
            .review_evidence_digest,
    ) {
        Ok(digest) => digest,
        Err(reason) => {
            return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid { reason };
        }
    };

    for (digest, reason) in [
        (
            &package.selected_profile_binding_digest,
            "P1 external backend closure candidate profile binding digest is all zero",
        ),
        (
            &package.threshold_output_certificate_digest,
            "P1 external backend closure candidate threshold-output certificate digest is all zero",
        ),
        (
            &package.distributed_nonce_producer_artifact_digest,
            "P1 external backend closure candidate distributed nonce-producer artifact digest is all zero",
        ),
        (
            &package.real_threshold_backend_emission_artifact_digest,
            "P1 external backend closure candidate real-threshold backend emission artifact digest is all zero",
        ),
        (
            &package.standard_verifier_compatibility_artifact_digest,
            "P1 external backend closure candidate standard-verifier compatibility artifact digest is all zero",
        ),
        (
            &package.rejection_distribution_comparison_digest,
            "P1 external backend closure candidate rejection-distribution comparison digest is all zero",
        ),
        (
            &package.candidate_artifact_digest,
            "P1 external backend closure candidate artifact digest is all zero",
        ),
    ] {
        if is_all_zero(digest) {
            return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid { reason };
        }
    }

    if package.selected_profile_binding_digest != package.selected_profile.profile_binding_digest()
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason:
                "P1 external backend closure candidate profile binding digest does not match selected profile",
        };
    }
    if &package.selected_profile_binding_digest
        != threshold_certificate.selected_profile_binding_digest()
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate profile binding digest does not match threshold-output certificate",
        };
    }

    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    if package.threshold_output_certificate_digest != threshold_output_certificate_digest {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate threshold-output certificate digest does not match certificate",
        };
    }
    if package.rejection_distribution_comparison_digest != rejection_distribution_comparison_digest
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate rejection-distribution comparison digest does not match typed Criterion 2 slot artifact",
        };
    }

    let nonce_certificate = package.distributed_nonce_producer_artifact;
    let expected_nonce_artifact_digest =
        derive_p1_distributed_nonce_producer_artifact_digest(&nonce_certificate);
    if package.distributed_nonce_producer_artifact_digest != expected_nonce_artifact_digest {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate distributed nonce-producer digest does not match certificate",
        };
    }
    if nonce_certificate.selected_profile() != threshold_certificate.selected_profile()
        || nonce_certificate.selected_profile_binding_digest()
            != threshold_certificate.selected_profile_binding_digest()
        || nonce_certificate.threshold_output_certificate_digest()
            != &threshold_output_certificate_digest
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate distributed nonce-producer certificate does not bind the threshold-output certificate",
        };
    }
    if nonce_certificate.claim_boundary()
        != P1DistributedNonceProducerClaimBoundary::ProofReviewOnly
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate distributed nonce-producer certificate must remain proof-review-only",
        };
    }

    let backend_certificate = package.real_threshold_backend_emission_artifact;
    let expected_backend_artifact_digest =
        derive_p1_real_threshold_backend_emission_artifact_digest(&backend_certificate);
    if package.real_threshold_backend_emission_artifact_digest != expected_backend_artifact_digest {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate real-threshold backend emission digest does not match certificate",
        };
    }
    if backend_certificate.selected_profile() != threshold_certificate.selected_profile()
        || backend_certificate.selected_profile_binding_digest()
            != threshold_certificate.selected_profile_binding_digest()
        || backend_certificate.threshold_output_certificate_digest()
            != &threshold_output_certificate_digest
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate real-threshold backend emission certificate does not bind the threshold-output certificate",
        };
    }
    if backend_certificate.validator_count() != 10_000
        || backend_certificate.threshold() != 6_667
        || backend_certificate.aggregate_signature_len() != MLDSA65_SIGNATURE_BYTES
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate real-threshold backend emission must bind 10,000 validators with threshold 6,667 and a standard-size signature",
        };
    }
    if backend_certificate.verifier_result() != P1StandardVerifierCompatibilityResult::Accept {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate real-threshold backend emission must bind an accepted standard verifier result",
        };
    }
    if !backend_certificate.mutation_rejection_corpus_complete() {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate real-threshold backend emission requires complete mutation rejection evidence",
        };
    }
    if backend_certificate.claim_boundary()
        != P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate real-threshold backend emission certificate must remain proof-review-only",
        };
    }

    let compatibility_certificate = package.standard_verifier_compatibility_artifact;
    let expected_compatibility_artifact_digest =
        derive_p1_standard_verifier_compatibility_artifact_digest(&compatibility_certificate);
    if package.standard_verifier_compatibility_artifact_digest
        != expected_compatibility_artifact_digest
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate standard-verifier compatibility digest does not match certificate",
        };
    }
    if compatibility_certificate.selected_profile() != threshold_certificate.selected_profile()
        || compatibility_certificate.selected_profile_binding_digest()
            != threshold_certificate.selected_profile_binding_digest()
        || compatibility_certificate.threshold_output_certificate_digest()
            != &threshold_output_certificate_digest
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate standard-verifier compatibility certificate does not bind the threshold-output certificate",
        };
    }
    if compatibility_certificate.verifier_result() != P1StandardVerifierCompatibilityResult::Accept
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate compatibility certificate must bind an accepted verifier result",
        };
    }
    if compatibility_certificate.claim_boundary()
        != P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate compatibility certificate must remain proof-review-only",
        };
    }
    if nonce_certificate.standard_verifier_compatibility_artifact_digest()
        != &expected_compatibility_artifact_digest
        || backend_certificate.standard_verifier_compatibility_artifact_digest()
            != &expected_compatibility_artifact_digest
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate child certificates do not bind the same standard-verifier compatibility artifact",
        };
    }
    if backend_certificate.public_key_digest() != compatibility_certificate.public_key_digest()
        || backend_certificate.message_digest() != compatibility_certificate.message_digest()
        || backend_certificate.accepted_signature_digest()
            != compatibility_certificate.accepted_signature_digest()
    {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate real-threshold backend emission tuple does not match compatibility certificate",
        };
    }

    let expected_candidate_artifact_digest =
        derive_p1_external_backend_cryptographic_closure_candidate_digest_from_fields(
            package.selected_profile,
            &package.selected_profile_binding_digest,
            &package.threshold_output_certificate_digest,
            &package.distributed_nonce_producer_artifact_digest,
            &package.real_threshold_backend_emission_artifact_digest,
            &package.standard_verifier_compatibility_artifact_digest,
            &package.rejection_distribution_comparison_digest,
            package.claim_boundary,
            package.reviewed,
        );
    if package.candidate_artifact_digest != expected_candidate_artifact_digest {
        return P1ExternalBackendCryptographicClosureCandidateAssessment::Invalid {
            reason: "P1 external backend closure candidate artifact digest does not match payload",
        };
    }

    P1ExternalBackendCryptographicClosureCandidateAssessment::CandidateReady(
        P1ExternalBackendCryptographicClosureCandidateCertificate {
            selected_profile: package.selected_profile,
            selected_profile_binding_digest: package.selected_profile_binding_digest,
            threshold_output_certificate_digest: package.threshold_output_certificate_digest,
            distributed_nonce_producer_artifact_digest: package
                .distributed_nonce_producer_artifact_digest,
            real_threshold_backend_emission_artifact_digest: package
                .real_threshold_backend_emission_artifact_digest,
            standard_verifier_compatibility_artifact_digest: package
                .standard_verifier_compatibility_artifact_digest,
            rejection_distribution_comparison_digest: package
                .rejection_distribution_comparison_digest,
            candidate_artifact_digest: package.candidate_artifact_digest,
            claim_boundary: package.claim_boundary,
        },
    )
}

#[allow(clippy::result_large_err)]
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

fn digest_domain_separated_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn digest_signature(signature: &ThresholdSignature) -> [u8; 32] {
    digest_bytes(&signature.0)
}

fn decode_hex_array<const N: usize>(
    hex: &str,
    reason: &'static str,
) -> Result<[u8; N], ThresholdError> {
    let bytes = decode_hex_vec(hex, reason)?;
    if bytes.len() != N {
        return Err(ThresholdError::MalformedSerialization { reason });
    }
    let mut out = [0; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_vec(hex: &str, reason: &'static str) -> Result<Vec<u8>, ThresholdError> {
    if !hex.len().is_multiple_of(2) {
        return Err(ThresholdError::MalformedSerialization { reason });
    }

    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_hex_nibble(pair[0], reason)?;
            let low = decode_hex_nibble(pair[1], reason)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_hex_nibble(byte: u8, reason: &'static str) -> Result<u8, ThresholdError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ThresholdError::MalformedSerialization { reason }),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn is_all_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
