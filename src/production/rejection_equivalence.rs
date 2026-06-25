//! Aggregate rejection-equivalence evidence gates.
//!
//! This module is a hazmat/conformance-only bridge. It separates digest-only
//! scaffold evidence from provider-verified aggregate recomputation evidence
//! without claiming that the current coordinator profile implements production
//! threshold ML-DSA rejection-distribution preservation.

use sha3::{Digest, Sha3_256};

use crate::{
    production::{
        acceptance::{AcceptedAggregateCandidate, StandardVerifierEvidence},
        provider::StandardMldsa65Provider,
        selected_backend::SelectedProductionBackendProfile,
        transcript::ProductionSigningTranscript,
    },
    ThresholdError, ThresholdSignature, ValidatorId,
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
    full_kat_validation_source_digest: [u8; 32],
    rejection_distribution_review_source_digest: [u8; 32],
    theorem_linkage_source_digest: [u8; 32],
    claim_boundary: P1SelectedBackendProofClosureClaimBoundary,
    reviewed: bool,
) -> P1Criterion2ProofSlotArtifacts {
    let external_review_digest = *proof_artifacts.external_review_digest();
    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    P1Criterion2ProofSlotArtifacts::new(
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::FullKatValidation,
            full_kat_validation_source_digest,
            external_review_digest,
            claim_boundary,
            reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::RejectionDistributionReview,
            rejection_distribution_review_source_digest,
            external_review_digest,
            claim_boundary,
            reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::NormBound,
            *proof_artifacts.norm_bound_evidence_digest(),
            external_review_digest,
            claim_boundary,
            reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::HintBound,
            *proof_artifacts.hint_bound_evidence_digest(),
            external_review_digest,
            claim_boundary,
            reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::ChallengeBound,
            *proof_artifacts.challenge_bound_evidence_digest(),
            external_review_digest,
            claim_boundary,
            reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::TranscriptBinding,
            *proof_artifacts.transcript_binding_evidence_digest(),
            external_review_digest,
            claim_boundary,
            reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::TheoremLinkage,
            theorem_linkage_source_digest,
            external_review_digest,
            claim_boundary,
            reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::ExternalReview,
            external_review_digest,
            external_review_digest,
            claim_boundary,
            reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::ThresholdOutputCertificate,
            threshold_output_certificate_digest,
            external_review_digest,
            claim_boundary,
            reviewed,
        ),
        derive_p1_criterion2_proof_slot_artifact(
            threshold_certificate,
            P1Criterion2ProofSlotArtifactKind::RealRecomputationEvidence,
            *proof_artifacts.real_recomputation_evidence_digest(),
            external_review_digest,
            claim_boundary,
            reviewed,
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
        || threshold_output_certificate_artifact_digest == external_review_artifact_digest
        || real_recomputation_evidence_artifact_digest == external_review_artifact_digest
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

fn digest_signature(signature: &ThresholdSignature) -> [u8; 32] {
    digest_bytes(&signature.0)
}

fn is_all_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
