#![cfg(feature = "coordinator-assisted")]

use std::collections::BTreeSet;

use lattice_aggregation::{
    production::{
        acceptance::{
            AcceptedAggregateCandidate, AggregateAccept, AggregateAcceptEvidence, LocalAccept,
            LocalAcceptEvidence, StandardVerifierEvidence,
        },
        provider::StandardMldsa65Provider,
        rejection_equivalence::{
            assess_p1_aggregate_recomputation_closure,
            assess_p1_real_threshold_backend_emission_artifact,
            assess_p1_real_threshold_verifier_closure_contract,
            assess_p1_selected_backend_aggregate_artifact,
            assess_p1_selected_backend_proof_closure_artifact,
            assess_p1_selected_backend_threshold_output_artifact,
            assess_p1_standard_verifier_compatibility_artifact,
            assess_rejection_equivalence_closure, derive_p1_criterion2_proof_slot_artifact_digest,
            derive_p1_criterion2_proof_slot_artifacts,
            derive_p1_real_threshold_backend_emission_artifact_package,
            derive_p1_real_threshold_backend_emission_artifact_package_from_backend_output,
            derive_p1_real_threshold_backend_emission_evidence_digest,
            derive_p1_real_threshold_backend_implementation_digest,
            derive_p1_real_threshold_backend_source_package_digest,
            derive_p1_real_threshold_backend_transcript_digest,
            derive_p1_selected_backend_aggregate_certificate_digest,
            derive_p1_selected_backend_attempt_binding_digest,
            derive_p1_selected_backend_proof_closure_artifact_package,
            derive_p1_selected_backend_signer_set_digest,
            derive_p1_selected_backend_threshold_output_artifact_package,
            derive_p1_selected_backend_threshold_output_certificate_digest,
            derive_p1_selected_backend_threshold_output_source_digest,
            derive_p1_selected_backend_threshold_output_source_package_digest,
            derive_p1_selected_backend_transcript_binding_digest,
            derive_p1_standard_verifier_compatibility_artifact_digest,
            derive_p1_standard_verifier_compatibility_artifact_package,
            derive_p1_verified_real_threshold_backend_emission_artifact_package,
            derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture,
            derive_p1_verified_real_threshold_backend_emission_capture,
            derive_standard_verifier_bridge_evidence_digest, AcvpFips204EvidenceSource,
            AggregateRecomputationTranscript, AggregateRejectionClosureAssessment,
            AggregateRejectionClosurePackage, AggregateRejectionClosureStatus,
            AggregateRejectionConformanceBoundary, AggregateRejectionEquivalenceEvidence,
            AggregateRejectionEquivalenceGate, AggregateRejectionEvidenceDigest,
            AggregateRejectionEvidenceStrength, Mldsa65ProviderKatEvidence,
            P1AggregateRecomputationAssessment, P1AggregateRecomputationClosureCertificate,
            P1AggregateRecomputationClosurePackage, P1Criterion2ProofSlotArtifactKind,
            P1RealThresholdBackendEmissionArtifactAssessment,
            P1RealThresholdBackendEmissionArtifactPackage, P1RealThresholdBackendEmissionCapture,
            P1RealThresholdBackendEmissionOutput, P1RealThresholdVerifierClosureAssessment,
            P1RealThresholdVerifierClosureBackendEvidence,
            P1RealThresholdVerifierClosureClaimBoundary, P1RealThresholdVerifierClosurePackage,
            P1RejectionProofArtifacts, P1SelectedBackendAggregateArtifactAssessment,
            P1SelectedBackendAggregateArtifactCertificate,
            P1SelectedBackendAggregateArtifactPackage,
            P1SelectedBackendProofClosureArtifactAssessment,
            P1SelectedBackendProofClosureArtifactPackage,
            P1SelectedBackendProofClosureClaimBoundary,
            P1SelectedBackendThresholdOutputArtifactAssessment,
            P1SelectedBackendThresholdOutputArtifactCertificate,
            P1SelectedBackendThresholdOutputArtifactPackage,
            P1StandardVerifierCompatibilityArtifactAssessment,
            P1StandardVerifierCompatibilityArtifactCertificate,
            P1StandardVerifierCompatibilityArtifactPackage,
            P1StandardVerifierCompatibilityClaimBoundary, P1StandardVerifierCompatibilityResult,
            P1ThresholdOutputClaimBoundary, P1ThresholdOutputEvidenceSource,
        },
        selected_backend::SelectedProductionBackendProfile,
        transcript::{CommitmentDigest, ProductionSigningTranscript, ProductionTranscriptInput},
        types::{
            ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
            ValidatorSetDigest,
        },
    },
    ThresholdError, ThresholdPublicKey, ThresholdSignature, ValidatorId, MLDSA65_SIGNATURE_BYTES,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};

#[cfg(feature = "hazmat-real-mldsa")]
use lattice_aggregation::production::rejection_equivalence::{
    derive_p1_real_recomputation_evidence_digest,
    derive_p1_selected_backend_aggregate_artifact_package,
};

const EXPECTED_P1_STANDARD_VERIFIER_BRIDGE_FIXTURE_PACKAGE_DIGEST_HEX: &str =
    "28a59ad2845dc0e6694c997ed106c23f09966efb6028431dd55ac8ccdb9639fa";
const EXPECTED_P1_REAL_RECOMPUTATION_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX: &str =
    "b1f0f1ad5682c3d92781631bdd6d1bd412acc45e0408c0c8b16088e36307d1be";
const EXPECTED_P1_THRESHOLD_OUTPUT_CERTIFICATE_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX: &str =
    "b60af953ac22542646287f1ded308bd2e479e24da761bdc0371c77cb7bba2e92";
const EXPECTED_P1_REJECTION_DISTRIBUTION_REVIEW_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX: &str =
    "de7c71635f2c271f09856a1a4a0cffe292aa3d09a4e2bac09d9c04c90c7ce243";
const EXPECTED_P1_THEOREM_LINKAGE_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX: &str =
    "34e4d1907e8105ccbe883df67573e8ba55814b3d948c7a49fb21f665ead1c300";
const EXPECTED_P1_REAL_THRESHOLD_BACKEND_EMISSION_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX: &str =
    "fcd09b72c5443409c02e407d45b150cde307aba9346b82d0e2e818109574eb83";
const EXPECTED_P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA_FIXTURE_PACKAGE_DIGEST_HEX: &str =
    "efa8cd7dba97fa707dd0ee565a2b87e00fe91dc237008758fb97f604e65bbd8c";
#[cfg(feature = "hazmat-real-mldsa")]
const EXPECTED_P1_STANDARD_PROVIDER_SINGLE_KEY_EMISSION_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX: &str =
    "56de4e8bb21b601c1985483b469fd4fc9d591efbb015fd08852574a821eb9074";

struct AcceptingProvider;

impl StandardMldsa65Provider for AcceptingProvider {
    fn provider_identity() -> &'static str {
        "mock-provider-test-fixture"
    }

    fn provider_version() -> &'static str {
        "test-fixture-v1"
    }

    fn verify(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        assert_eq!(public_key, &ThresholdPublicKey([6; 1952]));
        assert_eq!(message, b"original application message");
        assert_eq!(signature, &ThresholdSignature([42; 3309]));
        Ok(true)
    }
}

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn standard_verifier_bridge_fixture() -> P1StandardVerifierBridgeFixture {
    serde_json::from_str(include_str!(
        "fixtures/p1_standard_verifier_bridge_fixture.json"
    ))
    .expect("P1 standard-verifier bridge fixture should parse")
}

fn standard_verifier_compatibility_fixture() -> P1StandardVerifierCompatibilityFixture {
    serde_json::from_str(include_str!(
        "fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
    ))
    .expect("P1 standard-verifier compatibility artifact fixture should parse")
}

fn real_recomputation_artifact_fixture() -> P1RealRecomputationArtifactFixture {
    serde_json::from_str(include_str!(
        "fixtures/p1_real_recomputation_artifact_fixture.json"
    ))
    .expect("P1 real recomputation artifact fixture should parse")
}

fn threshold_output_certificate_artifact_fixture() -> P1ThresholdOutputCertificateArtifactFixture {
    serde_json::from_str(include_str!(
        "fixtures/p1_threshold_output_certificate_artifact_fixture.json"
    ))
    .expect("P1 threshold-output certificate artifact fixture should parse")
}

fn rejection_distribution_review_artifact_fixture() -> P1RejectionDistributionReviewArtifactFixture
{
    serde_json::from_str(include_str!(
        "fixtures/p1_rejection_distribution_review_artifact_fixture.json"
    ))
    .expect("P1 rejection-distribution review artifact fixture should parse")
}

fn theorem_linkage_artifact_fixture() -> P1TheoremLinkageArtifactFixture {
    serde_json::from_str(include_str!(
        "fixtures/p1_theorem_linkage_artifact_fixture.json"
    ))
    .expect("P1 theorem-linkage artifact fixture should parse")
}

fn real_threshold_backend_emission_artifact_fixture(
) -> P1RealThresholdBackendEmissionArtifactFixture {
    serde_json::from_str(include_str!(
        "fixtures/p1_real_threshold_backend_emission_artifact_fixture.json"
    ))
    .expect("P1 real-threshold backend emission artifact fixture should parse")
}

fn real_threshold_backend_emission_capture_schema_fixture() -> P1RealThresholdBackendEmissionCapture
{
    P1RealThresholdBackendEmissionCapture::decode_json(include_bytes!(
        "fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json"
    ))
    .expect("P1 real-threshold backend emission capture schema fixture should parse")
}

#[cfg(feature = "hazmat-real-mldsa")]
fn standard_provider_single_key_emission_artifact_fixture(
) -> P1StandardProviderSingleKeyEmissionArtifactFixture {
    serde_json::from_str(include_str!(
        "fixtures/p1_standard_provider_single_key_emission_artifact_fixture.json"
    ))
    .expect("P1 standard-provider single-key emission artifact fixture should parse")
}

fn standard_verifier_bridge_digest() -> [u8; 32] {
    let fixture = standard_verifier_bridge_fixture();
    let evidence = fixture_bridge_evidence(&fixture);
    derive_standard_verifier_bridge_evidence_digest(
        &fixture.expected.selected_profile_binding_digest(),
        &fixture.expected.provider_kat_evidence_digest(),
        &evidence,
    )
    .expect("fixture bridge evidence should satisfy the bridge gate")
}

fn standard_verifier_bridge_fixture_package_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-standard-verifier-bridge-fixture-package:v1");
    hasher.update(include_bytes!(
        "fixtures/p1_standard_verifier_bridge_fixture.json"
    ));
    hasher.finalize().into()
}

fn real_recomputation_artifact_fixture_package_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-real-recomputation-artifact-fixture-package:v1");
    hasher.update(include_bytes!(
        "fixtures/p1_real_recomputation_artifact_fixture.json"
    ));
    hasher.finalize().into()
}

fn threshold_output_certificate_artifact_fixture_package_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher
        .update(b"lattice-aggregation:p1-threshold-output-certificate-artifact-fixture-package:v1");
    hasher.update(include_bytes!(
        "fixtures/p1_threshold_output_certificate_artifact_fixture.json"
    ));
    hasher.finalize().into()
}

fn rejection_distribution_review_artifact_fixture_package_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(
        b"lattice-aggregation:p1-rejection-distribution-review-artifact-fixture-package:v1",
    );
    hasher.update(include_bytes!(
        "fixtures/p1_rejection_distribution_review_artifact_fixture.json"
    ));
    hasher.finalize().into()
}

fn theorem_linkage_artifact_fixture_package_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-theorem-linkage-artifact-fixture-package:v1");
    hasher.update(include_bytes!(
        "fixtures/p1_theorem_linkage_artifact_fixture.json"
    ));
    hasher.finalize().into()
}

fn real_threshold_backend_emission_artifact_fixture_package_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(
        b"lattice-aggregation:p1-real-threshold-backend-emission-artifact-fixture-package:v1",
    );
    hasher.update(include_bytes!(
        "fixtures/p1_real_threshold_backend_emission_artifact_fixture.json"
    ));
    hasher.finalize().into()
}

fn real_threshold_backend_emission_capture_schema_fixture_package_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(
        b"lattice-aggregation:p1-real-threshold-backend-emission-capture-schema-fixture-package:v1",
    );
    hasher.update(include_bytes!(
        "fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json"
    ));
    hasher.finalize().into()
}

#[cfg(feature = "hazmat-real-mldsa")]
fn standard_provider_single_key_emission_artifact_fixture_package_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(
        b"lattice-aggregation:p1-standard-provider-single-key-emission-artifact-fixture-package:v1",
    );
    hasher.update(include_bytes!(
        "fixtures/p1_standard_provider_single_key_emission_artifact_fixture.json"
    ));
    hasher.finalize().into()
}

fn negative_test_corpus_digest() -> [u8; 32] {
    let fixture = standard_verifier_bridge_fixture();
    derive_negative_test_corpus_digest(&fixture)
}

fn closure_package() -> AggregateRejectionClosurePackage {
    AggregateRejectionClosurePackage::new(
        AggregateRejectionConformanceBoundary::ClosureCandidate,
        Some(AggregateRejectionEvidenceDigest::real_recomputation(
            digest(41),
        )),
        Some(AggregateRejectionEvidenceDigest::standard_provider_kat(
            provider_kat_fixture_digest(),
        )),
        Some(AggregateRejectionEvidenceDigest::standard_verifier_bridge(
            standard_verifier_bridge_digest(),
        )),
        Some(AggregateRejectionEvidenceDigest::norm_bound(digest(43))),
        Some(AggregateRejectionEvidenceDigest::hint_bound(digest(44))),
        Some(AggregateRejectionEvidenceDigest::challenge_bound(digest(
            45,
        ))),
        Some(AggregateRejectionEvidenceDigest::transcript_binding(
            digest(46),
        )),
        Some(AggregateRejectionEvidenceDigest::negative_test_corpus(
            negative_test_corpus_digest(),
        )),
        Some(AggregateRejectionEvidenceDigest::external_review(digest(
            48,
        ))),
    )
}

struct RejectingProvider;

impl StandardMldsa65Provider for RejectingProvider {
    fn verify(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        assert_eq!(public_key, &ThresholdPublicKey([6; 1952]));
        assert_eq!(message, b"original application message");
        assert_eq!(signature, &ThresholdSignature([42; 3309]));
        Ok(false)
    }
}

#[derive(Deserialize)]
struct P1StandardVerifierBridgeFixture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    standard_verifier_source: String,
    provider_kat_fixture: String,
    note: String,
    transcript: BridgeTranscriptFixture,
    recomputation: BridgeRecomputationFixture,
    expected: BridgeExpectedDigests,
    negative_cases: Vec<BridgeNegativeCase>,
}

#[derive(Deserialize)]
struct BridgeTranscriptFixture {
    session_id_fill_byte: u8,
    epoch: u64,
    key_id_fill_byte: u8,
    validator_set_digest_fill_byte: u8,
    dkg_transcript_digest_fill_byte: u8,
    active_signers: Vec<u16>,
    threshold: u16,
    public_key_fill_byte: u8,
    application_message_hex: String,
    message_binding_fill_byte: u8,
    attempt_id_fill_byte: u8,
    coordinator_attestation_digest_fill_byte: u8,
    retry_counter: u32,
    commitment_digests: Vec<BridgeCommitmentFixture>,
}

#[derive(Deserialize)]
struct BridgeCommitmentFixture {
    validator: u16,
    digest_fill_byte: u8,
}

#[derive(Deserialize)]
struct BridgeRecomputationFixture {
    aggregate_response_hex: String,
    hint_hex: String,
    candidate_signature_fill_byte: u8,
    recomputed_signature_fill_byte: u8,
}

#[derive(Deserialize)]
struct BridgeExpectedDigests {
    selected_profile_binding_digest_hex: String,
    provider_kat_evidence_digest_hex: String,
    challenge_digest_hex: String,
    aggregate_response_digest_hex: String,
    hint_digest_hex: String,
    candidate_signature_digest_hex: String,
    recomputed_signature_digest_hex: String,
    standard_verifier_bridge_evidence_digest_hex: String,
    negative_test_corpus_digest_hex: String,
}

impl BridgeExpectedDigests {
    fn selected_profile_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.selected_profile_binding_digest_hex)
    }

    fn provider_kat_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.provider_kat_evidence_digest_hex)
    }

    fn challenge_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.challenge_digest_hex)
    }

    fn aggregate_response_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.aggregate_response_digest_hex)
    }

    fn hint_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.hint_digest_hex)
    }

    fn candidate_signature_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.candidate_signature_digest_hex)
    }

    fn recomputed_signature_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.recomputed_signature_digest_hex)
    }

    fn standard_verifier_bridge_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.standard_verifier_bridge_evidence_digest_hex)
    }

    fn negative_test_corpus_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.negative_test_corpus_digest_hex)
    }
}

#[derive(Deserialize)]
struct BridgeNegativeCase {
    name: String,
    expected_error: String,
    provider_kat_evidence_digest_hex: String,
    candidate_signature_digest_hex: String,
    recomputed_signature_digest_hex: String,
    transcript_binding_digest_hex: String,
    selected_profile_binding_digest_hex: String,
}

#[derive(Deserialize)]
struct P1StandardVerifierCompatibilityFixture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    verifier_provider_identity: String,
    verifier_provider_version: String,
    verifier_result: String,
    source_bridge_fixture: String,
    note: String,
    payload: CompatibilityPayloadFixture,
    expected: CompatibilityExpectedDigests,
}

#[derive(Deserialize)]
struct CompatibilityPayloadFixture {
    public_key_fill_byte: u8,
    application_message_hex: String,
    candidate_signature_fill_byte: u8,
}

#[derive(Deserialize)]
struct CompatibilityExpectedDigests {
    threshold_output_certificate_digest_hex: String,
    artifact_digest_hex: String,
    provider_identity_digest_hex: String,
    public_key_digest_hex: String,
    message_digest_hex: String,
    transcript_binding_digest_hex: String,
    signer_set_digest_hex: String,
    attempt_binding_digest_hex: String,
    aggregate_response_digest_hex: String,
    hint_digest_hex: String,
    accepted_signature_digest_hex: String,
    standard_verifier_bridge_evidence_digest_hex: String,
    real_recomputation_evidence_digest_hex: String,
}

#[derive(Deserialize)]
struct P1RealRecomputationArtifactFixture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    source_bridge_fixture: String,
    source_standard_verifier_compatibility_fixture: String,
    note: String,
    slot_artifact: RealRecomputationSlotFixture,
    expected: RealRecomputationExpectedDigests,
    negative_cases: Vec<RealRecomputationNegativeCase>,
}

#[derive(Deserialize)]
struct P1ThresholdOutputCertificateArtifactFixture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    source_bridge_fixture: String,
    source_standard_verifier_compatibility_fixture: String,
    source_threshold_output_package: ThresholdOutputSourcePackageFixture,
    note: String,
    slot_artifact: ThresholdOutputCertificateSlotFixture,
    expected: ThresholdOutputCertificateExpectedDigests,
    negative_cases: Vec<ThresholdOutputCertificateNegativeCase>,
}

#[derive(Deserialize)]
struct P1RejectionDistributionReviewArtifactFixture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    source_bridge_fixture: String,
    source_standard_verifier_compatibility_fixture: String,
    source_threshold_output_certificate_artifact_fixture: String,
    source_real_recomputation_artifact_fixture: String,
    note: String,
    slot_artifact: RejectionDistributionReviewSlotFixture,
    expected: RejectionDistributionReviewExpectedDigests,
    negative_cases: Vec<RejectionDistributionReviewNegativeCase>,
}

#[derive(Deserialize)]
struct P1TheoremLinkageArtifactFixture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    source_bridge_fixture: String,
    source_standard_verifier_compatibility_fixture: String,
    source_threshold_output_certificate_artifact_fixture: String,
    source_real_recomputation_artifact_fixture: String,
    source_rejection_distribution_review_artifact_fixture: String,
    note: String,
    slot_artifact: TheoremLinkageSlotFixture,
    expected: TheoremLinkageExpectedDigests,
    negative_cases: Vec<TheoremLinkageNegativeCase>,
}

#[derive(Deserialize)]
struct P1RealThresholdBackendEmissionArtifactFixture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    source_bridge_fixture: String,
    source_standard_verifier_compatibility_fixture: String,
    source_threshold_output_certificate_artifact_fixture: String,
    backend_evidence: String,
    note: String,
    capture: RealThresholdBackendEmissionCaptureFixture,
    expected: RealThresholdBackendEmissionExpectedDigests,
}

#[cfg(feature = "hazmat-real-mldsa")]
#[derive(Deserialize)]
struct P1StandardProviderSingleKeyEmissionArtifactFixture {
    name: String,
    schema: String,
    claim_boundary: String,
    selected_profile: String,
    source_bridge_fixture: String,
    source_standard_verifier_compatibility_fixture: String,
    source_threshold_output_certificate_artifact_fixture: String,
    backend_evidence: String,
    note: String,
    capture: StandardProviderSingleKeyEmissionCaptureFixture,
    expected: StandardProviderSingleKeyEmissionExpectedDigests,
}

#[derive(Deserialize)]
struct RealRecomputationSlotFixture {
    slot_id: String,
    kind: String,
    evidence_source: String,
    artifact_package: String,
    current_status: String,
    reviewed: bool,
}

#[derive(Deserialize)]
struct ThresholdOutputCertificateSlotFixture {
    slot_id: String,
    kind: String,
    evidence_source: String,
    artifact_package: String,
    current_status: String,
    reviewed: bool,
}

#[derive(Deserialize)]
struct RejectionDistributionReviewSlotFixture {
    slot_id: String,
    kind: String,
    evidence_source: String,
    artifact_package: String,
    current_status: String,
    reviewed: bool,
}

#[derive(Deserialize)]
struct TheoremLinkageSlotFixture {
    slot_id: String,
    kind: String,
    evidence_source: String,
    artifact_package: String,
    current_status: String,
    reviewed: bool,
}

#[derive(Deserialize)]
struct RealThresholdBackendEmissionCaptureFixture {
    validator_count: u32,
    threshold: u32,
    aggregate_signature_len: usize,
    backend_source_package: ThresholdOutputSourcePackageFixture,
    backend_implementation: ThresholdOutputSourcePackageFixture,
    backend_transcript: ThresholdOutputSourcePackageFixture,
    mutated_message_rejected: bool,
    mutated_public_key_rejected: bool,
    mutated_signature_rejected: bool,
    reviewed: bool,
}

#[cfg(feature = "hazmat-real-mldsa")]
#[derive(Deserialize)]
struct StandardProviderSingleKeyEmissionCaptureFixture {
    validator_count: u32,
    threshold: u32,
    aggregate_signature_len: usize,
    seed_hex: String,
    message: ThresholdOutputSourcePackageFixture,
    public_key_hex: String,
    signature_hex: String,
    backend_source_package: ThresholdOutputSourcePackageFixture,
    backend_implementation: ThresholdOutputSourcePackageFixture,
    backend_transcript: ThresholdOutputSourcePackageFixture,
    mutated_message_rejected: bool,
    mutated_public_key_rejected: bool,
    mutated_signature_rejected: bool,
    reviewed: bool,
}

#[derive(Deserialize)]
struct ThresholdOutputSourcePackageFixture {
    encoding: String,
    value: String,
}

#[derive(Deserialize)]
struct RealRecomputationExpectedDigests {
    selected_profile_binding_digest_hex: String,
    threshold_output_certificate_digest_hex: String,
    transcript_binding_digest_hex: String,
    source_evidence_digest_hex: String,
    review_evidence_digest_hex: String,
    artifact_digest_hex: String,
    standard_verifier_bridge_evidence_digest_hex: String,
    aggregate_response_digest_hex: String,
    hint_digest_hex: String,
    accepted_signature_digest_hex: String,
}

#[derive(Deserialize)]
struct ThresholdOutputCertificateExpectedDigests {
    selected_profile_binding_digest_hex: String,
    aggregate_artifact_digest_hex: String,
    provider_kat_evidence_digest_hex: String,
    threshold_output_source_package_digest_hex: String,
    threshold_output_source_digest_hex: String,
    threshold_output_certificate_digest_hex: String,
    transcript_binding_digest_hex: String,
    signer_set_digest_hex: String,
    attempt_binding_digest_hex: String,
    aggregate_response_digest_hex: String,
    hint_digest_hex: String,
    accepted_signature_digest_hex: String,
    source_evidence_digest_hex: String,
    review_evidence_digest_hex: String,
    artifact_digest_hex: String,
    standard_verifier_bridge_evidence_digest_hex: String,
    real_recomputation_evidence_digest_hex: String,
}

#[derive(Deserialize)]
struct RejectionDistributionReviewExpectedDigests {
    selected_profile_binding_digest_hex: String,
    threshold_output_certificate_digest_hex: String,
    transcript_binding_digest_hex: String,
    source_evidence_digest_hex: String,
    review_evidence_digest_hex: String,
    artifact_digest_hex: String,
    rejection_distribution_review_digest_hex: String,
}

#[derive(Deserialize)]
struct TheoremLinkageExpectedDigests {
    selected_profile_binding_digest_hex: String,
    threshold_output_certificate_digest_hex: String,
    transcript_binding_digest_hex: String,
    source_evidence_digest_hex: String,
    review_evidence_digest_hex: String,
    artifact_digest_hex: String,
    theorem_linkage_artifact_digest_hex: String,
}

#[derive(Deserialize)]
struct RealThresholdBackendEmissionExpectedDigests {
    selected_profile_binding_digest_hex: String,
    threshold_output_certificate_digest_hex: String,
    standard_verifier_compatibility_artifact_digest_hex: String,
    backend_evidence_digest_hex: String,
    backend_source_package_digest_hex: String,
    backend_implementation_digest_hex: String,
    backend_transcript_digest_hex: String,
    artifact_digest_hex: String,
    public_key_digest_hex: String,
    message_digest_hex: String,
    transcript_binding_digest_hex: String,
    signer_set_digest_hex: String,
    attempt_binding_digest_hex: String,
    accepted_signature_digest_hex: String,
}

#[cfg(feature = "hazmat-real-mldsa")]
#[derive(Deserialize)]
struct StandardProviderSingleKeyEmissionExpectedDigests {
    selected_profile_binding_digest_hex: String,
    threshold_output_certificate_digest_hex: String,
    standard_verifier_compatibility_artifact_digest_hex: String,
    backend_evidence_digest_hex: String,
    backend_source_package_digest_hex: String,
    backend_implementation_digest_hex: String,
    backend_transcript_digest_hex: String,
    artifact_digest_hex: String,
    public_key_digest_hex: String,
    message_digest_hex: String,
    transcript_binding_digest_hex: String,
    signer_set_digest_hex: String,
    attempt_binding_digest_hex: String,
    accepted_signature_digest_hex: String,
}

#[derive(Deserialize)]
struct RealRecomputationNegativeCase {
    name: String,
    expected_gate: String,
}

#[derive(Deserialize)]
struct ThresholdOutputCertificateNegativeCase {
    name: String,
    expected_gate: String,
}

#[derive(Deserialize)]
struct RejectionDistributionReviewNegativeCase {
    name: String,
    expected_gate: String,
}

#[derive(Deserialize)]
struct TheoremLinkageNegativeCase {
    name: String,
    expected_gate: String,
}

impl CompatibilityExpectedDigests {
    fn threshold_output_certificate_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.threshold_output_certificate_digest_hex)
    }

    fn artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.artifact_digest_hex)
    }

    fn provider_identity_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.provider_identity_digest_hex)
    }

    fn public_key_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.public_key_digest_hex)
    }

    fn message_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.message_digest_hex)
    }

    fn transcript_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.transcript_binding_digest_hex)
    }

    fn signer_set_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.signer_set_digest_hex)
    }

    fn attempt_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.attempt_binding_digest_hex)
    }

    fn aggregate_response_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.aggregate_response_digest_hex)
    }

    fn hint_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.hint_digest_hex)
    }

    fn accepted_signature_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.accepted_signature_digest_hex)
    }

    fn standard_verifier_bridge_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.standard_verifier_bridge_evidence_digest_hex)
    }

    fn real_recomputation_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.real_recomputation_evidence_digest_hex)
    }
}

impl RealRecomputationExpectedDigests {
    fn selected_profile_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.selected_profile_binding_digest_hex)
    }

    fn threshold_output_certificate_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.threshold_output_certificate_digest_hex)
    }

    fn transcript_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.transcript_binding_digest_hex)
    }

    fn source_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.source_evidence_digest_hex)
    }

    fn review_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.review_evidence_digest_hex)
    }

    fn artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.artifact_digest_hex)
    }

    fn standard_verifier_bridge_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.standard_verifier_bridge_evidence_digest_hex)
    }

    fn aggregate_response_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.aggregate_response_digest_hex)
    }

    fn hint_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.hint_digest_hex)
    }

    fn accepted_signature_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.accepted_signature_digest_hex)
    }
}

impl ThresholdOutputSourcePackageFixture {
    fn bytes(&self) -> &[u8] {
        assert_eq!(self.encoding, "utf8");
        self.value.as_bytes()
    }
}

impl ThresholdOutputCertificateExpectedDigests {
    fn selected_profile_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.selected_profile_binding_digest_hex)
    }

    fn aggregate_artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.aggregate_artifact_digest_hex)
    }

    fn provider_kat_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.provider_kat_evidence_digest_hex)
    }

    fn threshold_output_source_package_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.threshold_output_source_package_digest_hex)
    }

    fn threshold_output_source_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.threshold_output_source_digest_hex)
    }

    fn threshold_output_certificate_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.threshold_output_certificate_digest_hex)
    }

    fn transcript_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.transcript_binding_digest_hex)
    }

    fn signer_set_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.signer_set_digest_hex)
    }

    fn attempt_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.attempt_binding_digest_hex)
    }

    fn aggregate_response_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.aggregate_response_digest_hex)
    }

    fn hint_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.hint_digest_hex)
    }

    fn accepted_signature_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.accepted_signature_digest_hex)
    }

    fn source_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.source_evidence_digest_hex)
    }

    fn review_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.review_evidence_digest_hex)
    }

    fn artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.artifact_digest_hex)
    }

    fn standard_verifier_bridge_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.standard_verifier_bridge_evidence_digest_hex)
    }

    fn real_recomputation_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.real_recomputation_evidence_digest_hex)
    }
}

impl RejectionDistributionReviewExpectedDigests {
    fn selected_profile_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.selected_profile_binding_digest_hex)
    }

    fn threshold_output_certificate_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.threshold_output_certificate_digest_hex)
    }

    fn transcript_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.transcript_binding_digest_hex)
    }

    fn source_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.source_evidence_digest_hex)
    }

    fn review_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.review_evidence_digest_hex)
    }

    fn artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.artifact_digest_hex)
    }

    fn rejection_distribution_review_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.rejection_distribution_review_digest_hex)
    }
}

impl TheoremLinkageExpectedDigests {
    fn selected_profile_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.selected_profile_binding_digest_hex)
    }

    fn threshold_output_certificate_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.threshold_output_certificate_digest_hex)
    }

    fn transcript_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.transcript_binding_digest_hex)
    }

    fn source_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.source_evidence_digest_hex)
    }

    fn review_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.review_evidence_digest_hex)
    }

    fn artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.artifact_digest_hex)
    }

    fn theorem_linkage_artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.theorem_linkage_artifact_digest_hex)
    }
}

impl RealThresholdBackendEmissionExpectedDigests {
    fn selected_profile_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.selected_profile_binding_digest_hex)
    }

    fn threshold_output_certificate_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.threshold_output_certificate_digest_hex)
    }

    fn standard_verifier_compatibility_artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.standard_verifier_compatibility_artifact_digest_hex)
    }

    fn backend_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.backend_evidence_digest_hex)
    }

    fn backend_source_package_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.backend_source_package_digest_hex)
    }

    fn backend_implementation_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.backend_implementation_digest_hex)
    }

    fn backend_transcript_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.backend_transcript_digest_hex)
    }

    fn artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.artifact_digest_hex)
    }

    fn public_key_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.public_key_digest_hex)
    }

    fn message_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.message_digest_hex)
    }

    fn transcript_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.transcript_binding_digest_hex)
    }

    fn signer_set_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.signer_set_digest_hex)
    }

    fn attempt_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.attempt_binding_digest_hex)
    }

    fn accepted_signature_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.accepted_signature_digest_hex)
    }
}

#[cfg(feature = "hazmat-real-mldsa")]
impl StandardProviderSingleKeyEmissionExpectedDigests {
    fn selected_profile_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.selected_profile_binding_digest_hex)
    }

    fn threshold_output_certificate_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.threshold_output_certificate_digest_hex)
    }

    fn standard_verifier_compatibility_artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.standard_verifier_compatibility_artifact_digest_hex)
    }

    fn backend_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.backend_evidence_digest_hex)
    }

    fn backend_source_package_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.backend_source_package_digest_hex)
    }

    fn backend_implementation_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.backend_implementation_digest_hex)
    }

    fn backend_transcript_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.backend_transcript_digest_hex)
    }

    fn artifact_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.artifact_digest_hex)
    }

    fn public_key_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.public_key_digest_hex)
    }

    fn message_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.message_digest_hex)
    }

    fn transcript_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.transcript_binding_digest_hex)
    }

    fn signer_set_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.signer_set_digest_hex)
    }

    fn attempt_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.attempt_binding_digest_hex)
    }

    fn accepted_signature_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.accepted_signature_digest_hex)
    }
}

impl BridgeNegativeCase {
    fn provider_kat_evidence_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.provider_kat_evidence_digest_hex)
    }

    fn candidate_signature_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.candidate_signature_digest_hex)
    }

    fn recomputed_signature_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.recomputed_signature_digest_hex)
    }

    fn transcript_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.transcript_binding_digest_hex)
    }

    fn selected_profile_binding_digest(&self) -> [u8; 32] {
        decode_hex_array(&self.selected_profile_binding_digest_hex)
    }
}

fn transcript() -> ProductionSigningTranscript {
    let fixture = standard_verifier_bridge_fixture();
    transcript_from_fixture(&fixture.transcript)
}

fn transcript_with_session_id_fill_byte(session_id_fill_byte: u8) -> ProductionSigningTranscript {
    let fixture = standard_verifier_bridge_fixture();
    let mut transcript = fixture.transcript;
    transcript.session_id_fill_byte = session_id_fill_byte;
    transcript_from_fixture(&transcript)
}

fn transcript_from_fixture(transcript: &BridgeTranscriptFixture) -> ProductionSigningTranscript {
    let active_signers = transcript
        .active_signers
        .iter()
        .copied()
        .map(ValidatorId)
        .collect::<Vec<_>>();
    let commitment_digests = transcript
        .commitment_digests
        .iter()
        .map(|commitment| {
            (
                ValidatorId(commitment.validator),
                CommitmentDigest([commitment.digest_fill_byte; 32]),
            )
        })
        .collect::<Vec<_>>();

    ProductionSigningTranscript::new(ProductionTranscriptInput {
        session_id: [transcript.session_id_fill_byte; 32],
        epoch: EpochId(transcript.epoch),
        key_id: KeyId([transcript.key_id_fill_byte; 32]),
        validator_set_digest: ValidatorSetDigest([transcript.validator_set_digest_fill_byte; 32]),
        dkg_transcript_digest: DkgTranscriptDigest(
            [transcript.dkg_transcript_digest_fill_byte; 32],
        ),
        active_signers: ActiveSignerSet::new(active_signers).unwrap(),
        threshold: transcript.threshold,
        public_key: ThresholdPublicKey([transcript.public_key_fill_byte; 1952]),
        application_message: decode_hex(&transcript.application_message_hex),
        message_binding: MessageBinding([transcript.message_binding_fill_byte; 64]),
        attempt_id: AttemptId([transcript.attempt_id_fill_byte; 32]),
        coordinator_attestation_digest: [transcript.coordinator_attestation_digest_fill_byte; 32],
        retry_counter: transcript.retry_counter,
        commitment_digests,
    })
    .unwrap()
}

fn fixture_bridge_evidence(
    fixture: &P1StandardVerifierBridgeFixture,
) -> AggregateRejectionEquivalenceEvidence {
    let transcript = transcript_from_fixture(&fixture.transcript);
    let candidate_signature =
        signature_from_fill_byte(fixture.recomputation.candidate_signature_fill_byte);
    let recomputed_signature =
        signature_from_fill_byte(fixture.recomputation.recomputed_signature_fill_byte);
    let aggregate_response = decode_hex(&fixture.recomputation.aggregate_response_hex);
    let hint = decode_hex(&fixture.recomputation.hint_hex);
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        &aggregate_response,
        &hint,
        &recomputed_signature,
    )
    .unwrap();

    AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<AcceptingProvider>(
        &transcript,
        &candidate_signature,
        &recomputation,
    )
    .unwrap()
}

fn signature_from_fill_byte(byte: u8) -> ThresholdSignature {
    ThresholdSignature([byte; 3309])
}

#[cfg(feature = "hazmat-real-mldsa")]
fn threshold_public_key_from(encoded: &[u8]) -> ThresholdPublicKey {
    let mut bytes = [0u8; 1952];
    bytes.copy_from_slice(encoded);
    ThresholdPublicKey(bytes)
}

#[cfg(feature = "hazmat-real-mldsa")]
fn threshold_signature_from(encoded: &[u8]) -> ThresholdSignature {
    let mut bytes = [0u8; 3309];
    bytes.copy_from_slice(encoded);
    ThresholdSignature(bytes)
}

#[cfg(feature = "hazmat-real-mldsa")]
fn real_mldsa_transcript(
    public_key: ThresholdPublicKey,
    application_message: &[u8],
) -> ProductionSigningTranscript {
    ProductionSigningTranscript::new(ProductionTranscriptInput {
        session_id: [0x71; 32],
        epoch: EpochId(7),
        key_id: KeyId([0x72; 32]),
        validator_set_digest: ValidatorSetDigest([0x73; 32]),
        dkg_transcript_digest: DkgTranscriptDigest([0x74; 32]),
        active_signers: ActiveSignerSet::new(vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)])
            .unwrap(),
        threshold: 2,
        public_key,
        application_message: application_message.to_vec(),
        message_binding: MessageBinding([0x75; 64]),
        attempt_id: AttemptId([0x76; 32]),
        coordinator_attestation_digest: [0x77; 32],
        retry_counter: 0,
        commitment_digests: vec![
            (ValidatorId(1), CommitmentDigest([0x81; 32])),
            (ValidatorId(2), CommitmentDigest([0x82; 32])),
            (ValidatorId(3), CommitmentDigest([0x83; 32])),
        ],
    })
    .unwrap()
}

#[cfg(feature = "hazmat-real-mldsa")]
fn real_mldsa_accepted_partials(
    transcript: &ProductionSigningTranscript,
) -> Vec<lattice_aggregation::production::acceptance::AcceptedPartialContribution> {
    transcript
        .input()
        .commitment_digests
        .iter()
        .enumerate()
        .map(|(index, (signer, commitment_digest))| {
            LocalAccept::accept(
                transcript,
                LocalAcceptEvidence {
                    signer: *signer,
                    commitment_digest: *commitment_digest,
                    partial_share_digest: [(0x91 + index) as u8; 32],
                    local_bounds_proof_digest: [(0xa1 + index) as u8; 32],
                },
            )
            .unwrap()
        })
        .collect()
}

fn signature_digest(signature: &ThresholdSignature) -> [u8; 32] {
    Sha3_256::digest(signature.0).into()
}

fn provider_kat_fixture_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:mldsa65-provider-kat-fixture:v1");
    hasher.update(include_bytes!(
        "fixtures/acvp_mldsa65_sigver_fips204_sample.json"
    ));
    hasher.finalize().into()
}

fn derive_negative_test_corpus_digest(fixture: &P1StandardVerifierBridgeFixture) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-standard-verifier-bridge-negative-corpus:v1");
    for case in &fixture.negative_cases {
        hasher.update(case.name.as_bytes());
        hasher.update(b"\0");
        hasher.update(case.expected_error.as_bytes());
        hasher.update(b"\0");
        hasher.update(case.candidate_signature_digest());
        hasher.update(case.recomputed_signature_digest());
        hasher.update(case.transcript_binding_digest());
        hasher.update(case.selected_profile_binding_digest());
        hasher.update(case.provider_kat_evidence_digest());
    }
    hasher.finalize().into()
}

fn error_label(error: &ThresholdError) -> &'static str {
    match error {
        ThresholdError::TranscriptMismatch => "TranscriptMismatch",
        ThresholdError::StandardVerificationFailed => "StandardVerificationFailed",
        ThresholdError::BackendUnavailable { reason } => reason,
        ThresholdError::MalformedSerialization { reason } => reason,
        ThresholdError::InvalidHintRoute { reason } => reason,
        _ => "unexpected ThresholdError variant",
    }
}

fn assert_p1_invalid_reason(assessment: P1AggregateRecomputationAssessment, expected: &str) {
    match assessment {
        P1AggregateRecomputationAssessment::Invalid { reason } => assert_eq!(reason, expected),
        other => panic!("expected invalid P1 assessment, got {other:?}"),
    }
}

fn assert_selected_artifact_invalid_reason(
    assessment: P1SelectedBackendAggregateArtifactAssessment,
    expected: &str,
) {
    match assessment {
        P1SelectedBackendAggregateArtifactAssessment::Invalid { reason } => {
            assert_eq!(reason, expected);
        }
        other => panic!("expected invalid selected-backend artifact assessment, got {other:?}"),
    }
}

fn decode_hex_array<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = decode_hex(hex);
    assert_eq!(bytes.len(), N, "hex value should decode to {N} bytes");
    let mut out = [0; N];
    out.copy_from_slice(&bytes);
    out
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "hex string should contain an even number of characters"
    );

    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            (high << 4) | low
        })
        .collect()
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

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}

#[test]
fn scaffold_only_evidence_is_not_bridge_equivalence_evidence() {
    let transcript = transcript();
    let evidence = AggregateRejectionEquivalenceEvidence::scaffold_only(
        *transcript.challenge_digest(),
        [31; 32],
        [32; 32],
        [33; 32],
    );

    assert_eq!(
        evidence.strength(),
        AggregateRejectionEvidenceStrength::ScaffoldOnly
    );
    assert!(!evidence.satisfies_equivalence_gate());

    let err = AggregateRejectionEquivalenceGate::require_verified_bridge(&evidence).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::BackendUnavailable {
            reason: "aggregate rejection equivalence requires provider bridge and recomputation transcript",
        }
    );
}

#[test]
fn provider_verified_recomputation_mints_bridge_equivalence_evidence() {
    let transcript = transcript();
    let candidate_signature = ThresholdSignature([42; 3309]);
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        b"aggregate response bytes",
        b"hint bytes",
        &candidate_signature,
    )
    .unwrap();

    let evidence =
        AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<AcceptingProvider>(
            &transcript,
            &candidate_signature,
            &recomputation,
        )
        .unwrap();

    assert_eq!(
        evidence.strength(),
        AggregateRejectionEvidenceStrength::ProviderRecomputedBridge
    );
    assert!(evidence.satisfies_equivalence_gate());
    assert_eq!(evidence.challenge_digest(), transcript.challenge_digest());
    assert_eq!(
        evidence.aggregate_response_digest(),
        recomputation.aggregate_response_digest()
    );
    assert_eq!(evidence.hint_digest(), recomputation.hint_digest());
    assert_eq!(
        evidence.candidate_signature_digest(),
        evidence.recomputed_signature_digest().unwrap()
    );
}

#[test]
fn standard_verifier_bridge_fixture_parses_and_matches_bound_transcript() {
    let fixture = standard_verifier_bridge_fixture();

    assert_eq!(fixture.name, "p1-standard-verifier-bridge-fixture-v1");
    assert_eq!(
        fixture.schema,
        "lattice-aggregation:p1-standard-verifier-bridge:v1"
    );
    assert_eq!(fixture.claim_boundary, "hazmat-conformance-fixture-only");
    assert_eq!(
        fixture.selected_profile,
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        fixture.standard_verifier_source,
        "mock-provider-test-fixture"
    );
    assert_eq!(
        fixture.provider_kat_fixture,
        "tests/fixtures/acvp_mldsa65_sigver_fips204_sample.json"
    );
    assert!(fixture
        .note
        .contains("not production threshold ML-DSA recomputation"));
    assert!(fixture.note.contains("not CAVP/ACVTS validation"));
    assert!(fixture
        .note
        .contains("not a completed standard-verifier compatibility proof"));
    assert_eq!(
        fixture.expected.selected_profile_binding_digest(),
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest()
    );
    assert_eq!(
        fixture.expected.provider_kat_evidence_digest(),
        provider_kat_fixture_digest()
    );

    let evidence = fixture_bridge_evidence(&fixture);

    assert_eq!(
        evidence.challenge_digest(),
        &fixture.expected.challenge_digest()
    );
    assert_eq!(
        evidence.aggregate_response_digest(),
        &fixture.expected.aggregate_response_digest()
    );
    assert_eq!(evidence.hint_digest(), &fixture.expected.hint_digest());
    assert_eq!(
        evidence.candidate_signature_digest(),
        &fixture.expected.candidate_signature_digest()
    );
    assert_eq!(
        evidence.recomputed_signature_digest().unwrap(),
        &fixture.expected.recomputed_signature_digest()
    );
}

#[test]
fn standard_verifier_compatibility_fixture_parses_and_matches_bound_payload() {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let compatibility_fixture = standard_verifier_compatibility_fixture();
    let certificate = standard_verifier_compatibility_artifact_certificate(&bridge_fixture);

    assert_eq!(
        compatibility_fixture.name,
        "p1-standard-verifier-compatibility-artifact-fixture-v1"
    );
    assert_eq!(
        compatibility_fixture.schema,
        "lattice-aggregation:p1-standard-verifier-compatibility-artifact:v1"
    );
    assert_eq!(
        compatibility_fixture.claim_boundary,
        "conformance/proof-review evidence only"
    );
    assert_eq!(
        compatibility_fixture.selected_profile,
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        compatibility_fixture.verifier_provider_identity,
        "mock-provider-test-fixture"
    );
    assert_eq!(
        compatibility_fixture.verifier_provider_version,
        "test-fixture-v1"
    );
    assert_eq!(compatibility_fixture.verifier_result, "accept");
    assert_eq!(
        compatibility_fixture.source_bridge_fixture,
        "tests/fixtures/p1_standard_verifier_bridge_fixture.json"
    );
    assert!(compatibility_fixture
        .note
        .contains("not selected-backend proof closure"));
    assert!(compatibility_fixture
        .note
        .contains("not CAVP/ACVTS validation"));
    assert!(compatibility_fixture.note.contains("not FIPS validation"));
    assert_eq!(compatibility_fixture.payload.public_key_fill_byte, 6);
    assert_eq!(
        compatibility_fixture.payload.application_message_hex,
        bridge_fixture.transcript.application_message_hex
    );
    assert_eq!(
        compatibility_fixture.payload.candidate_signature_fill_byte,
        bridge_fixture.recomputation.candidate_signature_fill_byte
    );
    assert_eq!(
        certificate.threshold_output_certificate_digest(),
        &compatibility_fixture
            .expected
            .threshold_output_certificate_digest()
    );
    assert_eq!(
        &derive_p1_standard_verifier_compatibility_artifact_digest(&certificate),
        &compatibility_fixture.expected.artifact_digest()
    );
    assert_eq!(
        certificate.provider_identity_digest(),
        &compatibility_fixture.expected.provider_identity_digest()
    );
    assert_eq!(
        certificate.public_key_digest(),
        &compatibility_fixture.expected.public_key_digest()
    );
    assert_eq!(
        certificate.message_digest(),
        &compatibility_fixture.expected.message_digest()
    );
    assert_eq!(
        certificate.transcript_binding_digest(),
        &compatibility_fixture.expected.transcript_binding_digest()
    );
    assert_eq!(
        certificate.signer_set_digest(),
        &compatibility_fixture.expected.signer_set_digest()
    );
    assert_eq!(
        certificate.attempt_binding_digest(),
        &compatibility_fixture.expected.attempt_binding_digest()
    );
    assert_eq!(
        certificate.aggregate_response_digest(),
        &compatibility_fixture.expected.aggregate_response_digest()
    );
    assert_eq!(
        certificate.hint_digest(),
        &compatibility_fixture.expected.hint_digest()
    );
    assert_eq!(
        certificate.accepted_signature_digest(),
        &compatibility_fixture.expected.accepted_signature_digest()
    );
    assert_eq!(
        certificate.standard_verifier_bridge_evidence_digest(),
        &compatibility_fixture
            .expected
            .standard_verifier_bridge_evidence_digest()
    );
    assert_eq!(
        certificate.real_recomputation_evidence_digest(),
        &compatibility_fixture
            .expected
            .real_recomputation_evidence_digest()
    );
}

#[test]
fn real_threshold_backend_emission_artifact_fixture_parses_and_remains_blocked_until_actual_backend_evidence_replaces_it(
) {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let emission_fixture = real_threshold_backend_emission_artifact_fixture();
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(&bridge_fixture);
    let compatibility_certificate =
        standard_verifier_compatibility_artifact_certificate(&bridge_fixture);
    let package = real_threshold_backend_emission_artifact_package_from_fixture(
        &emission_fixture,
        &bridge_fixture,
    );

    assert_eq!(
        emission_fixture.name,
        "p1-real-threshold-backend-emission-artifact-fixture-v1"
    );
    assert_eq!(
        emission_fixture.schema,
        "lattice-aggregation:p1-real-threshold-backend-emission-artifact:v1"
    );
    assert_eq!(
        emission_fixture.claim_boundary,
        "conformance/proof-review evidence only"
    );
    assert_eq!(
        emission_fixture.selected_profile,
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        emission_fixture.source_bridge_fixture,
        "tests/fixtures/p1_standard_verifier_bridge_fixture.json"
    );
    assert_eq!(
        emission_fixture.source_standard_verifier_compatibility_fixture,
        "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
    );
    assert_eq!(
        emission_fixture.source_threshold_output_certificate_artifact_fixture,
        "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json"
    );
    assert_eq!(
        emission_fixture.backend_evidence,
        "real_threshold_mldsa_fixture_harness"
    );
    assert!(emission_fixture
        .note
        .contains("not a real threshold backend implementation"));
    assert!(emission_fixture
        .note
        .contains("not production threshold ML-DSA security"));
    assert!(emission_fixture
        .note
        .contains("not a completed cryptographic proof"));
    assert_eq!(
        package.selected_profile_binding_digest,
        emission_fixture.expected.selected_profile_binding_digest()
    );
    assert_eq!(
        package.threshold_output_certificate_digest,
        emission_fixture
            .expected
            .threshold_output_certificate_digest()
    );
    assert_eq!(
        package.standard_verifier_compatibility_artifact_digest,
        emission_fixture
            .expected
            .standard_verifier_compatibility_artifact_digest()
    );
    assert_eq!(
        package.backend_evidence_digest,
        emission_fixture.expected.backend_evidence_digest()
    );
    assert_eq!(
        package.backend_source_package_digest,
        emission_fixture.expected.backend_source_package_digest()
    );
    assert_eq!(
        package.backend_implementation_digest,
        emission_fixture.expected.backend_implementation_digest()
    );
    assert_eq!(
        package.backend_transcript_digest,
        emission_fixture.expected.backend_transcript_digest()
    );
    assert_eq!(
        package.artifact_digest,
        emission_fixture.expected.artifact_digest()
    );
    assert_eq!(
        package.public_key_digest,
        emission_fixture.expected.public_key_digest()
    );
    assert_eq!(
        package.message_digest,
        emission_fixture.expected.message_digest()
    );
    assert_eq!(
        package.transcript_binding_digest,
        emission_fixture.expected.transcript_binding_digest()
    );
    assert_eq!(
        package.signer_set_digest,
        emission_fixture.expected.signer_set_digest()
    );
    assert_eq!(
        package.attempt_binding_digest,
        emission_fixture.expected.attempt_binding_digest()
    );
    assert_eq!(
        package.accepted_signature_digest,
        emission_fixture.expected.accepted_signature_digest()
    );
    assert_eq!(
        package.backend_evidence,
        P1RealThresholdVerifierClosureBackendEvidence::FixtureHarness
    );

    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );
    assert_eq!(
        assessment,
        P1RealThresholdBackendEmissionArtifactAssessment::BlockedFailClosed {
            reason: "P1 real-threshold backend emission requires actual real threshold ML-DSA backend evidence, not the checked fixture harness",
        }
    );
    assert!(!assessment.is_artifact_ready());
    assert!(assessment.backend_emission_certificate().is_none());
}

#[test]
fn real_threshold_backend_emission_artifact_fixture_package_digest_fails_loudly_on_drift() {
    assert_eq!(
        real_threshold_backend_emission_artifact_fixture_package_digest(),
        decode_hex_array(
            EXPECTED_P1_REAL_THRESHOLD_BACKEND_EMISSION_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX
        )
    );
}

#[test]
fn real_threshold_backend_output_material_derives_artifact_ready_package() {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(&bridge_fixture);
    let compatibility_certificate =
        standard_verifier_compatibility_artifact_certificate(&bridge_fixture);
    let public_key = ThresholdPublicKey([6; 1952]);
    let message = b"original application message";
    let aggregate_signature = ThresholdSignature([42; 3309]);
    let backend_source_package = b"reviewed real threshold source package bytes v1";
    let backend_implementation = b"reviewed real threshold implementation digest material v1";
    let backend_transcript = b"reviewed real threshold transcript digest material v1";

    let material = P1RealThresholdBackendEmissionOutput {
        backend_source_package,
        backend_implementation,
        backend_transcript,
        public_key: &public_key,
        message,
        aggregate_signature: &aggregate_signature,
        mutated_message_rejected: true,
        mutated_public_key_rejected: true,
        mutated_signature_rejected: true,
        claim_boundary: P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        reviewed: true,
    };

    let package = derive_p1_real_threshold_backend_emission_artifact_package_from_backend_output(
        &threshold_certificate,
        &compatibility_certificate,
        material,
    )
    .expect("matching backend-output material should derive a real-threshold package");

    assert_eq!(
        package.backend_evidence,
        P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa
    );
    assert_eq!(
        package.backend_source_package_digest,
        derive_p1_real_threshold_backend_source_package_digest(backend_source_package)
    );
    assert_eq!(
        package.backend_implementation_digest,
        derive_p1_real_threshold_backend_implementation_digest(backend_implementation)
    );
    assert_eq!(
        package.backend_transcript_digest,
        derive_p1_real_threshold_backend_transcript_digest(backend_transcript)
    );
    assert_eq!(
        package.backend_evidence_digest,
        derive_p1_real_threshold_backend_emission_evidence_digest(&material)
    );

    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );
    let certificate = assessment
        .backend_emission_certificate()
        .copied()
        .expect("reviewed real-threshold material should become artifact-ready");
    assert!(assessment.is_artifact_ready());
    assert_eq!(certificate.validator_count(), 10_000);
    assert_eq!(certificate.threshold(), 6_667);
    assert_eq!(
        certificate.aggregate_signature_len(),
        MLDSA65_SIGNATURE_BYTES
    );
    assert!(certificate.mutation_rejection_corpus_complete());
    assert!(!certificate.claims_real_threshold_backend_implemented());
    assert!(!certificate.claims_completed_cryptographic_proof());
}

#[test]
fn real_threshold_backend_output_material_rejects_tuple_digest_mismatch() {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(&bridge_fixture);
    let compatibility_certificate =
        standard_verifier_compatibility_artifact_certificate(&bridge_fixture);
    let public_key = ThresholdPublicKey([6; 1952]);
    let aggregate_signature = ThresholdSignature([43; 3309]);

    let material = P1RealThresholdBackendEmissionOutput {
        backend_source_package: b"reviewed real threshold source package bytes v1",
        backend_implementation: b"reviewed real threshold implementation digest material v1",
        backend_transcript: b"reviewed real threshold transcript digest material v1",
        public_key: &public_key,
        message: b"original application message",
        aggregate_signature: &aggregate_signature,
        mutated_message_rejected: true,
        mutated_public_key_rejected: true,
        mutated_signature_rejected: true,
        claim_boundary: P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        reviewed: true,
    };

    let err = derive_p1_real_threshold_backend_emission_artifact_package_from_backend_output(
        &threshold_certificate,
        &compatibility_certificate,
        material,
    )
    .unwrap_err();
    assert_eq!(err, ThresholdError::TranscriptMismatch);
}

#[test]
fn verified_real_threshold_backend_output_material_requires_standard_verifier_acceptance() {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&bridge_fixture.transcript);
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(&bridge_fixture);
    let compatibility_certificate =
        standard_verifier_compatibility_artifact_certificate(&bridge_fixture);
    let public_key = ThresholdPublicKey([6; 1952]);
    let message = b"original application message";
    let aggregate_signature = ThresholdSignature([42; 3309]);

    let material = P1RealThresholdBackendEmissionOutput {
        backend_source_package: b"reviewed real threshold source package bytes v1",
        backend_implementation: b"reviewed real threshold implementation digest material v1",
        backend_transcript: b"reviewed real threshold transcript digest material v1",
        public_key: &public_key,
        message,
        aggregate_signature: &aggregate_signature,
        mutated_message_rejected: true,
        mutated_public_key_rejected: true,
        mutated_signature_rejected: true,
        claim_boundary: P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        reviewed: true,
    };

    let package =
        derive_p1_verified_real_threshold_backend_emission_artifact_package::<AcceptingProvider>(
            &transcript,
            &threshold_certificate,
            &compatibility_certificate,
            material,
        )
        .expect("standard-verifier accepted backend material should derive a package");
    assert_eq!(
        package.backend_evidence,
        P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa
    );

    let err =
        derive_p1_verified_real_threshold_backend_emission_artifact_package::<RejectingProvider>(
            &transcript,
            &threshold_certificate,
            &compatibility_certificate,
            material,
        )
        .unwrap_err();
    assert_eq!(err, ThresholdError::StandardVerificationFailed);
}

#[test]
fn real_threshold_backend_capture_schema_fixture_parses_but_remains_blocked_until_actual_capture() {
    let capture = real_threshold_backend_emission_capture_schema_fixture();

    assert_eq!(
        capture.name(),
        "p1-real-threshold-backend-emission-capture-schema-fixture-v1"
    );
    assert_eq!(
        capture.schema(),
        "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
    );
    assert_eq!(
        capture.backend_evidence(),
        "real_threshold_mldsa_capture_schema_fixture"
    );
    assert_eq!(capture.validator_count(), 10_000);
    assert_eq!(capture.threshold(), 6_667);
    assert_eq!(capture.aggregate_signature_len(), MLDSA65_SIGNATURE_BYTES);
    assert!(capture
        .note()
        .contains("not actual real threshold backend emission evidence"));
    assert_eq!(
        real_threshold_backend_emission_capture_schema_fixture_package_digest(),
        decode_hex_array(
            EXPECTED_P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA_FIXTURE_PACKAGE_DIGEST_HEX
        )
    );

    let err = capture.to_backend_output_material().unwrap_err();
    assert_eq!(
        err,
        ThresholdError::BackendUnavailable {
            reason: "P1 real-threshold backend emission capture requires actual real threshold ML-DSA backend evidence",
        }
    );
}

fn real_threshold_backend_capture_test_inputs() -> (
    ProductionSigningTranscript,
    P1SelectedBackendThresholdOutputArtifactCertificate,
    P1StandardVerifierCompatibilityArtifactCertificate,
) {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&bridge_fixture.transcript);
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(&bridge_fixture);
    let compatibility_certificate =
        standard_verifier_compatibility_artifact_certificate(&bridge_fixture);
    (transcript, threshold_certificate, compatibility_certificate)
}

fn synthetic_actual_real_threshold_backend_capture_json(
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &P1StandardVerifierCompatibilityArtifactCertificate,
) -> Value {
    let public_key = ThresholdPublicKey([6; 1952]);
    let message = b"original application message";
    let aggregate_signature = ThresholdSignature([42; 3309]);
    let backend_source_package = b"reviewed real threshold source package bytes v1";
    let backend_implementation = b"reviewed real threshold implementation digest material v1";
    let backend_transcript = b"reviewed real threshold transcript digest material v1";
    let material = P1RealThresholdBackendEmissionOutput {
        backend_source_package,
        backend_implementation,
        backend_transcript,
        public_key: &public_key,
        message,
        aggregate_signature: &aggregate_signature,
        mutated_message_rejected: true,
        mutated_public_key_rejected: true,
        mutated_signature_rejected: true,
        claim_boundary: P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        reviewed: true,
    };
    let expected_package =
        derive_p1_real_threshold_backend_emission_artifact_package_from_backend_output(
            threshold_certificate,
            compatibility_certificate,
            material,
        )
        .expect("synthetic capture material should bind predecessor certificates");
    let selected_profile_binding_digest =
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest();
    let threshold_output_certificate_digest =
        derive_p1_selected_backend_threshold_output_certificate_digest(threshold_certificate);
    let standard_verifier_compatibility_artifact_digest =
        derive_p1_standard_verifier_compatibility_artifact_digest(compatibility_certificate);

    json!({
        "name": "synthetic-actual-real-threshold-capture-for-importer-test",
        "schema": "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1",
        "claim_boundary": "conformance/proof-review evidence only",
        "selected_profile": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        "backend_evidence": "real_threshold_mldsa_external_capture",
        "note": "Synthetic unit-test capture for importer behavior only; not checked proof evidence.",
        "predecessors": {
            "selected_profile_binding_digest_hex": encode_hex(&selected_profile_binding_digest),
            "threshold_output_certificate_digest_hex": encode_hex(&threshold_output_certificate_digest),
            "standard_verifier_compatibility_artifact_digest_hex": encode_hex(&standard_verifier_compatibility_artifact_digest),
        },
        "capture": {
            "validator_count": 10000,
            "threshold": 6667,
            "aggregate_signature_len": 3309,
            "public_key_hex": encode_hex(&public_key.0),
            "message": {
                "encoding": "utf8",
                "value": "original application message",
            },
            "aggregate_signature_hex": encode_hex(&aggregate_signature.0),
            "backend_source_package": {
                "encoding": "utf8",
                "value": "reviewed real threshold source package bytes v1",
            },
            "backend_implementation": {
                "encoding": "utf8",
                "value": "reviewed real threshold implementation digest material v1",
            },
            "backend_transcript": {
                "encoding": "utf8",
                "value": "reviewed real threshold transcript digest material v1",
            },
            "mutated_message_rejected": true,
            "mutated_public_key_rejected": true,
            "mutated_signature_rejected": true,
            "reviewed": true,
        },
        "expected": {
            "backend_evidence_digest_hex": encode_hex(&expected_package.backend_evidence_digest),
            "backend_source_package_digest_hex": encode_hex(&expected_package.backend_source_package_digest),
            "backend_implementation_digest_hex": encode_hex(&expected_package.backend_implementation_digest),
            "backend_transcript_digest_hex": encode_hex(&expected_package.backend_transcript_digest),
            "artifact_digest_hex": encode_hex(&expected_package.artifact_digest),
            "public_key_digest_hex": encode_hex(&expected_package.public_key_digest),
            "message_digest_hex": encode_hex(&expected_package.message_digest),
            "accepted_signature_digest_hex": encode_hex(&expected_package.accepted_signature_digest),
        },
    })
}

fn decode_real_threshold_backend_capture_json(
    capture_json: &Value,
) -> P1RealThresholdBackendEmissionCapture {
    let capture_json = serde_json::to_vec(capture_json).expect("synthetic capture JSON encodes");
    P1RealThresholdBackendEmissionCapture::decode_json(&capture_json)
        .expect("synthetic actual capture should parse")
}

#[test]
fn real_threshold_backend_capture_json_feeds_verified_ingestion_gate_when_actual_evidence_is_present(
) {
    let (transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let capture_json = synthetic_actual_real_threshold_backend_capture_json(
        &threshold_certificate,
        &compatibility_certificate,
    );
    let capture = decode_real_threshold_backend_capture_json(&capture_json);

    let package =
        derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture::<
            AcceptingProvider,
        >(
            &transcript,
            &threshold_certificate,
            &compatibility_certificate,
            &capture,
        )
        .expect("actual evidence capture should feed the verified ingestion gate");

    assert_eq!(
        package.backend_evidence,
        P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa
    );
    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );
    assert!(assessment.is_artifact_ready());
}

#[test]
fn real_threshold_backend_capture_json_requires_standard_verifier_acceptance() {
    let (transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let capture_json = synthetic_actual_real_threshold_backend_capture_json(
        &threshold_certificate,
        &compatibility_certificate,
    );
    let capture = decode_real_threshold_backend_capture_json(&capture_json);

    let err = derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture::<
        RejectingProvider,
    >(
        &transcript,
        &threshold_certificate,
        &compatibility_certificate,
        &capture,
    )
    .unwrap_err();
    assert_eq!(err, ThresholdError::StandardVerificationFailed);
}

#[test]
fn real_threshold_backend_capture_runner_emits_canonical_importable_capture() {
    let (transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let public_key = ThresholdPublicKey([6; 1952]);
    let message = b"original application message";
    let aggregate_signature = ThresholdSignature([42; 3309]);
    let output = P1RealThresholdBackendEmissionOutput {
        backend_source_package: b"actual external threshold backend source manifest v1",
        backend_implementation: b"actual external threshold backend implementation digest v1",
        backend_transcript: b"actual external threshold backend transcript digest v1",
        public_key: &public_key,
        message,
        aggregate_signature: &aggregate_signature,
        mutated_message_rejected: true,
        mutated_public_key_rejected: true,
        mutated_signature_rejected: true,
        claim_boundary: P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        reviewed: true,
    };
    let package =
        derive_p1_verified_real_threshold_backend_emission_artifact_package::<AcceptingProvider>(
            &transcript,
            &threshold_certificate,
            &compatibility_certificate,
            output,
        )
        .expect("standard-verifier accepted backend material should derive a package");

    let emitted_capture = derive_p1_verified_real_threshold_backend_emission_capture(
        &threshold_certificate,
        &compatibility_certificate,
        "actual-external-threshold-backend-capture-test",
        "Actual backend capture runner output fixture; evidence_present_unclosed.",
        output,
        package,
    )
    .expect("artifact-ready backend package should emit canonical capture JSON");
    let capture_json = emitted_capture
        .to_canonical_json()
        .expect("canonical capture should encode");
    let decoded_capture = P1RealThresholdBackendEmissionCapture::decode_json(&capture_json)
        .expect("emitted capture JSON should decode through canonical importer");

    assert_eq!(
        decoded_capture.backend_evidence(),
        "real_threshold_mldsa_external_capture"
    );
    assert_eq!(decoded_capture.validator_count(), 10_000);
    assert_eq!(decoded_capture.threshold(), 6_667);
    assert_eq!(
        decoded_capture.aggregate_signature_len(),
        MLDSA65_SIGNATURE_BYTES
    );

    let package =
        derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture::<
            AcceptingProvider,
        >(
            &transcript,
            &threshold_certificate,
            &compatibility_certificate,
            &decoded_capture,
        )
        .expect("emitted capture should feed the verified ingestion gate");
    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );
    assert!(assessment.is_artifact_ready());
}

#[test]
fn real_threshold_backend_capture_runner_rejects_unready_package_before_external_capture() {
    let (_transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let public_key = ThresholdPublicKey([6; 1952]);
    let message = b"original application message";
    let aggregate_signature = ThresholdSignature([42; 3309]);
    let output = P1RealThresholdBackendEmissionOutput {
        backend_source_package: b"fixture harness source bytes cannot mint external capture",
        backend_implementation:
            b"fixture harness implementation bytes cannot mint external capture",
        backend_transcript: b"fixture harness transcript bytes cannot mint external capture",
        public_key: &public_key,
        message,
        aggregate_signature: &aggregate_signature,
        mutated_message_rejected: true,
        mutated_public_key_rejected: true,
        mutated_signature_rejected: true,
        claim_boundary: P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        reviewed: true,
    };
    let fixture_package = derive_p1_real_threshold_backend_emission_artifact_package(
        &threshold_certificate,
        &compatibility_certificate,
        P1RealThresholdVerifierClosureBackendEvidence::FixtureHarness,
        derive_p1_real_threshold_backend_emission_evidence_digest(&output),
        derive_p1_real_threshold_backend_source_package_digest(output.backend_source_package),
        derive_p1_real_threshold_backend_implementation_digest(output.backend_implementation),
        derive_p1_real_threshold_backend_transcript_digest(output.backend_transcript),
        true,
        true,
        true,
        P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        true,
    );

    let err = derive_p1_verified_real_threshold_backend_emission_capture(
        &threshold_certificate,
        &compatibility_certificate,
        "fixture-harness-cannot-mint-external-capture",
        "Fixture harness must remain blocked before external capture emission.",
        output,
        fixture_package,
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::BackendUnavailable {
            reason: "P1 real-threshold backend capture runner requires artifact-ready external backend evidence",
        }
    );
}

#[test]
fn real_threshold_backend_capture_json_rejects_stale_predecessor_digest() {
    let (transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let mut capture_json = synthetic_actual_real_threshold_backend_capture_json(
        &threshold_certificate,
        &compatibility_certificate,
    );
    capture_json["predecessors"]["threshold_output_certificate_digest_hex"] =
        Value::String("00".repeat(32));
    let capture = decode_real_threshold_backend_capture_json(&capture_json);

    let err = derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture::<
        AcceptingProvider,
    >(
        &transcript,
        &threshold_certificate,
        &compatibility_certificate,
        &capture,
    )
    .unwrap_err();
    assert_eq!(err, ThresholdError::TranscriptMismatch);
}

#[test]
fn real_threshold_backend_capture_json_rejects_expected_artifact_digest_drift() {
    let (transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let mut capture_json = synthetic_actual_real_threshold_backend_capture_json(
        &threshold_certificate,
        &compatibility_certificate,
    );
    capture_json["expected"]["artifact_digest_hex"] = Value::String("00".repeat(32));
    let capture = decode_real_threshold_backend_capture_json(&capture_json);

    let err = derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture::<
        AcceptingProvider,
    >(
        &transcript,
        &threshold_certificate,
        &compatibility_certificate,
        &capture,
    )
    .unwrap_err();
    assert_eq!(err, ThresholdError::TranscriptMismatch);
}

#[test]
fn real_threshold_backend_capture_json_rejects_missing_predecessor_digests() {
    let (transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let mut capture_json = synthetic_actual_real_threshold_backend_capture_json(
        &threshold_certificate,
        &compatibility_certificate,
    );
    capture_json
        .as_object_mut()
        .expect("synthetic capture is an object")
        .remove("predecessors");
    let capture = decode_real_threshold_backend_capture_json(&capture_json);

    let err = derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture::<
        AcceptingProvider,
    >(
        &transcript,
        &threshold_certificate,
        &compatibility_certificate,
        &capture,
    )
    .unwrap_err();
    assert_eq!(
        err,
        ThresholdError::MalformedSerialization {
            reason:
                "P1 real-threshold backend emission capture requires predecessor certificate digests",
        }
    );
}

#[test]
fn real_threshold_backend_capture_json_rejects_missing_expected_digests() {
    let (transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let mut capture_json = synthetic_actual_real_threshold_backend_capture_json(
        &threshold_certificate,
        &compatibility_certificate,
    );
    capture_json
        .as_object_mut()
        .expect("synthetic capture is an object")
        .remove("expected");
    let capture = decode_real_threshold_backend_capture_json(&capture_json);

    let err = derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture::<
        AcceptingProvider,
    >(
        &transcript,
        &threshold_certificate,
        &compatibility_certificate,
        &capture,
    )
    .unwrap_err();
    assert_eq!(
        err,
        ThresholdError::MalformedSerialization {
            reason: "P1 real-threshold backend emission capture requires expected package digests",
        }
    );
}

#[test]
fn real_threshold_backend_capture_json_rejects_malformed_signature_length() {
    let (transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let mut capture_json = synthetic_actual_real_threshold_backend_capture_json(
        &threshold_certificate,
        &compatibility_certificate,
    );
    capture_json["capture"]["aggregate_signature_hex"] = Value::String("2a".repeat(3308));
    let capture = decode_real_threshold_backend_capture_json(&capture_json);

    let err = derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture::<
        AcceptingProvider,
    >(
        &transcript,
        &threshold_certificate,
        &compatibility_certificate,
        &capture,
    )
    .unwrap_err();
    assert_eq!(
        err,
        ThresholdError::MalformedSerialization {
            reason:
                "P1 real-threshold backend emission capture aggregate signature hex is malformed",
        }
    );
}

#[test]
fn real_threshold_backend_capture_json_rejects_unsupported_byte_encoding() {
    let (transcript, threshold_certificate, compatibility_certificate) =
        real_threshold_backend_capture_test_inputs();
    let mut capture_json = synthetic_actual_real_threshold_backend_capture_json(
        &threshold_certificate,
        &compatibility_certificate,
    );
    capture_json["capture"]["backend_transcript"]["encoding"] = Value::String("base64".to_owned());
    let capture = decode_real_threshold_backend_capture_json(&capture_json);

    let err = derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture::<
        AcceptingProvider,
    >(
        &transcript,
        &threshold_certificate,
        &compatibility_certificate,
        &capture,
    )
    .unwrap_err();
    assert_eq!(
        err,
        ThresholdError::MalformedSerialization {
            reason: "unsupported P1 real-threshold backend emission capture byte encoding",
        }
    );
}

#[cfg(feature = "hazmat-real-mldsa")]
#[test]
fn standard_provider_single_key_emission_fixture_verifies_real_mldsa_but_cannot_replace_threshold_backend_evidence(
) {
    use lattice_aggregation::production::provider::HazmatMldsa65Provider;
    use ml_dsa::{Keypair, MlDsa65, SignatureEncoding, Signer, SigningKey};

    let emission_fixture = standard_provider_single_key_emission_artifact_fixture();
    assert_eq!(
        emission_fixture.name,
        "p1-standard-provider-single-key-emission-artifact-v1"
    );
    assert_eq!(
        emission_fixture.schema,
        "lattice-aggregation:p1-standard-provider-single-key-emission-artifact:v1"
    );
    assert_eq!(
        emission_fixture.claim_boundary,
        "conformance/proof-review evidence only"
    );
    assert_eq!(
        emission_fixture.selected_profile,
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        emission_fixture.source_bridge_fixture,
        "generated-from-real-ml-dsa-provider-output"
    );
    assert_eq!(
        emission_fixture.source_standard_verifier_compatibility_fixture,
        "generated-from-real-ml-dsa-provider-output"
    );
    assert_eq!(
        emission_fixture.source_threshold_output_certificate_artifact_fixture,
        "generated-from-real-ml-dsa-provider-output"
    );
    assert_eq!(
        emission_fixture.backend_evidence,
        "standard_provider_single_key_actual_mldsa65_emission"
    );
    assert!(emission_fixture
        .note
        .contains("not threshold backend provenance"));
    assert_eq!(
        standard_provider_single_key_emission_artifact_fixture_package_digest(),
        decode_hex_array(
            EXPECTED_P1_STANDARD_PROVIDER_SINGLE_KEY_EMISSION_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX
        )
    );

    let seed = decode_hex_array::<32>(&emission_fixture.capture.seed_hex);
    let seed = seed.into();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let message = emission_fixture.capture.message.bytes();
    let expected_public_key = signing_key.verifying_key().encode();
    let expected_signature = signing_key.sign(message).to_bytes();
    assert_eq!(
        decode_hex(&emission_fixture.capture.public_key_hex),
        expected_public_key.as_slice()
    );
    assert_eq!(
        decode_hex(&emission_fixture.capture.signature_hex),
        expected_signature.as_slice()
    );

    let public_key = threshold_public_key_from(expected_public_key.as_slice());
    let signature = threshold_signature_from(expected_signature.as_slice());
    assert!(
        HazmatMldsa65Provider::verify(&public_key, message, &signature).unwrap(),
        "actual standard-provider ML-DSA emission should verify before threshold provenance checks"
    );

    let mut mutated_public_key = public_key.clone();
    mutated_public_key.0[0] ^= 0x01;
    let mut mutated_signature = signature.clone();
    mutated_signature.0[0] ^= 0x01;
    assert!(!HazmatMldsa65Provider::verify(&public_key, b"mutated message", &signature).unwrap());
    assert!(!HazmatMldsa65Provider::verify(&mutated_public_key, message, &signature).unwrap());
    assert!(!HazmatMldsa65Provider::verify(&public_key, message, &mutated_signature).unwrap());

    let transcript = real_mldsa_transcript(public_key, message);
    let partials = real_mldsa_accepted_partials(&transcript);
    let verifier =
        StandardVerifierEvidence::verify::<HazmatMldsa65Provider>(&transcript, &signature)
            .expect("real ML-DSA signature should mint standard-verifier evidence");
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        emission_fixture.capture.backend_transcript.bytes(),
        b"standard-provider-single-key-emission-hint-route",
        &signature,
    )
    .expect("public real-ML-DSA emission should derive a recomputation transcript");
    let bridge_evidence = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<
        HazmatMldsa65Provider,
    >(&transcript, &signature, &recomputation)
    .expect("real provider emission should satisfy the standard-verifier bridge");
    let standard_verifier_bridge_evidence_digest = derive_standard_verifier_bridge_evidence_digest(
        &SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        &provider_kat_fixture_digest(),
        &bridge_evidence,
    )
    .expect("real provider bridge evidence should derive a digest");
    let real_recomputation_evidence_digest =
        derive_p1_real_recomputation_evidence_digest(&recomputation);
    let accepted_aggregate = AggregateAccept::accept(
        &transcript,
        &partials,
        AggregateAcceptEvidence {
            aggregate_response_digest: *recomputation.aggregate_response_digest(),
            hint_digest: *recomputation.hint_digest(),
            standard_verifier: verifier,
        },
    )
    .expect("real standard-provider output should pass aggregate acceptance");
    let recomputation_certificate = p1_recomputation_certificate_for_output(
        standard_verifier_bridge_evidence_digest,
        real_recomputation_evidence_digest,
    );
    let aggregate_package =
        derive_p1_selected_backend_aggregate_artifact_package::<HazmatMldsa65Provider>(
            &transcript,
            &accepted_aggregate,
            &recomputation,
            &recomputation_certificate,
            &signature,
            true,
        )
        .expect("real provider emission should derive an aggregate artifact package");
    let aggregate_certificate = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(aggregate_package),
    )
    .artifact_certificate()
    .copied()
    .expect("real provider emission should produce an aggregate artifact certificate");
    let threshold_source = P1ThresholdOutputEvidenceSource::selected_backend_candidate(
        derive_p1_selected_backend_threshold_output_source_digest(
            &transcript,
            &accepted_aggregate,
            &recomputation,
            emission_fixture.capture.backend_source_package.bytes(),
        ),
        derive_p1_selected_backend_threshold_output_source_package_digest(
            emission_fixture.capture.backend_source_package.bytes(),
        ),
        true,
    );
    let threshold_package = derive_p1_selected_backend_threshold_output_artifact_package(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        threshold_source,
        P1ThresholdOutputClaimBoundary::ProofReviewOnly,
        true,
    )
    .expect("real provider emission should derive a threshold-output predecessor package");
    let threshold_certificate = assess_p1_selected_backend_threshold_output_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        Some(threshold_package),
    )
    .threshold_output_certificate()
    .copied()
    .expect("real provider emission should produce a threshold-output predecessor certificate");
    let compatibility_package =
        derive_p1_standard_verifier_compatibility_artifact_package::<HazmatMldsa65Provider>(
            &transcript,
            &threshold_certificate,
            &signature,
            P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly,
            true,
        )
        .expect("real provider emission should derive a compatibility package");
    let compatibility_certificate = assess_p1_standard_verifier_compatibility_artifact(
        &transcript,
        &threshold_certificate,
        Some(compatibility_package),
    )
    .standard_verifier_compatibility_certificate()
    .copied()
    .expect("real provider emission should produce a compatibility certificate");

    let package = standard_provider_single_key_emission_artifact_package_from_fixture(
        &emission_fixture,
        &threshold_certificate,
        &compatibility_certificate,
    );
    assert_eq!(
        package.backend_evidence,
        P1RealThresholdVerifierClosureBackendEvidence::StandardProviderSingleKey
    );
    assert_eq!(
        package.selected_profile_binding_digest,
        emission_fixture.expected.selected_profile_binding_digest()
    );
    assert_eq!(
        package.backend_evidence_digest,
        emission_fixture.expected.backend_evidence_digest()
    );
    assert_eq!(
        package.backend_source_package_digest,
        emission_fixture.expected.backend_source_package_digest()
    );
    assert_eq!(
        package.backend_implementation_digest,
        emission_fixture.expected.backend_implementation_digest()
    );
    assert_eq!(
        package.backend_transcript_digest,
        emission_fixture.expected.backend_transcript_digest()
    );
    assert_eq!(
        package.artifact_digest,
        emission_fixture.expected.artifact_digest()
    );
    assert_eq!(
        package.public_key_digest,
        emission_fixture.expected.public_key_digest()
    );
    assert_eq!(
        package.message_digest,
        emission_fixture.expected.message_digest()
    );
    assert_eq!(
        package.transcript_binding_digest,
        emission_fixture.expected.transcript_binding_digest()
    );
    assert_eq!(
        package.signer_set_digest,
        emission_fixture.expected.signer_set_digest()
    );
    assert_eq!(
        package.attempt_binding_digest,
        emission_fixture.expected.attempt_binding_digest()
    );
    assert_eq!(
        package.accepted_signature_digest,
        emission_fixture.expected.accepted_signature_digest()
    );
    assert_eq!(
        package.threshold_output_certificate_digest,
        emission_fixture
            .expected
            .threshold_output_certificate_digest()
    );
    assert_eq!(
        package.standard_verifier_compatibility_artifact_digest,
        emission_fixture
            .expected
            .standard_verifier_compatibility_artifact_digest()
    );

    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );
    assert_eq!(
        assessment,
        P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission requires threshold backend provenance, not ordinary single-key standard-provider output",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn real_recomputation_artifact_fixture_parses_and_matches_typed_slot() {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let recomputation_fixture = real_recomputation_artifact_fixture();
    let proof_closure_package = selected_backend_proof_closure_artifact_package(&bridge_fixture);
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(&bridge_fixture);
    let real_recomputation_slot = proof_closure_package
        .proof_slot_artifacts
        .real_recomputation_evidence_artifact;

    assert_eq!(
        recomputation_fixture.name,
        "p1-real-recomputation-artifact-fixture-v1"
    );
    assert_eq!(
        recomputation_fixture.schema,
        "lattice-aggregation:p1-real-recomputation-artifact:v1"
    );
    assert_eq!(
        recomputation_fixture.claim_boundary,
        "conformance/proof-review evidence only"
    );
    assert_eq!(
        recomputation_fixture.selected_profile,
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        recomputation_fixture.source_bridge_fixture,
        "tests/fixtures/p1_standard_verifier_bridge_fixture.json"
    );
    assert_eq!(
        recomputation_fixture.source_standard_verifier_compatibility_fixture,
        "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
    );
    assert!(recomputation_fixture
        .note
        .contains("not selected-backend proof closure"));
    assert!(recomputation_fixture
        .note
        .contains("not rejection-distribution preservation"));
    assert_eq!(
        recomputation_fixture.slot_artifact.slot_id,
        "real_recomputation_evidence_digest"
    );
    assert_eq!(
        recomputation_fixture.slot_artifact.kind,
        "RealRecomputationEvidence"
    );
    assert_eq!(
        recomputation_fixture.slot_artifact.evidence_source,
        "p1_criterion2_real_recomputation_evidence_artifact_gate"
    );
    assert_eq!(
        recomputation_fixture.slot_artifact.artifact_package,
        "p1_criterion2_proof_slot_artifact_package"
    );
    assert_eq!(
        recomputation_fixture.slot_artifact.current_status,
        "evidence_present_unclosed"
    );
    assert!(recomputation_fixture.slot_artifact.reviewed);
    assert_eq!(
        real_recomputation_slot.kind(),
        P1Criterion2ProofSlotArtifactKind::RealRecomputationEvidence
    );
    assert_eq!(
        real_recomputation_slot.selected_profile_binding_digest,
        recomputation_fixture
            .expected
            .selected_profile_binding_digest()
    );
    assert_eq!(
        real_recomputation_slot.threshold_output_certificate_digest,
        recomputation_fixture
            .expected
            .threshold_output_certificate_digest()
    );
    assert_eq!(
        real_recomputation_slot.threshold_output_certificate_digest,
        derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate)
    );
    assert_eq!(
        real_recomputation_slot.transcript_binding_digest,
        recomputation_fixture.expected.transcript_binding_digest()
    );
    assert_eq!(
        real_recomputation_slot.source_evidence_digest,
        recomputation_fixture.expected.source_evidence_digest()
    );
    assert_eq!(
        real_recomputation_slot.review_evidence_digest,
        recomputation_fixture.expected.review_evidence_digest()
    );
    assert_eq!(
        real_recomputation_slot.artifact_digest(),
        &recomputation_fixture.expected.artifact_digest()
    );
    assert_eq!(
        derive_p1_criterion2_proof_slot_artifact_digest(&real_recomputation_slot),
        recomputation_fixture.expected.artifact_digest()
    );
    assert_eq!(
        proof_closure_package.standard_verifier_bridge_evidence_digest,
        recomputation_fixture
            .expected
            .standard_verifier_bridge_evidence_digest()
    );
    assert_eq!(
        proof_closure_package.aggregate_response_digest,
        recomputation_fixture.expected.aggregate_response_digest()
    );
    assert_eq!(
        proof_closure_package.hint_digest,
        recomputation_fixture.expected.hint_digest()
    );
    assert_eq!(
        proof_closure_package.accepted_signature_digest,
        recomputation_fixture.expected.accepted_signature_digest()
    );
    assert_eq!(
        recomputation_fixture
            .negative_cases
            .iter()
            .map(|case| (case.name.as_str(), case.expected_gate.as_str()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "stale_recomputation_review_digest",
                "p1_selected_backend_proof_closure_artifact_rejects_recomputation_slot_review_tamper",
            ),
            (
                "stale_recomputation_source_digest",
                "p1_selected_backend_proof_closure_artifact_rejects_recomputation_slot_source_tamper",
            ),
            (
                "stale_transcript_binding_digest",
                "p1_selected_backend_proof_closure_artifact_rejects_stale_proof_transcript_binding",
            ),
            (
                "unreviewed_slot_artifact",
                "p1_selected_backend_proof_closure_artifact_rejects_unreviewed_typed_slot",
            ),
        ])
    );
}

#[test]
fn threshold_output_certificate_artifact_fixture_parses_and_matches_typed_slot() {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let threshold_fixture = threshold_output_certificate_artifact_fixture();
    let proof_closure_package = selected_backend_proof_closure_artifact_package(&bridge_fixture);
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(&bridge_fixture);
    let threshold_source = threshold_output_evidence_source(&bridge_fixture);
    let transcript = transcript_from_fixture(&bridge_fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&bridge_fixture);
    let recomputation = fixture_recomputation_transcript(&bridge_fixture);
    let threshold_slot = proof_closure_package
        .proof_slot_artifacts
        .threshold_output_certificate_artifact;

    assert_eq!(
        threshold_fixture.name,
        "p1-threshold-output-certificate-artifact-fixture-v1"
    );
    assert_eq!(
        threshold_fixture.schema,
        "lattice-aggregation:p1-threshold-output-certificate-artifact:v1"
    );
    assert_eq!(
        threshold_fixture.claim_boundary,
        "conformance/proof-review evidence only"
    );
    assert_eq!(
        threshold_fixture.selected_profile,
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        threshold_fixture.source_bridge_fixture,
        "tests/fixtures/p1_standard_verifier_bridge_fixture.json"
    );
    assert_eq!(
        threshold_fixture.source_standard_verifier_compatibility_fixture,
        "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
    );
    assert_eq!(
        threshold_fixture.source_threshold_output_package.bytes(),
        DEFAULT_THRESHOLD_OUTPUT_SOURCE_PACKAGE
    );
    assert!(threshold_fixture
        .note
        .contains("not selected-backend proof closure"));
    assert!(threshold_fixture
        .note
        .contains("not rejection-distribution preservation"));
    assert_eq!(
        threshold_fixture.slot_artifact.slot_id,
        "threshold_output_certificate_digest"
    );
    assert_eq!(
        threshold_fixture.slot_artifact.kind,
        "ThresholdOutputCertificate"
    );
    assert_eq!(
        threshold_fixture.slot_artifact.evidence_source,
        "p1_criterion2_threshold_output_certificate_artifact_gate"
    );
    assert_eq!(
        threshold_fixture.slot_artifact.artifact_package,
        "p1_criterion2_proof_slot_artifact_package"
    );
    assert_eq!(
        threshold_fixture.slot_artifact.current_status,
        "evidence_present_unclosed"
    );
    assert!(threshold_fixture.slot_artifact.reviewed);
    assert!(threshold_source.reviewed());
    assert_eq!(
        derive_p1_selected_backend_threshold_output_source_package_digest(
            threshold_fixture.source_threshold_output_package.bytes()
        ),
        threshold_fixture
            .expected
            .threshold_output_source_package_digest()
    );
    assert_eq!(
        derive_p1_selected_backend_threshold_output_source_digest(
            &transcript,
            &accepted_aggregate,
            &recomputation,
            threshold_fixture.source_threshold_output_package.bytes(),
        ),
        threshold_fixture.expected.threshold_output_source_digest()
    );
    assert_eq!(
        threshold_source.source_package_digest(),
        &threshold_fixture
            .expected
            .threshold_output_source_package_digest()
    );
    assert_eq!(
        threshold_source.source_digest(),
        &threshold_fixture.expected.threshold_output_source_digest()
    );
    assert_eq!(
        threshold_certificate.selected_profile_binding_digest(),
        &threshold_fixture.expected.selected_profile_binding_digest()
    );
    assert_eq!(
        threshold_certificate.aggregate_artifact_digest(),
        &threshold_fixture.expected.aggregate_artifact_digest()
    );
    assert_eq!(
        threshold_certificate.provider_kat_evidence_digest(),
        &threshold_fixture.expected.provider_kat_evidence_digest()
    );
    assert_eq!(
        threshold_certificate.threshold_output_source_package_digest(),
        &threshold_fixture
            .expected
            .threshold_output_source_package_digest()
    );
    assert_eq!(
        threshold_certificate.threshold_output_source_digest(),
        &threshold_fixture.expected.threshold_output_source_digest()
    );
    assert_eq!(
        derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate),
        threshold_fixture
            .expected
            .threshold_output_certificate_digest()
    );
    assert_eq!(
        threshold_certificate.transcript_binding_digest(),
        &threshold_fixture.expected.transcript_binding_digest()
    );
    assert_eq!(
        threshold_certificate.signer_set_digest(),
        &threshold_fixture.expected.signer_set_digest()
    );
    assert_eq!(
        threshold_certificate.attempt_binding_digest(),
        &threshold_fixture.expected.attempt_binding_digest()
    );
    assert_eq!(
        threshold_certificate.aggregate_response_digest(),
        &threshold_fixture.expected.aggregate_response_digest()
    );
    assert_eq!(
        threshold_certificate.hint_digest(),
        &threshold_fixture.expected.hint_digest()
    );
    assert_eq!(
        threshold_certificate.accepted_signature_digest(),
        &threshold_fixture.expected.accepted_signature_digest()
    );
    assert_eq!(
        threshold_certificate.standard_verifier_bridge_evidence_digest(),
        &threshold_fixture
            .expected
            .standard_verifier_bridge_evidence_digest()
    );
    assert_eq!(
        threshold_certificate.real_recomputation_evidence_digest(),
        &threshold_fixture
            .expected
            .real_recomputation_evidence_digest()
    );
    assert_eq!(
        threshold_slot.kind(),
        P1Criterion2ProofSlotArtifactKind::ThresholdOutputCertificate
    );
    assert_eq!(
        threshold_slot.selected_profile_binding_digest,
        threshold_fixture.expected.selected_profile_binding_digest()
    );
    assert_eq!(
        threshold_slot.threshold_output_certificate_digest,
        threshold_fixture
            .expected
            .threshold_output_certificate_digest()
    );
    assert_eq!(
        threshold_slot.transcript_binding_digest,
        threshold_fixture.expected.transcript_binding_digest()
    );
    assert_eq!(
        threshold_slot.source_evidence_digest,
        threshold_fixture.expected.source_evidence_digest()
    );
    assert_eq!(
        threshold_slot.review_evidence_digest,
        threshold_fixture.expected.review_evidence_digest()
    );
    assert_eq!(
        threshold_slot.artifact_digest(),
        &threshold_fixture.expected.artifact_digest()
    );
    assert_eq!(
        derive_p1_criterion2_proof_slot_artifact_digest(&threshold_slot),
        threshold_fixture.expected.artifact_digest()
    );
    assert_eq!(
        proof_closure_package.threshold_output_certificate_digest,
        threshold_fixture
            .expected
            .threshold_output_certificate_digest()
    );
    assert_eq!(
        proof_closure_package.standard_verifier_bridge_evidence_digest,
        threshold_fixture
            .expected
            .standard_verifier_bridge_evidence_digest()
    );
    assert_eq!(
        proof_closure_package
            .proof_artifacts
            .real_recomputation_evidence_digest(),
        &threshold_fixture
            .expected
            .real_recomputation_evidence_digest()
    );
    assert_eq!(
        proof_closure_package.aggregate_response_digest,
        threshold_fixture.expected.aggregate_response_digest()
    );
    assert_eq!(
        proof_closure_package.hint_digest,
        threshold_fixture.expected.hint_digest()
    );
    assert_eq!(
        proof_closure_package.accepted_signature_digest,
        threshold_fixture.expected.accepted_signature_digest()
    );
    assert_eq!(
        threshold_fixture
            .negative_cases
            .iter()
            .map(|case| (case.name.as_str(), case.expected_gate.as_str()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "stale_threshold_certificate_digest",
                "p1_selected_backend_proof_closure_artifact_rejects_stale_threshold_certificate_digest",
            ),
            (
                "threshold_slot_source_tamper",
                "p1_selected_backend_proof_closure_artifact_rejects_threshold_slot_source_tamper",
            ),
            (
                "threshold_slot_review_tamper",
                "p1_selected_backend_proof_closure_artifact_rejects_threshold_slot_review_tamper",
            ),
            (
                "typed_slot_digest_drift",
                "p1_selected_backend_proof_closure_artifact_rejects_typed_slot_digest_drift",
            ),
        ])
    );
}

#[test]
fn rejection_distribution_review_artifact_fixture_parses_and_matches_typed_slot() {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let rejection_fixture = rejection_distribution_review_artifact_fixture();
    let proof_closure_package = selected_backend_proof_closure_artifact_package(&bridge_fixture);
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(&bridge_fixture);
    let rejection_slot = proof_closure_package
        .proof_slot_artifacts
        .rejection_distribution_review_artifact;

    assert_eq!(
        rejection_fixture.name,
        "p1-rejection-distribution-review-artifact-fixture-v1"
    );
    assert_eq!(
        rejection_fixture.schema,
        "lattice-aggregation:p1-rejection-distribution-review-artifact:v1"
    );
    assert_eq!(
        rejection_fixture.claim_boundary,
        "conformance/proof-review evidence only"
    );
    assert_eq!(
        rejection_fixture.selected_profile,
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        rejection_fixture.source_bridge_fixture,
        "tests/fixtures/p1_standard_verifier_bridge_fixture.json"
    );
    assert_eq!(
        rejection_fixture.source_standard_verifier_compatibility_fixture,
        "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
    );
    assert_eq!(
        rejection_fixture.source_threshold_output_certificate_artifact_fixture,
        "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json"
    );
    assert_eq!(
        rejection_fixture.source_real_recomputation_artifact_fixture,
        "tests/fixtures/p1_real_recomputation_artifact_fixture.json"
    );
    assert!(rejection_fixture
        .note
        .contains("not selected-backend proof closure"));
    assert!(rejection_fixture
        .note
        .contains("not rejection-distribution preservation"));
    assert_eq!(
        rejection_fixture.slot_artifact.slot_id,
        "rejection_distribution_review_digest"
    );
    assert_eq!(
        rejection_fixture.slot_artifact.kind,
        "RejectionDistributionReview"
    );
    assert_eq!(
        rejection_fixture.slot_artifact.evidence_source,
        "p1_criterion2_rejection_distribution_review_artifact_gate"
    );
    assert_eq!(
        rejection_fixture.slot_artifact.artifact_package,
        "p1_criterion2_proof_slot_artifact_package"
    );
    assert_eq!(
        rejection_fixture.slot_artifact.current_status,
        "evidence_present_unclosed"
    );
    assert!(rejection_fixture.slot_artifact.reviewed);
    assert_eq!(
        rejection_slot.kind(),
        P1Criterion2ProofSlotArtifactKind::RejectionDistributionReview
    );
    assert_eq!(
        rejection_slot.selected_profile_binding_digest,
        rejection_fixture.expected.selected_profile_binding_digest()
    );
    assert_eq!(
        rejection_slot.threshold_output_certificate_digest,
        rejection_fixture
            .expected
            .threshold_output_certificate_digest()
    );
    assert_eq!(
        rejection_slot.threshold_output_certificate_digest,
        derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate)
    );
    assert_eq!(
        rejection_slot.transcript_binding_digest,
        rejection_fixture.expected.transcript_binding_digest()
    );
    assert_eq!(
        rejection_slot.source_evidence_digest,
        rejection_fixture.expected.source_evidence_digest()
    );
    assert_eq!(
        rejection_slot.review_evidence_digest,
        rejection_fixture.expected.review_evidence_digest()
    );
    assert_eq!(
        rejection_slot.artifact_digest(),
        &rejection_fixture.expected.artifact_digest()
    );
    assert_eq!(
        derive_p1_criterion2_proof_slot_artifact_digest(&rejection_slot),
        rejection_fixture.expected.artifact_digest()
    );
    assert_eq!(
        proof_closure_package.rejection_distribution_review_digest,
        rejection_fixture
            .expected
            .rejection_distribution_review_digest()
    );
    assert_eq!(
        proof_closure_package.rejection_distribution_review_digest,
        rejection_fixture.expected.artifact_digest()
    );

    let assessment = assess_p1_selected_backend_proof_closure_artifact(
        &threshold_certificate,
        Some(proof_closure_package),
    );
    let certificate = assessment
        .proof_closure_certificate()
        .expect("reviewed proof-closure artifact package should produce a certificate");
    assert_eq!(
        certificate.rejection_distribution_review_digest(),
        &rejection_fixture
            .expected
            .rejection_distribution_review_digest()
    );
    assert!(
        !certificate.claims_rejection_distribution_preservation(),
        "checked fixture must not promote rejection-distribution preservation"
    );
    assert_eq!(
        rejection_fixture
            .negative_cases
            .iter()
            .map(|case| (case.name.as_str(), case.expected_gate.as_str()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "missing_distribution_review_artifact",
                "p1_selected_backend_proof_closure_artifact_rejects_missing_distribution_review_artifact",
            ),
            (
                "rejection_distribution_slot_review_tamper",
                "p1_selected_backend_proof_closure_artifact_rejects_rejection_distribution_slot_review_tamper",
            ),
            (
                "rejection_distribution_slot_digest_drift",
                "p1_selected_backend_proof_closure_artifact_rejects_rejection_distribution_slot_digest_drift",
            ),
            (
                "rejection_distribution_package_digest_stale",
                "p1_selected_backend_proof_closure_artifact_rejects_rejection_distribution_package_digest_stale",
            ),
            (
                "unreviewed_rejection_distribution_slot",
                "p1_selected_backend_proof_closure_artifact_rejects_unreviewed_rejection_distribution_slot",
            ),
            (
                "rejection_distribution_slot_production_claim_boundary",
                "p1_selected_backend_proof_closure_artifact_rejects_rejection_distribution_slot_production_claim_boundary",
            ),
        ])
    );
}

#[test]
fn theorem_linkage_artifact_fixture_parses_and_matches_typed_slot() {
    let bridge_fixture = standard_verifier_bridge_fixture();
    let theorem_fixture = theorem_linkage_artifact_fixture();
    let proof_closure_package = selected_backend_proof_closure_artifact_package(&bridge_fixture);
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(&bridge_fixture);
    let theorem_slot = proof_closure_package
        .proof_slot_artifacts
        .theorem_linkage_artifact;

    assert_eq!(
        theorem_fixture.name,
        "p1-theorem-linkage-artifact-fixture-v1"
    );
    assert_eq!(
        theorem_fixture.schema,
        "lattice-aggregation:p1-theorem-linkage-artifact:v1"
    );
    assert_eq!(
        theorem_fixture.claim_boundary,
        "conformance/proof-review evidence only"
    );
    assert_eq!(
        theorem_fixture.selected_profile,
        "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1"
    );
    assert_eq!(
        theorem_fixture.source_bridge_fixture,
        "tests/fixtures/p1_standard_verifier_bridge_fixture.json"
    );
    assert_eq!(
        theorem_fixture.source_standard_verifier_compatibility_fixture,
        "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
    );
    assert_eq!(
        theorem_fixture.source_threshold_output_certificate_artifact_fixture,
        "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json"
    );
    assert_eq!(
        theorem_fixture.source_real_recomputation_artifact_fixture,
        "tests/fixtures/p1_real_recomputation_artifact_fixture.json"
    );
    assert_eq!(
        theorem_fixture.source_rejection_distribution_review_artifact_fixture,
        "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json"
    );
    assert!(theorem_fixture
        .note
        .contains("not selected-backend proof closure"));
    assert!(theorem_fixture
        .note
        .contains("not a completed cryptographic proof"));
    assert_eq!(
        theorem_fixture.slot_artifact.slot_id,
        "theorem_linkage_artifact_digest"
    );
    assert_eq!(theorem_fixture.slot_artifact.kind, "TheoremLinkage");
    assert_eq!(
        theorem_fixture.slot_artifact.evidence_source,
        "p1_criterion2_theorem_linkage_artifact_gate"
    );
    assert_eq!(
        theorem_fixture.slot_artifact.artifact_package,
        "p1_criterion2_proof_slot_artifact_package"
    );
    assert_eq!(
        theorem_fixture.slot_artifact.current_status,
        "evidence_present_unclosed"
    );
    assert!(theorem_fixture.slot_artifact.reviewed);
    assert_eq!(
        theorem_slot.kind(),
        P1Criterion2ProofSlotArtifactKind::TheoremLinkage
    );
    assert_eq!(
        theorem_slot.selected_profile_binding_digest,
        theorem_fixture.expected.selected_profile_binding_digest()
    );
    assert_eq!(
        theorem_slot.threshold_output_certificate_digest,
        theorem_fixture
            .expected
            .threshold_output_certificate_digest()
    );
    assert_eq!(
        theorem_slot.threshold_output_certificate_digest,
        derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate)
    );
    assert_eq!(
        theorem_slot.transcript_binding_digest,
        theorem_fixture.expected.transcript_binding_digest()
    );
    assert_eq!(
        theorem_slot.source_evidence_digest,
        theorem_fixture.expected.source_evidence_digest()
    );
    assert_eq!(
        theorem_slot.review_evidence_digest,
        theorem_fixture.expected.review_evidence_digest()
    );
    assert_eq!(
        theorem_slot.artifact_digest(),
        &theorem_fixture.expected.artifact_digest()
    );
    assert_eq!(
        derive_p1_criterion2_proof_slot_artifact_digest(&theorem_slot),
        theorem_fixture.expected.artifact_digest()
    );
    assert_eq!(
        proof_closure_package.theorem_linkage_artifact_digest,
        theorem_fixture.expected.theorem_linkage_artifact_digest()
    );
    assert_eq!(
        proof_closure_package.theorem_linkage_artifact_digest,
        theorem_fixture.expected.artifact_digest()
    );

    let assessment = assess_p1_selected_backend_proof_closure_artifact(
        &threshold_certificate,
        Some(proof_closure_package),
    );
    let certificate = assessment
        .proof_closure_certificate()
        .expect("reviewed proof-closure artifact package should produce a certificate");
    assert_eq!(
        certificate.theorem_linkage_artifact_digest(),
        &theorem_fixture.expected.theorem_linkage_artifact_digest()
    );
    assert!(
        !certificate.claims_completed_cryptographic_proof(),
        "checked theorem-linkage fixture must not promote proof closure"
    );
    assert_eq!(
        theorem_fixture
            .negative_cases
            .iter()
            .map(|case| (case.name.as_str(), case.expected_gate.as_str()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "missing_theorem_linkage_artifact",
                "p1_selected_backend_proof_closure_artifact_rejects_missing_theorem_linkage_artifact",
            ),
            (
                "unreviewed_theorem_linkage_slot",
                "p1_selected_backend_proof_closure_artifact_rejects_unreviewed_theorem_linkage_slot",
            ),
            (
                "theorem_linkage_slot_digest_drift",
                "p1_selected_backend_proof_closure_artifact_rejects_theorem_linkage_slot_digest_drift",
            ),
            (
                "theorem_linkage_slot_review_tamper",
                "p1_selected_backend_proof_closure_artifact_rejects_theorem_linkage_slot_review_tamper",
            ),
            (
                "theorem_linkage_package_digest_stale",
                "p1_selected_backend_proof_closure_artifact_rejects_theorem_linkage_package_digest_stale",
            ),
            (
                "theorem_linkage_slot_production_claim_boundary",
                "p1_selected_backend_proof_closure_artifact_rejects_theorem_linkage_slot_production_claim_boundary",
            ),
        ])
    );
}

#[test]
fn standard_verifier_bridge_fixture_digest_is_deterministic_nonzero_and_not_placeholder() {
    let fixture = standard_verifier_bridge_fixture();
    let derived = standard_verifier_bridge_digest();

    assert_eq!(
        derived,
        fixture.expected.standard_verifier_bridge_evidence_digest()
    );
    assert_ne!(derived, [0; 32]);
    assert_ne!(derived, digest(51));
}

#[test]
fn standard_verifier_bridge_fixture_package_digest_fails_loudly_on_drift() {
    assert_eq!(
        standard_verifier_bridge_fixture_package_digest(),
        decode_hex_array::<32>(EXPECTED_P1_STANDARD_VERIFIER_BRIDGE_FIXTURE_PACKAGE_DIGEST_HEX),
        "P1 standard-verifier bridge fixture package drifted; review fixture inputs, negative corpus, provider KAT/profile bindings, and non-claim docs before updating the digest"
    );
}

#[test]
fn real_recomputation_artifact_fixture_package_digest_fails_loudly_on_drift() {
    assert_eq!(
        real_recomputation_artifact_fixture_package_digest(),
        decode_hex_array::<32>(
            EXPECTED_P1_REAL_RECOMPUTATION_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX
        ),
        "P1 real recomputation artifact fixture drifted; review Criterion 2 source/review digests, predecessor certificate binding, negative cases, and non-claim docs before updating the digest"
    );
}

#[test]
fn threshold_output_certificate_artifact_fixture_package_digest_fails_loudly_on_drift() {
    assert_eq!(
        threshold_output_certificate_artifact_fixture_package_digest(),
        decode_hex_array::<32>(
            EXPECTED_P1_THRESHOLD_OUTPUT_CERTIFICATE_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX
        ),
        "P1 threshold-output certificate artifact fixture drifted; review Criterion 2 source package, certificate binding, typed slot digest, negative cases, and non-claim docs before updating the digest"
    );
}

#[test]
fn rejection_distribution_review_artifact_fixture_package_digest_fails_loudly_on_drift() {
    assert_eq!(
        rejection_distribution_review_artifact_fixture_package_digest(),
        decode_hex_array::<32>(
            EXPECTED_P1_REJECTION_DISTRIBUTION_REVIEW_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX
        ),
        "P1 rejection-distribution review artifact fixture drifted; review Criterion 2 source/review digests, typed slot digest, negative cases, and non-claim docs before updating the digest"
    );
}

#[test]
fn theorem_linkage_artifact_fixture_package_digest_fails_loudly_on_drift() {
    assert_eq!(
        theorem_linkage_artifact_fixture_package_digest(),
        decode_hex_array::<32>(EXPECTED_P1_THEOREM_LINKAGE_ARTIFACT_FIXTURE_PACKAGE_DIGEST_HEX),
        "P1 theorem-linkage artifact fixture drifted; review Criterion 2 source/review digests, typed slot digest, negative cases, and non-claim docs before updating the digest"
    );
}

#[test]
fn standard_verifier_bridge_fixture_negative_corpus_pins_expected_cases() {
    let fixture = standard_verifier_bridge_fixture();
    let names = fixture
        .negative_cases
        .iter()
        .map(|case| case.name.as_str())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        names,
        BTreeSet::from([
            "candidate_recomputed_signature_mismatch",
            "provider_rejection",
            "stale_selected_profile_binding",
            "stale_provider_kat_evidence_digest",
            "transcript_mismatch",
        ])
    );
    assert!(fixture
        .negative_cases
        .iter()
        .any(|case| case.expected_error == "TranscriptMismatch"));
    assert_eq!(
        derive_negative_test_corpus_digest(&fixture),
        fixture.expected.negative_test_corpus_digest()
    );
    assert_ne!(derive_negative_test_corpus_digest(&fixture), digest(47));
}

#[test]
fn standard_verifier_bridge_fixture_negative_cases_execute_expected_rejections() {
    let fixture = standard_verifier_bridge_fixture();
    for case in &fixture.negative_cases {
        match case.name.as_str() {
            "candidate_recomputed_signature_mismatch" => {
                let transcript = transcript_from_fixture(&fixture.transcript);
                let candidate_signature = ThresholdSignature([42; 3309]);
                let recomputed_signature = ThresholdSignature([43; 3309]);
                let recomputation = AggregateRecomputationTranscript::from_public_outputs(
                    &transcript,
                    &decode_hex(&fixture.recomputation.aggregate_response_hex),
                    &decode_hex(&fixture.recomputation.hint_hex),
                    &recomputed_signature,
                )
                .unwrap();

                assert_eq!(
                    case.candidate_signature_digest(),
                    signature_digest(&candidate_signature)
                );
                assert_eq!(
                    case.recomputed_signature_digest(),
                    *recomputation.recomputed_signature_digest()
                );
                assert_eq!(
                    case.transcript_binding_digest(),
                    *transcript.challenge_digest()
                );
                assert_eq!(
                    case.selected_profile_binding_digest(),
                    SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
                        .profile_binding_digest()
                );
                assert_eq!(
                    case.provider_kat_evidence_digest(),
                    provider_kat_fixture_digest()
                );

                let err = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<
                    AcceptingProvider,
                >(&transcript, &candidate_signature, &recomputation)
                .unwrap_err();
                assert_eq!(error_label(&err), case.expected_error);
            }
            "transcript_mismatch" => {
                let transcript = transcript_from_fixture(&fixture.transcript);
                let mismatched_transcript = transcript_with_session_id_fill_byte(10);
                let candidate_signature =
                    signature_from_fill_byte(fixture.recomputation.candidate_signature_fill_byte);
                let recomputation = AggregateRecomputationTranscript::from_public_outputs(
                    &mismatched_transcript,
                    &decode_hex(&fixture.recomputation.aggregate_response_hex),
                    &decode_hex(&fixture.recomputation.hint_hex),
                    &candidate_signature,
                )
                .unwrap();

                assert_eq!(
                    case.candidate_signature_digest(),
                    signature_digest(&candidate_signature)
                );
                assert_eq!(
                    case.recomputed_signature_digest(),
                    *recomputation.recomputed_signature_digest()
                );
                assert_eq!(
                    case.transcript_binding_digest(),
                    *mismatched_transcript.challenge_digest()
                );
                assert_eq!(
                    case.selected_profile_binding_digest(),
                    SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
                        .profile_binding_digest()
                );
                assert_eq!(
                    case.provider_kat_evidence_digest(),
                    provider_kat_fixture_digest()
                );

                let err = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<
                    AcceptingProvider,
                >(&transcript, &candidate_signature, &recomputation)
                .unwrap_err();
                assert_eq!(error_label(&err), case.expected_error);
            }
            "provider_rejection" => {
                let transcript = transcript_from_fixture(&fixture.transcript);
                let candidate_signature =
                    signature_from_fill_byte(fixture.recomputation.candidate_signature_fill_byte);
                let recomputation = AggregateRecomputationTranscript::from_public_outputs(
                    &transcript,
                    &decode_hex(&fixture.recomputation.aggregate_response_hex),
                    &decode_hex(&fixture.recomputation.hint_hex),
                    &candidate_signature,
                )
                .unwrap();

                assert_eq!(
                    case.candidate_signature_digest(),
                    signature_digest(&candidate_signature)
                );
                assert_eq!(
                    case.recomputed_signature_digest(),
                    *recomputation.recomputed_signature_digest()
                );
                assert_eq!(
                    case.transcript_binding_digest(),
                    *transcript.challenge_digest()
                );
                assert_eq!(
                    case.selected_profile_binding_digest(),
                    SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
                        .profile_binding_digest()
                );
                assert_eq!(
                    case.provider_kat_evidence_digest(),
                    provider_kat_fixture_digest()
                );

                let err = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<
                    RejectingProvider,
                >(&transcript, &candidate_signature, &recomputation)
                .unwrap_err();
                assert_eq!(error_label(&err), case.expected_error);
            }
            "stale_provider_kat_evidence_digest" => {
                let mut package = p1_recomputation_package();
                package.provider_kat_evidence = Mldsa65ProviderKatEvidence::new(
                    AcvpFips204EvidenceSource::NistAcvpServerFips204,
                    case.provider_kat_evidence_digest(),
                    digest(49),
                    digest(50),
                    true,
                );

                assert_ne!(
                    case.provider_kat_evidence_digest(),
                    provider_kat_fixture_digest()
                );
                assert_eq!(
                    case.candidate_signature_digest(),
                    fixture.expected.candidate_signature_digest()
                );
                assert_eq!(
                    case.recomputed_signature_digest(),
                    fixture.expected.recomputed_signature_digest()
                );
                assert_eq!(
                    case.transcript_binding_digest(),
                    fixture.expected.challenge_digest()
                );
                assert_eq!(
                    case.selected_profile_binding_digest(),
                    SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
                        .profile_binding_digest()
                );

                let assessment = assess_p1_aggregate_recomputation_closure(Some(package));
                assert_p1_invalid_reason(assessment, &case.expected_error);
            }
            "stale_selected_profile_binding" => {
                let mut package = p1_recomputation_package();
                package.proof_artifacts = P1RejectionProofArtifacts::new(
                    case.selected_profile_binding_digest(),
                    digest(41),
                    standard_verifier_bridge_digest(),
                    standard_verifier_bridge_fixture_package_digest(),
                    digest(43),
                    digest(44),
                    digest(45),
                    digest(46),
                    negative_test_corpus_digest(),
                    digest(48),
                    true,
                );

                assert_eq!(
                    case.provider_kat_evidence_digest(),
                    provider_kat_fixture_digest()
                );
                assert_eq!(
                    case.candidate_signature_digest(),
                    fixture.expected.candidate_signature_digest()
                );
                assert_eq!(
                    case.recomputed_signature_digest(),
                    fixture.expected.recomputed_signature_digest()
                );
                assert_eq!(
                    case.transcript_binding_digest(),
                    fixture.expected.challenge_digest()
                );
                assert_ne!(
                    case.selected_profile_binding_digest(),
                    SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
                        .profile_binding_digest()
                );

                let assessment = assess_p1_aggregate_recomputation_closure(Some(package));
                assert_p1_invalid_reason(assessment, &case.expected_error);
            }
            unknown => panic!("fixture contains unhandled negative case: {unknown}"),
        }
    }
}

#[test]
fn bridge_equivalence_rejects_failed_standard_verifier() {
    let transcript = transcript();
    let candidate_signature = ThresholdSignature([42; 3309]);
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        b"aggregate response bytes",
        b"hint bytes",
        &candidate_signature,
    )
    .unwrap();

    let err = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<RejectingProvider>(
        &transcript,
        &candidate_signature,
        &recomputation,
    )
    .unwrap_err();

    assert_eq!(err, ThresholdError::StandardVerificationFailed);
}

#[test]
fn bridge_equivalence_rejects_transcript_mismatch() {
    let transcript = transcript();
    let mismatched_transcript = transcript_with_session_id_fill_byte(10);
    let candidate_signature = ThresholdSignature([42; 3309]);
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &mismatched_transcript,
        b"aggregate response bytes",
        b"hint bytes",
        &candidate_signature,
    )
    .unwrap();

    let err = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<AcceptingProvider>(
        &transcript,
        &candidate_signature,
        &recomputation,
    )
    .unwrap_err();

    assert_eq!(err, ThresholdError::TranscriptMismatch);
}

#[test]
fn bridge_equivalence_rejects_recomputed_signature_mismatch() {
    let transcript = transcript();
    let candidate_signature = ThresholdSignature([42; 3309]);
    let recomputed_signature = ThresholdSignature([43; 3309]);
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        b"aggregate response bytes",
        b"hint bytes",
        &recomputed_signature,
    )
    .unwrap();

    let err = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<AcceptingProvider>(
        &transcript,
        &candidate_signature,
        &recomputation,
    )
    .unwrap_err();

    assert_eq!(err, ThresholdError::StandardVerificationFailed);
}

#[test]
fn complete_closure_package_exposes_closure_ready_status_without_production_claims() {
    let assessment = assess_rejection_equivalence_closure(Some(closure_package()));

    let certificate = assessment
        .closure_certificate()
        .expect("complete evidence should produce a closure certificate");
    assert!(assessment.is_closure_ready());
    assert_eq!(
        certificate.status(),
        AggregateRejectionClosureStatus::ClosureReady
    );
    assert_eq!(
        certificate.boundary(),
        AggregateRejectionConformanceBoundary::ClosureCandidate
    );
    assert_eq!(
        certificate.real_recomputation_evidence_digest(),
        &digest(41)
    );
    assert_eq!(
        certificate.standard_provider_kat_evidence_digest(),
        &provider_kat_fixture_digest()
    );
    assert_eq!(
        certificate.standard_verifier_bridge_evidence_digest(),
        &standard_verifier_bridge_digest()
    );
    assert_eq!(certificate.norm_bound_evidence_digest(), &digest(43));
    assert_eq!(certificate.hint_bound_evidence_digest(), &digest(44));
    assert_eq!(certificate.challenge_bound_evidence_digest(), &digest(45));
    assert_eq!(
        certificate.transcript_binding_evidence_digest(),
        &digest(46)
    );
    assert_eq!(
        certificate.negative_test_corpus_digest(),
        &negative_test_corpus_digest()
    );
    assert_eq!(certificate.external_review_digest(), &digest(48));
    assert!(!certificate.claims_production_verifier());
}

#[test]
fn closure_package_rejects_missing_real_recomputation_evidence() {
    let mut package = closure_package();
    package.real_recomputation_evidence = None;

    let assessment = assess_rejection_equivalence_closure(Some(package));

    assert_eq!(
        assessment,
        AggregateRejectionClosureAssessment::Missing {
            reason: "missing real aggregate recomputation evidence digest",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn closure_package_rejects_missing_standard_provider_kat_evidence() {
    let mut package = closure_package();
    package.standard_provider_kat_evidence = None;

    let assessment = assess_rejection_equivalence_closure(Some(package));

    assert_eq!(
        assessment,
        AggregateRejectionClosureAssessment::Missing {
            reason: "missing standard verifier provider KAT evidence digest",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn closure_package_rejects_wrong_kind_standard_provider_kat_evidence() {
    let mut package = closure_package();
    package.standard_provider_kat_evidence = Some(
        AggregateRejectionEvidenceDigest::real_recomputation(provider_kat_fixture_digest()),
    );

    let assessment = assess_rejection_equivalence_closure(Some(package));

    assert_eq!(
        assessment,
        AggregateRejectionClosureAssessment::Invalid {
            reason: "standard verifier provider KAT evidence has wrong artifact kind",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn closure_package_rejects_missing_standard_verifier_bridge_evidence() {
    let mut package = closure_package();
    package.standard_verifier_bridge_evidence = None;

    let assessment = assess_rejection_equivalence_closure(Some(package));

    assert_eq!(
        assessment,
        AggregateRejectionClosureAssessment::Missing {
            reason: "missing standard verifier bridge evidence digest",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn closure_package_rejects_scaffold_recomputation_evidence() {
    let mut package = closure_package();
    package.real_recomputation_evidence =
        Some(AggregateRejectionEvidenceDigest::scaffold_only(digest(41)));

    let assessment = assess_rejection_equivalence_closure(Some(package));

    assert_eq!(
        assessment,
        AggregateRejectionClosureAssessment::Invalid {
            reason: "real aggregate recomputation evidence must not be scaffold-only",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn closure_package_rejects_scaffold_provider_kat_evidence() {
    let mut package = closure_package();
    package.standard_provider_kat_evidence =
        Some(AggregateRejectionEvidenceDigest::scaffold_only(digest(42)));

    let assessment = assess_rejection_equivalence_closure(Some(package));

    assert_eq!(
        assessment,
        AggregateRejectionClosureAssessment::Invalid {
            reason: "standard verifier provider KAT evidence must not be scaffold-only",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn closure_package_rejects_missing_bound_evidence() {
    let mut package = closure_package();
    package.challenge_bound_evidence = None;

    let assessment = assess_rejection_equivalence_closure(Some(package));

    assert_eq!(
        assessment,
        AggregateRejectionClosureAssessment::Missing {
            reason: "missing challenge bound evidence digest",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn closure_package_rejects_zero_external_review_digest() {
    let mut package = closure_package();
    package.external_review_evidence =
        Some(AggregateRejectionEvidenceDigest::external_review(digest(0)));

    let assessment = assess_rejection_equivalence_closure(Some(package));

    assert_eq!(
        assessment,
        AggregateRejectionClosureAssessment::Invalid {
            reason: "external review digest is all zero",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn closure_package_rejects_scaffold_conformance_boundary() {
    let mut package = closure_package();
    package.boundary = AggregateRejectionConformanceBoundary::ScaffoldOnly;

    let assessment = assess_rejection_equivalence_closure(Some(package));

    assert_eq!(
        assessment,
        AggregateRejectionClosureAssessment::Invalid {
            reason: "closure package must use the closure-candidate conformance boundary",
        }
    );
    assert!(!assessment.is_closure_ready());
}

fn provider_kat_evidence(source: AcvpFips204EvidenceSource) -> Mldsa65ProviderKatEvidence {
    Mldsa65ProviderKatEvidence::new(
        source,
        provider_kat_fixture_digest(),
        digest(49),
        AcceptingProvider::provider_identity_digest(),
        true,
    )
}

fn proof_artifacts() -> P1RejectionProofArtifacts {
    P1RejectionProofArtifacts::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        digest(41),
        standard_verifier_bridge_digest(),
        standard_verifier_bridge_fixture_package_digest(),
        digest(43),
        digest(44),
        digest(45),
        digest(46),
        negative_test_corpus_digest(),
        digest(48),
        true,
    )
}

fn p1_recomputation_package() -> P1AggregateRecomputationClosurePackage {
    P1AggregateRecomputationClosurePackage::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1(),
        closure_package(),
        provider_kat_evidence(AcvpFips204EvidenceSource::NistAcvpServerFips204),
        proof_artifacts(),
    )
}

fn p1_recomputation_certificate() -> P1AggregateRecomputationClosureCertificate {
    match assess_p1_aggregate_recomputation_closure(Some(p1_recomputation_package())) {
        P1AggregateRecomputationAssessment::ArtifactReady(certificate) => certificate,
        other => panic!("expected P1 recomputation certificate, got {other:?}"),
    }
}

#[cfg(feature = "hazmat-real-mldsa")]
fn p1_recomputation_certificate_for_output(
    standard_verifier_bridge_evidence_digest: [u8; 32],
    real_recomputation_evidence_digest: [u8; 32],
) -> P1AggregateRecomputationClosureCertificate {
    let closure_package = AggregateRejectionClosurePackage::new(
        AggregateRejectionConformanceBoundary::ClosureCandidate,
        Some(AggregateRejectionEvidenceDigest::real_recomputation(
            real_recomputation_evidence_digest,
        )),
        Some(AggregateRejectionEvidenceDigest::standard_provider_kat(
            provider_kat_fixture_digest(),
        )),
        Some(AggregateRejectionEvidenceDigest::standard_verifier_bridge(
            standard_verifier_bridge_evidence_digest,
        )),
        Some(AggregateRejectionEvidenceDigest::norm_bound(digest(43))),
        Some(AggregateRejectionEvidenceDigest::hint_bound(digest(44))),
        Some(AggregateRejectionEvidenceDigest::challenge_bound(digest(
            45,
        ))),
        Some(AggregateRejectionEvidenceDigest::transcript_binding(
            digest(46),
        )),
        Some(AggregateRejectionEvidenceDigest::negative_test_corpus(
            negative_test_corpus_digest(),
        )),
        Some(AggregateRejectionEvidenceDigest::external_review(digest(
            48,
        ))),
    );
    let proof_artifacts = P1RejectionProofArtifacts::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        real_recomputation_evidence_digest,
        standard_verifier_bridge_evidence_digest,
        standard_verifier_bridge_fixture_package_digest(),
        digest(43),
        digest(44),
        digest(45),
        digest(46),
        negative_test_corpus_digest(),
        digest(48),
        true,
    );
    let package = P1AggregateRecomputationClosurePackage::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1(),
        closure_package,
        provider_kat_evidence(AcvpFips204EvidenceSource::NistAcvpServerFips204),
        proof_artifacts,
    );

    match assess_p1_aggregate_recomputation_closure(Some(package)) {
        P1AggregateRecomputationAssessment::ArtifactReady(certificate) => certificate,
        other => panic!("expected real-output P1 recomputation certificate, got {other:?}"),
    }
}

fn fixture_recomputation_transcript(
    fixture: &P1StandardVerifierBridgeFixture,
) -> AggregateRecomputationTranscript {
    let transcript = transcript_from_fixture(&fixture.transcript);
    let recomputed_signature =
        signature_from_fill_byte(fixture.recomputation.recomputed_signature_fill_byte);

    AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        &decode_hex(&fixture.recomputation.aggregate_response_hex),
        &decode_hex(&fixture.recomputation.hint_hex),
        &recomputed_signature,
    )
    .unwrap()
}

fn accepted_aggregate_from_fixture(
    fixture: &P1StandardVerifierBridgeFixture,
) -> AcceptedAggregateCandidate {
    accepted_aggregate_from_fixture_with_digests(
        fixture,
        fixture.expected.aggregate_response_digest(),
        fixture.expected.hint_digest(),
    )
}

fn accepted_aggregate_from_fixture_with_digests(
    fixture: &P1StandardVerifierBridgeFixture,
    aggregate_response_digest: [u8; 32],
    hint_digest: [u8; 32],
) -> AcceptedAggregateCandidate {
    let transcript = transcript_from_fixture(&fixture.transcript);
    let partials = fixture
        .transcript
        .commitment_digests
        .iter()
        .enumerate()
        .map(|(index, commitment)| {
            LocalAccept::accept(
                &transcript,
                LocalAcceptEvidence {
                    signer: ValidatorId(commitment.validator),
                    commitment_digest: CommitmentDigest([commitment.digest_fill_byte; 32]),
                    partial_share_digest: [(21 + index) as u8; 32],
                    local_bounds_proof_digest: [(31 + index) as u8; 32],
                },
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let candidate_signature =
        signature_from_fill_byte(fixture.recomputation.candidate_signature_fill_byte);
    let evidence = AggregateAcceptEvidence {
        aggregate_response_digest,
        hint_digest,
        standard_verifier: StandardVerifierEvidence::verify::<AcceptingProvider>(
            &transcript,
            &candidate_signature,
        )
        .unwrap(),
    };

    AggregateAccept::accept(&transcript, &partials, evidence).unwrap()
}

fn selected_backend_aggregate_artifact_package(
    fixture: &P1StandardVerifierBridgeFixture,
) -> P1SelectedBackendAggregateArtifactPackage {
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(fixture);

    P1SelectedBackendAggregateArtifactPackage::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1(),
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        provider_kat_fixture_digest(),
        standard_verifier_bridge_digest(),
        digest(41),
        derive_p1_selected_backend_transcript_binding_digest(&transcript),
        derive_p1_selected_backend_signer_set_digest(accepted_aggregate.signers()),
        derive_p1_selected_backend_attempt_binding_digest(&transcript),
        *accepted_aggregate.aggregate_response_digest(),
        *accepted_aggregate.hint_digest(),
        *accepted_aggregate.candidate_signature_digest(),
        true,
    )
}

fn selected_backend_aggregate_artifact_certificate(
    fixture: &P1StandardVerifierBridgeFixture,
) -> P1SelectedBackendAggregateArtifactCertificate {
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(fixture);
    let recomputation = fixture_recomputation_transcript(fixture);
    let recomputation_certificate = p1_recomputation_certificate();

    assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(selected_backend_aggregate_artifact_package(fixture)),
    )
    .artifact_certificate()
    .copied()
    .expect("complete selected-backend aggregate artifact should produce a certificate")
}

const DEFAULT_THRESHOLD_OUTPUT_SOURCE_PACKAGE: &[u8] =
    b"coordinator-assisted threshold-output transcript package v1";

fn threshold_output_evidence_source_with_bytes(
    fixture: &P1StandardVerifierBridgeFixture,
    source_package_bytes: &[u8],
) -> P1ThresholdOutputEvidenceSource {
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(fixture);
    let recomputation = fixture_recomputation_transcript(fixture);
    let source_package_digest =
        derive_p1_selected_backend_threshold_output_source_package_digest(source_package_bytes);

    P1ThresholdOutputEvidenceSource::selected_backend_candidate(
        derive_p1_selected_backend_threshold_output_source_digest(
            &transcript,
            &accepted_aggregate,
            &recomputation,
            source_package_bytes,
        ),
        source_package_digest,
        true,
    )
}

fn threshold_output_evidence_source(
    fixture: &P1StandardVerifierBridgeFixture,
) -> P1ThresholdOutputEvidenceSource {
    threshold_output_evidence_source_with_bytes(fixture, DEFAULT_THRESHOLD_OUTPUT_SOURCE_PACKAGE)
}

fn selected_backend_threshold_output_artifact_package_with_source_bytes(
    fixture: &P1StandardVerifierBridgeFixture,
    source_package_bytes: &[u8],
) -> P1SelectedBackendThresholdOutputArtifactPackage {
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(fixture);
    let recomputation = fixture_recomputation_transcript(fixture);
    let aggregate_certificate = selected_backend_aggregate_artifact_certificate(fixture);
    let source = threshold_output_evidence_source_with_bytes(fixture, source_package_bytes);

    derive_p1_selected_backend_threshold_output_artifact_package(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        source,
        P1ThresholdOutputClaimBoundary::ProofReviewOnly,
        true,
    )
    .expect("selected-backend threshold output artifact should derive from bound evidence")
}

fn selected_backend_threshold_output_artifact_package(
    fixture: &P1StandardVerifierBridgeFixture,
) -> P1SelectedBackendThresholdOutputArtifactPackage {
    selected_backend_threshold_output_artifact_package_with_source_bytes(
        fixture,
        DEFAULT_THRESHOLD_OUTPUT_SOURCE_PACKAGE,
    )
}

fn selected_backend_threshold_output_artifact_certificate(
    fixture: &P1StandardVerifierBridgeFixture,
) -> P1SelectedBackendThresholdOutputArtifactCertificate {
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(fixture);
    let recomputation = fixture_recomputation_transcript(fixture);
    let aggregate_certificate = selected_backend_aggregate_artifact_certificate(fixture);
    let package = selected_backend_threshold_output_artifact_package(fixture);

    assess_p1_selected_backend_threshold_output_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        Some(package),
    )
    .threshold_output_certificate()
    .copied()
    .expect("complete selected-backend threshold-output artifact should produce a certificate")
}

fn selected_backend_proof_closure_artifact_package(
    fixture: &P1StandardVerifierBridgeFixture,
) -> P1SelectedBackendProofClosureArtifactPackage {
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(fixture);
    let proof_artifacts = P1RejectionProofArtifacts::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        *threshold_certificate.real_recomputation_evidence_digest(),
        *threshold_certificate.standard_verifier_bridge_evidence_digest(),
        standard_verifier_bridge_fixture_package_digest(),
        digest(43),
        digest(44),
        digest(45),
        *threshold_certificate.transcript_binding_digest(),
        negative_test_corpus_digest(),
        digest(48),
        true,
    );
    let proof_slot_artifacts = derive_p1_criterion2_proof_slot_artifacts(
        &threshold_certificate,
        &proof_artifacts,
        digest(51),
        digest(52),
        digest(54),
        P1SelectedBackendProofClosureClaimBoundary::ProofReviewOnly,
        true,
    );

    derive_p1_selected_backend_proof_closure_artifact_package(
        &threshold_certificate,
        *threshold_certificate.provider_kat_evidence_digest(),
        proof_artifacts,
        proof_slot_artifacts,
        &compatibility_certificate,
        P1SelectedBackendProofClosureClaimBoundary::ProofReviewOnly,
        true,
    )
}

fn standard_verifier_compatibility_artifact_package(
    fixture: &P1StandardVerifierBridgeFixture,
) -> P1StandardVerifierCompatibilityArtifactPackage {
    let transcript = transcript_from_fixture(&fixture.transcript);
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(fixture);
    let candidate_signature =
        signature_from_fill_byte(fixture.recomputation.candidate_signature_fill_byte);
    derive_p1_standard_verifier_compatibility_artifact_package::<AcceptingProvider>(
        &transcript,
        &threshold_certificate,
        &candidate_signature,
        P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly,
        true,
    )
    .expect("accepted selected-backend output should derive compatibility artifact")
}

fn standard_verifier_compatibility_artifact_certificate(
    fixture: &P1StandardVerifierBridgeFixture,
) -> lattice_aggregation::production::rejection_equivalence::P1StandardVerifierCompatibilityArtifactCertificate
{
    let transcript = transcript_from_fixture(&fixture.transcript);
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(fixture);
    let package = standard_verifier_compatibility_artifact_package(fixture);

    assess_p1_standard_verifier_compatibility_artifact(
        &transcript,
        &threshold_certificate,
        Some(package),
    )
    .standard_verifier_compatibility_certificate()
    .copied()
    .expect("reviewed standard-verifier compatibility artifact should produce a certificate")
}

fn real_threshold_verifier_closure_package(
    fixture: &P1StandardVerifierBridgeFixture,
) -> P1RealThresholdVerifierClosurePackage {
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(fixture);

    P1RealThresholdVerifierClosurePackage {
        selected_profile: SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1(),
        selected_profile_binding_digest:
            SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
                .profile_binding_digest(),
        validator_count: 10_000,
        threshold: 6_667,
        aggregate_signature_len: MLDSA65_SIGNATURE_BYTES,
        backend_evidence: P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa,
        backend_evidence_digest: digest(77),
        threshold_output_certificate_digest:
            derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate),
        standard_verifier_compatibility_artifact_digest:
            derive_p1_standard_verifier_compatibility_artifact_digest(&compatibility_certificate),
        verifier_result: P1StandardVerifierCompatibilityResult::Accept,
        mutated_message_rejected: true,
        mutated_public_key_rejected: true,
        mutated_signature_rejected: true,
        claim_boundary: P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        reviewed: true,
    }
}

fn real_threshold_backend_emission_artifact_package(
    fixture: &P1StandardVerifierBridgeFixture,
) -> P1RealThresholdBackendEmissionArtifactPackage {
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(fixture);

    derive_p1_real_threshold_backend_emission_artifact_package(
        &threshold_certificate,
        &compatibility_certificate,
        P1RealThresholdVerifierClosureBackendEvidence::RealThresholdMldsa,
        digest(77),
        digest(78),
        digest(79),
        digest(80),
        true,
        true,
        true,
        P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        true,
    )
}

fn digest_fixture_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn real_threshold_backend_evidence_digest(
    fixture: &P1RealThresholdBackendEmissionArtifactFixture,
) -> [u8; 32] {
    let source_digest = digest_fixture_bytes(
        b"lattice-aggregation:p1-real-threshold-backend-source-package:v1",
        fixture.capture.backend_source_package.bytes(),
    );
    let implementation_digest = digest_fixture_bytes(
        b"lattice-aggregation:p1-real-threshold-backend-implementation:v1",
        fixture.capture.backend_implementation.bytes(),
    );
    let transcript_digest = digest_fixture_bytes(
        b"lattice-aggregation:p1-real-threshold-backend-transcript:v1",
        fixture.capture.backend_transcript.bytes(),
    );
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-real-threshold-backend-evidence:v1");
    hasher.update(source_digest);
    hasher.update(implementation_digest);
    hasher.update(transcript_digest);
    hasher.finalize().into()
}

#[cfg(feature = "hazmat-real-mldsa")]
fn standard_provider_single_key_backend_evidence_digest(
    fixture: &P1StandardProviderSingleKeyEmissionArtifactFixture,
) -> [u8; 32] {
    let source_digest = digest_fixture_bytes(
        b"lattice-aggregation:p1-standard-provider-single-key-source-package:v1",
        fixture.capture.backend_source_package.bytes(),
    );
    let implementation_digest = digest_fixture_bytes(
        b"lattice-aggregation:p1-standard-provider-single-key-implementation:v1",
        fixture.capture.backend_implementation.bytes(),
    );
    let transcript_digest = digest_fixture_bytes(
        b"lattice-aggregation:p1-standard-provider-single-key-transcript:v1",
        fixture.capture.backend_transcript.bytes(),
    );
    let public_key_digest = digest_fixture_bytes(
        b"lattice-aggregation:p1-standard-provider-single-key-public-key:v1",
        &decode_hex(&fixture.capture.public_key_hex),
    );
    let message_digest = digest_fixture_bytes(
        b"lattice-aggregation:p1-standard-provider-single-key-message:v1",
        fixture.capture.message.bytes(),
    );
    let signature_digest = digest_fixture_bytes(
        b"lattice-aggregation:p1-standard-provider-single-key-signature:v1",
        &decode_hex(&fixture.capture.signature_hex),
    );
    let mut hasher = Sha3_256::new();
    hasher.update(b"lattice-aggregation:p1-standard-provider-single-key-emission-evidence:v1");
    hasher.update(source_digest);
    hasher.update(implementation_digest);
    hasher.update(transcript_digest);
    hasher.update(public_key_digest);
    hasher.update(message_digest);
    hasher.update(signature_digest);
    hasher.update([fixture.capture.mutated_message_rejected as u8]);
    hasher.update([fixture.capture.mutated_public_key_rejected as u8]);
    hasher.update([fixture.capture.mutated_signature_rejected as u8]);
    hasher.finalize().into()
}

fn real_threshold_backend_emission_artifact_package_from_fixture(
    emission_fixture: &P1RealThresholdBackendEmissionArtifactFixture,
    bridge_fixture: &P1StandardVerifierBridgeFixture,
) -> P1RealThresholdBackendEmissionArtifactPackage {
    let threshold_certificate =
        selected_backend_threshold_output_artifact_certificate(bridge_fixture);
    let compatibility_certificate =
        standard_verifier_compatibility_artifact_certificate(bridge_fixture);
    assert_eq!(emission_fixture.capture.validator_count, 10_000);
    assert_eq!(emission_fixture.capture.threshold, 6_667);
    assert_eq!(
        emission_fixture.capture.aggregate_signature_len,
        MLDSA65_SIGNATURE_BYTES
    );
    derive_p1_real_threshold_backend_emission_artifact_package(
        &threshold_certificate,
        &compatibility_certificate,
        P1RealThresholdVerifierClosureBackendEvidence::FixtureHarness,
        real_threshold_backend_evidence_digest(emission_fixture),
        digest_fixture_bytes(
            b"lattice-aggregation:p1-real-threshold-backend-source-package:v1",
            emission_fixture.capture.backend_source_package.bytes(),
        ),
        digest_fixture_bytes(
            b"lattice-aggregation:p1-real-threshold-backend-implementation:v1",
            emission_fixture.capture.backend_implementation.bytes(),
        ),
        digest_fixture_bytes(
            b"lattice-aggregation:p1-real-threshold-backend-transcript:v1",
            emission_fixture.capture.backend_transcript.bytes(),
        ),
        emission_fixture.capture.mutated_message_rejected,
        emission_fixture.capture.mutated_public_key_rejected,
        emission_fixture.capture.mutated_signature_rejected,
        P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        emission_fixture.capture.reviewed,
    )
}

#[cfg(feature = "hazmat-real-mldsa")]
fn standard_provider_single_key_emission_artifact_package_from_fixture(
    emission_fixture: &P1StandardProviderSingleKeyEmissionArtifactFixture,
    threshold_certificate: &P1SelectedBackendThresholdOutputArtifactCertificate,
    compatibility_certificate: &lattice_aggregation::production::rejection_equivalence::P1StandardVerifierCompatibilityArtifactCertificate,
) -> P1RealThresholdBackendEmissionArtifactPackage {
    assert_eq!(emission_fixture.capture.validator_count, 10_000);
    assert_eq!(emission_fixture.capture.threshold, 6_667);
    assert_eq!(
        emission_fixture.capture.aggregate_signature_len,
        MLDSA65_SIGNATURE_BYTES
    );
    derive_p1_real_threshold_backend_emission_artifact_package(
        threshold_certificate,
        compatibility_certificate,
        P1RealThresholdVerifierClosureBackendEvidence::StandardProviderSingleKey,
        standard_provider_single_key_backend_evidence_digest(emission_fixture),
        digest_fixture_bytes(
            b"lattice-aggregation:p1-standard-provider-single-key-source-package:v1",
            emission_fixture.capture.backend_source_package.bytes(),
        ),
        digest_fixture_bytes(
            b"lattice-aggregation:p1-standard-provider-single-key-implementation:v1",
            emission_fixture.capture.backend_implementation.bytes(),
        ),
        digest_fixture_bytes(
            b"lattice-aggregation:p1-standard-provider-single-key-transcript:v1",
            emission_fixture.capture.backend_transcript.bytes(),
        ),
        emission_fixture.capture.mutated_message_rejected,
        emission_fixture.capture.mutated_public_key_rejected,
        emission_fixture.capture.mutated_signature_rejected,
        P1RealThresholdVerifierClosureClaimBoundary::ProofReviewOnly,
        emission_fixture.capture.reviewed,
    )
}

#[test]
fn p1_recomputation_closure_accepts_selected_profile_kat_and_proof_artifacts() {
    let assessment = assess_p1_aggregate_recomputation_closure(Some(p1_recomputation_package()));

    let certificate = assessment
        .closure_certificate()
        .expect("complete P1 artifact package should produce a certificate");
    assert!(assessment.is_artifact_ready());
    assert_eq!(
        certificate.selected_profile(),
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    );
    assert_eq!(
        certificate.provider_kat_source(),
        AcvpFips204EvidenceSource::NistAcvpServerFips204
    );
    assert_eq!(
        certificate.provider_kat_evidence_digest(),
        &provider_kat_fixture_digest()
    );
    assert_eq!(certificate.acvp_vector_set_digest(), &digest(49));
    assert_eq!(
        certificate.provider_identity_digest(),
        &AcceptingProvider::provider_identity_digest()
    );
    assert_eq!(
        certificate.real_recomputation_evidence_digest(),
        &digest(41)
    );
    assert_eq!(
        certificate.selected_profile_binding_digest(),
        &SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest()
    );
    assert_eq!(
        certificate.standard_verifier_bridge_evidence_digest(),
        &standard_verifier_bridge_digest()
    );
    assert_eq!(
        certificate.standard_verifier_bridge_fixture_package_digest(),
        &standard_verifier_bridge_fixture_package_digest()
    );
    assert!(!certificate.claims_fips_validation());
    assert!(!certificate.claims_production_approval());
    assert!(!certificate.claims_standard_verifier_compatibility());
}

#[test]
fn p1_recomputation_closure_rejects_zero_bridge_fixture_package_digest() {
    let mut package = p1_recomputation_package();
    package.proof_artifacts = P1RejectionProofArtifacts::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        digest(41),
        standard_verifier_bridge_digest(),
        [0; 32],
        digest(43),
        digest(44),
        digest(45),
        digest(46),
        negative_test_corpus_digest(),
        digest(48),
        true,
    );

    assert_p1_invalid_reason(
        assess_p1_aggregate_recomputation_closure(Some(package)),
        "P1 standard verifier bridge fixture package digest is all zero",
    );
}

#[test]
fn p1_selected_backend_aggregate_artifact_accepts_bound_acceptance_and_recomputation() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let recomputation_certificate = p1_recomputation_certificate();

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(selected_backend_aggregate_artifact_package(&fixture)),
    );

    let certificate = assessment
        .artifact_certificate()
        .expect("complete selected-backend aggregate artifact should produce a certificate");
    assert!(assessment.is_artifact_ready());
    assert_eq!(
        certificate.selected_profile(),
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    );
    assert_eq!(
        certificate.signer_set_digest(),
        &derive_p1_selected_backend_signer_set_digest(accepted_aggregate.signers())
    );
    assert_eq!(
        certificate.selected_profile_binding_digest(),
        &SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest()
    );
    assert_eq!(
        certificate.provider_kat_evidence_digest(),
        &provider_kat_fixture_digest()
    );
    assert_eq!(
        certificate.standard_verifier_bridge_evidence_digest(),
        &standard_verifier_bridge_digest()
    );
    assert_eq!(
        certificate.real_recomputation_evidence_digest(),
        &digest(41)
    );
    assert_eq!(
        certificate.attempt_binding_digest(),
        &derive_p1_selected_backend_attempt_binding_digest(&transcript)
    );
    assert_eq!(
        certificate.transcript_binding_digest(),
        &derive_p1_selected_backend_transcript_binding_digest(&transcript)
    );
    assert_eq!(
        certificate.accepted_signature_digest(),
        accepted_aggregate.candidate_signature_digest()
    );
    assert_eq!(
        certificate.aggregate_response_digest(),
        accepted_aggregate.aggregate_response_digest()
    );
    assert_eq!(certificate.hint_digest(), accepted_aggregate.hint_digest());
    assert!(!certificate.claims_selected_backend_production());
    assert!(!certificate.claims_standard_verifier_compatibility());
    assert!(!certificate.claims_completed_cryptographic_proof());
}

#[cfg(feature = "hazmat-real-mldsa")]
#[test]
fn p1_selected_backend_aggregate_artifact_accepts_real_mldsa_output_package() {
    use lattice_aggregation::production::provider::HazmatMldsa65Provider;
    use ml_dsa::{Keypair, MlDsa65, SignatureEncoding, Signer, SigningKey};

    let seed = [0x5a; 32].into();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let message = b"real selected-backend aggregate output package";
    let public_key = threshold_public_key_from(&signing_key.verifying_key().encode());
    let signature = threshold_signature_from(&signing_key.sign(message).to_bytes());
    let transcript = real_mldsa_transcript(public_key, message);
    let partials = real_mldsa_accepted_partials(&transcript);
    let verifier =
        StandardVerifierEvidence::verify::<HazmatMldsa65Provider>(&transcript, &signature)
            .expect("real ML-DSA signature should verify through the selected provider");
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        b"real selected-backend aggregate response bytes",
        b"real selected-backend hint bytes",
        &signature,
    )
    .expect("real output recomputation transcript should be derivable from public outputs");
    let bridge_evidence = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<
        HazmatMldsa65Provider,
    >(&transcript, &signature, &recomputation)
    .expect("real output should satisfy provider/recomputation bridge evidence");
    let standard_verifier_bridge_evidence_digest = derive_standard_verifier_bridge_evidence_digest(
        &SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        &provider_kat_fixture_digest(),
        &bridge_evidence,
    )
    .expect("real output bridge evidence should derive a bridge digest");
    let real_recomputation_evidence_digest =
        derive_p1_real_recomputation_evidence_digest(&recomputation);
    let accepted_aggregate = AggregateAccept::accept(
        &transcript,
        &partials,
        AggregateAcceptEvidence {
            aggregate_response_digest: *recomputation.aggregate_response_digest(),
            hint_digest: *recomputation.hint_digest(),
            standard_verifier: verifier,
        },
    )
    .expect("real selected-backend aggregate output should pass AggregateAccept");
    let recomputation_certificate = p1_recomputation_certificate_for_output(
        standard_verifier_bridge_evidence_digest,
        real_recomputation_evidence_digest,
    );

    let package = derive_p1_selected_backend_aggregate_artifact_package::<HazmatMldsa65Provider>(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        &signature,
        true,
    )
    .expect("real selected-backend package should derive from verified provider output");
    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(package),
    );

    let certificate = assessment
        .artifact_certificate()
        .expect("real selected-backend artifact package should produce a certificate");
    assert!(assessment.is_artifact_ready());
    assert_eq!(
        certificate.accepted_signature_digest(),
        verifier.candidate_signature_digest()
    );
    assert_eq!(
        certificate.aggregate_response_digest(),
        accepted_aggregate.aggregate_response_digest()
    );
    assert_eq!(
        certificate.standard_verifier_bridge_evidence_digest(),
        &derive_standard_verifier_bridge_evidence_digest(
            certificate.selected_profile_binding_digest(),
            certificate.provider_kat_evidence_digest(),
            &bridge_evidence,
        )
        .unwrap()
    );
    assert!(!certificate.claims_selected_backend_production());
    assert!(!certificate.claims_standard_verifier_compatibility());
    assert!(!certificate.claims_completed_cryptographic_proof());
}

#[cfg(feature = "hazmat-real-mldsa")]
#[test]
fn p1_selected_backend_threshold_output_artifact_accepts_real_mldsa_package() {
    use lattice_aggregation::production::provider::HazmatMldsa65Provider;
    use ml_dsa::{Keypair, MlDsa65, SignatureEncoding, Signer, SigningKey};

    let seed = [0x7c; 32].into();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let message = b"real selected-backend threshold output artifact package";
    let public_key = threshold_public_key_from(&signing_key.verifying_key().encode());
    let signature = threshold_signature_from(&signing_key.sign(message).to_bytes());
    let transcript = real_mldsa_transcript(public_key, message);
    let partials = real_mldsa_accepted_partials(&transcript);
    let verifier =
        StandardVerifierEvidence::verify::<HazmatMldsa65Provider>(&transcript, &signature)
            .expect("real ML-DSA signature should verify through the selected provider");
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        b"real selected-backend threshold output aggregate response bytes",
        b"real selected-backend threshold output hint bytes",
        &signature,
    )
    .expect("real threshold-output recomputation transcript should be derivable");
    let bridge_evidence = AggregateRejectionEquivalenceGate::verify_recomputed_bridge::<
        HazmatMldsa65Provider,
    >(&transcript, &signature, &recomputation)
    .expect("real output should satisfy provider/recomputation bridge evidence");
    let standard_verifier_bridge_evidence_digest = derive_standard_verifier_bridge_evidence_digest(
        &SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        &provider_kat_fixture_digest(),
        &bridge_evidence,
    )
    .expect("real output bridge evidence should derive a bridge digest");
    let real_recomputation_evidence_digest =
        derive_p1_real_recomputation_evidence_digest(&recomputation);
    let accepted_aggregate = AggregateAccept::accept(
        &transcript,
        &partials,
        AggregateAcceptEvidence {
            aggregate_response_digest: *recomputation.aggregate_response_digest(),
            hint_digest: *recomputation.hint_digest(),
            standard_verifier: verifier,
        },
    )
    .expect("real selected-backend threshold output should pass AggregateAccept");
    let recomputation_certificate = p1_recomputation_certificate_for_output(
        standard_verifier_bridge_evidence_digest,
        real_recomputation_evidence_digest,
    );
    let aggregate_package =
        derive_p1_selected_backend_aggregate_artifact_package::<HazmatMldsa65Provider>(
            &transcript,
            &accepted_aggregate,
            &recomputation,
            &recomputation_certificate,
            &signature,
            true,
        )
        .expect("real aggregate artifact package should derive before threshold-output wrap");
    let aggregate_certificate = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(aggregate_package),
    )
    .artifact_certificate()
    .copied()
    .expect("real aggregate artifact should produce a certificate");
    let source = P1ThresholdOutputEvidenceSource::selected_backend_candidate(
        derive_p1_selected_backend_threshold_output_source_digest(
            &transcript,
            &accepted_aggregate,
            &recomputation,
            DEFAULT_THRESHOLD_OUTPUT_SOURCE_PACKAGE,
        ),
        derive_p1_selected_backend_threshold_output_source_package_digest(
            DEFAULT_THRESHOLD_OUTPUT_SOURCE_PACKAGE,
        ),
        true,
    );
    let threshold_package = derive_p1_selected_backend_threshold_output_artifact_package(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        source,
        P1ThresholdOutputClaimBoundary::ProofReviewOnly,
        true,
    )
    .expect("real threshold-output package should derive from bound aggregate evidence");
    let assessment = assess_p1_selected_backend_threshold_output_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        Some(threshold_package),
    );

    let certificate = assessment
        .threshold_output_certificate()
        .expect("real threshold-output artifact package should produce a certificate");
    assert!(assessment.is_artifact_ready());
    assert_eq!(
        certificate.aggregate_artifact_digest(),
        &derive_p1_selected_backend_aggregate_certificate_digest(&aggregate_certificate)
    );
    assert_eq!(
        certificate.accepted_signature_digest(),
        verifier.candidate_signature_digest()
    );
    assert_eq!(
        certificate.standard_verifier_bridge_evidence_digest(),
        aggregate_certificate.standard_verifier_bridge_evidence_digest()
    );
    assert_eq!(
        certificate.real_recomputation_evidence_digest(),
        aggregate_certificate.real_recomputation_evidence_digest()
    );
    assert_eq!(
        certificate.claim_boundary(),
        P1ThresholdOutputClaimBoundary::ProofReviewOnly
    );
    assert!(!certificate.claims_real_threshold_signer());
    assert!(!certificate.claims_selected_backend_production());
    assert!(!certificate.claims_standard_verifier_compatibility());
    assert!(!certificate.claims_completed_cryptographic_proof());
}

#[cfg(feature = "hazmat-real-mldsa")]
#[test]
fn p1_selected_backend_aggregate_artifact_deriver_rejects_stale_recomputation_output() {
    use lattice_aggregation::production::provider::HazmatMldsa65Provider;
    use ml_dsa::{Keypair, MlDsa65, SignatureEncoding, Signer, SigningKey};

    let seed = [0x6b; 32].into();
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let message = b"real selected-backend stale recomputation rejection";
    let public_key = threshold_public_key_from(&signing_key.verifying_key().encode());
    let signature = threshold_signature_from(&signing_key.sign(message).to_bytes());
    let mut stale_signature = signature.clone();
    stale_signature.0[0] ^= 0x01;
    let transcript = real_mldsa_transcript(public_key, message);
    let partials = real_mldsa_accepted_partials(&transcript);
    let verifier =
        StandardVerifierEvidence::verify::<HazmatMldsa65Provider>(&transcript, &signature)
            .expect("real ML-DSA signature should verify through the selected provider");
    let accepted_recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        b"real selected-backend aggregate response bytes",
        b"real selected-backend hint bytes",
        &signature,
    )
    .unwrap();
    let stale_recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        b"real selected-backend aggregate response bytes",
        b"real selected-backend hint bytes",
        &stale_signature,
    )
    .unwrap();
    let accepted_aggregate = AggregateAccept::accept(
        &transcript,
        &partials,
        AggregateAcceptEvidence {
            aggregate_response_digest: *accepted_recomputation.aggregate_response_digest(),
            hint_digest: *accepted_recomputation.hint_digest(),
            standard_verifier: verifier,
        },
    )
    .expect("real selected-backend aggregate output should pass AggregateAccept");

    let err = derive_p1_selected_backend_aggregate_artifact_package::<HazmatMldsa65Provider>(
        &transcript,
        &accepted_aggregate,
        &stale_recomputation,
        &p1_recomputation_certificate(),
        &signature,
        true,
    )
    .unwrap_err();

    assert_eq!(err, ThresholdError::StandardVerificationFailed);
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_missing_package() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let recomputation_certificate = p1_recomputation_certificate();

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        None,
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Missing {
            reason: "missing P1 selected-backend aggregate artifact package",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_unreviewed_package() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let recomputation_certificate = p1_recomputation_certificate();
    let mut package = selected_backend_aggregate_artifact_package(&fixture);
    package.reviewed = false;

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason:
                "P1 selected-backend aggregate artifact must be reviewed before artifact closure",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_stale_bridge_for_changed_outputs() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let alternate_response = b"alternate aggregate response bytes";
    let alternate_response_digest = Sha3_256::digest(alternate_response).into();
    let accepted_aggregate = accepted_aggregate_from_fixture_with_digests(
        &fixture,
        alternate_response_digest,
        fixture.expected.hint_digest(),
    );
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        alternate_response,
        &decode_hex(&fixture.recomputation.hint_hex),
        &signature_from_fill_byte(fixture.recomputation.recomputed_signature_fill_byte),
    )
    .unwrap();
    let recomputation_certificate = p1_recomputation_certificate();
    let mut package = selected_backend_aggregate_artifact_package(&fixture);
    package.aggregate_response_digest = *accepted_aggregate.aggregate_response_digest();

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate bridge digest does not match accepted aggregate and recomputation evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_acceptance_recomputation_mismatch() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        b"different aggregate response bytes",
        &decode_hex(&fixture.recomputation.hint_hex),
        &signature_from_fill_byte(fixture.recomputation.recomputed_signature_fill_byte),
    )
    .unwrap();
    let recomputation_certificate = p1_recomputation_certificate();

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(selected_backend_aggregate_artifact_package(&fixture)),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 accepted aggregate response digest does not match recomputation transcript",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_bridge_digest_mismatch() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let recomputation_certificate = p1_recomputation_certificate();
    let mut package = selected_backend_aggregate_artifact_package(&fixture);
    package.standard_verifier_bridge_evidence_digest = digest(99);

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate bridge digest does not match recomputation certificate",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_provider_kat_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let recomputation_certificate = p1_recomputation_certificate();
    let mut package = selected_backend_aggregate_artifact_package(&fixture);
    package.provider_kat_evidence_digest = digest(97);

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate provider KAT digest does not match recomputation certificate",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_threshold_output_artifact_accepts_bound_source_and_aggregate_certificate() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let aggregate_certificate = selected_backend_aggregate_artifact_certificate(&fixture);
    let package = selected_backend_threshold_output_artifact_package(&fixture);

    let assessment = assess_p1_selected_backend_threshold_output_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        Some(package),
    );

    let certificate = assessment
        .threshold_output_certificate()
        .expect("bound threshold-output artifact should produce a certificate");
    assert!(assessment.is_artifact_ready());
    assert_eq!(
        certificate.selected_profile(),
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    );
    assert_eq!(
        certificate.aggregate_artifact_digest(),
        &derive_p1_selected_backend_aggregate_certificate_digest(&aggregate_certificate)
    );
    assert_eq!(
        certificate.threshold_output_source_digest(),
        threshold_output_evidence_source(&fixture).source_digest()
    );
    assert_eq!(
        certificate.accepted_signature_digest(),
        accepted_aggregate.candidate_signature_digest()
    );
    assert_eq!(
        certificate.aggregate_response_digest(),
        accepted_aggregate.aggregate_response_digest()
    );
    assert_eq!(certificate.hint_digest(), accepted_aggregate.hint_digest());
    assert_eq!(
        certificate.claim_boundary(),
        P1ThresholdOutputClaimBoundary::ProofReviewOnly
    );
    assert!(!certificate.claims_real_threshold_signer());
    assert!(!certificate.claims_selected_backend_production());
    assert!(!certificate.claims_standard_verifier_compatibility());
    assert!(!certificate.claims_completed_cryptographic_proof());
}

#[test]
fn p1_selected_backend_threshold_output_artifact_accepts_arbitrary_source_package_bytes() {
    let fixture = standard_verifier_bridge_fixture();
    let source_package_bytes = b"reviewed alternate threshold-output source artifact bundle";
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let aggregate_certificate = selected_backend_aggregate_artifact_certificate(&fixture);
    let package = selected_backend_threshold_output_artifact_package_with_source_bytes(
        &fixture,
        source_package_bytes,
    );

    let assessment = assess_p1_selected_backend_threshold_output_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        Some(package),
    );

    let certificate = assessment
        .threshold_output_certificate()
        .expect("alternate source-package bytes should still produce a certificate");
    assert!(assessment.is_artifact_ready());
    assert_eq!(
        certificate.threshold_output_source_package_digest(),
        &derive_p1_selected_backend_threshold_output_source_package_digest(source_package_bytes)
    );
    assert_eq!(
        certificate.threshold_output_source_digest(),
        &derive_p1_selected_backend_threshold_output_source_digest(
            &transcript,
            &accepted_aggregate,
            &recomputation,
            source_package_bytes,
        )
    );
}

#[test]
fn p1_selected_backend_threshold_output_artifact_rejects_stale_source_digest() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let aggregate_certificate = selected_backend_aggregate_artifact_certificate(&fixture);
    let mut package = selected_backend_threshold_output_artifact_package(&fixture);
    package.threshold_output_source_digest = digest(222);

    let assessment = assess_p1_selected_backend_threshold_output_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output source digest does not match selected-backend aggregate evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_threshold_output_artifact_rejects_production_claim_boundary() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let aggregate_certificate = selected_backend_aggregate_artifact_certificate(&fixture);
    let mut package = selected_backend_threshold_output_artifact_package(&fixture);
    package.claim_boundary = P1ThresholdOutputClaimBoundary::ProductionClaim;

    let assessment = assess_p1_selected_backend_threshold_output_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &aggregate_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendThresholdOutputArtifactAssessment::Invalid {
            reason: "P1 threshold-output artifact must remain proof-review-only",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_standard_verifier_compatibility_artifact_accepts_bound_verifier_payload() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let package = standard_verifier_compatibility_artifact_package(&fixture);

    let assessment = assess_p1_standard_verifier_compatibility_artifact(
        &transcript,
        &threshold_certificate,
        Some(package),
    );

    let certificate = assessment
        .standard_verifier_compatibility_certificate()
        .expect("accepted verifier payload should produce a compatibility certificate");
    let expected_public_key_digest: [u8; 32] =
        Sha3_256::digest(transcript.input().public_key.0).into();
    let expected_message_digest: [u8; 32] =
        Sha3_256::digest(&transcript.input().application_message).into();
    let recomputation_certificate = p1_recomputation_certificate();
    assert!(assessment.is_artifact_ready());
    assert_eq!(
        certificate.selected_profile(),
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    );
    assert_eq!(
        certificate.threshold_output_certificate_digest(),
        &derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate)
    );
    assert_eq!(
        certificate.provider_kat_evidence_digest(),
        threshold_certificate.provider_kat_evidence_digest()
    );
    assert_eq!(
        certificate.provider_identity_digest(),
        recomputation_certificate.provider_identity_digest()
    );
    assert_eq!(certificate.public_key_digest(), &expected_public_key_digest);
    assert_eq!(certificate.message_digest(), &expected_message_digest);
    assert_eq!(
        certificate.standard_verifier_bridge_evidence_digest(),
        threshold_certificate.standard_verifier_bridge_evidence_digest()
    );
    assert_eq!(
        certificate.real_recomputation_evidence_digest(),
        threshold_certificate.real_recomputation_evidence_digest()
    );
    assert_eq!(
        certificate.transcript_binding_digest(),
        threshold_certificate.transcript_binding_digest()
    );
    assert_eq!(
        certificate.accepted_signature_digest(),
        threshold_certificate.accepted_signature_digest()
    );
    assert_eq!(
        certificate.verifier_result(),
        P1StandardVerifierCompatibilityResult::Accept
    );
    assert_ne!(
        derive_p1_standard_verifier_compatibility_artifact_digest(certificate),
        standard_verifier_bridge_digest(),
        "compatibility artifacts must not reuse bridge-fixture confidence as their artifact digest"
    );
    assert!(!certificate.claims_selected_backend_proof_closure());
    assert!(!certificate.claims_standard_verifier_compatibility());
    assert!(!certificate.claims_rejection_distribution_preservation());
    assert!(!certificate.claims_cavp_acvts_validation());
    assert!(!certificate.claims_fips_validation());
    assert!(!certificate.claims_completed_cryptographic_proof());
}

#[test]
fn p1_standard_verifier_compatibility_artifact_rejects_failed_standard_verifier() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let candidate_signature =
        signature_from_fill_byte(fixture.recomputation.candidate_signature_fill_byte);
    let err = derive_p1_standard_verifier_compatibility_artifact_package::<RejectingProvider>(
        &transcript,
        &threshold_certificate,
        &candidate_signature,
        P1StandardVerifierCompatibilityClaimBoundary::ProofReviewOnly,
        true,
    )
    .unwrap_err();

    assert_eq!(err, ThresholdError::StandardVerificationFailed);
}

#[test]
fn p1_standard_verifier_compatibility_artifact_rejects_threshold_certificate_mismatch() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = standard_verifier_compatibility_artifact_package(&fixture);
    package.threshold_output_certificate_digest = digest(219);

    let assessment = assess_p1_standard_verifier_compatibility_artifact(
        &transcript,
        &threshold_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility threshold-output certificate digest does not match certificate",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_standard_verifier_compatibility_artifact_rejects_bridge_digest_as_artifact_digest() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = standard_verifier_compatibility_artifact_package(&fixture);
    package.artifact_digest = standard_verifier_bridge_digest();

    let assessment = assess_p1_standard_verifier_compatibility_artifact(
        &transcript,
        &threshold_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason:
                "P1 standard-verifier compatibility artifact digest does not match verifier payload",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_standard_verifier_compatibility_artifact_rejects_recomputation_digest_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = standard_verifier_compatibility_artifact_package(&fixture);
    package.real_recomputation_evidence_digest = digest(217);

    let assessment = assess_p1_standard_verifier_compatibility_artifact(
        &transcript,
        &threshold_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility recomputation digest does not match threshold-output certificate",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_standard_verifier_compatibility_artifact_rejects_bridge_digest_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = standard_verifier_compatibility_artifact_package(&fixture);
    package.standard_verifier_bridge_evidence_digest = digest(218);

    let assessment = assess_p1_standard_verifier_compatibility_artifact(
        &transcript,
        &threshold_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility bridge digest does not match threshold-output certificate",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_standard_verifier_compatibility_artifact_rejects_production_claim_boundary() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = standard_verifier_compatibility_artifact_package(&fixture);
    package.claim_boundary = P1StandardVerifierCompatibilityClaimBoundary::ProductionClaim;

    let assessment = assess_p1_standard_verifier_compatibility_artifact(
        &transcript,
        &threshold_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1StandardVerifierCompatibilityArtifactAssessment::Invalid {
            reason: "P1 standard-verifier compatibility artifact must remain proof-review-only",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_real_threshold_backend_emission_ingestion_accepts_reviewed_external_threshold_output() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let package = real_threshold_backend_emission_artifact_package(&fixture);

    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );

    let certificate = assessment
        .backend_emission_certificate()
        .expect("reviewed real-threshold backend emission should produce an artifact certificate");
    assert!(assessment.is_artifact_ready());
    assert_eq!(certificate.validator_count(), 10_000);
    assert_eq!(certificate.threshold(), 6_667);
    assert_eq!(
        certificate.aggregate_signature_len(),
        MLDSA65_SIGNATURE_BYTES
    );
    assert_eq!(certificate.backend_evidence_digest(), &digest(77));
    assert_eq!(certificate.backend_source_package_digest(), &digest(78));
    assert_eq!(certificate.backend_implementation_digest(), &digest(79));
    assert_eq!(certificate.backend_transcript_digest(), &digest(80));
    assert_eq!(
        certificate.threshold_output_certificate_digest(),
        &derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate)
    );
    assert_eq!(
        certificate.standard_verifier_compatibility_artifact_digest(),
        &derive_p1_standard_verifier_compatibility_artifact_digest(&compatibility_certificate)
    );
    assert!(certificate.mutation_rejection_corpus_complete());
    assert!(!certificate.claims_real_threshold_backend_implemented());
    assert!(!certificate.claims_production_threshold_mldsa_security());
    assert!(!certificate.claims_completed_cryptographic_proof());

    let closure_package = certificate.to_verifier_closure_package();
    let closure_assessment = assess_p1_real_threshold_verifier_closure_contract(
        &threshold_certificate,
        &compatibility_certificate,
        Some(closure_package),
    );
    assert!(closure_assessment.is_closure_ready());
}

#[test]
fn p1_real_threshold_backend_emission_ingestion_blocks_simulated_backend() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let mut package = real_threshold_backend_emission_artifact_package(&fixture);
    package.backend_evidence =
        P1RealThresholdVerifierClosureBackendEvidence::SimulatedDeterministic;

    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1RealThresholdBackendEmissionArtifactAssessment::BlockedFailClosed {
            reason: "P1 real-threshold backend emission requires real threshold ML-DSA backend evidence, not deterministic simulation",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_real_threshold_backend_emission_ingestion_rejects_standard_provider_single_key_output() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let mut package = real_threshold_backend_emission_artifact_package(&fixture);
    package.backend_evidence =
        P1RealThresholdVerifierClosureBackendEvidence::StandardProviderSingleKey;

    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission requires threshold backend provenance, not ordinary single-key standard-provider output",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_real_threshold_backend_emission_ingestion_rejects_stale_threshold_certificate_digest() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let mut package = real_threshold_backend_emission_artifact_package(&fixture);
    package.threshold_output_certificate_digest = digest(81);

    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission threshold-output digest does not match predecessor certificate",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_real_threshold_backend_emission_ingestion_rejects_unreviewed_external_backend_evidence() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let mut package = real_threshold_backend_emission_artifact_package(&fixture);
    package.reviewed = false;

    let assessment = assess_p1_real_threshold_backend_emission_artifact(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1RealThresholdBackendEmissionArtifactAssessment::Invalid {
            reason: "P1 real-threshold backend emission artifact must be reviewed",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_real_threshold_verifier_closure_contract_blocks_simulated_backend() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let mut package = real_threshold_verifier_closure_package(&fixture);
    package.backend_evidence =
        P1RealThresholdVerifierClosureBackendEvidence::SimulatedDeterministic;

    let assessment = assess_p1_real_threshold_verifier_closure_contract(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1RealThresholdVerifierClosureAssessment::BlockedFailClosed {
            reason: "P1 real-threshold verifier closure requires real threshold ML-DSA backend evidence, not deterministic simulation",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn p1_real_threshold_verifier_closure_contract_rejects_standard_provider_single_key_output() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let mut package = real_threshold_verifier_closure_package(&fixture);
    package.backend_evidence =
        P1RealThresholdVerifierClosureBackendEvidence::StandardProviderSingleKey;

    let assessment = assess_p1_real_threshold_verifier_closure_contract(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure requires threshold backend provenance, not ordinary single-key standard-provider output",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn p1_real_threshold_verifier_closure_contract_accepts_reviewed_verifier_tuple() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let package = real_threshold_verifier_closure_package(&fixture);

    let assessment = assess_p1_real_threshold_verifier_closure_contract(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );

    let certificate = assessment
        .closure_certificate()
        .expect("reviewed real-threshold verifier tuple should produce a contract certificate");
    assert!(assessment.is_closure_ready());
    assert_eq!(certificate.validator_count(), 10_000);
    assert_eq!(certificate.threshold(), 6_667);
    assert_eq!(
        certificate.aggregate_signature_len(),
        MLDSA65_SIGNATURE_BYTES
    );
    assert_eq!(
        certificate.standard_verifier_compatibility_artifact_digest(),
        &derive_p1_standard_verifier_compatibility_artifact_digest(&compatibility_certificate)
    );
    assert_eq!(
        certificate.threshold_output_certificate_digest(),
        &derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate)
    );
    assert_eq!(
        certificate.verifier_result(),
        P1StandardVerifierCompatibilityResult::Accept
    );
    assert!(certificate.mutation_rejection_corpus_complete());
    assert!(!certificate.claims_production_threshold_mldsa_security());
    assert!(!certificate.claims_cavp_acvts_validation());
    assert!(!certificate.claims_fips_validation());
    assert!(!certificate.claims_completed_cryptographic_proof());
}

#[test]
fn p1_real_threshold_verifier_closure_contract_rejects_missing_mutation_corpus() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let mut package = real_threshold_verifier_closure_package(&fixture);
    package.mutated_signature_rejected = false;

    let assessment = assess_p1_real_threshold_verifier_closure_contract(
        &threshold_certificate,
        &compatibility_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1RealThresholdVerifierClosureAssessment::Invalid {
            reason: "P1 real-threshold verifier closure requires mutated message, public key, and signature rejection evidence",
        }
    );
    assert!(!assessment.is_closure_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_accepts_reviewed_threshold_output_and_proof_artifacts(
) {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let package = selected_backend_proof_closure_artifact_package(&fixture);
    let compatibility_certificate = standard_verifier_compatibility_artifact_certificate(&fixture);
    let expected_full_kat_validation_artifact_digest = *package
        .proof_slot_artifacts
        .full_kat_validation_artifact
        .artifact_digest();
    let expected_rejection_distribution_review_digest = *package
        .proof_slot_artifacts
        .rejection_distribution_review_artifact
        .artifact_digest();
    let expected_threshold_output_certificate_artifact_digest = *package
        .proof_slot_artifacts
        .threshold_output_certificate_artifact
        .artifact_digest();
    let expected_real_recomputation_evidence_artifact_digest = *package
        .proof_slot_artifacts
        .real_recomputation_evidence_artifact
        .artifact_digest();
    let expected_theorem_linkage_artifact_digest = *package
        .proof_slot_artifacts
        .theorem_linkage_artifact
        .artifact_digest();
    assert_eq!(
        package
            .proof_slot_artifacts
            .threshold_output_certificate_artifact
            .kind(),
        P1Criterion2ProofSlotArtifactKind::ThresholdOutputCertificate
    );
    assert_eq!(
        package
            .proof_slot_artifacts
            .threshold_output_certificate_artifact
            .source_evidence_digest,
        derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate)
    );
    assert_eq!(
        package
            .proof_slot_artifacts
            .real_recomputation_evidence_artifact
            .kind(),
        P1Criterion2ProofSlotArtifactKind::RealRecomputationEvidence
    );
    assert_eq!(
        &package
            .proof_slot_artifacts
            .real_recomputation_evidence_artifact
            .source_evidence_digest,
        package.proof_artifacts.real_recomputation_evidence_digest()
    );

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    let certificate = assessment
        .proof_closure_certificate()
        .expect("reviewed proof-closure artifact package should produce a certificate");
    assert!(assessment.is_artifact_ready());
    assert_eq!(
        certificate.selected_profile(),
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
    );
    assert_eq!(
        certificate.threshold_output_certificate_digest(),
        &derive_p1_selected_backend_threshold_output_certificate_digest(&threshold_certificate)
    );
    assert_eq!(
        certificate.threshold_output_source_digest(),
        threshold_certificate.threshold_output_source_digest()
    );
    assert_eq!(
        certificate.threshold_output_source_package_digest(),
        threshold_certificate.threshold_output_source_package_digest()
    );
    assert_eq!(
        certificate.provider_kat_evidence_digest(),
        threshold_certificate.provider_kat_evidence_digest()
    );
    assert_eq!(
        certificate.standard_verifier_bridge_evidence_digest(),
        threshold_certificate.standard_verifier_bridge_evidence_digest()
    );
    assert_eq!(
        certificate.real_recomputation_evidence_digest(),
        threshold_certificate.real_recomputation_evidence_digest()
    );
    assert_eq!(
        certificate.transcript_binding_digest(),
        threshold_certificate.transcript_binding_digest()
    );
    assert_eq!(
        certificate.full_kat_validation_artifact_digest(),
        &expected_full_kat_validation_artifact_digest
    );
    assert_eq!(
        certificate.rejection_distribution_review_digest(),
        &expected_rejection_distribution_review_digest
    );
    assert_eq!(
        certificate.threshold_output_certificate_artifact_digest(),
        &expected_threshold_output_certificate_artifact_digest
    );
    assert_eq!(
        certificate.real_recomputation_evidence_artifact_digest(),
        &expected_real_recomputation_evidence_artifact_digest
    );
    assert_eq!(
        certificate.standard_verifier_compatibility_artifact_digest(),
        &derive_p1_standard_verifier_compatibility_artifact_digest(&compatibility_certificate,)
    );
    assert_eq!(
        certificate.theorem_linkage_artifact_digest(),
        &expected_theorem_linkage_artifact_digest
    );
    assert_eq!(
        certificate.claim_boundary(),
        P1SelectedBackendProofClosureClaimBoundary::ProofReviewOnly
    );
    assert!(!certificate.claims_real_threshold_signer());
    assert!(!certificate.claims_selected_backend_production());
    assert!(!certificate.claims_selected_backend_proof_closure());
    assert!(!certificate.claims_standard_verifier_compatibility());
    assert!(!certificate.claims_rejection_distribution_preservation());
    assert!(!certificate.claims_cavp_acvts_validation());
    assert!(!certificate.claims_fips_validation());
    assert!(!certificate.claims_completed_cryptographic_proof());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_stale_threshold_certificate_digest() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.threshold_output_certificate_digest = digest(222);

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason:
                "P1 proof-closure threshold-output certificate digest does not match certificate",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_stale_proof_transcript_binding() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.proof_artifacts = P1RejectionProofArtifacts::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        *threshold_certificate.real_recomputation_evidence_digest(),
        *threshold_certificate.standard_verifier_bridge_evidence_digest(),
        standard_verifier_bridge_fixture_package_digest(),
        digest(43),
        digest(44),
        digest(45),
        digest(201),
        negative_test_corpus_digest(),
        digest(48),
        true,
    );

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact source digest does not match expected proof evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_missing_validation_artifact() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.full_kat_validation_artifact_digest = [0; 32];

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure full KAT/validation artifact digest is all zero",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_missing_distribution_review_artifact() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.rejection_distribution_review_digest = [0; 32];

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure rejection-distribution review digest is all zero",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_missing_standard_verifier_compatibility_artifact(
) {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.standard_verifier_compatibility_artifact_digest = [0; 32];

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure standard-verifier compatibility artifact digest is all zero",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_stale_standard_verifier_compatibility_artifact_digest(
) {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.standard_verifier_compatibility_artifact_digest = digest(222);

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure standard-verifier compatibility artifact digest does not match compatibility certificate",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_missing_theorem_linkage_artifact() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.theorem_linkage_artifact_digest = [0; 32];

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure theorem-linkage artifact digest is all zero",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_unreviewed_theorem_linkage_slot() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .theorem_linkage_artifact
        .reviewed = false;

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact must be reviewed",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_theorem_linkage_slot_digest_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .theorem_linkage_artifact
        .artifact_digest = digest(79);

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact digest does not match payload",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_theorem_linkage_slot_review_tamper() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .theorem_linkage_artifact
        .review_evidence_digest = digest(96);
    package
        .proof_slot_artifacts
        .theorem_linkage_artifact
        .artifact_digest = derive_p1_criterion2_proof_slot_artifact_digest(
        &package.proof_slot_artifacts.theorem_linkage_artifact,
    );

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact review digest does not match expected external review evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_theorem_linkage_package_digest_stale() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.theorem_linkage_artifact_digest = digest(97);

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure theorem-linkage artifact digest does not match typed Criterion 2 slot artifact",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_theorem_linkage_slot_production_claim_boundary(
) {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .theorem_linkage_artifact
        .claim_boundary = P1SelectedBackendProofClosureClaimBoundary::ProductionClaim;

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact must remain proof-review-only",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_typed_slot_kind_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.proof_slot_artifacts.norm_bound_artifact.kind =
        P1Criterion2ProofSlotArtifactKind::HintBound;

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact kind mismatch",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_unreviewed_typed_slot() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .rejection_distribution_review_artifact
        .reviewed = false;

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact must be reviewed",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_unreviewed_rejection_distribution_slot() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .rejection_distribution_review_artifact
        .reviewed = false;

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact must be reviewed",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_typed_slot_digest_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .theorem_linkage_artifact
        .artifact_digest = digest(77);

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact digest does not match payload",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_rejection_distribution_slot_digest_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .rejection_distribution_review_artifact
        .artifact_digest = digest(78);

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact digest does not match payload",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_recomputed_review_digest_tamper() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .norm_bound_artifact
        .review_evidence_digest = digest(88);
    package
        .proof_slot_artifacts
        .norm_bound_artifact
        .artifact_digest = derive_p1_criterion2_proof_slot_artifact_digest(
        &package.proof_slot_artifacts.norm_bound_artifact,
    );

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact review digest does not match expected external review evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_rejection_distribution_slot_review_tamper() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .rejection_distribution_review_artifact
        .review_evidence_digest = digest(89);
    package
        .proof_slot_artifacts
        .rejection_distribution_review_artifact
        .artifact_digest = derive_p1_criterion2_proof_slot_artifact_digest(
        &package
            .proof_slot_artifacts
            .rejection_distribution_review_artifact,
    );

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact review digest does not match expected external review evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_rejection_distribution_package_digest_stale()
{
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.rejection_distribution_review_digest = digest(94);

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure rejection-distribution review digest does not match typed Criterion 2 slot artifact",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_rejection_distribution_slot_production_claim_boundary(
) {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .rejection_distribution_review_artifact
        .claim_boundary = P1SelectedBackendProofClosureClaimBoundary::ProductionClaim;

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact must remain proof-review-only",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_threshold_slot_source_tamper() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .threshold_output_certificate_artifact
        .source_evidence_digest = digest(90);
    package
        .proof_slot_artifacts
        .threshold_output_certificate_artifact
        .artifact_digest = derive_p1_criterion2_proof_slot_artifact_digest(
        &package
            .proof_slot_artifacts
            .threshold_output_certificate_artifact,
    );

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact source digest does not match expected proof evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_threshold_slot_review_tamper() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .threshold_output_certificate_artifact
        .review_evidence_digest = digest(92);
    package
        .proof_slot_artifacts
        .threshold_output_certificate_artifact
        .artifact_digest = derive_p1_criterion2_proof_slot_artifact_digest(
        &package
            .proof_slot_artifacts
            .threshold_output_certificate_artifact,
    );

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact review digest does not match expected external review evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_recomputation_slot_source_tamper() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .real_recomputation_evidence_artifact
        .source_evidence_digest = digest(93);
    package
        .proof_slot_artifacts
        .real_recomputation_evidence_artifact
        .artifact_digest = derive_p1_criterion2_proof_slot_artifact_digest(
        &package
            .proof_slot_artifacts
            .real_recomputation_evidence_artifact,
    );

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact source digest does not match expected proof evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_recomputation_slot_review_tamper() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package
        .proof_slot_artifacts
        .real_recomputation_evidence_artifact
        .review_evidence_digest = digest(91);
    package
        .proof_slot_artifacts
        .real_recomputation_evidence_artifact
        .artifact_digest = derive_p1_criterion2_proof_slot_artifact_digest(
        &package
            .proof_slot_artifacts
            .real_recomputation_evidence_artifact,
    );

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure Criterion 2 slot artifact review digest does not match expected external review evidence",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_proof_closure_artifact_rejects_production_claim_boundary() {
    let fixture = standard_verifier_bridge_fixture();
    let threshold_certificate = selected_backend_threshold_output_artifact_certificate(&fixture);
    let mut package = selected_backend_proof_closure_artifact_package(&fixture);
    package.claim_boundary = P1SelectedBackendProofClosureClaimBoundary::ProductionClaim;

    let assessment =
        assess_p1_selected_backend_proof_closure_artifact(&threshold_certificate, Some(package));

    assert_eq!(
        assessment,
        P1SelectedBackendProofClosureArtifactAssessment::Invalid {
            reason: "P1 proof-closure artifact must remain proof-review-only",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_zero_provider_kat_digest() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let recomputation_certificate = p1_recomputation_certificate();
    let mut package = selected_backend_aggregate_artifact_package(&fixture);
    package.provider_kat_evidence_digest = [0; 32];

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(package),
    );

    assert_selected_artifact_invalid_reason(
        assessment,
        "P1 selected-backend aggregate provider KAT digest is all zero",
    );
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_transcript_binding_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let recomputation_certificate = p1_recomputation_certificate();
    let mut package = selected_backend_aggregate_artifact_package(&fixture);
    package.transcript_binding_digest = digest(96);

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate transcript binding digest does not match production transcript",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_attempt_binding_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let recomputation_certificate = p1_recomputation_certificate();
    let mut package = selected_backend_aggregate_artifact_package(&fixture);
    package.attempt_binding_digest = digest(95);

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason: "P1 selected-backend aggregate attempt binding digest does not match production transcript",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_accepted_signature_mismatch() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = AggregateRecomputationTranscript::from_public_outputs(
        &transcript,
        &decode_hex(&fixture.recomputation.aggregate_response_hex),
        &decode_hex(&fixture.recomputation.hint_hex),
        &ThresholdSignature([43; 3309]),
    )
    .unwrap();
    let recomputation_certificate = p1_recomputation_certificate();

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(selected_backend_aggregate_artifact_package(&fixture)),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason:
                "P1 accepted aggregate signature digest does not match recomputation transcript",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_selected_backend_aggregate_artifact_rejects_signer_set_drift() {
    let fixture = standard_verifier_bridge_fixture();
    let transcript = transcript_from_fixture(&fixture.transcript);
    let accepted_aggregate = accepted_aggregate_from_fixture(&fixture);
    let recomputation = fixture_recomputation_transcript(&fixture);
    let recomputation_certificate = p1_recomputation_certificate();
    let mut package = selected_backend_aggregate_artifact_package(&fixture);
    package.signer_set_digest = digest(98);

    let assessment = assess_p1_selected_backend_aggregate_artifact(
        &transcript,
        &accepted_aggregate,
        &recomputation,
        &recomputation_certificate,
        Some(package),
    );

    assert_eq!(
        assessment,
        P1SelectedBackendAggregateArtifactAssessment::Invalid {
            reason:
                "P1 selected-backend aggregate signer-set digest does not match accepted aggregate",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_recomputation_closure_rejects_smoke_only_kat_evidence() {
    let mut package = p1_recomputation_package();
    package.provider_kat_evidence =
        provider_kat_evidence(AcvpFips204EvidenceSource::NonAcvpSmokeOnly);

    let assessment = assess_p1_aggregate_recomputation_closure(Some(package));

    assert_eq!(
        assessment,
        P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 provider KAT evidence must be ACVP/FIPS204-backed, not smoke-only",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_recomputation_closure_rejects_unreviewed_provider_kat_evidence() {
    let mut package = p1_recomputation_package();
    package.provider_kat_evidence = Mldsa65ProviderKatEvidence::new(
        AcvpFips204EvidenceSource::NistAcvpServerFips204,
        provider_kat_fixture_digest(),
        digest(49),
        digest(50),
        false,
    );

    assert_p1_invalid_reason(
        assess_p1_aggregate_recomputation_closure(Some(package)),
        "P1 provider KAT evidence must be reviewed before artifact closure",
    );
}

#[test]
fn p1_recomputation_closure_rejects_zero_provider_kat_digest() {
    let mut package = p1_recomputation_package();
    package.provider_kat_evidence = Mldsa65ProviderKatEvidence::new(
        AcvpFips204EvidenceSource::NistAcvpServerFips204,
        [0; 32],
        digest(49),
        digest(50),
        true,
    );

    assert_p1_invalid_reason(
        assess_p1_aggregate_recomputation_closure(Some(package)),
        "P1 provider KAT evidence digest is all zero",
    );
}

#[test]
fn p1_recomputation_closure_rejects_zero_acvp_vector_set_digest() {
    let mut package = p1_recomputation_package();
    package.provider_kat_evidence = Mldsa65ProviderKatEvidence::new(
        AcvpFips204EvidenceSource::NistAcvpServerFips204,
        provider_kat_fixture_digest(),
        [0; 32],
        digest(50),
        true,
    );

    assert_p1_invalid_reason(
        assess_p1_aggregate_recomputation_closure(Some(package)),
        "P1 ACVP/FIPS204 vector-set digest is all zero",
    );
}

#[test]
fn p1_recomputation_closure_rejects_zero_provider_identity_digest() {
    let mut package = p1_recomputation_package();
    package.provider_kat_evidence = Mldsa65ProviderKatEvidence::new(
        AcvpFips204EvidenceSource::NistAcvpServerFips204,
        provider_kat_fixture_digest(),
        digest(49),
        [0; 32],
        true,
    );

    assert_p1_invalid_reason(
        assess_p1_aggregate_recomputation_closure(Some(package)),
        "P1 provider identity digest is all zero",
    );
}

#[test]
fn p1_recomputation_closure_rejects_unreviewed_proof_artifacts() {
    let mut package = p1_recomputation_package();
    package.proof_artifacts = P1RejectionProofArtifacts::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        digest(41),
        standard_verifier_bridge_digest(),
        standard_verifier_bridge_fixture_package_digest(),
        digest(43),
        digest(44),
        digest(45),
        digest(46),
        negative_test_corpus_digest(),
        digest(48),
        false,
    );

    let assessment = assess_p1_aggregate_recomputation_closure(Some(package));

    assert_eq!(
        assessment,
        P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 proof artifacts must be reviewed before artifact closure",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_recomputation_closure_rejects_profile_binding_digest_mismatch() {
    let mut package = p1_recomputation_package();
    package.proof_artifacts = P1RejectionProofArtifacts::new(
        digest(99),
        digest(41),
        standard_verifier_bridge_digest(),
        standard_verifier_bridge_fixture_package_digest(),
        digest(43),
        digest(44),
        digest(45),
        digest(46),
        negative_test_corpus_digest(),
        digest(48),
        true,
    );

    let assessment = assess_p1_aggregate_recomputation_closure(Some(package));

    assert_eq!(
        assessment,
        P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 selected profile binding digest does not match selected profile",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_recomputation_closure_rejects_verifier_bridge_digest_mismatch() {
    let mut package = p1_recomputation_package();
    package.proof_artifacts = P1RejectionProofArtifacts::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        digest(41),
        digest(99),
        standard_verifier_bridge_fixture_package_digest(),
        digest(43),
        digest(44),
        digest(45),
        digest(46),
        negative_test_corpus_digest(),
        digest(48),
        true,
    );

    let assessment = assess_p1_aggregate_recomputation_closure(Some(package));

    assert_eq!(
        assessment,
        P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 standard verifier bridge evidence digest does not match closure package",
        }
    );
    assert!(!assessment.is_artifact_ready());
}

#[test]
fn p1_recomputation_closure_rejects_closure_digest_mismatch() {
    let mut package = p1_recomputation_package();
    package.provider_kat_evidence = Mldsa65ProviderKatEvidence::new(
        AcvpFips204EvidenceSource::NistAcvpServerFips204,
        digest(99),
        digest(49),
        digest(50),
        true,
    );

    let assessment = assess_p1_aggregate_recomputation_closure(Some(package));

    assert_eq!(
        assessment,
        P1AggregateRecomputationAssessment::Invalid {
            reason: "P1 provider KAT evidence digest does not match closure package",
        }
    );
    assert!(!assessment.is_artifact_ready());
}
