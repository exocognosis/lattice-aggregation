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
            assess_p1_selected_backend_aggregate_artifact,
            assess_p1_selected_backend_threshold_output_artifact,
            assess_rejection_equivalence_closure,
            derive_p1_selected_backend_aggregate_certificate_digest,
            derive_p1_selected_backend_attempt_binding_digest,
            derive_p1_selected_backend_signer_set_digest,
            derive_p1_selected_backend_threshold_output_artifact_package,
            derive_p1_selected_backend_threshold_output_source_digest,
            derive_p1_selected_backend_threshold_output_source_package_digest,
            derive_p1_selected_backend_transcript_binding_digest,
            derive_standard_verifier_bridge_evidence_digest, AcvpFips204EvidenceSource,
            AggregateRecomputationTranscript, AggregateRejectionClosureAssessment,
            AggregateRejectionClosurePackage, AggregateRejectionClosureStatus,
            AggregateRejectionConformanceBoundary, AggregateRejectionEquivalenceEvidence,
            AggregateRejectionEquivalenceGate, AggregateRejectionEvidenceDigest,
            AggregateRejectionEvidenceStrength, Mldsa65ProviderKatEvidence,
            P1AggregateRecomputationAssessment, P1AggregateRecomputationClosureCertificate,
            P1AggregateRecomputationClosurePackage, P1RejectionProofArtifacts,
            P1SelectedBackendAggregateArtifactAssessment,
            P1SelectedBackendAggregateArtifactCertificate,
            P1SelectedBackendAggregateArtifactPackage,
            P1SelectedBackendThresholdOutputArtifactAssessment,
            P1SelectedBackendThresholdOutputArtifactPackage, P1ThresholdOutputClaimBoundary,
            P1ThresholdOutputEvidenceSource,
        },
        selected_backend::SelectedProductionBackendProfile,
        transcript::{CommitmentDigest, ProductionSigningTranscript, ProductionTranscriptInput},
        types::{
            ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
            ValidatorSetDigest,
        },
    },
    ThresholdError, ThresholdPublicKey, ThresholdSignature, ValidatorId,
};
use serde::Deserialize;
use sha3::{Digest, Sha3_256};

#[cfg(feature = "hazmat-real-mldsa")]
use lattice_aggregation::production::rejection_equivalence::{
    derive_p1_real_recomputation_evidence_digest,
    derive_p1_selected_backend_aggregate_artifact_package,
};

const EXPECTED_P1_STANDARD_VERIFIER_BRIDGE_FIXTURE_PACKAGE_DIGEST_HEX: &str =
    "28a59ad2845dc0e6694c997ed106c23f09966efb6028431dd55ac8ccdb9639fa";

struct AcceptingProvider;

impl StandardMldsa65Provider for AcceptingProvider {
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
        digest(50),
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
    assert_eq!(certificate.provider_identity_digest(), &digest(50));
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
