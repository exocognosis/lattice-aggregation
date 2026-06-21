#![cfg(feature = "coordinator-assisted")]

use std::collections::BTreeSet;

use lattice_aggregation::{
    production::{
        provider::StandardMldsa65Provider,
        rejection_equivalence::{
            assess_p1_aggregate_recomputation_closure, assess_rejection_equivalence_closure,
            derive_standard_verifier_bridge_evidence_digest, AcvpFips204EvidenceSource,
            AggregateRecomputationTranscript, AggregateRejectionClosureAssessment,
            AggregateRejectionClosurePackage, AggregateRejectionClosureStatus,
            AggregateRejectionConformanceBoundary, AggregateRejectionEquivalenceEvidence,
            AggregateRejectionEquivalenceGate, AggregateRejectionEvidenceDigest,
            AggregateRejectionEvidenceStrength, Mldsa65ProviderKatEvidence,
            P1AggregateRecomputationAssessment, P1AggregateRecomputationClosurePackage,
            P1RejectionProofArtifacts,
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
    candidate_signature_digest_hex: String,
    recomputed_signature_digest_hex: String,
    transcript_binding_digest_hex: String,
    selected_profile_binding_digest_hex: String,
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
        hasher.update(decode_hex_array::<32>(&case.candidate_signature_digest_hex));
        hasher.update(decode_hex_array::<32>(
            &case.recomputed_signature_digest_hex,
        ));
        hasher.update(decode_hex_array::<32>(&case.transcript_binding_digest_hex));
        hasher.update(decode_hex_array::<32>(
            &case.selected_profile_binding_digest_hex,
        ));
    }
    hasher.finalize().into()
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
    assert!(!certificate.claims_fips_validation());
    assert!(!certificate.claims_production_approval());
    assert!(!certificate.claims_standard_verifier_compatibility());
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
fn p1_recomputation_closure_rejects_unreviewed_proof_artifacts() {
    let mut package = p1_recomputation_package();
    package.proof_artifacts = P1RejectionProofArtifacts::new(
        SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1()
            .profile_binding_digest(),
        digest(41),
        standard_verifier_bridge_digest(),
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
