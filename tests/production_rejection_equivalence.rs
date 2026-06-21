#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        provider::StandardMldsa65Provider,
        rejection_equivalence::{
            assess_rejection_equivalence_closure, AggregateRecomputationTranscript,
            AggregateRejectionClosureAssessment, AggregateRejectionClosurePackage,
            AggregateRejectionClosureStatus, AggregateRejectionConformanceBoundary,
            AggregateRejectionEquivalenceEvidence, AggregateRejectionEquivalenceGate,
            AggregateRejectionEvidenceDigest, AggregateRejectionEvidenceStrength,
        },
        transcript::{CommitmentDigest, ProductionSigningTranscript, ProductionTranscriptInput},
        types::{
            ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
            ValidatorSetDigest,
        },
    },
    ThresholdError, ThresholdPublicKey, ThresholdSignature, ValidatorId,
};

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

fn closure_package() -> AggregateRejectionClosurePackage {
    AggregateRejectionClosurePackage::new(
        AggregateRejectionConformanceBoundary::ClosureCandidate,
        Some(AggregateRejectionEvidenceDigest::real_recomputation(
            digest(41),
        )),
        Some(AggregateRejectionEvidenceDigest::standard_provider_kat(
            digest(42),
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
            digest(47),
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

fn transcript() -> ProductionSigningTranscript {
    ProductionSigningTranscript::new(ProductionTranscriptInput {
        session_id: [1; 32],
        epoch: EpochId(2),
        key_id: KeyId([3; 32]),
        validator_set_digest: ValidatorSetDigest([4; 32]),
        dkg_transcript_digest: DkgTranscriptDigest([5; 32]),
        active_signers: ActiveSignerSet::new(vec![ValidatorId(1), ValidatorId(2)]).unwrap(),
        threshold: 2,
        public_key: ThresholdPublicKey([6; 1952]),
        application_message: b"original application message".to_vec(),
        message_binding: MessageBinding([7; 64]),
        attempt_id: AttemptId([8; 32]),
        coordinator_attestation_digest: [9; 32],
        retry_counter: 0,
        commitment_digests: vec![
            (ValidatorId(1), CommitmentDigest([11; 32])),
            (ValidatorId(2), CommitmentDigest([12; 32])),
        ],
    })
    .unwrap()
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
        &digest(42)
    );
    assert_eq!(certificate.norm_bound_evidence_digest(), &digest(43));
    assert_eq!(certificate.hint_bound_evidence_digest(), &digest(44));
    assert_eq!(certificate.challenge_bound_evidence_digest(), &digest(45));
    assert_eq!(
        certificate.transcript_binding_evidence_digest(),
        &digest(46)
    );
    assert_eq!(certificate.negative_test_corpus_digest(), &digest(47));
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
