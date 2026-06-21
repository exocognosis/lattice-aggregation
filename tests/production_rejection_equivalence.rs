#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        provider::StandardMldsa65Provider,
        rejection_equivalence::{
            AggregateRecomputationTranscript, AggregateRejectionEquivalenceEvidence,
            AggregateRejectionEquivalenceGate, AggregateRejectionEvidenceStrength,
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
