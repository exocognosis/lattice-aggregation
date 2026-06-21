#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        acceptance::{
            AggregateAccept, AggregateAcceptEvidence, LocalAccept, LocalAcceptEvidence,
            StandardVerifierEvidence,
        },
        provider::StandardMldsa65Provider,
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

struct ErrorProvider;

impl StandardMldsa65Provider for ErrorProvider {
    fn verify(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        assert_eq!(public_key, &ThresholdPublicKey([6; 1952]));
        assert_eq!(message, b"original application message");
        assert_eq!(signature, &ThresholdSignature([42; 3309]));
        Err(ThresholdError::BackendUnavailable {
            reason: "test provider unavailable",
        })
    }
}

fn make_transcript(
    active_signers: Vec<ValidatorId>,
    threshold: u16,
    commitments: Vec<(ValidatorId, [u8; 32])>,
) -> ProductionSigningTranscript {
    make_transcript_with_retry_counter(active_signers, threshold, commitments, 0)
}

fn make_transcript_with_retry_counter(
    active_signers: Vec<ValidatorId>,
    threshold: u16,
    commitments: Vec<(ValidatorId, [u8; 32])>,
    retry_counter: u32,
) -> ProductionSigningTranscript {
    ProductionSigningTranscript::new(ProductionTranscriptInput {
        session_id: [1; 32],
        epoch: EpochId(2),
        key_id: KeyId([3; 32]),
        validator_set_digest: ValidatorSetDigest([4; 32]),
        dkg_transcript_digest: DkgTranscriptDigest([5; 32]),
        active_signers: ActiveSignerSet::new(active_signers).unwrap(),
        threshold,
        public_key: ThresholdPublicKey([6; 1952]),
        application_message: b"original application message".to_vec(),
        message_binding: MessageBinding([7; 64]),
        attempt_id: AttemptId([8; 32]),
        coordinator_attestation_digest: [9; 32],
        retry_counter,
        commitment_digests: commitments
            .into_iter()
            .map(|(validator, digest)| (validator, CommitmentDigest(digest)))
            .collect(),
    })
    .unwrap()
}

fn base_transcript() -> ProductionSigningTranscript {
    make_transcript(
        vec![ValidatorId(1), ValidatorId(2)],
        2,
        vec![(ValidatorId(1), [11; 32]), (ValidatorId(2), [12; 32])],
    )
}

fn local_evidence(signer: ValidatorId, commitment_digest: [u8; 32]) -> LocalAcceptEvidence {
    LocalAcceptEvidence {
        signer,
        commitment_digest: CommitmentDigest(commitment_digest),
        partial_share_digest: [21; 32],
        local_bounds_proof_digest: [22; 32],
    }
}

fn accepted_partial(
    transcript: &ProductionSigningTranscript,
    signer: ValidatorId,
    commitment_digest: [u8; 32],
) -> lattice_aggregation::production::acceptance::AcceptedPartialContribution {
    LocalAccept::accept(transcript, local_evidence(signer, commitment_digest)).unwrap()
}

fn aggregate_evidence(transcript: &ProductionSigningTranscript) -> AggregateAcceptEvidence {
    AggregateAcceptEvidence {
        aggregate_response_digest: [31; 32],
        hint_digest: [32; 32],
        standard_verifier: StandardVerifierEvidence::verify::<AcceptingProvider>(
            transcript,
            &ThresholdSignature([42; 3309]),
        )
        .unwrap(),
    }
}

#[test]
fn local_accept_returns_capability_for_matching_evidence() {
    let transcript = base_transcript();

    let accepted =
        LocalAccept::accept(&transcript, local_evidence(ValidatorId(1), [11; 32])).unwrap();

    assert_eq!(accepted.signer(), ValidatorId(1));
    assert_eq!(accepted.commitment_digest(), CommitmentDigest([11; 32]));
    assert_eq!(accepted.partial_share_digest(), &[21; 32]);
    assert_eq!(accepted.local_bounds_proof_digest(), &[22; 32]);
}

#[test]
fn standard_verifier_evidence_records_provider_verified_transcript_binding() {
    let transcript = base_transcript();

    let evidence = StandardVerifierEvidence::verify::<AcceptingProvider>(
        &transcript,
        &ThresholdSignature([42; 3309]),
    )
    .unwrap();

    assert_eq!(evidence.challenge_digest(), transcript.challenge_digest());
}

#[test]
fn standard_verifier_evidence_rejects_failed_provider_verification() {
    let transcript = base_transcript();

    let err = StandardVerifierEvidence::verify::<RejectingProvider>(
        &transcript,
        &ThresholdSignature([42; 3309]),
    )
    .unwrap_err();

    assert_eq!(err, ThresholdError::StandardVerificationFailed);
}

#[test]
fn standard_verifier_evidence_propagates_provider_errors() {
    let transcript = base_transcript();

    let err = StandardVerifierEvidence::verify::<ErrorProvider>(
        &transcript,
        &ThresholdSignature([42; 3309]),
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::BackendUnavailable {
            reason: "test provider unavailable",
        }
    );
}

#[test]
fn local_accept_rejects_unknown_or_inactive_signer() {
    let transcript = base_transcript();

    let err =
        LocalAccept::accept(&transcript, local_evidence(ValidatorId(3), [13; 32])).unwrap_err();

    assert_eq!(
        err,
        ThresholdError::UnknownValidator {
            validator: ValidatorId(3),
        }
    );
}

#[test]
fn local_accept_rejects_commitment_digest_mismatch() {
    let transcript = base_transcript();

    let err =
        LocalAccept::accept(&transcript, local_evidence(ValidatorId(1), [99; 32])).unwrap_err();

    assert_eq!(
        err,
        ThresholdError::CommitmentVerificationFailed {
            validator: ValidatorId(1),
        }
    );
}

#[test]
fn local_accept_rejects_all_zero_partial_digest() {
    let transcript = base_transcript();
    let mut evidence = local_evidence(ValidatorId(1), [11; 32]);
    evidence.partial_share_digest = [0; 32];

    let err = LocalAccept::accept(&transcript, evidence).unwrap_err();

    assert_eq!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1),
        }
    );
}

#[test]
fn local_accept_rejects_all_zero_local_bounds_proof_digest() {
    let transcript = base_transcript();
    let mut evidence = local_evidence(ValidatorId(1), [11; 32]);
    evidence.local_bounds_proof_digest = [0; 32];

    let err = LocalAccept::accept(&transcript, evidence).unwrap_err();

    assert_eq!(
        err,
        ThresholdError::RejectionSamplingFailed {
            validator: ValidatorId(1),
        }
    );
}

#[test]
fn aggregate_accept_returns_candidate_for_threshold_partials() {
    let transcript = base_transcript();
    let partials = vec![
        accepted_partial(&transcript, ValidatorId(1), [11; 32]),
        accepted_partial(&transcript, ValidatorId(2), [12; 32]),
    ];
    let evidence = aggregate_evidence(&transcript);
    let expected_signature_digest = *evidence.standard_verifier.candidate_signature_digest();

    let accepted = AggregateAccept::accept(&transcript, &partials, evidence).unwrap();

    assert_eq!(accepted.signers(), &[ValidatorId(1), ValidatorId(2)]);
    assert_eq!(accepted.aggregate_response_digest(), &[31; 32]);
    assert_eq!(accepted.hint_digest(), &[32; 32]);
    assert_eq!(accepted.challenge_digest(), transcript.challenge_digest());
    assert_eq!(
        accepted.candidate_signature_digest(),
        &expected_signature_digest
    );
}

#[test]
fn aggregate_accept_rejects_insufficient_partials_for_threshold() {
    let transcript = base_transcript();
    let partials = vec![accepted_partial(&transcript, ValidatorId(1), [11; 32])];

    let err = AggregateAccept::accept(&transcript, &partials, aggregate_evidence(&transcript))
        .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::InsufficientPartialShares {
            required: 2,
            received: 1,
        }
    );
}

#[test]
fn aggregate_accept_rejects_duplicate_partial_signers() {
    let transcript = base_transcript();
    let partial = accepted_partial(&transcript, ValidatorId(1), [11; 32]);
    let partials = vec![partial, partial];

    let err = AggregateAccept::accept(&transcript, &partials, aggregate_evidence(&transcript))
        .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::DuplicateValidator {
            validator: ValidatorId(1),
        }
    );
}

#[test]
fn aggregate_accept_rejects_partial_signer_outside_active_set() {
    let transcript = base_transcript();
    let other_transcript = make_transcript(
        vec![ValidatorId(3), ValidatorId(4)],
        2,
        vec![(ValidatorId(3), [13; 32]), (ValidatorId(4), [14; 32])],
    );
    let partials = vec![
        accepted_partial(&transcript, ValidatorId(1), [11; 32]),
        accepted_partial(&other_transcript, ValidatorId(3), [13; 32]),
    ];

    let err = AggregateAccept::accept(&transcript, &partials, aggregate_evidence(&transcript))
        .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::UnknownValidator {
            validator: ValidatorId(3),
        }
    );
}

#[test]
fn aggregate_accept_rejects_partial_token_minted_for_different_transcript() {
    let transcript = base_transcript();
    let other_transcript = make_transcript(
        vec![ValidatorId(1), ValidatorId(2)],
        2,
        vec![(ValidatorId(1), [91; 32]), (ValidatorId(2), [12; 32])],
    );
    assert_ne!(
        transcript.challenge_digest(),
        other_transcript.challenge_digest()
    );
    let partials = vec![
        accepted_partial(&other_transcript, ValidatorId(1), [91; 32]),
        accepted_partial(&transcript, ValidatorId(2), [12; 32]),
    ];

    let err = AggregateAccept::accept(&transcript, &partials, aggregate_evidence(&transcript))
        .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::CommitmentVerificationFailed {
            validator: ValidatorId(1),
        }
    );
}

#[test]
fn aggregate_accept_rejects_all_zero_aggregate_response_digest() {
    let transcript = base_transcript();
    let partials = vec![
        accepted_partial(&transcript, ValidatorId(1), [11; 32]),
        accepted_partial(&transcript, ValidatorId(2), [12; 32]),
    ];
    let mut evidence = aggregate_evidence(&transcript);
    evidence.aggregate_response_digest = [0; 32];

    let err = AggregateAccept::accept(&transcript, &partials, evidence).unwrap_err();

    assert_eq!(
        err,
        ThresholdError::MalformedSerialization {
            reason: "aggregate response digest is all zero",
        }
    );
}

#[test]
fn aggregate_accept_rejects_partial_token_with_matching_commitment_but_different_challenge() {
    let transcript = base_transcript();
    let other_transcript = make_transcript_with_retry_counter(
        vec![ValidatorId(1), ValidatorId(2)],
        2,
        vec![(ValidatorId(1), [11; 32]), (ValidatorId(2), [12; 32])],
        1,
    );
    assert_ne!(
        transcript.challenge_digest(),
        other_transcript.challenge_digest()
    );
    let partials = vec![
        accepted_partial(&other_transcript, ValidatorId(1), [11; 32]),
        accepted_partial(&transcript, ValidatorId(2), [12; 32]),
    ];

    let err = AggregateAccept::accept(&transcript, &partials, aggregate_evidence(&transcript))
        .unwrap_err();

    assert_eq!(err, ThresholdError::TranscriptMismatch);
}

#[test]
fn aggregate_accept_rejects_all_zero_hint_digest() {
    let transcript = base_transcript();
    let partials = vec![
        accepted_partial(&transcript, ValidatorId(1), [11; 32]),
        accepted_partial(&transcript, ValidatorId(2), [12; 32]),
    ];
    let mut evidence = aggregate_evidence(&transcript);
    evidence.hint_digest = [0; 32];

    let err = AggregateAccept::accept(&transcript, &partials, evidence).unwrap_err();

    assert_eq!(
        err,
        ThresholdError::InvalidHintRoute {
            reason: "hint digest is all zero",
        }
    );
}

#[test]
fn aggregate_accept_rejects_verifier_token_minted_for_different_challenge() {
    let transcript = base_transcript();
    let verifier_transcript = make_transcript_with_retry_counter(
        vec![ValidatorId(1), ValidatorId(2)],
        2,
        vec![(ValidatorId(1), [11; 32]), (ValidatorId(2), [12; 32])],
        1,
    );
    let partials = vec![
        accepted_partial(&transcript, ValidatorId(1), [11; 32]),
        accepted_partial(&transcript, ValidatorId(2), [12; 32]),
    ];
    let evidence = AggregateAcceptEvidence {
        aggregate_response_digest: [31; 32],
        hint_digest: [32; 32],
        standard_verifier: StandardVerifierEvidence::verify::<AcceptingProvider>(
            &verifier_transcript,
            &ThresholdSignature([42; 3309]),
        )
        .unwrap(),
    };

    let err = AggregateAccept::accept(&transcript, &partials, evidence).unwrap_err();

    assert_eq!(err, ThresholdError::TranscriptMismatch);
}
