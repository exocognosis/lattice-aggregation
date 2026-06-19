#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::production::transcript::{
    CommitmentDigest, ProductionSigningTranscript, ProductionTranscriptInput,
};
use lattice_aggregation::production::types::{
    ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
    ProtocolProfile, ValidatorSetDigest,
};
use lattice_aggregation::{ThresholdError, ThresholdPublicKey, ValidatorId};

#[test]
fn production_context_types_have_stable_bytes() {
    assert_eq!(
        ProtocolProfile::coordinator_assisted_v1().as_bytes(),
        b"mldsa65-coordinator-v1"
    );
    assert_eq!(EpochId(7).to_be_bytes(), 7u64.to_be_bytes());
    assert_eq!(KeyId([1; 32]).as_bytes(), &[1; 32]);
    assert_eq!(AttemptId([2; 32]).as_bytes(), &[2; 32]);
    assert_eq!(ValidatorSetDigest([3; 32]).as_bytes(), &[3; 32]);
    assert_eq!(DkgTranscriptDigest([4; 32]).as_bytes(), &[4; 32]);
    assert_eq!(MessageBinding([5; 64]).as_bytes(), &[5; 64]);
}

#[test]
fn active_signer_set_is_canonical() {
    let active =
        ActiveSignerSet::new(vec![ValidatorId(3), ValidatorId(1), ValidatorId(2)]).unwrap();
    assert_eq!(
        active.as_slice(),
        &[ValidatorId(1), ValidatorId(2), ValidatorId(3)]
    );
}

#[test]
fn active_signer_set_rejects_duplicates() {
    let err = ActiveSignerSet::new(vec![ValidatorId(1), ValidatorId(1)]).unwrap_err();
    assert!(err.to_string().contains("duplicate validator 1"));
}

fn transcript_input(
    attempt_byte: u8,
    commitments: Vec<(ValidatorId, [u8; 32])>,
) -> ProductionTranscriptInput {
    ProductionTranscriptInput {
        session_id: [9; 32],
        epoch: EpochId(11),
        key_id: KeyId([12; 32]),
        validator_set_digest: ValidatorSetDigest([13; 32]),
        dkg_transcript_digest: DkgTranscriptDigest([14; 32]),
        active_signers: ActiveSignerSet::new(vec![ValidatorId(2), ValidatorId(1)]).unwrap(),
        threshold: 2,
        public_key: ThresholdPublicKey([15; 1952]),
        message_binding: MessageBinding([16; 64]),
        attempt_id: AttemptId([attempt_byte; 32]),
        coordinator_attestation_digest: [17; 32],
        retry_counter: 0,
        commitment_digests: commitments
            .into_iter()
            .map(|(validator, digest)| (validator, CommitmentDigest(digest)))
            .collect(),
    }
}

fn challenge_digest(input: ProductionTranscriptInput) -> [u8; 32] {
    *ProductionSigningTranscript::new(input)
        .unwrap()
        .challenge_digest()
}

#[test]
fn production_transcript_is_order_independent() {
    let a = ProductionSigningTranscript::new(transcript_input(
        21,
        vec![(ValidatorId(2), [2; 32]), (ValidatorId(1), [1; 32])],
    ))
    .unwrap();
    let b = ProductionSigningTranscript::new(transcript_input(
        21,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(2), [2; 32])],
    ))
    .unwrap();
    assert_eq!(a.challenge_digest(), b.challenge_digest());
}

#[test]
fn production_transcript_binds_attempt_id() {
    let a = ProductionSigningTranscript::new(transcript_input(
        21,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(2), [2; 32])],
    ))
    .unwrap();
    let b = ProductionSigningTranscript::new(transcript_input(
        22,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(2), [2; 32])],
    ))
    .unwrap();
    assert_ne!(a.challenge_digest(), b.challenge_digest());
}

#[test]
fn production_transcript_rejects_commitment_from_inactive_signer() {
    let err = ProductionSigningTranscript::new(transcript_input(
        21,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(3), [3; 32])],
    ))
    .unwrap_err();
    assert!(err.to_string().contains("transcript mismatch"));
}

#[test]
fn production_transcript_rejects_invalid_thresholds() {
    let mut zero = transcript_input(
        21,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(2), [2; 32])],
    );
    zero.threshold = 0;
    assert_eq!(
        ProductionSigningTranscript::new(zero).unwrap_err(),
        ThresholdError::InvalidThresholdParameters {
            threshold: 0,
            total_nodes: 2,
        }
    );

    let mut too_large = transcript_input(
        21,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(2), [2; 32])],
    );
    too_large.threshold = 3;
    assert_eq!(
        ProductionSigningTranscript::new(too_large).unwrap_err(),
        ThresholdError::InvalidThresholdParameters {
            threshold: 3,
            total_nodes: 2,
        }
    );
}

#[test]
fn production_transcript_rejects_duplicate_commitment_validator() {
    let err = ProductionSigningTranscript::new(transcript_input(
        21,
        vec![
            (ValidatorId(1), [1; 32]),
            (ValidatorId(1), [9; 32]),
            (ValidatorId(2), [2; 32]),
        ],
    ))
    .unwrap_err();
    assert_eq!(
        err,
        ThresholdError::DuplicateValidator {
            validator: ValidatorId(1),
        }
    );
}

#[test]
fn production_transcript_rejects_insufficient_commitments() {
    let err =
        ProductionSigningTranscript::new(transcript_input(21, vec![(ValidatorId(1), [1; 32])]))
            .unwrap_err();
    assert_eq!(
        err,
        ThresholdError::InsufficientCommitments {
            required: 2,
            received: 1,
        }
    );
}

#[test]
fn production_transcript_binds_representative_context_fields() {
    let base = transcript_input(
        21,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(2), [2; 32])],
    );
    let base_digest = challenge_digest(base.clone());

    let mut changed_message = base.clone();
    changed_message.message_binding = MessageBinding([99; 64]);
    assert_ne!(base_digest, challenge_digest(changed_message));

    let mut changed_public_key = base.clone();
    changed_public_key.public_key = ThresholdPublicKey([98; 1952]);
    assert_ne!(base_digest, challenge_digest(changed_public_key));

    let mut changed_active_set = base.clone();
    changed_active_set.active_signers =
        ActiveSignerSet::new(vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]).unwrap();
    assert_ne!(base_digest, challenge_digest(changed_active_set));

    let mut changed_retry = base.clone();
    changed_retry.retry_counter = 1;
    assert_ne!(base_digest, challenge_digest(changed_retry));

    let mut changed_commitment = base;
    changed_commitment.commitment_digests[0].1 = CommitmentDigest([97; 32]);
    assert_ne!(base_digest, challenge_digest(changed_commitment));
}
