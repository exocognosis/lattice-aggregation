use dytallix_pq_threshold::{
    Commitment, CommitmentSet, SigningTranscript, ThresholdError, ThresholdPublicKey, ValidatorId,
};

fn public_key() -> ThresholdPublicKey {
    ThresholdPublicKey([9u8; 1952])
}

fn session(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn validators() -> Vec<ValidatorId> {
    vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]
}

#[test]
fn challenge_is_independent_of_network_order() {
    let left = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(3), Commitment([3; 32])),
            (ValidatorId(1), Commitment([1; 32])),
        ],
    )
    .unwrap();
    let right = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(3), Commitment([3; 32])),
        ],
    )
    .unwrap();

    let left_transcript =
        SigningTranscript::new(session(7), 2, validators(), public_key(), b"block-42", left)
            .unwrap();
    let right_transcript = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        right,
    )
    .unwrap();

    assert_eq!(left_transcript.challenge(), right_transcript.challenge());
}

#[test]
fn challenge_binds_message() {
    let commitments = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();

    let left = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        commitments.clone(),
    )
    .unwrap();
    let right = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-43",
        commitments,
    )
    .unwrap();

    assert_ne!(left.challenge(), right.challenge());
}

#[test]
fn transcript_rejects_duplicate_validator_set() {
    let commitments = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();

    let result = SigningTranscript::new(
        session(7),
        2,
        vec![ValidatorId(1), ValidatorId(1), ValidatorId(2)],
        public_key(),
        b"block-42",
        commitments,
    );

    assert_eq!(
        result.unwrap_err(),
        ThresholdError::DuplicateValidator {
            validator: ValidatorId(1)
        }
    );
}

#[test]
fn transcript_rejects_commitment_validator_universe_mismatch() {
    let commitments = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();

    let result = SigningTranscript::new(
        session(7),
        2,
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(4)],
        public_key(),
        b"block-42",
        commitments,
    );

    assert_eq!(result.unwrap_err(), ThresholdError::TranscriptMismatch);
}
