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
fn challenge_binds_session_id_and_public_key() {
    let commitments = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();

    let baseline = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        commitments.clone(),
    )
    .unwrap();
    let different_session = SigningTranscript::new(
        session(8),
        2,
        validators(),
        public_key(),
        b"block-42",
        commitments.clone(),
    )
    .unwrap();
    let mut public_key_bytes = [9u8; 1952];
    public_key_bytes[0] ^= 0x01;
    let different_public_key = SigningTranscript::new(
        session(7),
        2,
        validators(),
        ThresholdPublicKey(public_key_bytes),
        b"block-42",
        commitments,
    )
    .unwrap();

    assert_ne!(baseline.challenge(), different_session.challenge());
    assert_ne!(baseline.challenge(), different_public_key.challenge());
}

#[test]
fn challenge_binds_threshold_validator_set_and_commitment_bytes() {
    let baseline_commitments = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();
    let baseline = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        baseline_commitments.clone(),
    )
    .unwrap();

    let higher_threshold_commitments = CommitmentSet::new(
        validators(),
        3,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
            (ValidatorId(3), Commitment([3; 32])),
        ],
    )
    .unwrap();
    let higher_threshold = SigningTranscript::new(
        session(7),
        3,
        validators(),
        public_key(),
        b"block-42",
        higher_threshold_commitments,
    )
    .unwrap();

    let different_validator_set = vec![ValidatorId(1), ValidatorId(2), ValidatorId(4)];
    let different_validator_commitments = CommitmentSet::new(
        different_validator_set.clone(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();
    let different_validator = SigningTranscript::new(
        session(7),
        2,
        different_validator_set,
        public_key(),
        b"block-42",
        different_validator_commitments,
    )
    .unwrap();

    let different_commitment_bytes = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([0xA2; 32])),
        ],
    )
    .unwrap();
    let different_commitment = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        different_commitment_bytes,
    )
    .unwrap();

    assert_ne!(baseline.challenge(), higher_threshold.challenge());
    assert_ne!(baseline.challenge(), different_validator.challenge());
    assert_ne!(baseline.challenge(), different_commitment.challenge());
}

#[test]
fn challenge_binds_active_commitment_set_with_same_validator_universe() {
    let left_commitments = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();
    let right_commitments = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(3), Commitment([3; 32])),
        ],
    )
    .unwrap();

    let left = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        left_commitments,
    )
    .unwrap();
    let right = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        right_commitments,
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
