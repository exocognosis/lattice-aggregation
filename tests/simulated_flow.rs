use dytallix_pq_threshold::{
    Commitment, CommitmentSet, Mldsa65Backend, PartialShareSet, PartialSignatureShare,
    PrivateKeyShare, SignatureAggregator, SigningSession, SigningTranscript, SimulatedAggregator,
    SimulatedBackend, SimulatedDkg, ThresholdError, ThresholdKeyGeneration, ThresholdPublicKey,
    ThresholdSigner, ThresholdSigningTranscript, ValidatorId,
};

#[test]
fn simulated_backend_derives_repeatable_commitment() {
    let share = PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec());
    let public_key = ThresholdPublicKey([5; 1952]);
    let commitments = CommitmentSet::new(
        vec![ValidatorId(1), ValidatorId(2)],
        1,
        vec![(ValidatorId(1), Commitment([1; 32]))],
    )
    .unwrap();
    let transcript = SigningTranscript::new(
        [8; 32],
        1,
        vec![ValidatorId(1), ValidatorId(2)],
        public_key,
        b"message",
        commitments,
    )
    .unwrap();

    let (left, _) = SimulatedBackend::derive_commitment(&share, &transcript).unwrap();
    let (right, _) = SimulatedBackend::derive_commitment(&share, &transcript).unwrap();

    assert_eq!(left, right);
}

#[test]
fn simulated_backend_uses_planned_signing_api_shape() {
    let share = PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec());
    let public_key = ThresholdPublicKey([5; 1952]);
    let commitments = CommitmentSet::new(
        vec![ValidatorId(1), ValidatorId(2)],
        1,
        vec![(ValidatorId(1), Commitment([1; 32]))],
    )
    .unwrap();
    let transcript = SigningTranscript::new(
        [8; 32],
        1,
        vec![ValidatorId(1), ValidatorId(2)],
        public_key.clone(),
        b"message",
        commitments,
    )
    .unwrap();

    let (_, secret) = SimulatedBackend::derive_commitment(&share, &transcript).unwrap();
    let partial = SimulatedBackend::partial_sign(&share, secret, &transcript).unwrap();
    let shares =
        PartialShareSet::new(vec![ValidatorId(1), ValidatorId(2)], 1, vec![partial]).unwrap();
    let signature = SimulatedBackend::aggregate(&public_key, &transcript, shares).unwrap();
    let verification: Result<bool, ThresholdError> =
        SimulatedBackend::verify_standard(&public_key, b"message", &signature);

    assert_eq!(
        verification.unwrap_err(),
        ThresholdError::BackendUnavailable {
            reason: "simulation backend does not implement standard ML-DSA verification"
        }
    );
}

#[test]
fn simulated_backend_rejects_aggregate_public_key_mismatch() {
    let transcript_public_key = ThresholdPublicKey([5; 1952]);
    let mismatched_public_key = ThresholdPublicKey([6; 1952]);
    let commitments = CommitmentSet::new(
        vec![ValidatorId(1), ValidatorId(2)],
        1,
        vec![(ValidatorId(1), Commitment([1; 32]))],
    )
    .unwrap();
    let transcript = SigningTranscript::new(
        [8; 32],
        1,
        vec![ValidatorId(1), ValidatorId(2)],
        transcript_public_key,
        b"message",
        commitments,
    )
    .unwrap();
    let shares = PartialShareSet::new(
        vec![ValidatorId(1), ValidatorId(2)],
        1,
        vec![PartialSignatureShare {
            signer: ValidatorId(1),
            bytes: vec![1, 2, 3],
        }],
    )
    .unwrap();

    let result = SimulatedBackend::aggregate(&mismatched_public_key, &transcript, shares);

    assert_eq!(result.unwrap_err(), ThresholdError::TranscriptMismatch);
}

#[test]
fn simulated_backend_aggregates_canonical_share_order_deterministically() {
    let public_key = ThresholdPublicKey([5; 1952]);
    let commitments = CommitmentSet::new(
        vec![ValidatorId(1), ValidatorId(2)],
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();
    let transcript = SigningTranscript::new(
        [8; 32],
        2,
        vec![ValidatorId(1), ValidatorId(2)],
        public_key.clone(),
        b"message",
        commitments,
    )
    .unwrap();
    let first = PartialSignatureShare {
        signer: ValidatorId(1),
        bytes: vec![1, 2, 3],
    };
    let second = PartialSignatureShare {
        signer: ValidatorId(2),
        bytes: vec![4, 5, 6],
    };
    let left = PartialShareSet::new(
        vec![ValidatorId(1), ValidatorId(2)],
        2,
        vec![second.clone(), first.clone()],
    )
    .unwrap();
    let left_order: Vec<_> = left.iter().map(|(id, _)| *id).collect();
    let right =
        PartialShareSet::new(vec![ValidatorId(1), ValidatorId(2)], 2, vec![first, second]).unwrap();

    assert_eq!(left_order, vec![ValidatorId(1), ValidatorId(2)]);

    let left_signature = SimulatedBackend::aggregate(&public_key, &transcript, left).unwrap();
    let right_signature = SimulatedBackend::aggregate(&public_key, &transcript, right).unwrap();

    assert_eq!(left_signature, right_signature);
}

#[test]
fn signing_session_advances_through_commitment_and_partial_rounds() {
    let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
    let public_key = ThresholdPublicKey([4; 1952]);
    let share = PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec());
    let session = SigningSession::new([3; 32], 2, validators.clone(), public_key, share).unwrap();

    let (awaiting, local_commitment) = session.initiate_signing().unwrap();
    let commitments = CommitmentSet::new(
        validators,
        2,
        vec![
            (ValidatorId(1), local_commitment),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();

    let (awaiting_partials, partial) =
        SigningSession::generate_partial_signature(awaiting, commitments, b"block payload")
            .unwrap();

    assert_eq!(partial.signer, ValidatorId(1));
    assert_eq!(awaiting_partials.challenge().0.len(), 32);
}

#[test]
fn signing_session_rejects_mismatched_local_commitment() {
    let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
    let public_key = ThresholdPublicKey([4; 1952]);
    let share = PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec());
    let session = SigningSession::new([3; 32], 2, validators.clone(), public_key, share).unwrap();

    let (awaiting, _) = session.initiate_signing().unwrap();
    let commitments = CommitmentSet::new(
        validators,
        2,
        vec![
            (ValidatorId(1), Commitment([9; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();

    let result =
        SigningSession::generate_partial_signature(awaiting, commitments, b"block payload");

    assert_eq!(
        result.unwrap_err(),
        ThresholdError::CommitmentVerificationFailed {
            validator: ValidatorId(1)
        }
    );
}

#[test]
fn simulated_dkg_sign_and_aggregate_flow_returns_standard_size_signature() {
    let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
    let session_id = [11; 32];

    let dkg_commitment = SimulatedDkg::generate_share_commitment(session_id, 3).unwrap();
    let dkg_shares = CommitmentSet::new(
        validators.clone(),
        2,
        vec![
            (ValidatorId(1), dkg_commitment),
            (ValidatorId(2), Commitment([22; 32])),
        ],
    )
    .unwrap();
    let public_key = SimulatedDkg::finalize_public_key(dkg_shares).unwrap();

    let share_1 = PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec());
    let share_2 = PrivateKeyShare::new(ValidatorId(2), b"share-2".to_vec());
    let session_1 = SigningSession::new(
        session_id,
        2,
        validators.clone(),
        public_key.clone(),
        share_1,
    )
    .unwrap();
    let session_2 = SigningSession::new(
        session_id,
        2,
        validators.clone(),
        public_key.clone(),
        share_2,
    )
    .unwrap();

    let (awaiting_1, commitment_1) = session_1.initiate_signing().unwrap();
    let (awaiting_2, commitment_2) = session_2.initiate_signing().unwrap();
    let commitments = CommitmentSet::new(
        validators.clone(),
        2,
        vec![
            (ValidatorId(1), commitment_1),
            (ValidatorId(2), commitment_2),
        ],
    )
    .unwrap();

    let (state_1, partial_1) =
        SigningSession::generate_partial_signature(awaiting_1, commitments.clone(), b"block")
            .unwrap();
    let (_, partial_2) =
        SigningSession::generate_partial_signature(awaiting_2, commitments.clone(), b"block")
            .unwrap();
    let transcript = ThresholdSigningTranscript::new(
        session_id,
        2,
        validators.clone(),
        public_key,
        b"block",
        commitments,
    )
    .unwrap();

    assert_eq!(state_1.challenge(), transcript.challenge());

    let shares = PartialShareSet::new(validators, 2, vec![partial_1, partial_2]).unwrap();
    let signature = SimulatedAggregator::aggregate_shares(transcript, shares).unwrap();

    assert_eq!(signature.0.len(), 3309);
}

#[test]
fn simulated_aggregator_rejects_partial_share_validator_universe_mismatch() {
    let transcript_validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
    let public_key = ThresholdPublicKey([7; 1952]);
    let commitments = CommitmentSet::new(
        transcript_validators.clone(),
        2,
        vec![
            (ValidatorId(1), Commitment([1; 32])),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();
    let transcript = ThresholdSigningTranscript::new(
        [9; 32],
        2,
        transcript_validators,
        public_key,
        b"message",
        commitments,
    )
    .unwrap();
    let shares = PartialShareSet::new(
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(4)],
        2,
        vec![
            PartialSignatureShare {
                signer: ValidatorId(1),
                bytes: vec![1, 2, 3],
            },
            PartialSignatureShare {
                signer: ValidatorId(2),
                bytes: vec![4, 5, 6],
            },
        ],
    )
    .unwrap();

    let result = SimulatedAggregator::aggregate_shares(transcript, shares);

    assert_eq!(result.unwrap_err(), ThresholdError::TranscriptMismatch);
}

#[test]
fn simulated_dkg_public_key_binds_full_validator_universe() {
    let commitments = vec![
        (ValidatorId(1), Commitment([1; 32])),
        (ValidatorId(2), Commitment([2; 32])),
    ];
    let first = CommitmentSet::new(
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
        2,
        commitments.clone(),
    )
    .unwrap();
    let second = CommitmentSet::new(
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(4)],
        2,
        commitments,
    )
    .unwrap();

    let first_public_key = SimulatedDkg::finalize_public_key(first).unwrap();
    let second_public_key = SimulatedDkg::finalize_public_key(second).unwrap();

    assert_ne!(first_public_key, second_public_key);
}
