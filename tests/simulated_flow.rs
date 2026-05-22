use dytallix_pq_threshold::{
    Commitment, CommitmentSet, Mldsa65Backend, PartialShareSet, PartialSignatureShare,
    PrivateKeyShare, SigningTranscript, SimulatedBackend, ThresholdError, ThresholdPublicKey,
    ValidatorId,
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
