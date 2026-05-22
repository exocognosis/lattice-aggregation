use dytallix_pq_threshold::{
    Commitment, CommitmentSet, Mldsa65Backend, PartialShareSet, PrivateKeyShare, SigningTranscript,
    SimulatedBackend, ThresholdError, ThresholdPublicKey, ValidatorId,
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
