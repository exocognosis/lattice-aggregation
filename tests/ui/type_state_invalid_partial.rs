use dytallix_pq_threshold::{
    Commitment, CommitmentSet, PrivateKeyShare, SigningSession, ThresholdPublicKey,
    ThresholdSigner, ValidatorId,
};

fn main() {
    let validators = vec![ValidatorId(1), ValidatorId(2)];
    let session = SigningSession::new(
        [1; 32],
        1,
        validators.clone(),
        ThresholdPublicKey([1; 1952]),
        PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec()),
    )
    .unwrap();
    let commitments = CommitmentSet::new(
        validators,
        1,
        vec![(ValidatorId(1), Commitment([1; 32]))],
    )
    .unwrap();

    let _ = SigningSession::generate_partial_signature(session, commitments, b"message");
}
