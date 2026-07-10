#![cfg(feature = "raw-real-mldsa")]

//! End-to-end tests for the real ML-DSA-65 seed-reconstruction backend.

use lattice_aggregation::{
    aggregate_with_backend,
    backend::Mldsa65Backend,
    collections::{CommitmentSet, PartialShareSet},
    RealAggregator, RealMldsa65Backend, RealMldsaConstruction, SignatureAggregator, SigningSession,
    SigningTranscript, ValidatorId, MLDSA65_SIGNATURE_BYTES, SEED_SHARE_DOMAIN_DEFAULT,
};

#[test]
fn real_backend_construction_is_seed_reconstruction() {
    assert_eq!(
        RealMldsa65Backend::construction(),
        RealMldsaConstruction::ThresholdSeedReconstruction
    );
    assert_eq!(
        RealMldsa65Backend::construction().core_mode(),
        "threshold_seed_reconstruction_mldsa65_provider"
    );
}

#[test]
fn real_aggregator_emits_standard_verifying_mldsa65_signature() {
    let seed = [0x7E; 32];
    let validators = vec![
        ValidatorId(0),
        ValidatorId(1),
        ValidatorId(2),
        ValidatorId(3),
    ];
    let threshold = 3u16;
    let (public_key, key_shares) = RealMldsa65Backend::split_seed_shares(
        &seed,
        threshold,
        &validators,
        SEED_SHARE_DOMAIN_DEFAULT,
    )
    .expect("split seed shares");

    let session_id = [0xCCu8; 32];
    let message = b"real aggregator standard-verifier bridge";

    let active: Vec<_> = key_shares.into_iter().take(threshold as usize).collect();
    let mut commitment_pairs = Vec::new();
    for share in &active {
        let (commitment, _secret) = RealMldsa65Backend::derive_commitment(
            share,
            &precommit_transcript(session_id, &public_key, share.share_id, &validators),
        )
        .expect("commitment");
        commitment_pairs.push((share.share_id, commitment));
    }

    let commitments = CommitmentSet::new(validators.clone(), threshold, commitment_pairs)
        .expect("commitment set");
    let transcript = SigningTranscript::new(
        session_id,
        threshold,
        validators.clone(),
        public_key.clone(),
        message,
        commitments,
    )
    .expect("transcript");

    let mut partials = Vec::new();
    for share in &active {
        let (_c, secret) =
            RealMldsa65Backend::derive_commitment(share, &transcript).expect("rebind");
        partials
            .push(RealMldsa65Backend::partial_sign(share, secret, &transcript).expect("partial"));
    }

    let share_set = PartialShareSet::new(validators, threshold, partials).expect("partial set");
    let signature = RealAggregator::aggregate_shares(transcript, share_set).expect("aggregate");

    assert_eq!(signature.0.len(), MLDSA65_SIGNATURE_BYTES);
    assert!(
        RealMldsa65Backend::verify_standard(&public_key, message, &signature).unwrap(),
        "standard ML-DSA-65 verifier must accept the aggregate"
    );
    assert!(
        !RealMldsa65Backend::verify_standard(&public_key, b"wrong message", &signature).unwrap(),
        "standard verifier must reject a different message"
    );
}

#[test]
fn type_state_session_with_real_backend_aggregates_verifying_signature() {
    let seed = [0x3C; 32];
    let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
    let threshold = 2u16;
    let (public_key, key_shares) = RealMldsa65Backend::split_seed_shares(
        &seed,
        threshold,
        &validators,
        SEED_SHARE_DOMAIN_DEFAULT,
    )
    .unwrap();
    let session_id = [0xEEu8; 32];
    let message = b"parameterized SigningSession real backend";

    let mut commit_pairs = Vec::new();
    let mut sessions = Vec::new();
    for share in key_shares.iter().take(threshold as usize) {
        let session = SigningSession::<_, RealMldsa65Backend>::with_backend(
            session_id,
            threshold,
            validators.clone(),
            public_key.clone(),
            share.clone(),
        )
        .unwrap();
        let (awaiting, commitment) = session.initiate_signing().unwrap();
        commit_pairs.push((share.share_id, commitment));
        sessions.push(awaiting);
    }

    let commitment_set = CommitmentSet::new(validators.clone(), threshold, commit_pairs).unwrap();
    let mut partials = Vec::new();
    for session in sessions {
        let (_done, partial) = session
            .generate_partial_signature(commitment_set.clone(), message)
            .unwrap();
        partials.push(partial);
    }

    let share_set = PartialShareSet::new(validators.clone(), threshold, partials).unwrap();
    let transcript = SigningTranscript::new(
        session_id,
        threshold,
        validators,
        public_key.clone(),
        message,
        commitment_set,
    )
    .unwrap();
    let signature = aggregate_with_backend::<RealMldsa65Backend>(transcript, share_set).unwrap();
    assert!(RealMldsa65Backend::verify_standard(&public_key, message, &signature).unwrap());
}

#[test]
fn subthreshold_shares_fail_closed() {
    let seed = [0x19; 32];
    let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
    let threshold = 3u16;
    let (public_key, key_shares) = RealMldsa65Backend::split_seed_shares(
        &seed,
        threshold,
        &validators,
        SEED_SHARE_DOMAIN_DEFAULT,
    )
    .unwrap();

    let session_id = [1u8; 32];
    let message = b"need all three";
    let two = key_shares[..2].to_vec();
    let t2 = 2u16;
    let mut pairs = Vec::new();
    for share in &two {
        let (c, _) = RealMldsa65Backend::derive_commitment(
            share,
            &precommit_transcript(session_id, &public_key, share.share_id, &validators),
        )
        .unwrap();
        pairs.push((share.share_id, c));
    }
    let commitments = CommitmentSet::new(validators.clone(), t2, pairs).unwrap();
    let transcript = SigningTranscript::new(
        session_id,
        t2,
        validators.clone(),
        public_key.clone(),
        message,
        commitments,
    )
    .unwrap();

    let one_partial = {
        let share = &two[0];
        let (_c, secret) = RealMldsa65Backend::derive_commitment(share, &transcript).unwrap();
        RealMldsa65Backend::partial_sign(share, secret, &transcript).unwrap()
    };

    let err = PartialShareSet::new(validators, t2, vec![one_partial]).unwrap_err();
    assert!(matches!(
        err,
        lattice_aggregation::ThresholdError::InsufficientPartialShares { .. }
    ));
}

fn precommit_transcript(
    session_id: [u8; 32],
    public_key: &lattice_aggregation::ThresholdPublicKey,
    local: ValidatorId,
    validators: &[ValidatorId],
) -> SigningTranscript {
    use lattice_aggregation::Commitment;

    let commitments =
        CommitmentSet::new(validators.to_vec(), 1, vec![(local, Commitment([0; 32]))]).unwrap();
    SigningTranscript::new(
        session_id,
        1,
        validators.to_vec(),
        public_key.clone(),
        b"precommit",
        commitments,
    )
    .unwrap()
}
