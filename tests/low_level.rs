use lattice_aggregation::{
    adapter::evidence::{
        EvidenceDecodeError, EvidenceKind, SlashingEvidence, SlashingEvidencePayload,
    },
    Commitment, CommitmentSet, Poly, PrivateKeyShare, SigningSession, ThresholdPublicKey,
    ValidatorId, N, Q,
};

#[test]
fn poly_addition_wraps_mod_q_without_allocation() {
    let mut left = Poly { coeffs: [Q - 1; N] };
    let right = Poly { coeffs: [1; N] };

    left.add_assign(&right);

    assert!(left.coeffs.iter().all(|coeff| *coeff == 0));
}

#[test]
fn poly_noise_bound_check_rejects_boundary_and_negative_overflow() {
    let mut poly = Poly::zero();
    poly.coeffs[0] = 12;
    poly.coeffs[1] = -12;

    assert!(poly.check_noise_bounds(13));
    assert!(!poly.check_noise_bounds(12));
    assert!(!poly.check_noise_bounds(0));
}

#[test]
fn slashing_evidence_payload_has_canonical_bytes() {
    let payload = SlashingEvidencePayload {
        block_height: 0x0102_0304_0506_0708,
        session_id: [0x11; 32],
        offending_validator_index: 0x1234,
        round_1_commitment: [0x22; 32],
        round_2_malicious_share: vec![0xAA, 0xBB],
        error_vector_proof: vec![0xCC],
    };

    let encoded = payload.encode();

    assert_eq!(&encoded[0..8], &0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(&encoded[8..40], &[0x11; 32]);
    assert_eq!(&encoded[40..42], &0x1234u16.to_be_bytes());
    assert_eq!(&encoded[42..74], &[0x22; 32]);
    assert_eq!(&encoded[74..78], &2u32.to_be_bytes());
    assert_eq!(&encoded[78..80], &[0xAA, 0xBB]);
    assert_eq!(&encoded[80..84], &1u32.to_be_bytes());
    assert_eq!(&encoded[84..85], &[0xCC]);
    assert_eq!(SlashingEvidencePayload::decode(&encoded).unwrap(), payload);
}

#[test]
fn local_evidence_maps_to_slashing_payload_schema() {
    let evidence = SlashingEvidence::new(
        [7; 32],
        ValidatorId(9),
        EvidenceKind::InvalidPartialSignature,
        Some(vec![1, 2, 3]),
        "invalid low-level share",
    );

    let payload = evidence.to_fraud_proof_payload(55, [8; 32], vec![4, 5], vec![6]);

    assert_eq!(payload.block_height, 55);
    assert_eq!(payload.session_id, [7; 32]);
    assert_eq!(payload.offending_validator_index, 9);
    assert_eq!(payload.round_1_commitment, [8; 32]);
    assert_eq!(payload.round_2_malicious_share, vec![4, 5]);
    assert_eq!(payload.error_vector_proof, vec![6]);
}

#[test]
fn slashing_evidence_payload_rejects_truncated_vectors() {
    let payload = SlashingEvidencePayload {
        block_height: 1,
        session_id: [2; 32],
        offending_validator_index: 3,
        round_1_commitment: [4; 32],
        round_2_malicious_share: vec![5, 6, 7],
        error_vector_proof: vec![8],
    };
    let mut encoded = payload.encode();
    encoded.pop();

    assert_eq!(
        SlashingEvidencePayload::decode(&encoded),
        Err(EvidenceDecodeError::InvalidVectorLength)
    );
}

#[test]
fn signing_state_exposes_polynomial_buffers() {
    let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
    let public_key = ThresholdPublicKey([4; 1952]);
    let share = PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec());
    let session = SigningSession::new([3; 32], 2, validators.clone(), public_key, share).unwrap();

    let (awaiting, local_commitment) = session.initiate_signing().unwrap();

    assert_eq!(awaiting.internal_state().local_y, Poly::zero());
    assert_eq!(awaiting.internal_state().local_commitment, local_commitment);
    assert!(awaiting.internal_state().received_commitments.is_empty());

    let commitments = CommitmentSet::new(
        validators,
        2,
        vec![
            (ValidatorId(1), local_commitment),
            (ValidatorId(2), Commitment([2; 32])),
        ],
    )
    .unwrap();
    let (awaiting_partials, _) = awaiting
        .generate_partial_signature(commitments, b"block")
        .unwrap();

    assert_eq!(
        awaiting_partials.internal_state().global_challenge,
        awaiting_partials.challenge()
    );
    assert!(awaiting_partials.internal_state().partial_shares.is_empty());
}
