#![cfg(feature = "hazmat-real-mldsa")]

use dytallix_pq_threshold::{
    mldsa65::{
        aggregate_mldsa65_masking_contributions, begin_mldsa65_threshold_attempt,
        derive_mldsa65_challenge_from_aggregated_masking,
        derive_mldsa65_expanded_secret_key_from_seed,
        derive_mldsa65_masking_contribution_from_share,
        derive_mldsa65_public_key_from_expanded_secret_key,
        derive_mldsa65_secret_contribution_from_expanded_secret_key,
        derive_mldsa65_secret_contribution_from_share,
        derive_mldsa65_session_challenge_once_quorum_met,
        finalize_mldsa65_session_signature_once_quorum_met, finalize_mldsa65_threshold_response,
        finalize_mldsa65_threshold_signature_attempt,
        reconstruct_mldsa65_expanded_secret_key_from_shares,
        reconstruct_mldsa65_secret_contribution_from_shares,
        sign_mldsa65_external_pure_deterministic_from_expanded_secret_key,
        split_mldsa65_expanded_secret_key, split_mldsa65_expanded_secret_key_with_vss_session,
        submit_mldsa65_masking_contribution, submit_mldsa65_secret_contribution,
        verify_mldsa65_internal_mu, Mldsa65ThresholdSigningPhase, MLDSA65_CHALLENGE_BYTES,
        MLDSA65_KEYGEN_SEED_BYTES, MLDSA65_MU_BYTES, MLDSA65_Z_NORM_BOUND,
    },
    Poly, ThresholdError, ThresholdPublicKey, ThresholdSignature, MLDSA65_SIGNATURE_BYTES, Q,
};

#[test]
fn expanded_secret_components_reconstruct_and_sign_identically() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(23).wrapping_add(5));
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");

    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");

    assert_eq!(shares.len(), 5);
    assert_eq!(shares[0].receiver_index(), 1);
    assert_eq!(shares[0].threshold(), 3);
    assert_eq!(shares[0].total_nodes(), 5);
    let dkg_digest = shares[0].dkg_public_commitment_digest();
    assert_ne!(dkg_digest, [0; 32]);
    assert!(
        shares
            .iter()
            .all(|share| share.dkg_public_commitment_digest() == dkg_digest),
        "all shares from one DKG transcript must bind the same public commitment digest"
    );
    assert!(
        shares
            .iter()
            .all(|share| share.vss_commitment_digest() != [0; 32]),
        "expanded-key shares must cross the checked VSS commitment boundary"
    );
    assert_ne!(shares[0].s1().polys()[0], shares[1].s1().polys()[0]);
    assert!(
        !format!("{:?}", shares[0]).contains("key_seed"),
        "debug output must not expose the expanded secret key's K component"
    );

    let active_shares = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let reconstructed_secret = reconstruct_mldsa65_expanded_secret_key_from_shares(&active_shares)
        .expect("reconstruct expanded secret key");

    assert_eq!(
        reconstructed_secret.as_bytes(),
        original_secret.as_bytes(),
        "reconstructed expanded secret key must match the original standard byte layout"
    );

    let message = b"real expanded secret threshold bridge";
    let context = b"threshold-bridge";
    let original_signature = sign_mldsa65_external_pure_deterministic_from_expanded_secret_key(
        original_secret.as_bytes(),
        message,
        context,
    )
    .expect("sign with original secret");
    let reconstructed_signature =
        sign_mldsa65_external_pure_deterministic_from_expanded_secret_key(
            reconstructed_secret.as_bytes(),
            message,
            context,
        )
        .expect("sign with reconstructed secret");

    assert_eq!(
        reconstructed_signature.as_bytes(),
        original_signature.as_bytes(),
        "reconstructed expanded key must preserve deterministic signing behavior"
    );
}

#[test]
fn expanded_secret_vss_commitment_digest_binds_split_session() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(21));
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let first_session = [0x51; 32];
    let second_session = [0x52; 32];

    let first = split_mldsa65_expanded_secret_key_with_vss_session(
        first_session,
        original_secret.as_bytes(),
        3,
        5,
    )
    .expect("split first VSS session");
    let second = split_mldsa65_expanded_secret_key_with_vss_session(
        second_session,
        original_secret.as_bytes(),
        3,
        5,
    )
    .expect("split second VSS session");

    assert_ne!(
        first[0].vss_commitment_digest(),
        second[0].vss_commitment_digest(),
        "VSS commitment transcript must bind the split session"
    );
    assert_eq!(
        first[0].dkg_public_commitment_digest(),
        second[0].dkg_public_commitment_digest(),
        "public DKG digest stays bound to key material, not local split session"
    );
}

#[test]
fn expanded_secret_dkg_commitment_digest_changes_with_key_transcript() {
    let first_seed = core::array::from_fn(|index| (index as u8).wrapping_mul(11).wrapping_add(3));
    let second_seed = core::array::from_fn(|index| (index as u8).wrapping_mul(13).wrapping_add(9));
    let first_secret = derive_mldsa65_expanded_secret_key_from_seed(&first_seed)
        .expect("derive first expanded secret key");
    let second_secret = derive_mldsa65_expanded_secret_key_from_seed(&second_seed)
        .expect("derive second expanded secret key");
    let first_shares = split_mldsa65_expanded_secret_key(first_secret.as_bytes(), 2, 3)
        .expect("split first expanded secret key");
    let second_shares = split_mldsa65_expanded_secret_key(second_secret.as_bytes(), 2, 3)
        .expect("split second expanded secret key");

    assert_ne!(
        first_shares[0].dkg_public_commitment_digest(),
        second_shares[0].dkg_public_commitment_digest(),
        "different expanded-key transcripts must not share a DKG commitment digest"
    );
}

#[test]
fn expanded_secret_reconstruction_rejects_insufficient_shares() {
    let seed = [7u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");

    let err = reconstruct_mldsa65_expanded_secret_key_from_shares(&shares[..2])
        .expect_err("two shares cannot reconstruct a 3-of-5 split");

    assert_eq!(
        err,
        ThresholdError::InsufficientPartialShares {
            required: 3,
            received: 2
        }
    );
}

#[test]
fn partial_secret_contributions_interpolate_to_centralized_signing_terms() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(11));
    let challenge = core::array::from_fn(|index| (index as u8).wrapping_mul(7).wrapping_add(3));
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let centralized = derive_mldsa65_secret_contribution_from_expanded_secret_key(
        original_secret.as_bytes(),
        &challenge,
    )
    .expect("derive centralized secret contribution");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");

    let partials = [0usize, 2, 4]
        .into_iter()
        .map(|index| {
            derive_mldsa65_secret_contribution_from_share(&shares[index], &challenge)
                .expect("derive partial secret contribution")
        })
        .collect::<Vec<_>>();
    let reconstructed = reconstruct_mldsa65_secret_contribution_from_shares(&partials)
        .expect("reconstruct secret contribution");

    assert_eq!(reconstructed.challenge(), centralized.challenge());
    assert_eq!(reconstructed.cs1(), centralized.cs1());
    assert_eq!(reconstructed.cs2(), centralized.cs2());
    assert_eq!(reconstructed.ct0(), centralized.ct0());
}

#[test]
fn partial_secret_contribution_reconstruction_rejects_challenge_mismatch() {
    let seed = [9u8; MLDSA65_KEYGEN_SEED_BYTES];
    let challenge_a = [0xA5u8; MLDSA65_CHALLENGE_BYTES];
    let challenge_b = [0x5Au8; MLDSA65_CHALLENGE_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 2, 3)
        .expect("split expanded secret key");

    let partial_a = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge_a)
        .expect("derive first partial contribution");
    let partial_b = derive_mldsa65_secret_contribution_from_share(&shares[1], &challenge_b)
        .expect("derive second partial contribution");

    let err = reconstruct_mldsa65_secret_contribution_from_shares(&[partial_a, partial_b])
        .expect_err("mismatched challenges must not reconstruct");

    assert!(matches!(err, ThresholdError::MalformedSerialization { .. }));
}

#[test]
fn masking_contributions_derive_challenge_and_bounded_threshold_response() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(17));
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");
    let active_shares = [&shares[0], &shares[2], &shares[4]];
    let masking_seed = [0x33u8; MLDSA65_MU_BYTES];
    let mu = [0x44u8; MLDSA65_MU_BYTES];

    let masking_contributions = active_shares
        .iter()
        .enumerate()
        .map(|(round, share)| {
            derive_mldsa65_masking_contribution_from_share(share, &masking_seed, round as u16)
                .expect("derive local masking contribution")
        })
        .collect::<Vec<_>>();
    let aggregate = aggregate_mldsa65_masking_contributions(&masking_contributions)
        .expect("aggregate masking contributions");

    let mut expected_y = aggregate.y().polys()[0];
    expected_y.coeffs = [0; dytallix_pq_threshold::N];
    for contribution in &masking_contributions {
        expected_y = add_poly_mod_q(&expected_y, &contribution.y().polys()[0]);
    }
    assert_eq!(aggregate.y().polys()[0], expected_y);

    let challenge = derive_mldsa65_challenge_from_aggregated_masking(&mu, &aggregate);
    let partial_secret_contributions = active_shares
        .iter()
        .map(|share| {
            derive_mldsa65_secret_contribution_from_share(share, &challenge)
                .expect("derive partial secret contribution")
        })
        .collect::<Vec<_>>();
    let secret_contribution =
        reconstruct_mldsa65_secret_contribution_from_shares(&partial_secret_contributions)
            .expect("reconstruct secret contribution");
    let response = finalize_mldsa65_threshold_response(&aggregate, &mu, &secret_contribution)
        .expect("finalize threshold response");

    assert_eq!(response.challenge(), &challenge);
    for poly in response.z().polys() {
        assert!(
            poly.check_noise_bounds(MLDSA65_Z_NORM_BOUND),
            "threshold z response must stay inside the ML-DSA-65 rejection bound"
        );
    }
}

#[test]
fn masking_contributions_are_domain_separated_by_validator() {
    let seed = [0x21u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 2, 3)
        .expect("split expanded secret key");
    let masking_seed = [0x77u8; MLDSA65_MU_BYTES];

    let first = derive_mldsa65_masking_contribution_from_share(&shares[0], &masking_seed, 0)
        .expect("derive first contribution");
    let second = derive_mldsa65_masking_contribution_from_share(&shares[1], &masking_seed, 0)
        .expect("derive second contribution");

    assert_ne!(
        first.y(),
        second.y(),
        "same signing round must still produce validator-distinct masking vectors"
    );
    assert_ne!(
        first.w(),
        second.w(),
        "same signing round must still produce validator-distinct commitment vectors"
    );
}

#[test]
fn masking_contribution_rejects_counter_overflow_without_panic() {
    let seed = [0x22u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 2, 3)
        .expect("split expanded secret key");
    let masking_seed = [0x88u8; MLDSA65_MU_BYTES];

    let result =
        derive_mldsa65_masking_contribution_from_share(&shares[0], &masking_seed, u16::MAX / 5);

    assert!(matches!(
        result,
        Err(ThresholdError::MalformedSerialization { .. })
    ));
}

#[test]
fn threshold_response_rejects_stale_secret_challenge() {
    let seed = [0x23u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 2, 3)
        .expect("split expanded secret key");
    let active_shares = [&shares[0], &shares[1]];
    let masking_seed = [0x99u8; MLDSA65_MU_BYTES];
    let mu = [0xAAu8; MLDSA65_MU_BYTES];

    let masking_contributions = active_shares
        .iter()
        .map(|share| {
            derive_mldsa65_masking_contribution_from_share(share, &masking_seed, 0)
                .expect("derive local masking contribution")
        })
        .collect::<Vec<_>>();
    let aggregate = aggregate_mldsa65_masking_contributions(&masking_contributions)
        .expect("aggregate masking contributions");
    let mut stale_challenge = derive_mldsa65_challenge_from_aggregated_masking(&mu, &aggregate);
    stale_challenge[0] ^= 0x01;
    let partial_secret_contributions = active_shares
        .iter()
        .map(|share| {
            derive_mldsa65_secret_contribution_from_share(share, &stale_challenge)
                .expect("derive partial secret contribution")
        })
        .collect::<Vec<_>>();
    let secret_contribution =
        reconstruct_mldsa65_secret_contribution_from_shares(&partial_secret_contributions)
            .expect("reconstruct stale secret contribution");

    let err = finalize_mldsa65_threshold_response(&aggregate, &mu, &secret_contribution)
        .expect_err("stale challenge must be rejected before signature packing");

    assert!(matches!(err, ThresholdError::TranscriptMismatch));
}

#[test]
fn threshold_signature_attempt_packs_and_verifies_with_standard_internal_mu_path() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(41).wrapping_add(19));
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let public_key = ThresholdPublicKey(
        *derive_mldsa65_public_key_from_expanded_secret_key(original_secret.as_bytes())
            .expect("derive public key")
            .as_bytes(),
    );
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");
    let active_shares = [&shares[0], &shares[2], &shares[4]];
    let mu = [0x66u8; MLDSA65_MU_BYTES];

    let mut accepted_signature = None;
    for attempt in 0..64u8 {
        let masking_seed = [attempt; MLDSA65_MU_BYTES];
        let masking_contributions = active_shares
            .iter()
            .enumerate()
            .map(|(round, share)| {
                derive_mldsa65_masking_contribution_from_share(share, &masking_seed, round as u16)
                    .expect("derive local masking contribution")
            })
            .collect::<Vec<_>>();
        let aggregate = aggregate_mldsa65_masking_contributions(&masking_contributions)
            .expect("aggregate masking contributions");
        let challenge = derive_mldsa65_challenge_from_aggregated_masking(&mu, &aggregate);
        let partial_secret_contributions = active_shares
            .iter()
            .map(|share| {
                derive_mldsa65_secret_contribution_from_share(share, &challenge)
                    .expect("derive partial secret contribution")
            })
            .collect::<Vec<_>>();
        let secret_contribution =
            reconstruct_mldsa65_secret_contribution_from_shares(&partial_secret_contributions)
                .expect("reconstruct secret contribution");

        if let Ok(signature) =
            finalize_mldsa65_threshold_signature_attempt(&aggregate, &mu, &secret_contribution)
        {
            accepted_signature = Some(signature);
            break;
        }
    }

    let signature = accepted_signature.expect("one deterministic masking retry should pass");
    assert_eq!(signature.as_bytes().len(), MLDSA65_SIGNATURE_BYTES);

    let signature = ThresholdSignature(*signature.as_bytes());
    assert!(
        verify_mldsa65_internal_mu(&public_key, &mu, &signature)
            .expect("standard internal-mu verification should run"),
        "threshold signature attempt must verify through the standard ML-DSA-65 verifier"
    );
}

#[test]
fn threshold_signature_attempt_reports_rejection_for_bad_masking_sample() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(41).wrapping_add(19));
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");
    let active_shares = [&shares[0], &shares[2], &shares[4]];
    let mu = [0x66u8; MLDSA65_MU_BYTES];

    let mut rejected = None;
    for attempt in 0..64u8 {
        let masking_seed = [attempt; MLDSA65_MU_BYTES];
        let masking_contributions = active_shares
            .iter()
            .map(|share| {
                derive_mldsa65_masking_contribution_from_share(share, &masking_seed, 0)
                    .expect("derive local masking contribution")
            })
            .collect::<Vec<_>>();
        let aggregate = aggregate_mldsa65_masking_contributions(&masking_contributions)
            .expect("aggregate masking contributions");
        let challenge = derive_mldsa65_challenge_from_aggregated_masking(&mu, &aggregate);
        let partial_secret_contributions = active_shares
            .iter()
            .map(|share| {
                derive_mldsa65_secret_contribution_from_share(share, &challenge)
                    .expect("derive partial secret contribution")
            })
            .collect::<Vec<_>>();
        let secret_contribution =
            reconstruct_mldsa65_secret_contribution_from_shares(&partial_secret_contributions)
                .expect("reconstruct secret contribution");

        if let Err(err) =
            finalize_mldsa65_threshold_signature_attempt(&aggregate, &mu, &secret_contribution)
        {
            rejected = Some(err);
            break;
        }
    }

    assert!(matches!(
        rejected.expect("one deterministic masking retry should be rejected"),
        ThresholdError::RejectionSamplingFailed { .. }
    ));
}

#[test]
fn threshold_session_ideal_3_of_5_flow_emits_standard_verifying_signature() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(43).wrapping_add(21));
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let public_key = ThresholdPublicKey(
        *derive_mldsa65_public_key_from_expanded_secret_key(original_secret.as_bytes())
            .expect("derive public key")
            .as_bytes(),
    );
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");
    let active_shares = [&shares[0], &shares[2], &shares[4]];
    let mu = [0xC1u8; MLDSA65_MU_BYTES];

    let mut accepted_signature = None;
    for attempt_id in 0..64u8 {
        let mut session =
            begin_mldsa65_threshold_attempt(3, 5, mu).expect("begin threshold signing session");
        let masking_seed = [attempt_id; MLDSA65_MU_BYTES];
        for share in active_shares {
            let contribution =
                derive_mldsa65_masking_contribution_from_share(share, &masking_seed, 0)
                    .expect("derive masking contribution");
            submit_mldsa65_masking_contribution(&mut session, contribution)
                .expect("submit masking contribution");
        }

        let challenge = derive_mldsa65_session_challenge_once_quorum_met(&mut session)
            .expect("derive session challenge");
        assert_eq!(
            session.phase(),
            Mldsa65ThresholdSigningPhase::AwaitingSecretContributions
        );
        for share in active_shares {
            let contribution = derive_mldsa65_secret_contribution_from_share(share, &challenge)
                .expect("derive secret contribution");
            submit_mldsa65_secret_contribution(&mut session, contribution)
                .expect("submit secret contribution");
        }

        match finalize_mldsa65_session_signature_once_quorum_met(&mut session) {
            Ok(signature) => {
                assert_eq!(session.phase(), Mldsa65ThresholdSigningPhase::Finalized);
                accepted_signature = Some(signature);
                break;
            }
            Err(ThresholdError::RejectionSamplingFailed { .. }) => {
                assert_eq!(session.phase(), Mldsa65ThresholdSigningPhase::Rejected);
            }
            Err(err) => panic!("unexpected session finalization error: {err:?}"),
        }
    }

    let signature = accepted_signature.expect("one threshold session retry should pass");
    assert_eq!(signature.as_bytes().len(), MLDSA65_SIGNATURE_BYTES);
    assert!(verify_mldsa65_internal_mu(
        &public_key,
        &mu,
        &ThresholdSignature(*signature.as_bytes())
    )
    .expect("standard internal-mu verification should run"));
}

#[test]
fn threshold_session_rejects_out_of_order_secret_contribution() {
    let seed = [0x31u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 2, 3)
        .expect("split expanded secret key");
    let challenge = [0xA1u8; MLDSA65_CHALLENGE_BYTES];
    let contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");
    let mut session =
        begin_mldsa65_threshold_attempt(2, 3, [0xB1u8; MLDSA65_MU_BYTES]).expect("begin session");

    let err = submit_mldsa65_secret_contribution(&mut session, contribution)
        .expect_err("secret contribution before challenge must fail");

    assert!(matches!(err, ThresholdError::TranscriptMismatch));
}

#[test]
fn threshold_session_rejects_duplicate_masking_contribution() {
    let seed = [0x32u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 2, 3)
        .expect("split expanded secret key");
    let masking_seed = [0xB2u8; MLDSA65_MU_BYTES];
    let contribution = derive_mldsa65_masking_contribution_from_share(&shares[0], &masking_seed, 0)
        .expect("derive masking contribution");
    let mut session =
        begin_mldsa65_threshold_attempt(2, 3, [0xC2u8; MLDSA65_MU_BYTES]).expect("begin session");

    submit_mldsa65_masking_contribution(&mut session, contribution)
        .expect("first contribution should be accepted");
    let err = submit_mldsa65_masking_contribution(&mut session, contribution)
        .expect_err("duplicate contribution must fail");

    assert_eq!(
        err,
        ThresholdError::DuplicateValidator {
            validator: dytallix_pq_threshold::ValidatorId(1)
        }
    );
}

#[test]
fn threshold_session_rejects_challenge_derivation_before_masking_quorum_without_phase_change() {
    let mut session =
        begin_mldsa65_threshold_attempt(3, 5, [0xD1u8; MLDSA65_MU_BYTES]).expect("begin session");

    let err = derive_mldsa65_session_challenge_once_quorum_met(&mut session)
        .expect_err("challenge derivation before masking quorum must fail");

    assert_eq!(
        err,
        ThresholdError::InsufficientCommitments {
            required: 3,
            received: 0
        }
    );
    assert_eq!(
        session.phase(),
        Mldsa65ThresholdSigningPhase::AwaitingMaskingContributions
    );
}

#[test]
fn threshold_session_rejects_duplicate_secret_contribution() {
    let seed = [0x34u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 2, 3)
        .expect("split expanded secret key");
    let active_shares = [&shares[0], &shares[1]];
    let masking_seed = [0xD2u8; MLDSA65_MU_BYTES];
    let mut session =
        begin_mldsa65_threshold_attempt(2, 3, [0xD3u8; MLDSA65_MU_BYTES]).expect("begin session");
    for share in active_shares {
        let contribution = derive_mldsa65_masking_contribution_from_share(share, &masking_seed, 0)
            .expect("derive masking contribution");
        submit_mldsa65_masking_contribution(&mut session, contribution)
            .expect("submit masking contribution");
    }
    let challenge = derive_mldsa65_session_challenge_once_quorum_met(&mut session)
        .expect("derive session challenge");
    let contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");

    submit_mldsa65_secret_contribution(&mut session, contribution)
        .expect("first secret contribution should be accepted");
    let err = submit_mldsa65_secret_contribution(&mut session, contribution)
        .expect_err("duplicate secret contribution must fail");

    assert_eq!(
        err,
        ThresholdError::DuplicateValidator {
            validator: dytallix_pq_threshold::ValidatorId(1)
        }
    );
}

#[test]
fn threshold_session_rejects_finalize_before_secret_quorum_without_phase_change() {
    let seed = [0x35u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");
    let active_shares = [&shares[0], &shares[2], &shares[4]];
    let masking_seed = [0xD4u8; MLDSA65_MU_BYTES];
    let mut session =
        begin_mldsa65_threshold_attempt(3, 5, [0xD5u8; MLDSA65_MU_BYTES]).expect("begin session");
    for share in active_shares {
        let contribution = derive_mldsa65_masking_contribution_from_share(share, &masking_seed, 0)
            .expect("derive masking contribution");
        submit_mldsa65_masking_contribution(&mut session, contribution)
            .expect("submit masking contribution");
    }
    let challenge = derive_mldsa65_session_challenge_once_quorum_met(&mut session)
        .expect("derive session challenge");
    let contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");
    submit_mldsa65_secret_contribution(&mut session, contribution)
        .expect("first secret contribution should be accepted");

    let err = finalize_mldsa65_session_signature_once_quorum_met(&mut session)
        .expect_err("finalization before secret quorum must fail");

    assert_eq!(
        err,
        ThresholdError::InsufficientPartialShares {
            required: 3,
            received: 1
        }
    );
    assert_eq!(
        session.phase(),
        Mldsa65ThresholdSigningPhase::AwaitingSecretContributions
    );
}

#[test]
fn threshold_session_rejects_stale_challenge_contribution() {
    let seed = [0x33u8; MLDSA65_KEYGEN_SEED_BYTES];
    let original_secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let shares = split_mldsa65_expanded_secret_key(original_secret.as_bytes(), 2, 3)
        .expect("split expanded secret key");
    let active_shares = [&shares[0], &shares[1]];
    let masking_seed = [0xB3u8; MLDSA65_MU_BYTES];
    let mut session =
        begin_mldsa65_threshold_attempt(2, 3, [0xC3u8; MLDSA65_MU_BYTES]).expect("begin session");
    for share in active_shares {
        let contribution = derive_mldsa65_masking_contribution_from_share(share, &masking_seed, 0)
            .expect("derive masking contribution");
        submit_mldsa65_masking_contribution(&mut session, contribution)
            .expect("submit masking contribution");
    }
    let mut stale_challenge = derive_mldsa65_session_challenge_once_quorum_met(&mut session)
        .expect("derive session challenge");
    stale_challenge[0] ^= 0x01;
    let stale_contribution =
        derive_mldsa65_secret_contribution_from_share(&shares[0], &stale_challenge)
            .expect("derive stale contribution");

    let err = submit_mldsa65_secret_contribution(&mut session, stale_contribution)
        .expect_err("stale challenge contribution must fail");

    assert!(matches!(err, ThresholdError::TranscriptMismatch));
}

fn add_poly_mod_q(lhs: &Poly, rhs: &Poly) -> Poly {
    let mut coeffs = [0i32; dytallix_pq_threshold::N];
    for (out, (left, right)) in coeffs
        .iter_mut()
        .zip(lhs.coeffs.iter().zip(rhs.coeffs.iter()))
    {
        let mut sum = *left + *right;
        sum %= Q;
        if sum < 0 {
            sum += Q;
        }
        *out = sum;
    }
    Poly::from_coeffs(coeffs)
}
