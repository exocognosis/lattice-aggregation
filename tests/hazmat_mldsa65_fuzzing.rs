#![cfg(feature = "hazmat-real-mldsa")]

use std::time::Duration;

use dytallix_pq_threshold::{
    adapter::{actor::HazmatMldsa65ActorSession, wire::PqcThresholdWireMsg},
    mldsa65::{
        derive_mldsa65_expanded_secret_key_from_seed,
        derive_mldsa65_masking_contribution_from_share,
        derive_mldsa65_public_key_from_expanded_secret_key,
        derive_mldsa65_secret_contribution_from_share, encode_mldsa65_masking_contribution,
        encode_mldsa65_secret_contribution, masking_commitment_digest, secret_commitment_digest,
        split_mldsa65_expanded_secret_key, verify_mldsa65_internal_mu, MLDSA65_CHALLENGE_BYTES,
        MLDSA65_MU_BYTES,
    },
    utils::hazmat_fuzz::{
        deterministic_wire_mutations, run_actor_event_permutation_corpus,
        verify_decode_is_stable_or_rejected,
    },
    ThresholdError, ThresholdPublicKey, ThresholdSignature, MLDSA65_SIGNATURE_BYTES,
};

#[test]
fn hazmat_wire_mutation_corpus_is_stably_rejected_or_round_trips() {
    let frames = sample_hazmat_frames();

    for frame in frames {
        let encoded = frame.encode();
        assert!(
            verify_decode_is_stable_or_rejected(&encoded),
            "valid frame should be stable"
        );

        for mutation in deterministic_wire_mutations(&encoded) {
            assert!(
                verify_decode_is_stable_or_rejected(&mutation.bytes),
                "mutation '{}' should reject or decode stably",
                mutation.label
            );
        }
    }
}

#[test]
fn hazmat_actor_event_permutation_corpus_rejects_out_of_order_sequences() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(41).wrapping_add(3));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");

    let summary = run_actor_event_permutation_corpus(&shares, [0xA1; MLDSA65_MU_BYTES])
        .expect("permutation corpus should run");

    assert!(summary.rejected_out_of_order_sequences >= 2);
    assert_eq!(summary.unexpected_finalizations, 0);
}

#[test]
fn hazmat_actor_finalizes_under_reordered_honest_contributions() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(47).wrapping_add(25));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret key");
    let public_key = ThresholdPublicKey(
        *derive_mldsa65_public_key_from_expanded_secret_key(secret.as_bytes())
            .expect("derive public key")
            .as_bytes(),
    );
    let shares = split_mldsa65_expanded_secret_key(secret.as_bytes(), 3, 5)
        .expect("split expanded secret key");
    let mu = [0xD1u8; MLDSA65_MU_BYTES];
    let orders = [
        [0usize, 2, 4],
        [4usize, 0, 2],
        [2usize, 4, 0],
        [4usize, 2, 0],
    ];

    for (case, order) in orders.into_iter().enumerate() {
        let mut accepted = None;
        for attempt_id in 0..64u8 {
            let mut actor_session = HazmatMldsa65ActorSession::new(
                [attempt_id.wrapping_add(case as u8); 32],
                99,
                3,
                5,
                mu,
                Duration::from_secs(2),
            )
            .expect("create actor session");
            let masking_seed = [attempt_id; MLDSA65_MU_BYTES];
            for share_index in order {
                actor_session
                    .submit_masking_contribution(
                        derive_mldsa65_masking_contribution_from_share(
                            &shares[share_index],
                            &masking_seed,
                            0,
                        )
                        .expect("derive masking contribution"),
                    )
                    .expect("submit masking contribution");
            }
            let challenge = actor_session.derive_challenge().expect("derive challenge");
            for share_index in order.into_iter().rev() {
                actor_session
                    .submit_secret_contribution(
                        derive_mldsa65_secret_contribution_from_share(
                            &shares[share_index],
                            &challenge,
                        )
                        .expect("derive secret contribution"),
                    )
                    .expect("submit secret contribution");
            }

            match actor_session.finalize_signature() {
                Ok((_height, signature)) => {
                    accepted = Some(signature);
                    break;
                }
                Err(ThresholdError::RejectionSamplingFailed { .. }) => {}
                Err(err) => panic!("unexpected actor session error: {err:?}"),
            }
        }

        let signature = accepted.expect("one reordered retry should pass");
        assert_eq!(signature.len(), MLDSA65_SIGNATURE_BYTES);
        let signature = ThresholdSignature(signature.try_into().expect("signature length"));
        assert!(verify_mldsa65_internal_mu(&public_key, &mu, &signature)
            .expect("standard internal-mu verification should run"));
    }
}

fn sample_hazmat_frames() -> Vec<PqcThresholdWireMsg> {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(9));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let masking =
        derive_mldsa65_masking_contribution_from_share(&shares[0], &[0x71; MLDSA65_MU_BYTES], 0)
            .expect("derive masking");
    let masking_payload = encode_mldsa65_masking_contribution(&masking);
    let challenge = [0x72; MLDSA65_CHALLENGE_BYTES];
    let secret_contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");
    let secret_payload = encode_mldsa65_secret_contribution(&secret_contribution);

    vec![
        PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment {
            session_id: [0x80; 32],
            block_height: 1,
            attempt: 0,
            validator_index: masking.receiver_index(),
            commitment: masking_commitment_digest(
                &[0x80; 32],
                1,
                0,
                masking.receiver_index(),
                &masking_payload,
            ),
        },
        PqcThresholdWireMsg::HazmatMldsa65MaskingContribution {
            session_id: [0x81; 32],
            block_height: 1,
            attempt: 0,
            validator_index: masking.receiver_index(),
            payload: masking_payload,
        },
        PqcThresholdWireMsg::HazmatMldsa65Challenge {
            session_id: [0x82; 32],
            block_height: 2,
            attempt: 0,
            challenge,
        },
        PqcThresholdWireMsg::HazmatMldsa65SecretCommitment {
            session_id: [0x83; 32],
            block_height: 3,
            attempt: 0,
            validator_index: secret_contribution.receiver_index(),
            challenge,
            commitment: secret_commitment_digest(
                &[0x83; 32],
                3,
                0,
                secret_contribution.receiver_index(),
                &challenge,
                &secret_payload,
            ),
        },
        PqcThresholdWireMsg::HazmatMldsa65SecretContribution {
            session_id: [0x83; 32],
            block_height: 3,
            attempt: 0,
            validator_index: secret_contribution.receiver_index(),
            challenge,
            payload: secret_payload,
        },
    ]
}
