#![cfg(feature = "hazmat-real-mldsa")]

use std::time::Duration;

use dytallix_pq_threshold::{
    adapter::actor::HazmatMldsa65ActorSession,
    mldsa65::{
        derive_mldsa65_expanded_secret_key_from_seed,
        derive_mldsa65_masking_contribution_from_share,
        derive_mldsa65_public_key_from_expanded_secret_key,
        derive_mldsa65_secret_contribution_from_share, split_mldsa65_expanded_secret_key,
        verify_mldsa65_internal_mu, Mldsa65ThresholdSigningPhase, MLDSA65_MU_BYTES,
    },
    ThresholdError, ThresholdPublicKey, ThresholdSignature, MLDSA65_SIGNATURE_BYTES,
};

#[test]
fn hazmat_actor_session_finalizes_standard_verifying_signature() {
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
    let active_shares = [&shares[0], &shares[2], &shares[4]];
    let mu = [0xD1u8; MLDSA65_MU_BYTES];

    let mut accepted = None;
    for attempt_id in 0..64u8 {
        let mut actor_session =
            HazmatMldsa65ActorSession::new([attempt_id; 32], 99, 3, 5, mu, Duration::from_secs(2))
                .expect("create hazmat actor session");
        let masking_seed = [attempt_id; MLDSA65_MU_BYTES];
        for share in active_shares {
            actor_session
                .submit_masking_contribution(
                    derive_mldsa65_masking_contribution_from_share(share, &masking_seed, 0)
                        .expect("derive masking contribution"),
                )
                .expect("submit masking contribution");
        }
        let challenge = actor_session.derive_challenge().expect("derive challenge");
        for share in active_shares {
            actor_session
                .submit_secret_contribution(
                    derive_mldsa65_secret_contribution_from_share(share, &challenge)
                        .expect("derive secret contribution"),
                )
                .expect("submit secret contribution");
        }

        match actor_session.finalize_signature() {
            Ok((height, signature)) => {
                assert_eq!(height, 99);
                assert_eq!(
                    actor_session.phase(),
                    Mldsa65ThresholdSigningPhase::Finalized
                );
                accepted = Some(signature);
                break;
            }
            Err(ThresholdError::RejectionSamplingFailed { .. }) => {
                assert_eq!(
                    actor_session.phase(),
                    Mldsa65ThresholdSigningPhase::Rejected
                );
            }
            Err(err) => panic!("unexpected actor session error: {err:?}"),
        }
    }

    let signature = accepted.expect("one actor-session retry should pass");
    assert_eq!(signature.len(), MLDSA65_SIGNATURE_BYTES);
    let signature = ThresholdSignature(signature.try_into().expect("standard signature length"));
    assert!(verify_mldsa65_internal_mu(&public_key, &mu, &signature)
        .expect("standard internal-mu verification should run"));
}

#[test]
fn hazmat_actor_session_reports_timeout_without_finalizing() {
    let mut actor_session = HazmatMldsa65ActorSession::new(
        [0xE1; 32],
        100,
        2,
        3,
        [0xE2; MLDSA65_MU_BYTES],
        Duration::ZERO,
    )
    .expect("create hazmat actor session");

    assert!(actor_session.is_timed_out());
    let err = actor_session
        .finalize_signature()
        .expect_err("cannot finalize before threshold contributions");

    assert!(matches!(err, ThresholdError::TranscriptMismatch));
}
