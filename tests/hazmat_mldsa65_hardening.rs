#![cfg(feature = "hazmat-real-mldsa")]

use dytallix_pq_threshold::{
    crypto::{
        interpolation::{try_reconstruct_secret_poly, try_reconstruct_secret_poly_with_threshold},
        vss::split_secret_poly,
    },
    mldsa65::{
        decode_mldsa65_masking_contribution, decode_mldsa65_secret_contribution,
        derive_mldsa65_expanded_secret_key_from_seed,
        derive_mldsa65_masking_contribution_from_share,
        derive_mldsa65_secret_contribution_from_share, encode_mldsa65_masking_contribution,
        encode_mldsa65_secret_contribution, split_mldsa65_expanded_secret_key,
        MLDSA65_CHALLENGE_BYTES, MLDSA65_MU_BYTES,
    },
    Poly, ThresholdError, Q,
};

#[test]
fn deterministic_vss_reconstructs_many_threshold_subsets() {
    for threshold in 2..=4 {
        let total_nodes = threshold + 2;
        let mut secret = Poly::zero();
        for (index, coeff) in secret.coeffs.iter_mut().enumerate() {
            *coeff = ((index as i32 * 97) + i32::from(threshold) * 13) % Q;
        }

        let shares = split_secret_poly(&secret, threshold, total_nodes);
        for start in 0..=usize::from(total_nodes - threshold) {
            let subset = shares[start..start + usize::from(threshold)]
                .iter()
                .map(|share| (share.receiver_index, share.polynomial_share))
                .collect::<Vec<_>>();
            let reconstructed = try_reconstruct_secret_poly_with_threshold(&subset, threshold)
                .expect("checked reconstruction should succeed");

            assert_eq!(
                reconstructed, secret,
                "failed reconstruction for threshold {threshold} subset starting at {start}"
            );
        }
    }
}

#[test]
fn checked_vss_reconstructs_nonconsecutive_threshold_subsets() {
    let mut secret = Poly::zero();
    for (index, coeff) in secret.coeffs.iter_mut().enumerate() {
        *coeff = ((index as i32 * 113) + 19) % Q;
    }

    let shares = split_secret_poly(&secret, 3, 5);
    for subset_indices in [&[0usize, 1, 4][..], &[0, 2, 4], &[1, 3, 4], &[0, 1, 2, 4]] {
        let subset = subset_indices
            .iter()
            .map(|index| {
                let share = &shares[*index];
                (share.receiver_index, share.polynomial_share)
            })
            .collect::<Vec<_>>();

        let reconstructed =
            try_reconstruct_secret_poly(&subset).expect("checked reconstruction should succeed");

        assert_eq!(
            reconstructed, secret,
            "failed reconstruction for nonconsecutive subset {subset_indices:?}"
        );
    }
}

#[test]
fn checked_vss_reconstruction_rejects_zero_and_duplicate_indices() {
    let shares = split_secret_poly(&Poly::zero(), 2, 3);

    let zero_index_subset = vec![
        (0, shares[0].polynomial_share),
        (2, shares[1].polynomial_share),
    ];
    assert_malformed_serialization(try_reconstruct_secret_poly(&zero_index_subset));

    let duplicate_index_subset = vec![
        (shares[0].receiver_index, shares[0].polynomial_share),
        (shares[0].receiver_index, shares[1].polynomial_share),
    ];
    assert_eq!(
        try_reconstruct_secret_poly(&duplicate_index_subset),
        Err(ThresholdError::DuplicateValidator {
            validator: dytallix_pq_threshold::ValidatorId(shares[0].receiver_index)
        })
    );
}

#[test]
fn checked_vss_reconstruction_rejects_subsets_below_threshold() {
    let shares = split_secret_poly(&Poly::zero(), 3, 5);
    let too_few = vec![
        (shares[0].receiver_index, shares[0].polynomial_share),
        (shares[2].receiver_index, shares[2].polynomial_share),
    ];

    assert_eq!(
        try_reconstruct_secret_poly_with_threshold(&too_few, 3),
        Err(ThresholdError::InsufficientPartialShares {
            required: 3,
            received: 2
        })
    );
    assert_eq!(
        try_reconstruct_secret_poly_with_threshold(&too_few, 0),
        Err(ThresholdError::InvalidThresholdParameters {
            threshold: 0,
            total_nodes: 2
        })
    );
}

#[test]
fn hazmat_contribution_decoders_reject_noncanonical_coefficients() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(23).wrapping_add(17));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");

    let masking =
        derive_mldsa65_masking_contribution_from_share(&shares[0], &[0xA7; MLDSA65_MU_BYTES], 0)
            .expect("derive masking");
    let mut masking_payload = encode_mldsa65_masking_contribution(&masking);
    // First coefficient after receiver/threshold/total/rho metadata.
    let first_masking_coeff_offset = 2 + 2 + 2 + 32;
    masking_payload[first_masking_coeff_offset..first_masking_coeff_offset + 4]
        .copy_from_slice(&Q.to_be_bytes());
    assert_malformed_serialization(decode_mldsa65_masking_contribution(&masking_payload));

    let challenge = [0xB8; MLDSA65_CHALLENGE_BYTES];
    let secret_contribution = derive_mldsa65_secret_contribution_from_share(&shares[0], &challenge)
        .expect("derive secret contribution");
    let mut secret_payload = encode_mldsa65_secret_contribution(&secret_contribution);
    // First coefficient after receiver/threshold/total/challenge metadata.
    let first_secret_coeff_offset = 2 + 2 + 2 + MLDSA65_CHALLENGE_BYTES;
    secret_payload[first_secret_coeff_offset..first_secret_coeff_offset + 4]
        .copy_from_slice(&(-1i32).to_be_bytes());
    assert_malformed_serialization(decode_mldsa65_secret_contribution(&secret_payload));
}

#[test]
fn hazmat_contribution_decoders_reject_truncated_and_extended_payloads() {
    let seed = core::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(11));
    let secret =
        derive_mldsa65_expanded_secret_key_from_seed(&seed).expect("derive expanded secret");
    let shares =
        split_mldsa65_expanded_secret_key(secret.as_bytes(), 2, 3).expect("split secret key");
    let masking =
        derive_mldsa65_masking_contribution_from_share(&shares[0], &[0xC9; MLDSA65_MU_BYTES], 0)
            .expect("derive masking");
    let masking_payload = encode_mldsa65_masking_contribution(&masking);

    assert_malformed_serialization(decode_mldsa65_masking_contribution(
        &masking_payload[..masking_payload.len() - 1],
    ));
    let mut extended_masking = masking_payload;
    extended_masking.push(0);
    assert_malformed_serialization(decode_mldsa65_masking_contribution(&extended_masking));

    let secret_contribution =
        derive_mldsa65_secret_contribution_from_share(&shares[0], &[0xDA; MLDSA65_CHALLENGE_BYTES])
            .expect("derive secret contribution");
    let secret_payload = encode_mldsa65_secret_contribution(&secret_contribution);

    assert_malformed_serialization(decode_mldsa65_secret_contribution(
        &secret_payload[..secret_payload.len() - 1],
    ));
    let mut extended_secret = secret_payload;
    extended_secret.push(0);
    assert_malformed_serialization(decode_mldsa65_secret_contribution(&extended_secret));
}

fn assert_malformed_serialization<T>(result: Result<T, ThresholdError>) {
    assert!(matches!(
        result,
        Err(ThresholdError::MalformedSerialization { .. })
    ));
}
