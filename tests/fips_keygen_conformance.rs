#![cfg(feature = "raw-real-mldsa")]

//! Provider-parity checks for the shared, centralized FIPS 204 KeyGen
//! primitives.
//!
//! These tests deliberately do not claim distributed key generation: each
//! fixture begins with a complete 32-byte seed. Their purpose is to pin the
//! byte-exact 1,952-byte public-key target that a future distributed derivation
//! must reproduce.

use lattice_aggregation::{
    crypto::{
        fips_public_key::{
            aggregate_public_key_from_t_shares, evaluate_public_t_share, FipsModuleSecretShare65,
            FipsPublicKeyContext65, FipsPublicTShare65, ShareAggregation, MLDSA65_K, MLDSA65_L,
        },
        poly::{Poly, N, Q},
    },
    keygen_from_seed, ThresholdError, ValidatorId, MLDSA65_PUBLICKEY_BYTES,
};
use ml_dsa::{Keypair, MlDsa65, SigningKey};

#[test]
fn centralized_fips_keygen_matches_standard_provider_for_fixed_seed_corpus() {
    let seeds = [
        [0x00; 32],
        [0x11; 32],
        [0x80; 32],
        core::array::from_fn(|index| index as u8),
        core::array::from_fn(|index| 0xff_u8.wrapping_sub(index as u8)),
    ];

    for seed in seeds {
        let derived = keygen_from_seed(&seed).expect("centralized reference KeyGen must succeed");
        let provider = SigningKey::<MlDsa65>::from_seed(&seed.into());
        let provider_public_key = provider.verifying_key().encode();

        assert_eq!(derived.public_key.0.len(), MLDSA65_PUBLICKEY_BYTES);
        assert_eq!(MLDSA65_PUBLICKEY_BYTES, 1_952);
        assert_eq!(
            derived.public_key.0.as_slice(),
            provider_public_key.as_slice(),
            "public-key bytes must match ml-dsa for fixed seed {seed:02x?}"
        );
    }
}

#[test]
fn centralized_fips_keygen_is_deterministic_and_seed_separating() {
    let first_seed = [0x42; 32];
    let second_seed = [0x43; 32];

    let first = keygen_from_seed(&first_seed).expect("first KeyGen");
    let repeated = keygen_from_seed(&first_seed).expect("repeated KeyGen");
    let second = keygen_from_seed(&second_seed).expect("second KeyGen");

    assert_eq!(first.public_key, repeated.public_key);
    assert_ne!(first.public_key, second.public_key);
}

#[test]
fn supplied_additive_shares_match_provider_and_are_order_invariant() {
    let seeds = [
        [0x00; 32],
        [0x11; 32],
        [0x80; 32],
        core::array::from_fn(|index| index as u8),
        core::array::from_fn(|index| 0xff_u8.wrapping_sub(index as u8)),
    ];
    for seed in seeds {
        let fixture = keygen_from_seed(&seed).expect("centralized conformance fixture");
        let context = FipsPublicKeyContext65::new(fixture.rho, [0xc1; 32]);
        let provider = SigningKey::<MlDsa65>::from_seed(&seed.into());
        let provider_public_key = provider.verifying_key().encode();
        let [first_s1, second_s1, third_s1] = split_additive_three(&fixture.s1, 17);
        let [first_s2, second_s2, third_s2] = split_additive_three(&fixture.s2, 29);
        let secret_shares = [
            FipsModuleSecretShare65::new(1, first_s1, first_s2).unwrap(),
            FipsModuleSecretShare65::new(2, second_s1, second_s2).unwrap(),
            FipsModuleSecretShare65::new(3, third_s1, third_s2).unwrap(),
        ];
        let public_shares: [FipsPublicTShare65; 3] = secret_shares
            .each_ref()
            .map(|share| evaluate_public_t_share(&context, share));

        let forward = aggregate_public_key_from_t_shares(
            &context,
            &public_shares,
            ShareAggregation::Additive { expected_shares: 3 },
        )
        .expect("complete additive share set");
        let reordered = [
            public_shares[2].clone(),
            public_shares[0].clone(),
            public_shares[1].clone(),
        ];
        let backward = aggregate_public_key_from_t_shares(
            &context,
            &reordered,
            ShareAggregation::Additive { expected_shares: 3 },
        )
        .expect("reordered complete additive share set");

        assert_eq!(forward, backward, "share input order must be irrelevant");
        assert_eq!(forward.public_key().0.len(), 1_952);
        // This end-to-end byte comparison pins result equivalence even though
        // the shared low-level NTT uses a different internal representation
        // and ordering from the standard provider.
        assert_eq!(
            forward.public_key().0.as_slice(),
            provider_public_key.as_slice(),
            "supplied-share derivation must reproduce the standard provider key"
        );
    }
}

#[test]
fn shamir_threshold_subsets_match_provider_but_subthreshold_fails_closed() {
    let seed = [0x5c; 32];
    let fixture = keygen_from_seed(&seed).expect("centralized conformance fixture");
    let context = FipsPublicKeyContext65::new(fixture.rho, [0xc2; 32]);
    let provider = SigningKey::<MlDsa65>::from_seed(&seed.into());
    let provider_public_key = provider.verifying_key().encode();
    let mut public_shares = Vec::new();
    for receiver_index in 1..=4 {
        let s1 = evaluate_shamir_share(&fixture.s1, receiver_index, 41);
        let s2 = evaluate_shamir_share(&fixture.s2, receiver_index, 73);
        let share = FipsModuleSecretShare65::new(receiver_index, s1, s2).unwrap();
        public_shares.push(evaluate_public_t_share(&context, &share));
    }

    for indices in [[0, 1, 2], [3, 1, 0], [1, 3, 2]] {
        let subset = indices.map(|index| public_shares[index].clone());
        let derived = aggregate_public_key_from_t_shares(
            &context,
            &subset,
            ShareAggregation::ShamirAtZero { threshold: 3 },
        )
        .expect("every three-share subset reconstructs the same public image");
        assert_eq!(
            derived.public_key().0.as_slice(),
            provider_public_key.as_slice()
        );
    }

    assert_eq!(
        aggregate_public_key_from_t_shares(
            &context,
            &public_shares[..2],
            ShareAggregation::ShamirAtZero { threshold: 3 },
        ),
        Err(ThresholdError::InsufficientPartialShares {
            required: 3,
            received: 2,
        })
    );
}

#[test]
fn committee8_threshold6_shamir_subsets_match_standard_provider() {
    let seed = [0x68; 32];
    let fixture = keygen_from_seed(&seed).expect("centralized conformance fixture");
    let context = FipsPublicKeyContext65::new(fixture.rho, [0xc8; 32]);
    let provider = SigningKey::<MlDsa65>::from_seed(&seed.into());
    let provider_public_key = provider.verifying_key().encode();
    let mut public_shares = Vec::new();
    for receiver_index in 1..=8 {
        let s1 = evaluate_shamir_share_with_degree(&fixture.s1, receiver_index, 89, 5);
        let s2 = evaluate_shamir_share_with_degree(&fixture.s2, receiver_index, 131, 5);
        let share = FipsModuleSecretShare65::new(receiver_index, s1, s2).unwrap();
        public_shares.push(evaluate_public_t_share(&context, &share));
    }

    for indices in [[0, 1, 2, 3, 4, 5], [2, 3, 4, 5, 6, 7], [7, 0, 6, 2, 5, 3]] {
        let subset = indices.map(|index| public_shares[index].clone());
        let derived = aggregate_public_key_from_t_shares(
            &context,
            &subset,
            ShareAggregation::ShamirAtZero { threshold: 6 },
        )
        .expect("every six-share committee subset reconstructs the public image");
        assert_eq!(derived.context(), &context);
        assert_eq!(
            derived.public_key().0.as_slice(),
            provider_public_key.as_slice()
        );
    }

    assert_eq!(
        aggregate_public_key_from_t_shares(
            &context,
            &public_shares[..5],
            ShareAggregation::ShamirAtZero { threshold: 6 },
        ),
        Err(ThresholdError::InsufficientPartialShares {
            required: 6,
            received: 5,
        })
    );
}

#[test]
fn public_share_aggregation_rejects_missing_duplicate_and_wrong_rho_inputs() {
    let rho = [0x31; 32];
    let wrong_rho = [0x32; 32];
    let context = FipsPublicKeyContext65::new(rho, [0xd1; 32]);
    let wrong_rho_context = FipsPublicKeyContext65::new(wrong_rho, [0xd1; 32]);
    let wrong_ceremony_context = FipsPublicKeyContext65::new(rho, [0xd2; 32]);
    let first = zero_secret_share(1);
    let second = zero_secret_share(2);
    let first_public = evaluate_public_t_share(&context, &first);
    let second_public = evaluate_public_t_share(&context, &second);

    assert_eq!(
        aggregate_public_key_from_t_shares(
            &context,
            core::slice::from_ref(&first_public),
            ShareAggregation::Additive { expected_shares: 2 },
        ),
        Err(ThresholdError::InsufficientPartialShares {
            required: 2,
            received: 1,
        })
    );

    assert_eq!(
        aggregate_public_key_from_t_shares(
            &context,
            &[first_public.clone(), first_public.clone()],
            ShareAggregation::Additive { expected_shares: 2 },
        ),
        Err(ThresholdError::DuplicateValidator {
            validator: ValidatorId(1),
        })
    );

    assert_eq!(
        aggregate_public_key_from_t_shares(
            &wrong_rho_context,
            &[first_public.clone(), second_public.clone()],
            ShareAggregation::Additive { expected_shares: 2 },
        ),
        Err(ThresholdError::TranscriptMismatch)
    );

    assert_eq!(
        aggregate_public_key_from_t_shares(
            &wrong_ceremony_context,
            &[first_public, second_public],
            ShareAggregation::Additive { expected_shares: 2 },
        ),
        Err(ThresholdError::TranscriptMismatch),
        "public contributions cannot be replayed into another ceremony"
    );
}

#[test]
fn power2round_is_applied_after_public_contributions_are_aggregated() {
    let rho = [0x7d; 32];
    let context = FipsPublicKeyContext65::new(rho, [0xe1; 32]);
    let mut first_s2 = [Poly::zero(); MLDSA65_K];
    let mut second_s2 = [Poly::zero(); MLDSA65_K];
    first_s2[0].coeffs[0] = 4_096;
    second_s2[0].coeffs[0] = 1;
    let first = FipsModuleSecretShare65::new(1, [Poly::zero(); MLDSA65_L], first_s2).unwrap();
    let second = FipsModuleSecretShare65::new(2, [Poly::zero(); MLDSA65_L], second_s2).unwrap();
    let first_public = evaluate_public_t_share(&context, &first);
    let second_public = evaluate_public_t_share(&context, &second);

    let first_rounded = aggregate_public_key_from_t_shares(
        &context,
        core::slice::from_ref(&first_public),
        ShareAggregation::Additive { expected_shares: 1 },
    )
    .unwrap();
    let second_rounded = aggregate_public_key_from_t_shares(
        &context,
        core::slice::from_ref(&second_public),
        ShareAggregation::Additive { expected_shares: 1 },
    )
    .unwrap();
    let combined = aggregate_public_key_from_t_shares(
        &context,
        &[first_public, second_public],
        ShareAggregation::Additive { expected_shares: 2 },
    )
    .unwrap();

    assert_eq!(first_rounded.t1()[0].coeffs[0], 0);
    assert_eq!(second_rounded.t1()[0].coeffs[0], 0);
    assert_eq!(combined.public_t()[0].coeffs[0], 4_097);
    assert_eq!(combined.t1()[0].coeffs[0], 1);
    assert_eq!(combined.t0()[0].coeffs[0], -4_095);
}

fn zero_secret_share(receiver_index: u16) -> FipsModuleSecretShare65 {
    FipsModuleSecretShare65::new(
        receiver_index,
        [Poly::zero(); MLDSA65_L],
        [Poly::zero(); MLDSA65_K],
    )
    .unwrap()
}

fn split_additive_three<const WIDTH: usize>(
    secret: &[Poly; WIDTH],
    domain: i32,
) -> [[Poly; WIDTH]; 3] {
    let mut outputs = [[Poly::zero(); WIDTH]; 3];
    for component in 0..WIDTH {
        for coefficient in 0..N {
            let first = deterministic_coefficient(component, coefficient, domain);
            let second = deterministic_coefficient(component, coefficient, domain + 101);
            outputs[0][component].coeffs[coefficient] = first;
            outputs[1][component].coeffs[coefficient] = second;
            outputs[2][component].coeffs[coefficient] =
                (secret[component].coeffs[coefficient] - first - second).rem_euclid(Q);
        }
    }
    outputs
}

fn evaluate_shamir_share<const WIDTH: usize>(
    secret: &[Poly; WIDTH],
    receiver_index: u16,
    domain: i32,
) -> [Poly; WIDTH] {
    evaluate_shamir_share_with_degree(secret, receiver_index, domain, 2)
}

fn evaluate_shamir_share_with_degree<const WIDTH: usize>(
    secret: &[Poly; WIDTH],
    receiver_index: u16,
    domain: i32,
    degree: usize,
) -> [Poly; WIDTH] {
    let x = i64::from(receiver_index);
    let mut output = [Poly::zero(); WIDTH];
    for component in 0..WIDTH {
        for coefficient in 0..N {
            let mut value = i64::from(secret[component].coeffs[coefficient]);
            let mut x_power = 1_i64;
            for power in 1..=degree {
                x_power = (x_power * x).rem_euclid(i64::from(Q));
                let polynomial_coefficient = i64::from(deterministic_coefficient(
                    component,
                    coefficient,
                    domain + (power as i32 * 211),
                ));
                value = (value + polynomial_coefficient * x_power).rem_euclid(i64::from(Q));
            }
            output[component].coeffs[coefficient] = value as i32;
        }
    }
    output
}

fn deterministic_coefficient(component: usize, coefficient: usize, domain: i32) -> i32 {
    ((component as i64 + 1) * 65_537 + (coefficient as i64 + 1) * i64::from(domain))
        .rem_euclid(i64::from(Q)) as i32
}
