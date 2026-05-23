#![cfg(feature = "hazmat-real-mldsa")]

use dytallix_pq_threshold::{
    low_level::mldsa65::{
        check_poly_bound, expand_a, pack_public_key, pack_signature, reduce_mod_q, rej_ntt_poly,
        sample_in_ball, unpack_public_key, unpack_signature, verify_standard_mldsa65, HintVector,
        Mldsa65PublicKeyBytes, Mldsa65SignatureBytes, VectorK, VectorL, MLDSA65_BETA,
        MLDSA65_CHALLENGE_BYTES, MLDSA65_D, MLDSA65_ETA, MLDSA65_GAMMA1, MLDSA65_GAMMA2, MLDSA65_K,
        MLDSA65_L, MLDSA65_OMEGA, MLDSA65_POLYZ_PACKED_BYTES, MLDSA65_PUBLIC_SEED_BYTES,
        MLDSA65_SECRETKEY_BYTES, MLDSA65_TAU,
    },
    Poly, ThresholdError, ThresholdPublicKey, ThresholdSignature, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES, N, Q,
};

#[test]
fn hazmat_mldsa65_constants_match_fips_204_profile() {
    assert_eq!(MLDSA65_K, 6);
    assert_eq!(MLDSA65_L, 5);
    assert_eq!(MLDSA65_ETA, 4);
    assert_eq!(MLDSA65_D, 13);
    assert_eq!(MLDSA65_TAU, 49);
    assert_eq!(MLDSA65_BETA, 196);
    assert_eq!(MLDSA65_GAMMA1, 1 << 19);
    assert_eq!(MLDSA65_GAMMA2, (Q - 1) / 32);
    assert_eq!(MLDSA65_OMEGA, 55);
    assert_eq!(MLDSA65_SECRETKEY_BYTES, 4032);
}

#[test]
fn hazmat_power2round_reconstructs_canonical_values() {
    for value in [0, 1, 4096, 4097, Q - 2, Q - 1] {
        let (high, low) = dytallix_pq_threshold::mldsa65::power2round(value);
        assert_eq!(
            reduce_mod_q(((high as i64) << MLDSA65_D) + low as i64),
            value
        );
        assert!(low > -(1 << (MLDSA65_D - 1)));
        assert!(low <= 1 << (MLDSA65_D - 1));
    }
}

#[test]
fn hazmat_decompose_handles_mldsa65_top_bucket_wrap() {
    let (high, low) = dytallix_pq_threshold::mldsa65::decompose(Q - 1);

    assert_eq!(high, 0);
    assert_eq!(low, -1);
    assert_eq!(
        reduce_mod_q(high as i64 * (2 * MLDSA65_GAMMA2) as i64 + low as i64),
        Q - 1
    );
}

#[test]
fn hazmat_high_low_bits_match_decompose() {
    let value = 3 * 2 * MLDSA65_GAMMA2 + 17;
    let (high, low) = dytallix_pq_threshold::mldsa65::decompose(value);

    assert_eq!(dytallix_pq_threshold::mldsa65::high_bits(value), high);
    assert_eq!(dytallix_pq_threshold::mldsa65::low_bits(value), low);
}

#[test]
fn hazmat_use_hint_adjusts_high_bits_by_low_sign() {
    let positive_low = 2 * MLDSA65_GAMMA2 + 7;
    let negative_low = 2 * MLDSA65_GAMMA2 - 7;

    assert_eq!(
        dytallix_pq_threshold::mldsa65::use_hint(false, positive_low),
        1
    );
    assert_eq!(
        dytallix_pq_threshold::mldsa65::use_hint(true, positive_low),
        2
    );
    assert_eq!(
        dytallix_pq_threshold::mldsa65::use_hint(false, negative_low),
        1
    );
    assert_eq!(
        dytallix_pq_threshold::mldsa65::use_hint(true, negative_low),
        0
    );
}

#[test]
fn hazmat_make_hint_reports_high_bit_changes() {
    let base = 2 * MLDSA65_GAMMA2 + MLDSA65_GAMMA2 - 5;

    assert!(!dytallix_pq_threshold::mldsa65::make_hint(1, base));
    assert!(dytallix_pq_threshold::mldsa65::make_hint(20, base));
}

#[test]
fn hazmat_sample_in_ball_is_deterministic_sparse_and_ternary() {
    let seed = [0xA7; MLDSA65_CHALLENGE_BYTES];

    let first = sample_in_ball(&seed);
    let second = sample_in_ball(&seed);

    assert_eq!(first, second);
    assert_eq!(
        first.coeffs.iter().filter(|coeff| **coeff != 0).count(),
        MLDSA65_TAU as usize
    );
    assert!(first.coeffs.iter().all(|coeff| matches!(*coeff, -1..=1)));
}

#[test]
fn hazmat_sample_in_ball_changes_with_seed() {
    let left = sample_in_ball(&[0x11; MLDSA65_CHALLENGE_BYTES]);
    let right = sample_in_ball(&[0x22; MLDSA65_CHALLENGE_BYTES]);

    assert_ne!(left, right);
}

#[test]
fn hazmat_rej_ntt_poly_is_deterministic_and_canonical() {
    let seed = [0x5C; MLDSA65_PUBLIC_SEED_BYTES + 2];

    let first = rej_ntt_poly(&seed);
    let second = rej_ntt_poly(&seed);

    assert_eq!(first, second);
    assert!(first.coeffs.iter().all(|coeff| (0..Q).contains(coeff)));
}

#[test]
fn hazmat_expand_a_builds_mldsa65_matrix_dimensions() {
    let matrix = expand_a(&[0x42; MLDSA65_PUBLIC_SEED_BYTES]);

    assert_eq!(matrix.rows().len(), MLDSA65_K);
    assert!(matrix
        .rows()
        .iter()
        .all(|row| row.polys().len() == MLDSA65_L));
    assert_ne!(matrix.rows()[0].polys()[0], matrix.rows()[1].polys()[0]);
}

#[test]
fn hazmat_byte_wrappers_enforce_standard_lengths() {
    let public_key = Mldsa65PublicKeyBytes::new([7; MLDSA65_PUBLICKEY_BYTES]);
    let signature = Mldsa65SignatureBytes::new([8; MLDSA65_SIGNATURE_BYTES]);

    assert_eq!(public_key.as_bytes().len(), MLDSA65_PUBLICKEY_BYTES);
    assert_eq!(signature.as_bytes().len(), MLDSA65_SIGNATURE_BYTES);
}

#[test]
fn hazmat_field_reduction_canonicalizes_signed_inputs() {
    assert_eq!(reduce_mod_q(0), 0);
    assert_eq!(reduce_mod_q(Q as i64), 0);
    assert_eq!(reduce_mod_q(-1), Q - 1);
    assert_eq!(reduce_mod_q((Q as i64 * 3) + 42), 42);
}

#[test]
fn hazmat_vector_types_preserve_mldsa65_matrix_dimensions() {
    let vector_k = VectorK::zero();
    let vector_l = VectorL::zero();

    assert_eq!(vector_k.polys().len(), MLDSA65_K);
    assert_eq!(vector_l.polys().len(), MLDSA65_L);
}

#[test]
fn hazmat_bound_check_rejects_boundary_value() {
    let mut poly = dytallix_pq_threshold::Poly::zero();
    poly.coeffs[0] = MLDSA65_BETA - 1;

    assert!(check_poly_bound(&poly, MLDSA65_BETA));

    poly.coeffs[N - 1] = -MLDSA65_BETA;

    assert!(!check_poly_bound(&poly, MLDSA65_BETA));
}

#[test]
fn hazmat_verifier_stub_is_explicitly_unavailable_until_kats_land() {
    let public_key = ThresholdPublicKey([0; MLDSA65_PUBLICKEY_BYTES]);
    let signature = structurally_valid_zero_z_signature();

    assert_eq!(
        verify_standard_mldsa65(&public_key, b"message", &signature),
        Err(ThresholdError::BackendUnavailable {
            reason: "hazmat-real-mldsa verifier requires FIPS 204 KAT-backed implementation"
        })
    );
}

#[test]
fn hazmat_public_key_unpacking_splits_seed_and_t1_vector() {
    let mut bytes = [0u8; MLDSA65_PUBLICKEY_BYTES];
    bytes[..MLDSA65_PUBLIC_SEED_BYTES].copy_from_slice(&[0xA5; MLDSA65_PUBLIC_SEED_BYTES]);

    let unpacked = unpack_public_key(&bytes).unwrap();

    assert_eq!(unpacked.rho(), &[0xA5; MLDSA65_PUBLIC_SEED_BYTES]);
    assert_eq!(unpacked.t1().polys().len(), MLDSA65_K);
    assert!(unpacked
        .t1()
        .polys()
        .iter()
        .flat_map(|poly| poly.coeffs)
        .all(|coeff| coeff == 0));
}

#[test]
fn hazmat_public_key_unpacking_rejects_wrong_length() {
    assert_eq!(
        unpack_public_key(&[0u8; MLDSA65_PUBLICKEY_BYTES - 1]),
        Err(ThresholdError::MalformedSerialization {
            reason: "ML-DSA-65 public key length mismatch"
        })
    );
}

#[test]
fn hazmat_public_key_pack_round_trips_t1_coefficients() {
    let rho = [0x44; MLDSA65_PUBLIC_SEED_BYTES];
    let t1 = VectorK::from_polys([t1_pattern_poly(); MLDSA65_K]);

    let packed = pack_public_key(rho, &t1).unwrap();
    let unpacked = unpack_public_key(packed.as_bytes()).unwrap();

    assert_eq!(unpacked.rho(), &rho);
    assert_eq!(unpacked.t1(), &t1);
}

#[test]
fn hazmat_signature_unpacking_splits_challenge_z_and_hint() {
    let signature = structurally_valid_zero_z_signature();

    let unpacked = unpack_signature(&signature.0).unwrap();

    assert_eq!(unpacked.challenge(), &[0xC3; MLDSA65_CHALLENGE_BYTES]);
    assert_eq!(unpacked.z().polys().len(), MLDSA65_L);
    assert!(unpacked
        .z()
        .polys()
        .iter()
        .flat_map(|poly| poly.coeffs)
        .all(|coeff| coeff == 0));
    assert_eq!(unpacked.hint().weight(), 0);
}

#[test]
fn hazmat_signature_unpacking_rejects_nonzero_unused_hint_slots() {
    let mut signature = structurally_valid_zero_z_signature();
    let hint_start = MLDSA65_CHALLENGE_BYTES + (MLDSA65_L * MLDSA65_POLYZ_PACKED_BYTES);
    signature.0[hint_start] = 1;

    assert_eq!(
        unpack_signature(&signature.0),
        Err(ThresholdError::MalformedSerialization {
            reason: "ML-DSA-65 hint encoding has nonzero unused slot"
        })
    );
}

#[test]
fn hazmat_signature_pack_round_trips_challenge_z_and_empty_hint() {
    let challenge = [0x9A; MLDSA65_CHALLENGE_BYTES];
    let z = VectorL::from_polys([z_pattern_poly(); MLDSA65_L]);
    let hint = HintVector::empty();

    let packed = pack_signature(challenge, &z, &hint).unwrap();
    let unpacked = unpack_signature(packed.as_bytes()).unwrap();

    assert_eq!(unpacked.challenge(), &challenge);
    assert_eq!(unpacked.z(), &z);
    assert_eq!(unpacked.hint(), &hint);
}

#[test]
fn hazmat_signature_packing_rejects_z_values_outside_packed_range() {
    let challenge = [0u8; MLDSA65_CHALLENGE_BYTES];
    let mut z = VectorL::zero();
    z.polys_mut()[0].coeffs[0] = -MLDSA65_GAMMA1;

    assert_eq!(
        pack_signature(challenge, &z, &HintVector::empty()),
        Err(ThresholdError::MalformedSerialization {
            reason: "ML-DSA-65 z coefficient cannot be packed"
        })
    );
}

#[test]
fn hazmat_verifier_rejects_z_outside_mldsa65_norm_bound() {
    let public_key = ThresholdPublicKey([0; MLDSA65_PUBLICKEY_BYTES]);
    let signature = ThresholdSignature([0; MLDSA65_SIGNATURE_BYTES]);

    assert_eq!(
        verify_standard_mldsa65(&public_key, b"message", &signature),
        Err(ThresholdError::StandardVerificationFailed)
    );
}

fn structurally_valid_zero_z_signature() -> ThresholdSignature {
    let mut bytes = [0u8; MLDSA65_SIGNATURE_BYTES];
    bytes[..MLDSA65_CHALLENGE_BYTES].copy_from_slice(&[0xC3; MLDSA65_CHALLENGE_BYTES]);

    let z_start = MLDSA65_CHALLENGE_BYTES;
    let z_end = z_start + (MLDSA65_L * MLDSA65_POLYZ_PACKED_BYTES);
    for poly_bytes in bytes[z_start..z_end].chunks_exact_mut(MLDSA65_POLYZ_PACKED_BYTES) {
        for coeff_index in 0..N {
            write_bits_le(poly_bytes, coeff_index * 20, 20, MLDSA65_GAMMA1 as u32);
        }
    }

    ThresholdSignature(bytes)
}

fn t1_pattern_poly() -> Poly {
    let mut poly = Poly::zero();
    for (index, coeff) in poly.coeffs.iter_mut().enumerate() {
        *coeff = (index as i32 * 3) & 0x03ff;
    }
    poly
}

fn z_pattern_poly() -> Poly {
    let mut poly = Poly::zero();
    for (index, coeff) in poly.coeffs.iter_mut().enumerate() {
        *coeff = (index as i32 % 101) - 50;
    }
    poly
}

fn write_bits_le(output: &mut [u8], bit_offset: usize, width: usize, value: u32) {
    for bit in 0..width {
        let bit_value = ((value >> bit) & 1) as u8;
        let absolute_bit = bit_offset + bit;
        output[absolute_bit / 8] |= bit_value << (absolute_bit % 8);
    }
}
