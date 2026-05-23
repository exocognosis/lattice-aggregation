#![cfg(feature = "hazmat-real-mldsa")]

use dytallix_pq_threshold::{
    low_level::mldsa65::{
        check_poly_bound, reduce_mod_q, unpack_public_key, unpack_signature,
        verify_standard_mldsa65, Mldsa65PublicKeyBytes, Mldsa65SignatureBytes, VectorK, VectorL,
        MLDSA65_BETA, MLDSA65_CHALLENGE_BYTES, MLDSA65_ETA, MLDSA65_GAMMA1, MLDSA65_GAMMA2,
        MLDSA65_K, MLDSA65_L, MLDSA65_OMEGA, MLDSA65_POLYZ_PACKED_BYTES, MLDSA65_PUBLIC_SEED_BYTES,
        MLDSA65_SECRETKEY_BYTES, MLDSA65_TAU,
    },
    ThresholdError, ThresholdPublicKey, ThresholdSignature, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES, N, Q,
};

#[test]
fn hazmat_mldsa65_constants_match_fips_204_profile() {
    assert_eq!(MLDSA65_K, 6);
    assert_eq!(MLDSA65_L, 5);
    assert_eq!(MLDSA65_ETA, 4);
    assert_eq!(MLDSA65_TAU, 49);
    assert_eq!(MLDSA65_BETA, 196);
    assert_eq!(MLDSA65_GAMMA1, 1 << 19);
    assert_eq!(MLDSA65_GAMMA2, (Q - 1) / 32);
    assert_eq!(MLDSA65_OMEGA, 55);
    assert_eq!(MLDSA65_SECRETKEY_BYTES, 4032);
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

fn write_bits_le(output: &mut [u8], bit_offset: usize, width: usize, value: u32) {
    for bit in 0..width {
        let bit_value = ((value >> bit) & 1) as u8;
        let absolute_bit = bit_offset + bit;
        output[absolute_bit / 8] |= bit_value << (absolute_bit % 8);
    }
}
