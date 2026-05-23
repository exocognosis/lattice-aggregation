#![cfg(feature = "hazmat-real-mldsa")]

use dytallix_pq_threshold::{
    low_level::mldsa65::{
        check_poly_bound, reduce_mod_q, verify_standard_mldsa65, Mldsa65PublicKeyBytes,
        Mldsa65SignatureBytes, VectorK, VectorL, MLDSA65_BETA, MLDSA65_ETA, MLDSA65_GAMMA1,
        MLDSA65_GAMMA2, MLDSA65_K, MLDSA65_L, MLDSA65_OMEGA, MLDSA65_SECRETKEY_BYTES, MLDSA65_TAU,
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
    let signature = ThresholdSignature([0; MLDSA65_SIGNATURE_BYTES]);

    assert_eq!(
        verify_standard_mldsa65(&public_key, b"message", &signature),
        Err(ThresholdError::BackendUnavailable {
            reason: "hazmat-real-mldsa verifier requires FIPS 204 KAT-backed implementation"
        })
    );
}
