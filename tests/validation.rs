use dytallix_pq_threshold::{
    PrivateKeyShare, ThresholdError, ValidatorId, COMMITMENT_BYTES, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES, POLY_SEED_BYTES,
};

#[test]
fn exposes_mldsa65_fips_204_sizes() {
    assert_eq!(MLDSA65_PUBLICKEY_BYTES, 1952);
    assert_eq!(MLDSA65_SIGNATURE_BYTES, 3309);
    assert_eq!(POLY_SEED_BYTES, 32);
    assert_eq!(COMMITMENT_BYTES, 32);
}

#[test]
fn validator_id_is_orderable() {
    let mut ids = vec![ValidatorId(3), ValidatorId(1), ValidatorId(2)];
    ids.sort();
    assert_eq!(ids, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
}

#[test]
fn error_message_includes_attributable_validator() {
    let err = ThresholdError::DuplicateValidator {
        validator: ValidatorId(7),
    };
    assert!(err.to_string().contains("validator 7"));
}

#[test]
fn private_key_share_debug_redacts_secret_bytes() {
    let share = PrivateKeyShare::new(ValidatorId(7), vec![11, 22, 33]);
    let debug = format!("{share:?}");

    assert!(debug.contains("validator 7"));
    assert!(debug.contains("secret_len"));
    assert!(!debug.contains("[11, 22, 33]"));
}
