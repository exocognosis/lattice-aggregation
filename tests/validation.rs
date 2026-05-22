use dytallix_pq_threshold::{
    Commitment, CommitmentSet, PartialShareSet, PartialSignatureShare, PrivateKeyShare,
    ThresholdError, ValidatorId, COMMITMENT_BYTES, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES, POLY_SEED_BYTES,
};

fn validators() -> Vec<ValidatorId> {
    vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]
}

fn commitment(byte: u8) -> Commitment {
    Commitment([byte; COMMITMENT_BYTES])
}

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

#[test]
fn commitment_set_rejects_duplicate_validators() {
    let result = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(1), commitment(1)),
            (ValidatorId(1), commitment(2)),
        ],
    );

    assert_eq!(
        result.unwrap_err(),
        ThresholdError::DuplicateValidator {
            validator: ValidatorId(1)
        }
    );
}

#[test]
fn commitment_set_rejects_unknown_validator() {
    let result = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(4), commitment(4)),
            (ValidatorId(2), commitment(2)),
        ],
    );

    assert_eq!(
        result.unwrap_err(),
        ThresholdError::UnknownValidator {
            validator: ValidatorId(4)
        }
    );
}

#[test]
fn commitment_set_reports_unknown_validator_before_insufficient_count() {
    let result = CommitmentSet::new(validators(), 2, vec![(ValidatorId(4), commitment(4))]);

    assert_eq!(
        result.unwrap_err(),
        ThresholdError::UnknownValidator {
            validator: ValidatorId(4)
        }
    );
}

#[test]
fn commitment_set_canonicalizes_order() {
    let set = CommitmentSet::new(
        validators(),
        2,
        vec![
            (ValidatorId(3), commitment(3)),
            (ValidatorId(1), commitment(1)),
        ],
    )
    .unwrap();

    let ordered: Vec<_> = set.iter().map(|(id, _)| *id).collect();

    assert_eq!(ordered, vec![ValidatorId(1), ValidatorId(3)]);
}

#[test]
fn partial_share_set_rejects_insufficient_shares() {
    let result = PartialShareSet::new(
        validators(),
        2,
        vec![PartialSignatureShare {
            signer: ValidatorId(1),
            bytes: vec![1, 2, 3],
        }],
    );

    assert_eq!(
        result.unwrap_err(),
        ThresholdError::InsufficientPartialShares {
            required: 2,
            received: 1
        }
    );
}

#[test]
fn partial_share_set_reports_duplicate_signer_before_insufficient_count() {
    let result = PartialShareSet::new(
        validators(),
        2,
        vec![
            PartialSignatureShare {
                signer: ValidatorId(1),
                bytes: vec![1, 2, 3],
            },
            PartialSignatureShare {
                signer: ValidatorId(1),
                bytes: vec![4, 5, 6],
            },
        ],
    );

    assert_eq!(
        result.unwrap_err(),
        ThresholdError::DuplicateValidator {
            validator: ValidatorId(1)
        }
    );
}
