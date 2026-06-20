#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        epsilon::{EpsilonLedger, EpsilonUnit},
        prefilter::{BlindedCommitmentSummary, BlindedPreFilter, PreFilterOutcome},
        preprocess::{PreprocessedAttempt, PreprocessingStore},
        types::AttemptId,
    },
    ThresholdError, ValidatorId,
};

#[test]
fn preprocessing_store_consumes_attempt_once() {
    let attempt = PreprocessedAttempt::new(AttemptId([7; 32]), vec![1, 2, 3]).unwrap();
    let mut store = PreprocessingStore::default();
    store.insert(attempt).unwrap();

    let mut ledger = EpsilonLedger::default();
    let token = match BlindedPreFilter::evaluate(
        AttemptId([7; 32]),
        10,
        EpsilonUnit::from_units(1),
        vec![BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 5)],
        &mut ledger,
    )
    .unwrap()
    {
        PreFilterOutcome::Passed(token) => token,
        PreFilterOutcome::Aborted(_) => panic!("expected pass"),
    };
    let authorization = token.into_share_release_authorization();

    let first = store.consume(authorization).unwrap();
    assert_eq!(first.attempt_id(), AttemptId([7; 32]));

    let mut ledger = EpsilonLedger::default();
    let token = match BlindedPreFilter::evaluate(
        AttemptId([7; 32]),
        10,
        EpsilonUnit::from_units(1),
        vec![BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 5)],
        &mut ledger,
    )
    .unwrap()
    {
        PreFilterOutcome::Passed(token) => token,
        PreFilterOutcome::Aborted(_) => panic!("expected pass"),
    };
    let err = store
        .consume(token.into_share_release_authorization())
        .unwrap_err();
    assert_eq!(
        err,
        ThresholdError::InvalidPreprocessedAttempt {
            reason: "attempt is unknown or already consumed",
        }
    );
}

#[test]
fn preprocessing_attempt_rejects_empty_secret() {
    let err = PreprocessedAttempt::new(AttemptId([8; 32]), Vec::new()).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::InvalidPreprocessedAttempt {
            reason: "attempt secret material is empty",
        }
    );
}
