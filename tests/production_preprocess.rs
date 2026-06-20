#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        preprocess::{PreprocessedAttempt, PreprocessingStore},
        types::AttemptId,
    },
    ThresholdError,
};

#[test]
fn preprocessing_store_consumes_attempt_once() {
    let attempt = PreprocessedAttempt::new(AttemptId([7; 32]), vec![1, 2, 3]).unwrap();
    let mut store = PreprocessingStore::default();
    store.insert(attempt).unwrap();

    let first = store.consume(AttemptId([7; 32])).unwrap();
    assert_eq!(first.attempt_id(), AttemptId([7; 32]));

    let err = store.consume(AttemptId([7; 32])).unwrap_err();
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
