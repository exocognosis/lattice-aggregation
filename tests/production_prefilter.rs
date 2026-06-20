#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        epsilon::{EpsilonLedger, EpsilonUnit},
        prefilter::{
            BlindedCommitmentSummary, BlindedPreFilter, MaskVector, PreFilterOutcome,
            ValidatorShare,
        },
        types::AttemptId,
    },
    ThresholdError, ValidatorId,
};

#[test]
fn prefilter_pass_returns_share_release_token() {
    let mut ledger = EpsilonLedger::default();
    let summaries = vec![
        BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 40),
        BlindedCommitmentSummary::new(ValidatorId(2), [2; 32], 45),
    ];

    let outcome = BlindedPreFilter::evaluate(
        AttemptId([1; 32]),
        100,
        EpsilonUnit::from_units(2),
        summaries,
        &mut ledger,
    )
    .unwrap();

    match outcome {
        PreFilterOutcome::Passed(token) => {
            assert_eq!(token.clearance_boundary(), 100);
            assert_eq!(token.aggregate_infinity_norm(), 85);
            assert_eq!(ledger.epsilon_rej(), EpsilonUnit::ZERO);
        }
        PreFilterOutcome::Aborted(_) => panic!("expected pass"),
    }
}

#[test]
fn prefilter_abort_increments_rejection_budget() {
    let mut ledger = EpsilonLedger::default();
    let summaries = vec![BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 101)];

    let outcome = BlindedPreFilter::evaluate(
        AttemptId([2; 32]),
        100,
        EpsilonUnit::from_units(2),
        summaries,
        &mut ledger,
    )
    .unwrap();

    match outcome {
        PreFilterOutcome::Passed(_) => panic!("expected abort"),
        PreFilterOutcome::Aborted(abort) => {
            assert_eq!(abort.clearance_boundary(), 100);
            assert_eq!(abort.aggregate_infinity_norm(), 101);
            assert_eq!(ledger.epsilon_rej(), EpsilonUnit::from_units(2));
        }
    }
}

#[test]
fn prefilter_abort_uses_aggregate_norm_not_per_validator_max() {
    let mut ledger = EpsilonLedger::default();
    let summaries = vec![
        BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 60),
        BlindedCommitmentSummary::new(ValidatorId(2), [2; 32], 50),
    ];

    let outcome = BlindedPreFilter::evaluate(
        AttemptId([3; 32]),
        100,
        EpsilonUnit::from_units(3),
        summaries,
        &mut ledger,
    )
    .unwrap();

    match outcome {
        PreFilterOutcome::Passed(_) => panic!("expected aggregate overflow abort"),
        PreFilterOutcome::Aborted(abort) => {
            assert_eq!(abort.aggregate_infinity_norm(), 110);
            assert_eq!(ledger.epsilon_rej(), EpsilonUnit::from_units(3));
        }
    }
}

#[test]
fn share_release_request_requires_prefilter_pass_token() {
    let mut ledger = EpsilonLedger::default();
    let outcome = BlindedPreFilter::evaluate(
        AttemptId([9; 32]),
        100,
        EpsilonUnit::from_units(1),
        vec![BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 50)],
        &mut ledger,
    )
    .unwrap();
    let token = match outcome {
        PreFilterOutcome::Passed(token) => token,
        PreFilterOutcome::Aborted(_) => panic!("expected pass"),
    };

    let request = token.into_share_release_authorization();
    assert_eq!(request.attempt_id(), AttemptId([9; 32]));
    assert_eq!(request.prefilter().aggregate_infinity_norm(), 50);
}

#[test]
fn prefilter_rejects_aggregate_norm_overflow() {
    let mut ledger = EpsilonLedger::default();
    let summaries = vec![
        BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], u32::MAX),
        BlindedCommitmentSummary::new(ValidatorId(2), [2; 32], 1),
    ];

    let err = BlindedPreFilter::evaluate(
        AttemptId([4; 32]),
        u32::MAX,
        EpsilonUnit::from_units(1),
        summaries,
        &mut ledger,
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::InvalidPreFilter {
            reason: "aggregate infinity norm overflow",
        }
    );
    assert_eq!(ledger.epsilon_rej(), EpsilonUnit::ZERO);
}

#[test]
fn validator_share_debug_redacts_secret_vector() {
    let mut secret = MaskVector::zero();
    secret.elements[0].coeffs[0] = 12345;
    let share = ValidatorShare::new(7, secret);

    let debug = format!("{share:?}");
    assert!(debug.contains("secret_s1_share_redacted"));
    assert!(!debug.contains("12345"));
}
