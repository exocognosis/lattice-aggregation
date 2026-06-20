#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::epsilon::{EpsilonLedger, EpsilonUnit, NoiseFloodingParameters},
    ThresholdError,
};

#[test]
fn epsilon_ledger_starts_at_zero_and_increments_independent_components() {
    let mut ledger = EpsilonLedger::default();
    assert_eq!(ledger.epsilon_mask(), EpsilonUnit::ZERO);
    assert_eq!(ledger.epsilon_rej(), EpsilonUnit::ZERO);
    assert_eq!(ledger.epsilon_withhold(), EpsilonUnit::ZERO);

    ledger.increment_mask(EpsilonUnit::from_units(3));
    ledger.increment_rejection(EpsilonUnit::from_units(5));
    ledger.increment_withholding(EpsilonUnit::from_units(7));

    assert_eq!(ledger.epsilon_mask(), EpsilonUnit::from_units(3));
    assert_eq!(ledger.epsilon_rej(), EpsilonUnit::from_units(5));
    assert_eq!(ledger.epsilon_withhold(), EpsilonUnit::from_units(7));
}

#[test]
fn noise_flooding_rejects_sigma_above_beta_quarter() {
    let err = NoiseFloodingParameters::new(100, 26, EpsilonUnit::from_units(1)).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::InvalidNoiseFloodingParameters {
            reason: "gaussian sigma bound exceeds beta / 4",
        }
    );
}

#[test]
fn noise_flooding_records_renyi_budget_when_valid() {
    let params = NoiseFloodingParameters::new(100, 25, EpsilonUnit::from_units(9)).unwrap();
    assert_eq!(params.beta(), 100);
    assert_eq!(params.gaussian_sigma_bound(), 25);
    assert_eq!(params.renyi_epsilon_increment(), EpsilonUnit::from_units(9));
}
