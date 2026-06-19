#[cfg(not(feature = "coordinator-assisted"))]
#[test]
fn production_module_is_not_exported_without_gate() {
    assert!(!cfg!(feature = "coordinator-assisted"));
}

#[cfg(feature = "coordinator-assisted")]
use lattice_aggregation::{production::policy::ProductionPolicy, ThresholdError};

#[cfg(feature = "coordinator-assisted")]
#[test]
fn production_policy_rejects_unreviewed_profile() {
    let err = ProductionPolicy::hazmat_unreviewed()
        .require_production_release()
        .unwrap_err();
    assert_eq!(
        err,
        ThresholdError::ProductionPolicyBlocked {
            reason: "coordinator profile has not passed production release gates",
        }
    );
}

#[cfg(feature = "coordinator-assisted")]
#[test]
fn production_approved_policy_allows_release_gate() {
    assert_eq!(
        ProductionPolicy::production_approved().require_production_release(),
        Ok(())
    );
}

#[cfg(feature = "production-mldsa65-coordinator")]
#[test]
fn production_feature_still_requires_runtime_release_gate() {
    let err = ProductionPolicy::hazmat_unreviewed()
        .require_production_release()
        .unwrap_err();
    assert_eq!(
        err,
        ThresholdError::ProductionPolicyBlocked {
            reason: "coordinator profile has not passed production release gates",
        }
    );
}
