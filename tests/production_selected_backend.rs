#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::selected_backend::{
        BackendSelectionMetadata, BackendSelectionStatus, DeploymentProfile, MigrationCandidate,
        ParameterSet, ProofStatus, SelectedProductionBackendProfile, StandardVerifierCompatibility,
        ThresholdConstruction,
    },
    SimulatedBackend,
};

#[test]
fn selected_profile_names_mldsa65_shamir_nonce_dkg_p1() {
    let profile = SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1();

    assert_eq!(profile.parameter_set(), ParameterSet::Mldsa65);
    assert_eq!(profile.parameter_set().name(), "ML-DSA-65");
    assert_eq!(
        profile.threshold_construction(),
        ThresholdConstruction::CoordinatorAssistedShamirNonceDkg
    );
    assert_eq!(
        profile.threshold_construction().name(),
        "coordinator-assisted Shamir nonce DKG"
    );
    assert_eq!(
        profile.deployment_profile(),
        DeploymentProfile::P1CoordinatorAssistedTeeHsm
    );
    assert_eq!(
        profile.deployment_profile().name(),
        "P1 coordinator-assisted TEE/HSM"
    );
    assert_eq!(profile.feature_gate(), "production-mldsa65-coordinator");
    assert!(profile
        .migration_candidates()
        .contains(&MigrationCandidate::P2Mpc));
    assert!(profile
        .migration_candidates()
        .contains(&MigrationCandidate::Talus));
}

#[test]
fn selected_profile_is_not_proved_or_production_approved() {
    let profile = SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1();

    assert_eq!(
        profile.proof_status(),
        ProofStatus::NotProvedHazmatCandidate
    );
    assert!(!profile.production_approved());
}

#[test]
fn selected_profile_requires_standard_verifier_compatibility() {
    let profile = SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1();

    assert_eq!(
        profile.standard_verifier_compatibility(),
        StandardVerifierCompatibility::Required
    );
    assert!(profile.standard_verifier_required());
}

#[test]
fn selected_profile_binding_digest_is_stable_and_nonzero() {
    let profile = SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1();
    let digest = profile.profile_binding_digest();

    assert_eq!(digest, profile.profile_binding_digest());
    assert_ne!(digest, [0; 32]);
}

#[test]
fn simulated_backend_is_not_the_selected_production_backend() {
    let status = SimulatedBackend::selection_status();

    assert_eq!(status, BackendSelectionStatus::SimulationOnly);
    assert_ne!(status, BackendSelectionStatus::SelectedProductionCandidate);
    assert!(!status.is_selected_production_candidate());
}

#[cfg(feature = "raw-real-mldsa")]
#[test]
fn real_mldsa_backend_is_selected_hazmat_candidate() {
    use lattice_aggregation::RealMldsa65Backend;

    let status = RealMldsa65Backend::selection_status();
    assert_eq!(status, BackendSelectionStatus::SelectedProductionCandidate);
    assert!(status.is_selected_production_candidate());
    assert!(
        !SelectedProductionBackendProfile::mldsa65_coordinator_assisted_p1().production_approved()
    );
}
