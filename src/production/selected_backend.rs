//! Selected production-candidate backend metadata.
//!
//! This module records the currently selected reviewed-construction target. It
//! is selection metadata only and does not implement signing, DKG, attestation,
//! or proof logic.

use sha3::{Digest, Sha3_256};

use crate::SimulatedBackend;

#[cfg(feature = "raw-real-mldsa")]
use crate::RealMldsa65Backend;

/// ML-DSA parameter set selected for the production-candidate profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParameterSet {
    /// FIPS 204 ML-DSA-65 parameter set.
    Mldsa65,
}

impl ParameterSet {
    /// Return the stable reader-facing parameter-set name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mldsa65 => "ML-DSA-65",
        }
    }
}

/// Threshold construction selected for the production-candidate profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ThresholdConstruction {
    /// Coordinator-assisted Shamir nonce DKG construction.
    CoordinatorAssistedShamirNonceDkg,
}

impl ThresholdConstruction {
    /// Return the stable reader-facing construction name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CoordinatorAssistedShamirNonceDkg => "coordinator-assisted Shamir nonce DKG",
        }
    }
}

/// Deployment profile selected for the production-candidate profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeploymentProfile {
    /// P1 coordinator-assisted deployment with explicit TEE/HSM coordinator assumption.
    P1CoordinatorAssistedTeeHsm,
}

impl DeploymentProfile {
    /// Return the stable reader-facing deployment profile name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::P1CoordinatorAssistedTeeHsm => "P1 coordinator-assisted TEE/HSM",
        }
    }
}

/// Standard verifier compatibility requirement for a selected profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StandardVerifierCompatibility {
    /// The selected profile must produce signatures accepted by a standard ML-DSA verifier.
    Required,
}

/// Proof status for the selected profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofStatus {
    /// Not proved; hazmat production-candidate boundary only.
    NotProvedHazmatCandidate,
}

/// Later construction/backend migration candidates.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MigrationCandidate {
    /// P2 profile using an MPC construction.
    P2Mpc,
    /// TALUS-family migration candidate.
    Talus,
}

/// Classification of a backend against the selected production-candidate profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendSelectionStatus {
    /// The backend represents the selected production-candidate profile.
    SelectedProductionCandidate,
    /// The backend is deterministic simulation machinery only.
    SimulationOnly,
}

impl BackendSelectionStatus {
    /// Return true only for the selected production-candidate backend/profile.
    pub const fn is_selected_production_candidate(self) -> bool {
        match self {
            Self::SelectedProductionCandidate => true,
            Self::SimulationOnly => false,
        }
    }
}

/// Backend selection metadata exposed by concrete backend marker types.
pub trait BackendSelectionMetadata {
    /// Return the backend classification for selected-profile assessments.
    fn selection_status() -> BackendSelectionStatus;
}

impl BackendSelectionMetadata for SimulatedBackend {
    fn selection_status() -> BackendSelectionStatus {
        BackendSelectionStatus::SimulationOnly
    }
}

/// Real ML-DSA-65 seed-reconstruction backend is the selected hazmat candidate
/// construction target. It remains not production-approved until proof/audit gates close.
#[cfg(feature = "raw-real-mldsa")]
impl BackendSelectionMetadata for RealMldsa65Backend {
    fn selection_status() -> BackendSelectionStatus {
        BackendSelectionStatus::SelectedProductionCandidate
    }
}

/// Typed metadata report for the selected production-candidate backend profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SelectedProductionBackendProfile {
    parameter_set: ParameterSet,
    threshold_construction: ThresholdConstruction,
    deployment_profile: DeploymentProfile,
    standard_verifier_compatibility: StandardVerifierCompatibility,
    feature_gate: &'static str,
    proof_status: ProofStatus,
    production_approved: bool,
    migration_candidates: [MigrationCandidate; 2],
}

impl SelectedProductionBackendProfile {
    /// Construct the ML-DSA-65 coordinator-assisted Shamir nonce DKG P1 profile.
    pub const fn mldsa65_coordinator_assisted_p1() -> Self {
        Self {
            parameter_set: ParameterSet::Mldsa65,
            threshold_construction: ThresholdConstruction::CoordinatorAssistedShamirNonceDkg,
            deployment_profile: DeploymentProfile::P1CoordinatorAssistedTeeHsm,
            standard_verifier_compatibility: StandardVerifierCompatibility::Required,
            feature_gate: "production-mldsa65-coordinator",
            proof_status: ProofStatus::NotProvedHazmatCandidate,
            production_approved: false,
            migration_candidates: [MigrationCandidate::P2Mpc, MigrationCandidate::Talus],
        }
    }

    /// Return the selected ML-DSA parameter set.
    pub const fn parameter_set(self) -> ParameterSet {
        self.parameter_set
    }

    /// Return the selected threshold construction.
    pub const fn threshold_construction(self) -> ThresholdConstruction {
        self.threshold_construction
    }

    /// Return the selected deployment profile.
    pub const fn deployment_profile(self) -> DeploymentProfile {
        self.deployment_profile
    }

    /// Return whether standard ML-DSA verifier compatibility is required.
    pub const fn standard_verifier_compatibility(self) -> StandardVerifierCompatibility {
        self.standard_verifier_compatibility
    }

    /// Return true when standard ML-DSA verifier compatibility is required.
    pub const fn standard_verifier_required(self) -> bool {
        match self.standard_verifier_compatibility {
            StandardVerifierCompatibility::Required => true,
        }
    }

    /// Return the Cargo feature gate for the selected production-candidate profile.
    pub const fn feature_gate(self) -> &'static str {
        self.feature_gate
    }

    /// Return the profile proof status.
    pub const fn proof_status(self) -> ProofStatus {
        self.proof_status
    }

    /// Return true only after production release gates approve this profile.
    pub const fn production_approved(self) -> bool {
        self.production_approved
    }

    /// Return later migration candidates recorded for planning and assessment.
    pub fn migration_candidates(&self) -> &[MigrationCandidate] {
        &self.migration_candidates
    }

    /// Return the selected profile classification.
    pub const fn backend_status(self) -> BackendSelectionStatus {
        BackendSelectionStatus::SelectedProductionCandidate
    }

    /// Return a stable digest binding the selected production-candidate profile.
    pub fn profile_binding_digest(self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattice-aggregation:selected-production-backend-profile:v1");
        hasher.update(self.parameter_set.name().as_bytes());
        hasher.update(self.threshold_construction.name().as_bytes());
        hasher.update(self.deployment_profile.name().as_bytes());
        hasher.update(match self.standard_verifier_compatibility {
            StandardVerifierCompatibility::Required => b"standard-verifier-required".as_slice(),
        });
        hasher.update(self.feature_gate.as_bytes());
        hasher.update(match self.proof_status {
            ProofStatus::NotProvedHazmatCandidate => b"not-proved-hazmat-candidate".as_slice(),
        });
        hasher.update(if self.production_approved {
            b"production-approved".as_slice()
        } else {
            b"production-not-approved".as_slice()
        });
        for candidate in self.migration_candidates {
            hasher.update(match candidate {
                MigrationCandidate::P2Mpc => b"migration:p2-mpc".as_slice(),
                MigrationCandidate::Talus => b"migration:talus".as_slice(),
            });
        }
        hasher.finalize().into()
    }
}
