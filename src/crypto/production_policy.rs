//! Combined production-readiness policy gates for threshold backend families.
//!
//! These helpers are policy guards only. Passing them means the selected
//! backend types declare production-oriented security profiles; it does not
//! replace cryptographic proofs, side-channel review, implementation audit, or
//! operational key-management requirements.

use crate::{
    crypto::{
        contribution_proof::{ContributionProofBackend, ContributionProofSecurityProfile},
        vss::{VssCommitmentBackend, VssCommitmentSecurityProfile},
    },
    ThresholdError,
};

/// Declared production-policy status for the backend families required by the
/// threshold ML-DSA scaffold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionBackendPolicyReport {
    /// Declared VSS/DKG commitment security profile.
    pub vss_profile: VssCommitmentSecurityProfile,
    /// Declared contribution proof security profile.
    pub contribution_profile: ContributionProofSecurityProfile,
}

impl ProductionBackendPolicyReport {
    /// Build a policy report from selected backend instances.
    pub fn from_backends<V, P>(vss_backend: &V, proof_backend: &P) -> Self
    where
        V: VssCommitmentBackend,
        P: ContributionProofBackend,
    {
        Self {
            vss_profile: vss_backend.security_profile(),
            contribution_profile: proof_backend.security_profile(),
        }
    }

    /// Returns whether all selected backend families declare production
    /// security profiles.
    pub const fn supports_production_security_claim(self) -> bool {
        self.vss_profile.supports_production_security_claim()
            && self
                .contribution_profile
                .supports_production_security_claim()
    }
}

/// Require production-declared VSS and contribution proof backend families.
///
/// This fails closed if either backend is a scaffold or production-candidate
/// placeholder. It is intentionally stricter than checking a single backend
/// family because a threshold ML-DSA production claim depends on both DKG/VSS
/// soundness and proof-bound contribution soundness.
pub fn require_production_threshold_backends<V, P>(
    vss_backend: &V,
    proof_backend: &P,
) -> Result<ProductionBackendPolicyReport, ThresholdError>
where
    V: VssCommitmentBackend,
    P: ContributionProofBackend,
{
    let report = ProductionBackendPolicyReport::from_backends(vss_backend, proof_backend);
    if report.supports_production_security_claim() {
        Ok(report)
    } else {
        Err(ThresholdError::BackendUnavailable {
            reason:
                "threshold production policy requires production VSS and contribution proof backends",
        })
    }
}
