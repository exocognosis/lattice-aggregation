//! Production profile policy gates.

use crate::ThresholdError;

/// Release status for the coordinator-assisted profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorReleaseStatus {
    /// Feature is available only for hazmat and conformance work.
    HazmatUnreviewed,
    /// Feature has evidence-backed production approval.
    ProductionApproved,
}

/// Runtime policy for the coordinator-assisted profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionPolicy {
    status: CoordinatorReleaseStatus,
}

impl ProductionPolicy {
    /// Construct the default unreviewed hazmat policy.
    pub fn hazmat_unreviewed() -> Self {
        Self {
            status: CoordinatorReleaseStatus::HazmatUnreviewed,
        }
    }

    /// Construct an approved policy for audited release builds.
    pub fn production_approved() -> Self {
        Self {
            status: CoordinatorReleaseStatus::ProductionApproved,
        }
    }

    /// Require production release gates to have passed.
    pub fn require_production_release(self) -> Result<(), ThresholdError> {
        match self.status {
            CoordinatorReleaseStatus::HazmatUnreviewed => {
                Err(ThresholdError::ProductionPolicyBlocked {
                    reason: "coordinator profile has not passed production release gates",
                })
            }
            CoordinatorReleaseStatus::ProductionApproved => Ok(()),
        }
    }

    /// Return the configured release status.
    pub fn status(self) -> CoordinatorReleaseStatus {
        self.status
    }
}
