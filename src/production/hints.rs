//! Public hint-routing state for coordinator-assisted conformance flows.

use crate::{SessionId, ValidatorId};

use super::types::AttemptId;

/// Public request for an interactive hint-routing step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HintRoutingRequest {
    session_id: SessionId,
    attempt_id: AttemptId,
    active_set_digest: [u8; 32],
    challenge_digest: [u8; 32],
    near_boundary_commitment_digest: [u8; 32],
}

impl HintRoutingRequest {
    /// Construct a hint-routing request from public transcript digests.
    pub const fn new(
        session_id: SessionId,
        attempt_id: AttemptId,
        active_set_digest: [u8; 32],
        challenge_digest: [u8; 32],
        near_boundary_commitment_digest: [u8; 32],
    ) -> Self {
        Self {
            session_id,
            attempt_id,
            active_set_digest,
            challenge_digest,
            near_boundary_commitment_digest,
        }
    }

    /// Borrow the session ID.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Return the attempt ID.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Borrow the active-set digest.
    pub const fn active_set_digest(&self) -> &[u8; 32] {
        &self.active_set_digest
    }

    /// Borrow the challenge digest.
    pub const fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }

    /// Borrow the near-boundary commitment digest.
    pub const fn near_boundary_commitment_digest(&self) -> &[u8; 32] {
        &self.near_boundary_commitment_digest
    }
}

/// Public response digest for a hint-routing step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HintRoutingResponse {
    validator: ValidatorId,
    response_digest: [u8; 32],
}

impl HintRoutingResponse {
    /// Construct a digest-only hint-routing response.
    pub const fn new(validator: ValidatorId, response_digest: [u8; 32]) -> Self {
        Self {
            validator,
            response_digest,
        }
    }

    /// Return the responding validator.
    pub const fn validator(self) -> ValidatorId {
        self.validator
    }

    /// Borrow the response digest.
    pub const fn response_digest(&self) -> &[u8; 32] {
        &self.response_digest
    }
}

/// Hint-routing completion decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HintRoutingDecision {
    /// Hint routing completed and later gates may continue.
    Completed,
    /// Abort before releasing response shares.
    AbortBeforeShareRelease,
}

impl HintRoutingDecision {
    /// Return true when hint routing completed.
    pub const fn hint_routing_completed(self) -> bool {
        matches!(self, Self::Completed)
    }
}
