//! Coordinator-assisted aggregate finalization gate.

use core::marker::PhantomData;

use crate::{ThresholdError, ThresholdSignature};

use super::{
    policy::ProductionPolicy, provider::StandardMldsa65Provider,
    transcript::ProductionSigningTranscript,
};

/// Aggregate finalization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateAttemptRequest {
    /// Bound production transcript.
    pub transcript: ProductionSigningTranscript,
    /// Candidate signature assembled by the coordinator profile.
    pub candidate_signature: ThresholdSignature,
    /// Runtime release policy.
    pub policy: ProductionPolicy,
}

/// Final standard-verifier gate for coordinator aggregates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoordinatorAggregateGate<P> {
    _provider: PhantomData<P>,
}

impl<P> CoordinatorAggregateGate<P>
where
    P: StandardMldsa65Provider,
{
    /// Finalize a candidate signature only after policy and standard verification pass.
    pub fn finalize(
        request: AggregateAttemptRequest,
    ) -> Result<ThresholdSignature, ThresholdError> {
        request.policy.require_production_release()?;
        let public_key = &request.transcript.input().public_key;
        let message = request.transcript.input().message_binding.as_bytes();
        if !P::verify(public_key, message, &request.candidate_signature)? {
            return Err(ThresholdError::StandardVerificationFailed);
        }
        Ok(request.candidate_signature)
    }
}
