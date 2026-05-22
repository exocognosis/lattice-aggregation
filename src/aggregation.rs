//! Threshold signature aggregation API surface.

use crate::{
    backend::{Mldsa65Backend, SimulatedBackend},
    collections::PartialShareSet,
    errors::ThresholdError,
    transcript::ThresholdSigningTranscript,
    types::ThresholdSignature,
};

/// Threshold signature aggregation interface.
pub trait SignatureAggregator {
    /// Error returned by aggregation operations.
    type Error;

    /// Aggregate partial shares into a standard-size threshold signature.
    fn aggregate_shares(
        transcript: ThresholdSigningTranscript,
        partial_shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error>;
}

/// Deterministic simulation aggregator reserved for the aggregation task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatedAggregator;

impl SignatureAggregator for SimulatedAggregator {
    type Error = ThresholdError;

    fn aggregate_shares(
        transcript: ThresholdSigningTranscript,
        partial_shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error> {
        SimulatedBackend::aggregate(transcript.public_key(), &transcript, partial_shares)
    }
}
