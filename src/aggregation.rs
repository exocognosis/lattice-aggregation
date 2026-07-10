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

/// Aggregate partial shares with an explicit cryptographic backend.
///
/// Validates transcript/validator binding, then delegates to
/// [`Mldsa65Backend::aggregate`].
pub fn aggregate_with_backend<B>(
    transcript: ThresholdSigningTranscript,
    partial_shares: PartialShareSet,
) -> Result<ThresholdSignature, ThresholdError>
where
    B: Mldsa65Backend<Error = ThresholdError>,
{
    if partial_shares.threshold() != transcript.threshold()
        || !partial_shares
            .validators()
            .iter()
            .copied()
            .eq(transcript.validator_set().iter().copied())
    {
        return Err(ThresholdError::TranscriptMismatch);
    }

    B::aggregate(transcript.public_key(), &transcript, partial_shares)
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
        aggregate_with_backend::<SimulatedBackend>(transcript, partial_shares)
    }
}
