//! Placeholder aggregation API surface for a later implementation task.

/// Threshold signature aggregation interface reserved for the aggregation task.
#[allow(private_bounds)]
pub trait SignatureAggregator: sealed::Sealed {}

/// Deterministic simulation aggregator reserved for the aggregation task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatedAggregator;

impl SignatureAggregator for SimulatedAggregator {}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::SimulatedAggregator {}
}
