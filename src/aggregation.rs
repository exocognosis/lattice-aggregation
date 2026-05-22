//! Placeholder aggregation API surface for a later implementation task.

/// Threshold signature aggregation interface reserved for the aggregation task.
pub trait SignatureAggregator {}

/// Deterministic simulation aggregator reserved for the aggregation task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatedAggregator;
