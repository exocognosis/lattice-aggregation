use lattice_aggregation::{
    production::coordinator::{AggregateAttemptRequest, CoordinatorAggregateGate},
    production::provider::StandardMldsa65Provider,
    SimulatedBackend,
};

fn assert_provider<P: StandardMldsa65Provider>() {}

fn main() {
    assert_provider::<SimulatedBackend>();
    let _ = core::any::type_name::<AggregateAttemptRequest>();
    let _ = CoordinatorAggregateGate::<SimulatedBackend>::finalize;
}
