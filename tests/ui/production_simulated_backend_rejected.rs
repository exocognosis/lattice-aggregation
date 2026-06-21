use lattice_aggregation::{
    production::coordinator::{AggregateAttemptRequest, CoordinatorAggregateGate},
    SimulatedBackend,
};

fn main() {
    let _ = core::any::type_name::<AggregateAttemptRequest>();
    let _ = CoordinatorAggregateGate::<SimulatedBackend>::finalize;
}
