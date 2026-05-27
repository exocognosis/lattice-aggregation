use dytallix_pq_threshold::{
    state, PartialShareSet, SignatureAggregator, SimulatedAggregator, SigningSession,
};

fn invalid(session: SigningSession<state::AwaitingPartialSignatures>, shares: PartialShareSet) {
    let _ = SimulatedAggregator::aggregate_shares(session, shares);
}

fn main() {}
