use dytallix_pq_threshold::{state, SigningSession, ThresholdSigner};

fn invalid(session: SigningSession<state::AwaitingPartialSignatures>) {
    let _ = session.initiate_signing();
}

fn main() {}
