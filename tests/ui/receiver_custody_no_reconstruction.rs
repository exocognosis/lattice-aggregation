use lattice_aggregation::crypto::{
    receiver_custody::{CoordinatorCustodyBundle, ReceiverShareVault},
    share_transport::Shake256Transport,
};

fn coordinator_cannot_export(bundle: CoordinatorCustodyBundle) {
    let _ = bundle.reconstruct_secret();
    let _ = bundle.export_secret();
}

fn receiver_cannot_reconstruct(vault: ReceiverShareVault<Shake256Transport>) {
    let _ = vault.reconstruct_secret();
    let _ = vault.export_secret();
}

fn main() {}
