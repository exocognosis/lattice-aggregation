//! Async adapter boundaries between the threshold scaffold and an L1 runtime.

use async_trait::async_trait;

use crate::adapter::{evidence::SlashingEvidence, wire::PqcThresholdWireMsg};

/// Boundary expected from the production P2P network layer.
#[async_trait]
pub trait P2pNetworkAdapter: Send + Sync + 'static {
    /// Adapter-specific network error.
    type Error: core::fmt::Debug + Send + Sync + 'static;

    /// Broadcast a threshold protocol message to validators in the active epoch.
    async fn broadcast(&self, msg: PqcThresholdWireMsg) -> Result<(), Self::Error>;

    /// Send a threshold protocol message to one validator.
    async fn send_to(&self, target: u16, msg: PqcThresholdWireMsg) -> Result<(), Self::Error>;
}

/// Boundary expected from the production consensus and state engine.
#[async_trait]
pub trait ConsensusStateAdapter: Send + Sync + 'static {
    /// Adapter-specific consensus/state error.
    type Error: core::fmt::Debug + Send + Sync + 'static;

    /// Called when a threshold signing session finishes with a flat signature.
    async fn on_signature_finalized(
        &self,
        block_height: u64,
        signature: Vec<u8>,
    ) -> Result<(), Self::Error>;

    /// Called when the adapter can attribute malicious or slashable behavior.
    async fn submit_slashing_evidence(&self, evidence: SlashingEvidence)
        -> Result<(), Self::Error>;

    /// Called when consensus should apply the flat threshold-signature gas baseline.
    async fn update_gas_baseline(&self, block_height: u64) -> Result<(), Self::Error>;
}
