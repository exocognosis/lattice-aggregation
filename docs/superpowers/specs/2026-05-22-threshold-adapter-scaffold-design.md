# Threshold Adapter Scaffold Design

Date: 2026-05-22

## Status

Approved direction for Phase 3 P2P Network Protocol Upgrades and Phase 4 Consensus Engine integration boundaries, implemented as an adapter scaffold inside `lattice-aggregation`.

This design does not integrate with the real production L1 networking, Noise transport, state trie, block proposal engine, or gas runtime. It defines the portable boundary that those systems will later implement.

## Scope

This spec covers:

- Versioned threshold wire message types for DKG, signing commitments, and partial signatures.
- Async actor boundaries driven by `tokio::sync::mpsc`.
- Adapter traits for P2P, consensus state callbacks, and gas baseline updates.
- Bounded in-memory session tracking for simulation and DoS-resistant API shape.
- Fault attribution structures for liveness and invalid-share evidence.
- In-memory async simulation tests for ideal, timeout, and poisoned-share flows.

This spec does not cover:

- Real `Noise_IK_PQC` transport integration.
- Real block proposal or state trie mutation.
- Real slashing transaction submission.
- Real ML-DSA threshold algebraic share verification.
- Production consensus deployment.

## Design Goals

The adapter scaffold must:

- Keep the Phase 1/2 cryptographic API separate from network and consensus code.
- Provide deterministic, bounded async behavior that can be tested in memory.
- Define stable wire framing for threshold protocol messages.
- Avoid unbounded memory growth from spam sessions or oversized payloads.
- Attribute protocol failures as liveness faults, malformed messages, invalid partial shares, or timeouts.
- Expose consensus callbacks for finalized signatures, slashing evidence, and gas baseline changes.
- Preserve the existing simulation-only guardrails until a real audited threshold backend exists.

## Module Layout

```text
lattice-aggregation/
├── src/
│   ├── adapter.rs
│   └── adapter/
│       ├── actor.rs
│       ├── evidence.rs
│       ├── traits.rs
│       └── wire.rs
└── tests/
    └── simulation.rs
```

`src/lib.rs` will expose `pub mod adapter;`.

## Wire Protocol

The scaffold introduces `PqcThresholdWireMsg` for the message families needed by Phase 3:

```rust
pub enum PqcThresholdWireMsg {
    DkgCommit {
        session_id: SessionId,
        validator_index: u16,
        commitment_hash: [u8; 32],
    },
    DkgShareExchange {
        session_id: SessionId,
        target_validator_index: u16,
        encrypted_share: Vec<u8>,
    },
    SignCommit {
        session_id: SessionId,
        block_height: u64,
        validator_index: u16,
        commitment: [u8; 32],
    },
    PartialSignature {
        session_id: SessionId,
        validator_index: u16,
        partial_sig_share: Vec<u8>,
    },
}
```

The implementation should not use serde as the canonical encoding. It should provide crate-owned `encode` and `decode` methods with:

- One-byte protocol version.
- One-byte message type.
- Fixed-width big-endian integer fields.
- Length-prefixed variable payloads.
- Maximum payload sizes for encrypted DKG shares and partial signatures.
- Exact malformed-input errors rather than panics.

The message enum may derive `Debug`, `Clone`, `Eq`, and `PartialEq` for tests. Serialization stability must be locked by golden byte tests.

## Adapter Traits

`adapter::traits` defines the upstream system boundaries:

```rust
#[async_trait]
pub trait P2pNetworkAdapter: Send + Sync + 'static {
    type Error: core::fmt::Debug + Send + Sync + 'static;

    async fn broadcast(&self, msg: PqcThresholdWireMsg) -> Result<(), Self::Error>;
    async fn send_to(&self, target: u16, msg: PqcThresholdWireMsg) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait ConsensusStateAdapter: Send + Sync + 'static {
    type Error: core::fmt::Debug + Send + Sync + 'static;

    async fn on_signature_finalized(
        &self,
        block_height: u64,
        signature: Vec<u8>,
    ) -> Result<(), Self::Error>;

    async fn submit_slashing_evidence(
        &self,
        evidence: SlashingEvidence,
    ) -> Result<(), Self::Error>;

    async fn update_gas_baseline(&self, block_height: u64) -> Result<(), Self::Error>;
}
```

The crate owns only these traits. The real L1 repository will implement them for its network and consensus systems.

## Actor Model

`ThresholdActor<N, C>` owns one validator's async threshold adapter state:

```rust
pub enum ActorEvent {
    IncomingNetworkMessage(PqcThresholdWireMsg),
    TriggerSigningRound {
        session_id: SessionId,
        block_height: u64,
        message_hash: [u8; 32],
    },
    TimeoutCheck,
}
```

The actor stores bounded active sessions:

```rust
pub struct ThresholdActor<N, C> {
    local_validator: ValidatorId,
    validator_set: Vec<ValidatorId>,
    threshold: u16,
    network: N,
    consensus: C,
    inbox: mpsc::Receiver<ActorEvent>,
    active_sessions: HashMap<SessionId, ActiveSigningSession>,
    round_timeout: Duration,
    max_sessions: usize,
}
```

The actor must never wait synchronously for validators. It reacts to messages and timeout ticks:

- `TriggerSigningRound` creates an active signing session if capacity allows.
- The local commitment is broadcast as `SignCommit`.
- Incoming `SignCommit` messages are validated and stored by session.
- Incoming `PartialSignature` messages are validated, stored, or converted into slashing evidence.
- Once a quorum is reached, the actor aggregates through the Phase 1/2 API and calls `on_signature_finalized`.
- `TimeoutCheck` marks stale sessions failed and emits liveness evidence for validators that committed but did not submit a partial signature.

## Session State

`ActiveSigningSession` is an adapter-level session record, not a replacement for `SigningSession`:

- Session ID.
- Block height.
- Message hash.
- Creation timestamp.
- Validator set.
- Threshold.
- Local state-machine handle.
- Received commitments.
- Received partial shares.
- Committed validators.
- Completed or failed status.

The session cache must:

- Reject new sessions when `max_sessions` is reached.
- Ignore messages for unknown sessions unless the message type is allowed to create a session.
- Reject duplicate validators using the same attribution model as `CommitmentSet` and `PartialShareSet`.
- Bound payload lengths before allocation-heavy processing.

## Fault Evidence

`adapter::evidence` defines:

```rust
pub enum EvidenceKind {
    MalformedWireMessage,
    DuplicateMessage,
    CommitmentWithoutPartial,
    InvalidPartialSignature,
    SessionTimeout,
}

pub struct SlashingEvidence {
    pub session_id: SessionId,
    pub validator: ValidatorId,
    pub kind: EvidenceKind,
    pub wire_frame: Option<Vec<u8>>,
    pub details: String,
}
```

Evidence is simulation-compatible. It is not an on-chain slashing transaction format.

## Consensus Boundary

Phase 4 is represented by trait callbacks instead of direct L1 mutation:

- Successful aggregation calls `on_signature_finalized(block_height, signature_bytes)`.
- Timeout, malformed input, duplicate input, or poisoned partial share calls `submit_slashing_evidence`.
- Flat gas migration calls `update_gas_baseline(block_height)`.

The adapter must not delete real Bitfield-Compressed Merkle Proof code because that code is not present in this workspace. Instead, it exposes the integration callback and documents the downstream work.

## Simulation Tests

`tests/simulation.rs` should use in-memory mocks:

- `MockNetwork` backed by `tokio::sync::mpsc::Sender<ActorEvent>`.
- `MockConsensus` recording finalized signatures, evidence, and gas updates.
- A deterministic validator set of three or four validators.

Required scenarios:

- Ideal signing flow finalizes one `MLDSA65_SIGNATURE_BYTES`-sized signature.
- Poisoned partial share creates `InvalidPartialSignature` evidence and does not finalize.
- Timeout after commitment without partial share creates `CommitmentWithoutPartial` evidence.
- Session capacity limit rejects spam sessions without unbounded map growth.
- Wire decoding rejects oversized payloads and malformed frames without panic.

## Dependencies

The crate will add:

- `tokio` with `macros`, `rt`, `sync`, and `time` features for tests and actor runtime.
- `async-trait` for async adapter traits.

No real network, consensus, or state trie dependencies are introduced.

## Production Gates

This adapter scaffold is not production consensus integration. Production use requires:

- Real production P2P implementation of `P2pNetworkAdapter`.
- Real consensus/state implementation of `ConsensusStateAdapter`.
- Real threshold ML-DSA backend with share verification.
- Wire compatibility tests against real network frames.
- End-to-end local testnet runs in the L1 repository.
- External review of timeout, evidence, and slashing semantics.
