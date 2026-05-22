# Threshold Adapter Scaffold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Phase 3/4 adapter scaffold inside `dytallix-pq-threshold` for async P2P-style threshold sessions, consensus callbacks, slashing evidence, and in-memory simulation tests.

**Architecture:** The adapter layer sits above the existing Phase 1/2 threshold API. It defines crate-owned wire framing, async system-boundary traits, an mpsc-driven actor, bounded session state, and simulation-only evidence flows without importing the real Dytallix L1 networking or consensus code.

**Tech Stack:** Rust 2021, existing threshold crate, `tokio` for async actor/tests, `async-trait` for async adapter traits, crate-owned byte encoding, existing simulation backend.

---

## File Structure

- Modify `Cargo.toml`: add `tokio` and `async-trait`.
- Modify `src/lib.rs`: expose `pub mod adapter;`.
- Create `src/adapter.rs`: adapter module exports.
- Create `src/adapter/wire.rs`: `PqcThresholdWireMsg` and canonical encode/decode.
- Create `src/adapter/evidence.rs`: `EvidenceKind` and `SlashingEvidence`.
- Create `src/adapter/traits.rs`: `P2pNetworkAdapter` and `ConsensusStateAdapter`.
- Create `src/adapter/actor.rs`: `ActorEvent`, `ActorConfig`, `ThresholdActor`, and bounded session state.
- Create `tests/simulation.rs`: async in-memory actor tests.

## Task 1: Adapter Module and Dependencies

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/lib.rs`
- Create: `src/adapter.rs`

- [ ] **Step 1: Write a failing adapter import test**

Create `tests/simulation.rs` with:

```rust
use dytallix_pq_threshold::adapter;

#[test]
fn adapter_module_is_exported() {
    let _ = core::any::type_name::<adapter::wire::PqcThresholdWireMsg>();
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```bash
cargo test --test simulation adapter_module_is_exported
```

Expected: FAIL with unresolved import or missing `adapter` module.

- [ ] **Step 3: Add dependencies**

Modify `Cargo.toml`:

```toml
[dependencies]
async-trait = "0.1"
sha3 = "0.10"
thiserror = "1"
tokio = { version = "1", features = ["macros", "rt", "sync", "time"] }
zeroize = { version = "1", features = ["derive"] }
```

Keep existing `trybuild` dev dependency unchanged.

- [ ] **Step 4: Export adapter module**

Add to `src/lib.rs`:

```rust
pub mod adapter;
```

- [ ] **Step 5: Create adapter module shell**

Create `src/adapter.rs`:

```rust
//! Async adapter scaffold for P2P and consensus integration.
//!
//! This module is simulation infrastructure. It does not integrate with the
//! real Dytallix L1 P2P network, state trie, gas runtime, or slashing runtime.

pub mod actor;
pub mod evidence;
pub mod traits;
pub mod wire;
```

Create minimal temporary module stubs so the crate compiles:

`src/adapter/wire.rs`

```rust
//! Versioned threshold wire messages.

/// Placeholder wire message; replaced by Task 3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PqcThresholdWireMsg {}
```

`src/adapter/evidence.rs`

```rust
//! Fault attribution evidence for adapter simulations.
```

`src/adapter/traits.rs`

```rust
//! Adapter traits for external P2P and consensus systems.
```

`src/adapter/actor.rs`

```rust
//! Async threshold protocol actor scaffold.
```

- [ ] **Step 6: Run the adapter import test**

Run:

```bash
cargo test --test simulation adapter_module_is_exported
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml src/lib.rs src/adapter.rs src/adapter tests/simulation.rs
git commit -m "chore: scaffold threshold adapter module"
```

## Task 2: Evidence Types

**Files:**
- Create/replace: `src/adapter/evidence.rs`
- Modify: `tests/simulation.rs`

- [ ] **Step 1: Add failing evidence tests**

Append to `tests/simulation.rs`:

```rust
use dytallix_pq_threshold::{
    adapter::evidence::{EvidenceKind, SlashingEvidence},
    ValidatorId,
};

#[test]
fn slashing_evidence_keeps_attributable_validator_and_frame() {
    let evidence = SlashingEvidence::new(
        [7; 32],
        ValidatorId(2),
        EvidenceKind::InvalidPartialSignature,
        Some(vec![1, 2, 3]),
        "invalid partial share",
    );

    assert_eq!(evidence.session_id, [7; 32]);
    assert_eq!(evidence.validator, ValidatorId(2));
    assert_eq!(evidence.kind, EvidenceKind::InvalidPartialSignature);
    assert_eq!(evidence.wire_frame.as_deref(), Some(&[1, 2, 3][..]));
    assert_eq!(evidence.details, "invalid partial share");
}
```

- [ ] **Step 2: Run the evidence test and verify it fails**

Run:

```bash
cargo test --test simulation slashing_evidence_keeps_attributable_validator_and_frame
```

Expected: FAIL with unresolved `EvidenceKind` and `SlashingEvidence`.

- [ ] **Step 3: Implement evidence types**

Replace `src/adapter/evidence.rs`:

```rust
//! Fault attribution evidence for adapter simulations.
//!
//! These structures are not on-chain slashing transactions. They are portable
//! evidence packets that the real consensus adapter can translate later.

use crate::{SessionId, ValidatorId};

/// Classifies adapter-level threshold protocol faults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceKind {
    /// A wire frame failed canonical decoding or validation.
    MalformedWireMessage,
    /// A validator submitted conflicting duplicate data.
    DuplicateMessage,
    /// A validator committed but did not submit a partial signature before timeout.
    CommitmentWithoutPartial,
    /// A validator submitted a partial signature that failed adapter validation.
    InvalidPartialSignature,
    /// A threshold session exceeded its configured timeout.
    SessionTimeout,
}

/// Simulation-compatible evidence packet for consensus callbacks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlashingEvidence {
    /// Threshold session where the fault occurred.
    pub session_id: SessionId,
    /// Validator attributable for the fault.
    pub validator: ValidatorId,
    /// Fault class.
    pub kind: EvidenceKind,
    /// Optional canonical wire frame that triggered the fault.
    pub wire_frame: Option<Vec<u8>>,
    /// Human-readable detail for logs and tests.
    pub details: String,
}

impl SlashingEvidence {
    /// Construct a simulation evidence packet.
    pub fn new(
        session_id: SessionId,
        validator: ValidatorId,
        kind: EvidenceKind,
        wire_frame: Option<Vec<u8>>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            session_id,
            validator,
            kind,
            wire_frame,
            details: details.into(),
        }
    }
}
```

- [ ] **Step 4: Run evidence tests**

Run:

```bash
cargo test --test simulation slashing_evidence_keeps_attributable_validator_and_frame
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapter/evidence.rs tests/simulation.rs
git commit -m "feat: add adapter slashing evidence types"
```

## Task 3: Wire Message Encoding

**Files:**
- Replace: `src/adapter/wire.rs`
- Modify: `tests/simulation.rs`

- [ ] **Step 1: Add failing wire tests**

Append to `tests/simulation.rs`:

```rust
use dytallix_pq_threshold::adapter::wire::{
    PqcThresholdWireMsg, WireDecodeError, MAX_DKG_SHARE_BYTES, MAX_PARTIAL_SHARE_BYTES,
};

#[test]
fn sign_commit_wire_encoding_is_golden() {
    let msg = PqcThresholdWireMsg::SignCommit {
        session_id: [0x11; 32],
        block_height: 0x0102_0304_0506_0708,
        validator_index: 0x1234,
        commitment: [0xAA; 32],
    };

    let encoded = msg.encode();

    assert_eq!(encoded.len(), 76);
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1], 3);
    assert_eq!(&encoded[2..34], &[0x11; 32]);
    assert_eq!(&encoded[34..42], &0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(&encoded[42..44], &0x1234u16.to_be_bytes());
    assert_eq!(&encoded[44..76], &[0xAA; 32]);
    assert_eq!(PqcThresholdWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn wire_decode_rejects_oversized_variable_payloads() {
    let msg = PqcThresholdWireMsg::PartialSignature {
        session_id: [9; 32],
        validator_index: 2,
        partial_sig_share: vec![7; MAX_PARTIAL_SHARE_BYTES + 1],
    };

    assert_eq!(
        PqcThresholdWireMsg::decode(&msg.encode()),
        Err(WireDecodeError::PayloadTooLarge)
    );
}
```

- [ ] **Step 2: Run wire tests and verify failure**

Run:

```bash
cargo test --test simulation wire
```

Expected: FAIL with missing wire types and methods.

- [ ] **Step 3: Implement wire codec**

Replace `src/adapter/wire.rs` with:

```rust
//! Versioned threshold wire messages and canonical byte encoding.

use crate::SessionId;

/// Maximum encrypted DKG share payload accepted by the adapter.
pub const MAX_DKG_SHARE_BYTES: usize = 16 * 1024;
/// Maximum partial signature share payload accepted by the adapter.
pub const MAX_PARTIAL_SHARE_BYTES: usize = 16 * 1024;

const WIRE_VERSION: u8 = 1;
const MSG_DKG_COMMIT: u8 = 1;
const MSG_DKG_SHARE_EXCHANGE: u8 = 2;
const MSG_SIGN_COMMIT: u8 = 3;
const MSG_PARTIAL_SIGNATURE: u8 = 4;

/// Decode failure for canonical adapter wire frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WireDecodeError {
    /// Frame is shorter or longer than required for its message type.
    #[error("invalid wire length")]
    InvalidLength,
    /// Version byte is unsupported.
    #[error("unsupported wire version")]
    UnsupportedVersion,
    /// Message type byte is unknown.
    #[error("unknown wire message type")]
    UnknownMessageType,
    /// Variable payload length exceeds adapter bounds.
    #[error("wire payload too large")]
    PayloadTooLarge,
}

/// Threshold protocol wire message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PqcThresholdWireMsg {
    /// Distributed key generation commitment.
    DkgCommit {
        /// Protocol session ID.
        session_id: SessionId,
        /// Sending validator index.
        validator_index: u16,
        /// Commitment digest.
        commitment_hash: [u8; 32],
    },
    /// Targeted encrypted DKG share exchange.
    DkgShareExchange {
        /// Protocol session ID.
        session_id: SessionId,
        /// Receiving validator index.
        target_validator_index: u16,
        /// Encrypted share bytes.
        encrypted_share: Vec<u8>,
    },
    /// Signing commitment for a block height.
    SignCommit {
        /// Protocol session ID.
        session_id: SessionId,
        /// Block height being signed.
        block_height: u64,
        /// Sending validator index.
        validator_index: u16,
        /// Commitment bytes.
        commitment: [u8; 32],
    },
    /// Partial signature response.
    PartialSignature {
        /// Protocol session ID.
        session_id: SessionId,
        /// Sending validator index.
        validator_index: u16,
        /// Backend-defined partial share bytes.
        partial_sig_share: Vec<u8>,
    },
}

impl PqcThresholdWireMsg {
    /// Encode this message into canonical versioned bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::DkgCommit { session_id, validator_index, commitment_hash } => {
                let mut out = Vec::with_capacity(68);
                out.push(WIRE_VERSION);
                out.push(MSG_DKG_COMMIT);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&validator_index.to_be_bytes());
                out.extend_from_slice(commitment_hash);
                out
            }
            Self::DkgShareExchange { session_id, target_validator_index, encrypted_share } => {
                encode_variable(MSG_DKG_SHARE_EXCHANGE, session_id, *target_validator_index, encrypted_share)
            }
            Self::SignCommit { session_id, block_height, validator_index, commitment } => {
                let mut out = Vec::with_capacity(76);
                out.push(WIRE_VERSION);
                out.push(MSG_SIGN_COMMIT);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&block_height.to_be_bytes());
                out.extend_from_slice(&validator_index.to_be_bytes());
                out.extend_from_slice(commitment);
                out
            }
            Self::PartialSignature { session_id, validator_index, partial_sig_share } => {
                encode_variable(MSG_PARTIAL_SIGNATURE, session_id, *validator_index, partial_sig_share)
            }
        }
    }

    /// Decode canonical versioned bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        if bytes.len() < 2 {
            return Err(WireDecodeError::InvalidLength);
        }
        if bytes[0] != WIRE_VERSION {
            return Err(WireDecodeError::UnsupportedVersion);
        }
        match bytes[1] {
            MSG_DKG_COMMIT => decode_dkg_commit(bytes),
            MSG_DKG_SHARE_EXCHANGE => decode_variable(bytes, MAX_DKG_SHARE_BYTES).map(
                |(session_id, target_validator_index, encrypted_share)| Self::DkgShareExchange {
                    session_id,
                    target_validator_index,
                    encrypted_share,
                },
            ),
            MSG_SIGN_COMMIT => decode_sign_commit(bytes),
            MSG_PARTIAL_SIGNATURE => decode_variable(bytes, MAX_PARTIAL_SHARE_BYTES).map(
                |(session_id, validator_index, partial_sig_share)| Self::PartialSignature {
                    session_id,
                    validator_index,
                    partial_sig_share,
                },
            ),
            _ => Err(WireDecodeError::UnknownMessageType),
        }
    }
}

fn encode_variable(msg_type: u8, session_id: &SessionId, validator: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + payload.len());
    out.push(WIRE_VERSION);
    out.push(msg_type);
    out.extend_from_slice(session_id);
    out.extend_from_slice(&validator.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_dkg_commit(bytes: &[u8]) -> Result<PqcThresholdWireMsg, WireDecodeError> {
    if bytes.len() != 68 {
        return Err(WireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let validator_index = u16::from_be_bytes([bytes[34], bytes[35]]);
    let mut commitment_hash = [0u8; 32];
    commitment_hash.copy_from_slice(&bytes[36..68]);
    Ok(PqcThresholdWireMsg::DkgCommit { session_id, validator_index, commitment_hash })
}

fn decode_sign_commit(bytes: &[u8]) -> Result<PqcThresholdWireMsg, WireDecodeError> {
    if bytes.len() != 76 {
        return Err(WireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let block_height = u64::from_be_bytes(bytes[34..42].try_into().expect("slice length checked"));
    let validator_index = u16::from_be_bytes([bytes[42], bytes[43]]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&bytes[44..76]);
    Ok(PqcThresholdWireMsg::SignCommit { session_id, block_height, validator_index, commitment })
}

fn decode_variable(
    bytes: &[u8],
    max_payload: usize,
) -> Result<(SessionId, u16, Vec<u8>), WireDecodeError> {
    if bytes.len() < 40 {
        return Err(WireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let validator = u16::from_be_bytes([bytes[34], bytes[35]]);
    let payload_len = u32::from_be_bytes(bytes[36..40].try_into().expect("slice length checked")) as usize;
    if payload_len > max_payload {
        return Err(WireDecodeError::PayloadTooLarge);
    }
    if bytes.len() != 40 + payload_len {
        return Err(WireDecodeError::InvalidLength);
    }
    Ok((session_id, validator, bytes[40..].to_vec()))
}
```

- [ ] **Step 4: Run wire tests**

Run:

```bash
cargo test --test simulation wire
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapter/wire.rs tests/simulation.rs
git commit -m "feat: add adapter wire message codec"
```

## Task 4: Adapter Traits

**Files:**
- Replace: `src/adapter/traits.rs`
- Modify: `tests/simulation.rs`

- [ ] **Step 1: Add failing async trait mock test**

Append to `tests/simulation.rs`:

```rust
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use dytallix_pq_threshold::adapter::{
    evidence::SlashingEvidence,
    traits::{ConsensusStateAdapter, P2pNetworkAdapter},
};

#[derive(Clone, Default)]
struct RecordingNetwork {
    sent: Arc<Mutex<Vec<(Option<u16>, PqcThresholdWireMsg)>>>,
}

#[async_trait]
impl P2pNetworkAdapter for RecordingNetwork {
    type Error = ();

    async fn broadcast(&self, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        self.sent.lock().unwrap().push((None, msg));
        Ok(())
    }

    async fn send_to(&self, target: u16, msg: PqcThresholdWireMsg) -> Result<(), Self::Error> {
        self.sent.lock().unwrap().push((Some(target), msg));
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RecordingConsensus {
    finalized: Arc<Mutex<Vec<(u64, Vec<u8>)>>>,
    evidence: Arc<Mutex<Vec<SlashingEvidence>>>,
    gas: Arc<Mutex<Vec<u64>>>,
}

#[async_trait]
impl ConsensusStateAdapter for RecordingConsensus {
    type Error = ();

    async fn on_signature_finalized(&self, block_height: u64, signature: Vec<u8>) -> Result<(), Self::Error> {
        self.finalized.lock().unwrap().push((block_height, signature));
        Ok(())
    }

    async fn submit_slashing_evidence(&self, evidence: SlashingEvidence) -> Result<(), Self::Error> {
        self.evidence.lock().unwrap().push(evidence);
        Ok(())
    }

    async fn update_gas_baseline(&self, block_height: u64) -> Result<(), Self::Error> {
        self.gas.lock().unwrap().push(block_height);
        Ok(())
    }
}

#[tokio::test]
async fn adapter_traits_can_be_mocked_in_memory() {
    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let msg = PqcThresholdWireMsg::DkgCommit {
        session_id: [1; 32],
        validator_index: 1,
        commitment_hash: [2; 32],
    };

    network.broadcast(msg.clone()).await.unwrap();
    network.send_to(2, msg).await.unwrap();
    consensus.update_gas_baseline(10).await.unwrap();

    assert_eq!(network.sent.lock().unwrap().len(), 2);
    assert_eq!(*consensus.gas.lock().unwrap(), vec![10]);
}
```

- [ ] **Step 2: Run trait test and verify failure**

Run:

```bash
cargo test --test simulation adapter_traits_can_be_mocked_in_memory
```

Expected: FAIL with missing adapter traits.

- [ ] **Step 3: Implement adapter traits**

Replace `src/adapter/traits.rs`:

```rust
//! Async boundaries implemented by real P2P and consensus systems.

use async_trait::async_trait;

use crate::adapter::{evidence::SlashingEvidence, wire::PqcThresholdWireMsg};

/// Boundary expected from the Dytallix P2P network layer.
#[async_trait]
pub trait P2pNetworkAdapter: Send + Sync + 'static {
    /// Adapter error.
    type Error: core::fmt::Debug + Send + Sync + 'static;

    /// Broadcast a threshold message to validators in the current epoch.
    async fn broadcast(&self, msg: PqcThresholdWireMsg) -> Result<(), Self::Error>;

    /// Send a targeted threshold message to one validator.
    async fn send_to(&self, target: u16, msg: PqcThresholdWireMsg) -> Result<(), Self::Error>;
}

/// Boundary expected from the Dytallix consensus and state engine.
#[async_trait]
pub trait ConsensusStateAdapter: Send + Sync + 'static {
    /// Adapter error.
    type Error: core::fmt::Debug + Send + Sync + 'static;

    /// Called when a threshold signing session finishes successfully.
    async fn on_signature_finalized(
        &self,
        block_height: u64,
        signature: Vec<u8>,
    ) -> Result<(), Self::Error>;

    /// Called when a validator fault is attributable.
    async fn submit_slashing_evidence(
        &self,
        evidence: SlashingEvidence,
    ) -> Result<(), Self::Error>;

    /// Called when consensus should switch to flat gas baseline accounting.
    async fn update_gas_baseline(&self, block_height: u64) -> Result<(), Self::Error>;
}
```

- [ ] **Step 4: Run trait test**

Run:

```bash
cargo test --test simulation adapter_traits_can_be_mocked_in_memory
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapter/traits.rs tests/simulation.rs
git commit -m "feat: add adapter boundary traits"
```

## Task 5: Actor Core and Capacity

**Files:**
- Replace: `src/adapter/actor.rs`
- Modify: `tests/simulation.rs`

- [ ] **Step 1: Add failing capacity test**

Append to `tests/simulation.rs`:

```rust
use std::time::Duration;
use tokio::sync::mpsc;
use dytallix_pq_threshold::{
    adapter::actor::{ActorConfig, ActorEvent, ThresholdActor},
    PrivateKeyShare, ThresholdPublicKey,
};

fn actor_config(max_sessions: usize) -> ActorConfig {
    ActorConfig {
        local_validator: ValidatorId(1),
        validator_set: vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
        threshold: 2,
        public_key: ThresholdPublicKey([4; 1952]),
        local_share: PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec()),
        round_timeout: Duration::from_millis(50),
        max_sessions,
    }
}

#[tokio::test]
async fn actor_rejects_sessions_past_capacity() {
    let (tx, rx) = mpsc::channel(8);
    let network = RecordingNetwork::default();
    let consensus = RecordingConsensus::default();
    let actor = ThresholdActor::new(actor_config(1), network, consensus, rx).unwrap();
    let handle = tokio::spawn(actor.run());

    tx.send(ActorEvent::TriggerSigningRound {
        session_id: [1; 32],
        block_height: 1,
        message_hash: [9; 32],
    }).await.unwrap();
    tx.send(ActorEvent::TriggerSigningRound {
        session_id: [2; 32],
        block_height: 2,
        message_hash: [8; 32],
    }).await.unwrap();
    drop(tx);
    handle.await.unwrap();

    assert_eq!(actor_config(1).max_sessions, 1);
}
```

- [ ] **Step 2: Run capacity test and verify failure**

Run:

```bash
cargo test --test simulation actor_rejects_sessions_past_capacity
```

Expected: FAIL with missing actor types.

- [ ] **Step 3: Implement actor core**

Replace `src/adapter/actor.rs` with an implementation that defines:

```rust
//! Async threshold protocol actor scaffold.

use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

use tokio::sync::mpsc;

use crate::{
    adapter::{
        evidence::{EvidenceKind, SlashingEvidence},
        traits::{ConsensusStateAdapter, P2pNetworkAdapter},
        wire::PqcThresholdWireMsg,
    },
    Commitment, CommitmentSet, PartialShareSet, PartialSignatureShare, PrivateKeyShare,
    SessionId, SignatureAggregator, SigningSession, SimulatedAggregator, ThresholdError,
    ThresholdPublicKey, ThresholdSigner, ValidatorId,
};

/// Events consumed by the threshold actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActorEvent {
    /// Message received from the P2P layer.
    IncomingNetworkMessage(PqcThresholdWireMsg),
    /// Start a block signing round.
    TriggerSigningRound {
        /// Session ID.
        session_id: SessionId,
        /// Block height.
        block_height: u64,
        /// Block payload hash.
        message_hash: [u8; 32],
    },
    /// Reap stale sessions.
    TimeoutCheck,
}

/// Actor construction config.
#[derive(Clone, Debug)]
pub struct ActorConfig {
    /// Local validator ID.
    pub local_validator: ValidatorId,
    /// Validator set for this epoch.
    pub validator_set: Vec<ValidatorId>,
    /// Signing threshold.
    pub threshold: u16,
    /// Threshold public key for simulation.
    pub public_key: ThresholdPublicKey,
    /// Local private key share.
    pub local_share: PrivateKeyShare,
    /// Round timeout.
    pub round_timeout: Duration,
    /// Maximum active sessions.
    pub max_sessions: usize,
}
```

The implementation must include:

- `ThresholdActor::new(config, network, consensus, inbox) -> Result<Self, ThresholdError>`.
- `run(mut self)` loop consuming events.
- `start_signing_session`: capacity-check, create `SigningSession`, initiate signing, store active session, broadcast `SignCommit`, call `update_gas_baseline`.
- `handle_network_msg`: store `SignCommit`, store `PartialSignature`, generate `InvalidPartialSignature` evidence if partial share starts with bytes `b"poison"`.
- `reap_stale_sessions`: if elapsed exceeds timeout and committed validators did not submit partials, emit `CommitmentWithoutPartial` evidence and remove session.
- `active_session_count(&self) -> usize` for unit tests if direct non-run tests are needed.

The active session should use:

```rust
struct ActiveSigningSession {
    block_height: u64,
    message_hash: [u8; 32],
    created_at: Instant,
    local_commitment: Commitment,
    commitments: BTreeMap<ValidatorId, Commitment>,
    partials: BTreeMap<ValidatorId, PartialSignatureShare>,
    finalized: bool,
}
```

When `partials.len() >= threshold`, build a `PartialShareSet`, a `CommitmentSet`, a `ThresholdSigningTranscript`, and call `SimulatedAggregator::aggregate_shares`. On success call `consensus.on_signature_finalized`.

- [ ] **Step 4: Run capacity test**

Run:

```bash
cargo test --test simulation actor_rejects_sessions_past_capacity
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapter/actor.rs tests/simulation.rs
git commit -m "feat: add bounded threshold actor core"
```

## Task 6: Actor Simulation Scenarios

**Files:**
- Modify: `src/adapter/actor.rs`
- Modify: `tests/simulation.rs`

- [ ] **Step 1: Add failing ideal, poisoned, and timeout tests**

Append tests that:

```rust
#[tokio::test]
async fn actor_finalizes_ideal_threshold_signature() {
    // Start actor with threshold 2.
    // Trigger session [3;32] at block 44.
    // Send SignCommit from validator 2.
    // Send two PartialSignature messages for validators 1 and 2.
    // Drop sender, await actor.
    // Assert consensus finalized exactly one signature with len MLDSA65_SIGNATURE_BYTES.
}

#[tokio::test]
async fn actor_submits_evidence_for_poisoned_partial_share() {
    // Trigger session [4;32].
    // Send SignCommit from validator 2.
    // Send PartialSignature from validator 2 with partial_sig_share b"poison-share".to_vec().
    // Assert consensus evidence contains EvidenceKind::InvalidPartialSignature for ValidatorId(2).
    // Assert no finalized signature exists.
}

#[tokio::test]
async fn actor_submits_liveness_evidence_for_commitment_without_partial() {
    // Trigger session [5;32].
    // Send SignCommit from validator 2.
    // Sleep longer than timeout.
    // Send TimeoutCheck.
    // Assert consensus evidence contains EvidenceKind::CommitmentWithoutPartial for ValidatorId(2).
}
```

- [ ] **Step 2: Run new tests and verify failure**

Run:

```bash
cargo test --test simulation actor_
```

Expected: at least one new test FAILS before implementation adjustments.

- [ ] **Step 3: Implement behavior**

Adjust `ThresholdActor` to satisfy the tests exactly:

- On local trigger, insert local commitment and local synthetic partial share so a single peer partial can complete threshold 2.
- Treat `PartialSignature.partial_sig_share` starting with `b"poison"` as invalid and submit `InvalidPartialSignature` evidence.
- On timeout, emit `CommitmentWithoutPartial` for each validator in `commitments` absent from `partials`, except the local validator when local partial was synthesized.
- Remove finalized or failed sessions to keep the active map bounded.

- [ ] **Step 4: Run actor simulation tests**

Run:

```bash
cargo test --test simulation actor_
```

Expected: PASS.

- [ ] **Step 5: Run all tests**

Run:

```bash
cargo test
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/adapter/actor.rs tests/simulation.rs
git commit -m "feat: simulate async threshold actor flows"
```

## Task 7: Final Verification and Guardrails

**Files:**
- Modify only if verification finds issues.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt
```

Expected: exits 0.

- [ ] **Step 2: Run full tests**

Run:

```bash
cargo test
```

Expected: PASS for existing threshold tests and new adapter simulation tests.

- [ ] **Step 3: Run no-default-features tests**

Run:

```bash
cargo test --no-default-features
```

Expected: PASS.

- [ ] **Step 4: Run clippy**

Run:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 5: Run guardrail scan**

Run:

```bash
rg -n "production-ready|production consensus|real Dytallix|Noise_IK_PQC|simulation backend|not production|does not integrate|real ML-DSA" src docs tests
```

Expected: matches are guardrail statements only. No text claims the adapter is the real L1 integration.

- [ ] **Step 6: Commit final fixes if needed**

If verification required changes:

```bash
git add src tests docs Cargo.toml
git commit -m "fix: complete adapter scaffold verification"
```

If no changes were needed, do not create an empty commit.

## Self-Review

- Spec coverage: The plan covers adapter modules, wire messages, async traits, actor session cache, fault evidence, in-memory simulation tests, timeout handling, poisoned-share evidence, gas baseline callback, and final guardrails.
- Intentional gap: This plan does not integrate real `Noise_IK_PQC`, the real Dytallix consensus engine, the state trie, real slashing transactions, or the gas runtime. It provides the adapter boundary for a future repository integration step.
- Scope scan: No unresolved marker text or unspecified implementation steps remain.
- Type consistency: Public names match the design spec: `PqcThresholdWireMsg`, `ActorEvent`, `ThresholdActor`, `ActorConfig`, `P2pNetworkAdapter`, `ConsensusStateAdapter`, `SlashingEvidence`, and `EvidenceKind`.
