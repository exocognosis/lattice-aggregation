# Threshold ML-DSA Core API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the initial `lattice-aggregation` Rust crate with research-grade threshold ML-DSA-65 API boundaries, type-state signing flow, canonical transcript validation, and a deterministic simulation backend.

**Architecture:** The crate exposes production-shaped public traits and opaque types while keeping cryptographic internals behind backend traits. The first backend is deterministic simulation only, so tests can exercise DKG, signing, transcript, validation, and aggregation behavior without claiming audited threshold ML-DSA security.

**Tech Stack:** Rust 2021, Cargo library crate, `sha3` for SHAKE-compatible hashing, `thiserror` for typed errors, `zeroize` for key-share cleanup, `trybuild` for compile-fail type-state tests.

---

## File Structure

- Create `Cargo.toml`: crate metadata, dependencies, library config, feature flags.
- Create `src/lib.rs`: public module graph and re-exports.
- Create `src/types.rs`: constants and opaque public type wrappers.
- Create `src/errors.rs`: crate-wide `ThresholdError`.
- Create `src/collections.rs`: validated `CommitmentSet`, `PartialShareSet`, and DKG share collections.
- Create `src/transcript.rs`: canonical transcript construction and challenge derivation.
- Create `src/backend.rs`: backend traits plus deterministic simulation backend types.
- Create `src/protocol.rs`: type-state `SigningSession` and round transitions.
- Create `src/dkg.rs`: simulated DKG engine implementing `ThresholdKeyGeneration`.
- Create `src/aggregation.rs`: aggregation trait and simulation aggregator.
- Create `src/serialization.rs`: explicit versioned wire encoding helpers for public payloads.
- Create `tests/transcript_determinism.rs`: transcript ordering and challenge tests.
- Create `tests/validation.rs`: threshold, duplicate, unknown validator, and malformed input tests.
- Create `tests/simulated_flow.rs`: end-to-end simulated DKG, signing, aggregation tests.
- Create `tests/type_state.rs`: `trybuild` harness.
- Create `tests/ui/type_state_invalid_partial.rs`: compile-fail invalid round call.
- Create `tests/ui/type_state_invalid_aggregate.rs`: compile-fail invalid aggregation state.
- Create `docs/cryptography/phase-1-noise-bound-model.md`: scoped mathematical model and non-production gates.

## Task 1: Scaffold the Rust Crate

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`

- [ ] **Step 1: Write the crate manifest**

Create `Cargo.toml` with:

```toml
[package]
name = "lattice-aggregation"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
description = "Research-grade threshold ML-DSA-65 API boundary and simulation backend"

[lib]
name = "lattice_aggregation"
path = "src/lib.rs"

[features]
default = ["simulated"]
simulated = []
hazmat = []

[dependencies]
sha3 = "0.10"
thiserror = "1"
zeroize = { version = "1", features = ["derive"] }

[dev-dependencies]
trybuild = "1"
```

- [ ] **Step 2: Create the public module graph**

Create `src/lib.rs` with:

```rust
#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Research-grade threshold ML-DSA-65 API boundary.
//!
//! This crate exposes protocol state, transcript, validation, and backend traits
//! for threshold ML-DSA-65 experiments. The default backend is a deterministic
//! simulation backend and does not produce real ML-DSA signatures.

pub mod aggregation;
pub mod backend;
pub mod collections;
pub mod dkg;
pub mod errors;
pub mod protocol;
pub mod serialization;
pub mod transcript;
pub mod types;

pub use aggregation::{SignatureAggregator, SimulatedAggregator};
pub use backend::{Mldsa65Backend, SimulatedBackend};
pub use collections::{CommitmentSet, PartialShareSet, ValidatedDkgShares};
pub use dkg::{SimulatedDkg, ThresholdKeyGeneration};
pub use errors::ThresholdError;
pub use protocol::{state, SigningSession, ThresholdSigner};
pub use transcript::{SigningTranscript, ThresholdSigningTranscript};
pub use types::{
    Challenge, Commitment, PartialSignatureShare, PrivateKeyShare, SessionId, ThresholdPublicKey,
    ThresholdSignature, ValidatorId, COMMITMENT_BYTES, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES, POLY_SEED_BYTES, SESSION_ID_BYTES,
};
```

- [ ] **Step 3: Run cargo check and capture the expected failure**

Run:

```bash
cargo check
```

Expected: FAIL because module files such as `src/types.rs` do not exist yet.

- [ ] **Step 4: Commit scaffold**

```bash
git add Cargo.toml src/lib.rs
git commit -m "chore: scaffold threshold ML-DSA crate"
```

## Task 2: Add Core Types and Errors

**Files:**
- Create: `src/types.rs`
- Create: `src/errors.rs`
- Test: `tests/validation.rs`

- [ ] **Step 1: Write failing tests for type constants and errors**

Create `tests/validation.rs` with:

```rust
use lattice_aggregation::{
    ThresholdError, ValidatorId, COMMITMENT_BYTES, MLDSA65_PUBLICKEY_BYTES,
    MLDSA65_SIGNATURE_BYTES, POLY_SEED_BYTES,
};

#[test]
fn exposes_mldsa65_fips_204_sizes() {
    assert_eq!(MLDSA65_PUBLICKEY_BYTES, 1952);
    assert_eq!(MLDSA65_SIGNATURE_BYTES, 3309);
    assert_eq!(POLY_SEED_BYTES, 32);
    assert_eq!(COMMITMENT_BYTES, 32);
}

#[test]
fn validator_id_is_orderable() {
    let mut ids = vec![ValidatorId(3), ValidatorId(1), ValidatorId(2)];
    ids.sort();
    assert_eq!(ids, vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
}

#[test]
fn error_message_includes_attributable_validator() {
    let err = ThresholdError::DuplicateValidator { validator: ValidatorId(7) };
    assert!(err.to_string().contains("validator 7"));
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
cargo test --test validation
```

Expected: FAIL with unresolved imports for `ThresholdError` and type wrappers.

- [ ] **Step 3: Implement public types**

Create `src/types.rs` with:

```rust
//! Public opaque types and ML-DSA-65 constants.

use zeroize::Zeroize;

/// FIPS 204 ML-DSA-65 public key byte length.
pub const MLDSA65_PUBLICKEY_BYTES: usize = 1952;
/// FIPS 204 ML-DSA-65 signature byte length.
pub const MLDSA65_SIGNATURE_BYTES: usize = 3309;
/// Seed length used by polynomial commitment derivation.
pub const POLY_SEED_BYTES: usize = 32;
/// Session identifier byte length.
pub const SESSION_ID_BYTES: usize = 32;
/// Commitment digest byte length.
pub const COMMITMENT_BYTES: usize = 32;

/// Unique identity tag for a protocol session.
pub type SessionId = [u8; SESSION_ID_BYTES];

/// Stable validator identity inside one threshold validator set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorId(pub u16);

impl core::fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "validator {}", self.0)
    }
}

/// Joint public verification key for the threshold identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdPublicKey(pub [u8; MLDSA65_PUBLICKEY_BYTES]);

/// Standard-size ML-DSA-65 signature bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdSignature(pub [u8; MLDSA65_SIGNATURE_BYTES]);

/// Commitment to a validator's local masking contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Commitment(pub [u8; COMMITMENT_BYTES]);

/// Transcript-derived challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge(pub [u8; 32]);

/// Serialized partial signature share produced by one validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialSignatureShare {
    /// Validator that produced this partial share.
    pub signer: ValidatorId,
    /// Backend-defined share encoding.
    pub bytes: Vec<u8>,
}

/// Opaque local signing key share.
#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct PrivateKeyShare {
    /// Validator that owns this share.
    pub share_id: ValidatorId,
    /// Backend-owned secret material. The simulation backend uses deterministic bytes.
    pub(crate) secret: Vec<u8>,
}

impl PrivateKeyShare {
    /// Construct a key share for backend-owned secret bytes.
    pub fn new(share_id: ValidatorId, secret: Vec<u8>) -> Self {
        Self { share_id, secret }
    }

    /// Borrow backend-owned secret bytes.
    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}
```

- [ ] **Step 4: Implement errors**

Create `src/errors.rs` with:

```rust
//! Error types for threshold protocol validation.

use crate::types::ValidatorId;

/// Errors surfaced by the threshold ML-DSA API boundary.
#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum ThresholdError {
    /// Threshold or validator-set parameters are invalid.
    #[error("invalid threshold parameters: threshold={threshold}, total_nodes={total_nodes}")]
    InvalidThresholdParameters { threshold: u16, total_nodes: u16 },

    /// Validator ID is not in the configured validator set.
    #[error("unknown {validator}")]
    UnknownValidator { validator: ValidatorId },

    /// Validator ID appeared more than once.
    #[error("duplicate {validator}")]
    DuplicateValidator { validator: ValidatorId },

    /// Too few commitments were supplied.
    #[error("insufficient commitments: required {required}, received {received}")]
    InsufficientCommitments { required: u16, received: usize },

    /// Too few partial shares were supplied.
    #[error("insufficient partial shares: required {required}, received {received}")]
    InsufficientPartialShares { required: u16, received: usize },

    /// Commitment validation failed for an attributable validator.
    #[error("commitment verification failed for {validator}")]
    CommitmentVerificationFailed { validator: ValidatorId },

    /// Partial share validation failed for an attributable validator.
    #[error("partial share verification failed for {validator}")]
    PartialShareVerificationFailed { validator: ValidatorId },

    /// Local or aggregate rejection sampling checks failed.
    #[error("rejection sampling failed for {validator}")]
    RejectionSamplingFailed { validator: ValidatorId },

    /// Transcript input does not match the current protocol session.
    #[error("transcript mismatch")]
    TranscriptMismatch,

    /// Versioned wire bytes could not be decoded.
    #[error("malformed serialization: {reason}")]
    MalformedSerialization { reason: &'static str },

    /// Requested backend is not enabled or is blocked by safety gates.
    #[error("backend unavailable: {reason}")]
    BackendUnavailable { reason: &'static str },

    /// Standard ML-DSA verification rejected the signature.
    #[error("standard ML-DSA verification failed")]
    StandardVerificationFailed,
}
```

- [ ] **Step 5: Run validation tests**

Run:

```bash
cargo test --test validation
```

Expected: PASS for the three tests in `tests/validation.rs`.

- [ ] **Step 6: Commit types and errors**

```bash
git add src/types.rs src/errors.rs tests/validation.rs
git commit -m "feat: add threshold core types and errors"
```

## Task 3: Add Validated Collections

**Files:**
- Create: `src/collections.rs`
- Modify: `tests/validation.rs`

- [ ] **Step 1: Add failing collection validation tests**

Append to `tests/validation.rs`:

```rust
use lattice_aggregation::{Commitment, CommitmentSet, PartialShareSet, PartialSignatureShare};

fn validators() -> Vec<ValidatorId> {
    vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]
}

fn commitment(byte: u8) -> Commitment {
    Commitment([byte; 32])
}

#[test]
fn commitment_set_rejects_duplicate_validators() {
    let result = CommitmentSet::new(
        validators(),
        2,
        vec![(ValidatorId(1), commitment(1)), (ValidatorId(1), commitment(2))],
    );
    assert_eq!(
        result.unwrap_err(),
        ThresholdError::DuplicateValidator { validator: ValidatorId(1) }
    );
}

#[test]
fn commitment_set_rejects_unknown_validator() {
    let result = CommitmentSet::new(
        validators(),
        2,
        vec![(ValidatorId(4), commitment(4)), (ValidatorId(2), commitment(2))],
    );
    assert_eq!(
        result.unwrap_err(),
        ThresholdError::UnknownValidator { validator: ValidatorId(4) }
    );
}

#[test]
fn commitment_set_canonicalizes_order() {
    let set = CommitmentSet::new(
        validators(),
        2,
        vec![(ValidatorId(3), commitment(3)), (ValidatorId(1), commitment(1))],
    )
    .unwrap();
    let ordered: Vec<_> = set.iter().map(|(id, _)| *id).collect();
    assert_eq!(ordered, vec![ValidatorId(1), ValidatorId(3)]);
}

#[test]
fn partial_share_set_rejects_insufficient_shares() {
    let result = PartialShareSet::new(
        validators(),
        2,
        vec![PartialSignatureShare { signer: ValidatorId(1), bytes: vec![1, 2, 3] }],
    );
    assert_eq!(
        result.unwrap_err(),
        ThresholdError::InsufficientPartialShares { required: 2, received: 1 }
    );
}
```

- [ ] **Step 2: Run validation tests to verify failure**

Run:

```bash
cargo test --test validation
```

Expected: FAIL with unresolved `CommitmentSet` and `PartialShareSet`.

- [ ] **Step 3: Implement validated collections**

Create `src/collections.rs` with:

```rust
//! Validated canonical collections for protocol inputs.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    errors::ThresholdError,
    types::{Commitment, PartialSignatureShare, ValidatorId},
};

/// Canonical set of commitments keyed by validator ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentSet {
    validator_set: BTreeSet<ValidatorId>,
    threshold: u16,
    commitments: BTreeMap<ValidatorId, Commitment>,
}

impl CommitmentSet {
    /// Validate and canonicalize network-provided commitments.
    pub fn new(
        validator_set: Vec<ValidatorId>,
        threshold: u16,
        commitments: Vec<(ValidatorId, Commitment)>,
    ) -> Result<Self, ThresholdError> {
        validate_threshold(threshold, validator_set.len() as u16)?;
        let validator_set = set_from_validators(validator_set)?;
        if commitments.len() < threshold as usize {
            return Err(ThresholdError::InsufficientCommitments {
                required: threshold,
                received: commitments.len(),
            });
        }
        let mut ordered = BTreeMap::new();
        for (id, commitment) in commitments {
            if !validator_set.contains(&id) {
                return Err(ThresholdError::UnknownValidator { validator: id });
            }
            if ordered.insert(id, commitment).is_some() {
                return Err(ThresholdError::DuplicateValidator { validator: id });
            }
        }
        Ok(Self { validator_set, threshold, commitments: ordered })
    }

    /// Iterate commitments in canonical validator order.
    pub fn iter(&self) -> impl Iterator<Item = (&ValidatorId, &Commitment)> {
        self.commitments.iter()
    }

    /// Return the configured threshold.
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Return number of commitments.
    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    /// Return true when no commitments exist.
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }
}

/// Canonical set of partial signature shares keyed by validator ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialShareSet {
    shares: BTreeMap<ValidatorId, PartialSignatureShare>,
}

impl PartialShareSet {
    /// Validate and canonicalize partial shares.
    pub fn new(
        validator_set: Vec<ValidatorId>,
        threshold: u16,
        shares: Vec<PartialSignatureShare>,
    ) -> Result<Self, ThresholdError> {
        validate_threshold(threshold, validator_set.len() as u16)?;
        let validator_set = set_from_validators(validator_set)?;
        if shares.len() < threshold as usize {
            return Err(ThresholdError::InsufficientPartialShares {
                required: threshold,
                received: shares.len(),
            });
        }
        let mut ordered = BTreeMap::new();
        for share in shares {
            if !validator_set.contains(&share.signer) {
                return Err(ThresholdError::UnknownValidator { validator: share.signer });
            }
            if ordered.insert(share.signer, share).is_some() {
                return Err(ThresholdError::DuplicateValidator { validator: share.signer });
            }
        }
        Ok(Self { shares: ordered })
    }

    /// Iterate shares in canonical validator order.
    pub fn iter(&self) -> impl Iterator<Item = (&ValidatorId, &PartialSignatureShare)> {
        self.shares.iter()
    }

    /// Return number of shares.
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Return true when no shares exist.
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }
}

/// Validated DKG share commitments.
pub type ValidatedDkgShares = CommitmentSet;

pub(crate) fn validate_threshold(threshold: u16, total_nodes: u16) -> Result<(), ThresholdError> {
    if threshold == 0 || threshold > total_nodes {
        return Err(ThresholdError::InvalidThresholdParameters { threshold, total_nodes });
    }
    Ok(())
}

pub(crate) fn set_from_validators(
    validators: Vec<ValidatorId>,
) -> Result<BTreeSet<ValidatorId>, ThresholdError> {
    let mut set = BTreeSet::new();
    for id in validators {
        if !set.insert(id) {
            return Err(ThresholdError::DuplicateValidator { validator: id });
        }
    }
    Ok(set)
}
```

- [ ] **Step 4: Run validation tests**

Run:

```bash
cargo test --test validation
```

Expected: PASS.

- [ ] **Step 5: Commit validated collections**

```bash
git add src/collections.rs tests/validation.rs
git commit -m "feat: validate threshold protocol collections"
```

## Task 4: Add Canonical Transcript and Challenge Derivation

**Files:**
- Create: `src/transcript.rs`
- Create: `tests/transcript_determinism.rs`

- [ ] **Step 1: Write failing transcript tests**

Create `tests/transcript_determinism.rs` with:

```rust
use lattice_aggregation::{
    Commitment, CommitmentSet, SigningTranscript, ThresholdPublicKey, ValidatorId,
};

fn public_key() -> ThresholdPublicKey {
    ThresholdPublicKey([9u8; 1952])
}

fn session(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn validators() -> Vec<ValidatorId> {
    vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]
}

#[test]
fn challenge_is_independent_of_network_order() {
    let left = CommitmentSet::new(
        validators(),
        2,
        vec![(ValidatorId(3), Commitment([3; 32])), (ValidatorId(1), Commitment([1; 32]))],
    )
    .unwrap();
    let right = CommitmentSet::new(
        validators(),
        2,
        vec![(ValidatorId(1), Commitment([1; 32])), (ValidatorId(3), Commitment([3; 32]))],
    )
    .unwrap();

    let left_transcript = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        left,
    )
    .unwrap();
    let right_transcript = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        right,
    )
    .unwrap();

    assert_eq!(left_transcript.challenge(), right_transcript.challenge());
}

#[test]
fn challenge_binds_message() {
    let commitments = CommitmentSet::new(
        validators(),
        2,
        vec![(ValidatorId(1), Commitment([1; 32])), (ValidatorId(2), Commitment([2; 32]))],
    )
    .unwrap();

    let left = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-42",
        commitments.clone(),
    )
    .unwrap();
    let right = SigningTranscript::new(
        session(7),
        2,
        validators(),
        public_key(),
        b"block-43",
        commitments,
    )
    .unwrap();

    assert_ne!(left.challenge(), right.challenge());
}
```

- [ ] **Step 2: Run transcript tests to verify failure**

Run:

```bash
cargo test --test transcript_determinism
```

Expected: FAIL with unresolved `SigningTranscript`.

- [ ] **Step 3: Implement transcript construction**

Create `src/transcript.rs` with:

```rust
//! Canonical transcript construction for threshold signing.

use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};

use crate::{
    collections::CommitmentSet,
    errors::ThresholdError,
    types::{Challenge, SessionId, ThresholdPublicKey, ValidatorId},
};

const PROTOCOL_LABEL: &[u8] = b"lattice-aggregation/threshold-mldsa65";
const PROTOCOL_VERSION: u16 = 1;

/// Fully bound signing transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningTranscript {
    session_id: SessionId,
    threshold: u16,
    validator_set: Vec<ValidatorId>,
    public_key: ThresholdPublicKey,
    message: Vec<u8>,
    commitments: CommitmentSet,
    challenge: Challenge,
}

/// Aggregator-facing transcript alias.
pub type ThresholdSigningTranscript = SigningTranscript;

impl SigningTranscript {
    /// Construct a canonical transcript and derive its challenge.
    pub fn new(
        session_id: SessionId,
        threshold: u16,
        mut validator_set: Vec<ValidatorId>,
        public_key: ThresholdPublicKey,
        message: &[u8],
        commitments: CommitmentSet,
    ) -> Result<Self, ThresholdError> {
        validator_set.sort();
        if commitments.threshold() != threshold {
            return Err(ThresholdError::TranscriptMismatch);
        }
        let challenge = derive_challenge(
            session_id,
            threshold,
            &validator_set,
            &public_key,
            message,
            &commitments,
        );
        Ok(Self {
            session_id,
            threshold,
            validator_set,
            public_key,
            message: message.to_vec(),
            commitments,
            challenge,
        })
    }

    /// Return the derived challenge.
    pub fn challenge(&self) -> Challenge {
        self.challenge
    }

    /// Return the message bound into the transcript.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Return the public key bound into the transcript.
    pub fn public_key(&self) -> &ThresholdPublicKey {
        &self.public_key
    }

    /// Return the validator set bound into the transcript.
    pub fn validator_set(&self) -> &[ValidatorId] {
        &self.validator_set
    }
}

fn derive_challenge(
    session_id: SessionId,
    threshold: u16,
    validator_set: &[ValidatorId],
    public_key: &ThresholdPublicKey,
    message: &[u8],
    commitments: &CommitmentSet,
) -> Challenge {
    let mut hasher = Shake256::default();
    hasher.update(PROTOCOL_LABEL);
    hasher.update(&PROTOCOL_VERSION.to_be_bytes());
    hasher.update(&session_id);
    hasher.update(&threshold.to_be_bytes());
    hasher.update(&(validator_set.len() as u16).to_be_bytes());
    for id in validator_set {
        hasher.update(&id.0.to_be_bytes());
    }
    hasher.update(&public_key.0);
    hasher.update(&(message.len() as u64).to_be_bytes());
    hasher.update(message);
    hasher.update(&(commitments.len() as u16).to_be_bytes());
    for (id, commitment) in commitments.iter() {
        hasher.update(&id.0.to_be_bytes());
        hasher.update(&commitment.0);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    Challenge(out)
}
```

- [ ] **Step 4: Run transcript tests**

Run:

```bash
cargo test --test transcript_determinism
```

Expected: PASS.

- [ ] **Step 5: Run all tests**

Run:

```bash
cargo test
```

Expected: PASS for validation and transcript tests.

- [ ] **Step 6: Commit transcript**

```bash
git add src/transcript.rs tests/transcript_determinism.rs
git commit -m "feat: derive canonical signing transcripts"
```

## Task 5: Add Backend Trait and Simulation Backend

**Files:**
- Create: `src/backend.rs`
- Modify: `tests/simulated_flow.rs`

- [ ] **Step 1: Write failing backend simulation test**

Create `tests/simulated_flow.rs` with:

```rust
use lattice_aggregation::{
    CommitmentSet, Mldsa65Backend, PrivateKeyShare, SigningTranscript, SimulatedBackend,
    ThresholdPublicKey, ValidatorId,
};

#[test]
fn simulated_backend_derives_repeatable_commitment() {
    let share = PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec());
    let public_key = ThresholdPublicKey([5; 1952]);
    let commitments = CommitmentSet::new(
        vec![ValidatorId(1), ValidatorId(2)],
        1,
        vec![(ValidatorId(1), lattice_aggregation::Commitment([1; 32]))],
    )
    .unwrap();
    let transcript = SigningTranscript::new(
        [8; 32],
        1,
        vec![ValidatorId(1), ValidatorId(2)],
        public_key,
        b"message",
        commitments,
    )
    .unwrap();

    let (left, _) = SimulatedBackend::derive_commitment(&share, &transcript).unwrap();
    let (right, _) = SimulatedBackend::derive_commitment(&share, &transcript).unwrap();
    assert_eq!(left, right);
}
```

- [ ] **Step 2: Run simulation test to verify failure**

Run:

```bash
cargo test --test simulated_flow simulated_backend_derives_repeatable_commitment
```

Expected: FAIL with unresolved `Mldsa65Backend` and `SimulatedBackend`.

- [ ] **Step 3: Implement backend trait and simulation backend**

Create `src/backend.rs` with:

```rust
//! Backend traits and deterministic simulation backend.

use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};

use crate::{
    collections::PartialShareSet,
    errors::ThresholdError,
    transcript::SigningTranscript,
    types::{
        Commitment, PartialSignatureShare, PrivateKeyShare, ThresholdPublicKey,
        ThresholdSignature, ValidatorId, MLDSA65_SIGNATURE_BYTES,
    },
};

/// Backend contract for ML-DSA-65 threshold operations.
pub trait Mldsa65Backend {
    /// Backend-specific error type.
    type Error;
    /// Backend key-share representation.
    type KeyShare;
    /// Secret retained between commitment and partial-sign rounds.
    type CommitmentSecret;

    /// Derive a local commitment and retained secret.
    fn derive_commitment(
        share: &Self::KeyShare,
        session: &SigningTranscript,
    ) -> Result<(Commitment, Self::CommitmentSecret), Self::Error>;

    /// Produce one partial signature share for the bound transcript.
    fn partial_sign(
        share: &Self::KeyShare,
        secret: Self::CommitmentSecret,
        transcript: &SigningTranscript,
    ) -> Result<PartialSignatureShare, Self::Error>;

    /// Aggregate validated shares into a standard-sized signature byte array.
    fn aggregate(
        public_key: &ThresholdPublicKey,
        transcript: &SigningTranscript,
        shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error>;

    /// Verify a standard signature. The simulation backend only verifies its own format.
    fn verify_standard(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, Self::Error>;
}

/// Deterministic simulation backend for tests and API development.
pub struct SimulatedBackend;

impl Mldsa65Backend for SimulatedBackend {
    type Error = ThresholdError;
    type KeyShare = PrivateKeyShare;
    type CommitmentSecret = [u8; 32];

    fn derive_commitment(
        share: &Self::KeyShare,
        session: &SigningTranscript,
    ) -> Result<(Commitment, Self::CommitmentSecret), Self::Error> {
        let seed = hash_parts(&[
            b"commitment-secret",
            share.secret(),
            &share.share_id.0.to_be_bytes(),
            &session.challenge().0,
        ]);
        let commitment = hash_parts(&[b"commitment", &seed, &session.challenge().0]);
        Ok((Commitment(commitment), seed))
    }

    fn partial_sign(
        share: &Self::KeyShare,
        secret: Self::CommitmentSecret,
        transcript: &SigningTranscript,
    ) -> Result<PartialSignatureShare, Self::Error> {
        let bytes = hash_parts(&[
            b"partial-signature",
            &secret,
            share.secret(),
            &share.share_id.0.to_be_bytes(),
            &transcript.challenge().0,
        ])
        .to_vec();
        Ok(PartialSignatureShare { signer: share.share_id, bytes })
    }

    fn aggregate(
        public_key: &ThresholdPublicKey,
        transcript: &SigningTranscript,
        shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error> {
        let mut hasher = Shake256::default();
        hasher.update(b"simulated-threshold-signature");
        hasher.update(&public_key.0);
        hasher.update(transcript.message());
        hasher.update(&transcript.challenge().0);
        for (id, share) in shares.iter() {
            hasher.update(&id.0.to_be_bytes());
            hasher.update(&(share.bytes.len() as u64).to_be_bytes());
            hasher.update(&share.bytes);
        }
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; MLDSA65_SIGNATURE_BYTES];
        reader.read(&mut out);
        Ok(ThresholdSignature(out))
    }

    fn verify_standard(
        _public_key: &ThresholdPublicKey,
        _message: &[u8],
        _signature: &ThresholdSignature,
    ) -> Result<bool, Self::Error> {
        Err(ThresholdError::BackendUnavailable {
            reason: "simulation backend does not implement standard ML-DSA verification",
        })
    }
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}
```

- [ ] **Step 4: Run backend simulation test**

Run:

```bash
cargo test --test simulated_flow simulated_backend_derives_repeatable_commitment
```

Expected: PASS.

- [ ] **Step 5: Commit backend**

```bash
git add src/backend.rs tests/simulated_flow.rs
git commit -m "feat: add simulated ML-DSA backend boundary"
```

## Task 6: Add Type-State Signing Protocol

**Files:**
- Create: `src/protocol.rs`
- Modify: `tests/simulated_flow.rs`

- [ ] **Step 1: Add failing signing-flow test**

Append to `tests/simulated_flow.rs`:

```rust
use lattice_aggregation::{SigningSession, ThresholdSigner};

#[test]
fn signing_session_advances_through_commitment_and_partial_rounds() {
    let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
    let public_key = ThresholdPublicKey([4; 1952]);
    let share = PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec());
    let session = SigningSession::new([3; 32], 2, validators.clone(), public_key, share).unwrap();

    let (awaiting, local_commitment) = session.initiate_signing().unwrap();
    let commitments = CommitmentSet::new(
        validators,
        2,
        vec![(ValidatorId(1), local_commitment), (ValidatorId(2), lattice_aggregation::Commitment([2; 32]))],
    )
    .unwrap();

    let (awaiting_partials, partial) =
        lattice_aggregation::SigningSession::generate_partial_signature(
            awaiting,
            commitments,
            b"block payload",
        )
        .unwrap();

    assert_eq!(partial.signer, ValidatorId(1));
    assert_eq!(awaiting_partials.challenge().0.len(), 32);
}
```

- [ ] **Step 2: Run signing-flow test to verify failure**

Run:

```bash
cargo test --test simulated_flow signing_session_advances_through_commitment_and_partial_rounds
```

Expected: FAIL with unresolved `SigningSession` and `ThresholdSigner`.

- [ ] **Step 3: Implement type-state protocol**

Create `src/protocol.rs` with:

```rust
//! Type-state signing protocol.

use crate::{
    backend::{Mldsa65Backend, SimulatedBackend},
    collections::{set_from_validators, validate_threshold, CommitmentSet},
    errors::ThresholdError,
    transcript::SigningTranscript,
    types::{
        Challenge, Commitment, PartialSignatureShare, PrivateKeyShare, SessionId,
        ThresholdPublicKey, ValidatorId,
    },
};

/// Signing session states.
pub mod state {
    use crate::types::{Challenge, Commitment};

    /// Initialized state containing local key share and session details.
    #[derive(Clone, Debug)]
    pub struct Initialized;

    /// Local commitment has been generated and peer commitments are needed.
    #[derive(Clone, Debug)]
    pub struct AwaitingCommitments {
        /// Local commitment broadcast to peers.
        pub local_commitment: Commitment,
    }

    /// Commitments are bound and partial signatures are being collected.
    #[derive(Clone, Debug)]
    pub struct AwaitingPartialSignatures {
        /// Transcript-derived challenge.
        pub challenge: Challenge,
    }

    /// Session concluded.
    #[derive(Clone, Debug)]
    pub struct Finalized;
}

/// Participant-local threshold signing session.
#[derive(Clone, Debug)]
pub struct SigningSession<State = state::Initialized> {
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    local_share: PrivateKeyShare,
    public_key: ThresholdPublicKey,
    validator_set: Vec<ValidatorId>,
    internal_state: State,
    commitment_secret: Option<[u8; 32]>,
}

impl SigningSession<state::Initialized> {
    /// Construct and validate an initialized signing session.
    pub fn new(
        session_id: SessionId,
        threshold: u16,
        validator_set: Vec<ValidatorId>,
        public_key: ThresholdPublicKey,
        local_share: PrivateKeyShare,
    ) -> Result<Self, ThresholdError> {
        let total_nodes = validator_set.len() as u16;
        validate_threshold(threshold, total_nodes)?;
        let set = set_from_validators(validator_set.clone())?;
        if !set.contains(&local_share.share_id) {
            return Err(ThresholdError::UnknownValidator { validator: local_share.share_id });
        }
        Ok(Self {
            session_id,
            threshold,
            total_nodes,
            local_share,
            public_key,
            validator_set,
            internal_state: state::Initialized,
            commitment_secret: None,
        })
    }
}

/// Public signing round interface.
pub trait ThresholdSigner: Sized {
    /// Error returned by the signing state machine.
    type Error;

    /// Round 1: generate local commitment.
    fn initiate_signing(
        self,
    ) -> Result<(SigningSession<state::AwaitingCommitments>, Commitment), Self::Error>;

    /// Round 2: bind commitments, derive challenge, and generate local partial signature.
    fn generate_partial_signature(
        session: SigningSession<state::AwaitingCommitments>,
        all_commitments: CommitmentSet,
        message: &[u8],
    ) -> Result<
        (
            SigningSession<state::AwaitingPartialSignatures>,
            PartialSignatureShare,
        ),
        Self::Error,
    >;
}

impl ThresholdSigner for SigningSession<state::Initialized> {
    type Error = ThresholdError;

    fn initiate_signing(
        self,
    ) -> Result<(SigningSession<state::AwaitingCommitments>, Commitment), Self::Error> {
        let empty_commitments = CommitmentSet::new(
            self.validator_set.clone(),
            1,
            vec![(self.local_share.share_id, Commitment([0; 32]))],
        )?;
        let pre_transcript = SigningTranscript::new(
            self.session_id,
            1,
            self.validator_set.clone(),
            self.public_key.clone(),
            b"precommit",
            empty_commitments,
        )?;
        let (commitment, secret) =
            SimulatedBackend::derive_commitment(&self.local_share, &pre_transcript)?;
        let next = SigningSession {
            session_id: self.session_id,
            threshold: self.threshold,
            total_nodes: self.total_nodes,
            local_share: self.local_share,
            public_key: self.public_key,
            validator_set: self.validator_set,
            internal_state: state::AwaitingCommitments { local_commitment: commitment },
            commitment_secret: Some(secret),
        };
        Ok((next, commitment))
    }

    fn generate_partial_signature(
        session: SigningSession<state::AwaitingCommitments>,
        all_commitments: CommitmentSet,
        message: &[u8],
    ) -> Result<
        (
            SigningSession<state::AwaitingPartialSignatures>,
            PartialSignatureShare,
        ),
        Self::Error,
    > {
        let transcript = SigningTranscript::new(
            session.session_id,
            session.threshold,
            session.validator_set.clone(),
            session.public_key.clone(),
            message,
            all_commitments,
        )?;
        let secret = session.commitment_secret.ok_or(ThresholdError::TranscriptMismatch)?;
        let partial = SimulatedBackend::partial_sign(&session.local_share, secret, &transcript)?;
        let challenge = transcript.challenge();
        let next = SigningSession {
            session_id: session.session_id,
            threshold: session.threshold,
            total_nodes: session.total_nodes,
            local_share: session.local_share,
            public_key: session.public_key,
            validator_set: session.validator_set,
            internal_state: state::AwaitingPartialSignatures { challenge },
            commitment_secret: None,
        };
        Ok((next, partial))
    }
}

impl SigningSession<state::AwaitingPartialSignatures> {
    /// Return transcript-derived challenge.
    pub fn challenge(&self) -> Challenge {
        self.internal_state.challenge
    }
}
```

- [ ] **Step 4: Run signing-flow test**

Run:

```bash
cargo test --test simulated_flow signing_session_advances_through_commitment_and_partial_rounds
```

Expected: PASS.

- [ ] **Step 5: Commit protocol**

```bash
git add src/protocol.rs tests/simulated_flow.rs
git commit -m "feat: add type-state signing protocol"
```

## Task 7: Add Simulated DKG and Aggregation APIs

**Files:**
- Create: `src/dkg.rs`
- Create: `src/aggregation.rs`
- Modify: `tests/simulated_flow.rs`

- [ ] **Step 1: Add failing DKG and aggregation flow test**

Append to `tests/simulated_flow.rs`:

```rust
use lattice_aggregation::{
    PartialShareSet, SignatureAggregator, SimulatedAggregator, SimulatedDkg,
    ThresholdKeyGeneration, ThresholdSignature,
};

#[test]
fn simulated_dkg_sign_and_aggregate_flow_returns_standard_size_signature() {
    let validators = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
    let session_id = [11; 32];

    let dkg_commitment = SimulatedDkg::generate_share_commitment(session_id, 3).unwrap();
    let dkg_shares = CommitmentSet::new(validators.clone(), 2, vec![
        (ValidatorId(1), dkg_commitment),
        (ValidatorId(2), lattice_aggregation::Commitment([22; 32])),
    ]).unwrap();
    let public_key = SimulatedDkg::finalize_public_key(dkg_shares).unwrap();

    let share_1 = PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec());
    let share_2 = PrivateKeyShare::new(ValidatorId(2), b"share-2".to_vec());

    let session_1 = SigningSession::new(session_id, 2, validators.clone(), public_key.clone(), share_1).unwrap();
    let session_2 = SigningSession::new(session_id, 2, validators.clone(), public_key.clone(), share_2).unwrap();

    let (awaiting_1, commitment_1) = session_1.initiate_signing().unwrap();
    let (awaiting_2, commitment_2) = session_2.initiate_signing().unwrap();
    let commitments = CommitmentSet::new(validators.clone(), 2, vec![
        (ValidatorId(1), commitment_1),
        (ValidatorId(2), commitment_2),
    ]).unwrap();

    let (state_1, partial_1) =
        SigningSession::generate_partial_signature(awaiting_1, commitments.clone(), b"block").unwrap();
    let (_state_2, partial_2) =
        SigningSession::generate_partial_signature(awaiting_2, commitments.clone(), b"block").unwrap();

    let transcript = lattice_aggregation::ThresholdSigningTranscript::new(
        session_id,
        2,
        validators.clone(),
        public_key,
        b"block",
        commitments,
    ).unwrap();
    assert_eq!(state_1.challenge(), transcript.challenge());

    let shares = PartialShareSet::new(validators, 2, vec![partial_1, partial_2]).unwrap();
    let signature: ThresholdSignature = SimulatedAggregator::aggregate_shares(transcript, shares).unwrap();
    assert_eq!(signature.0.len(), 3309);
}
```

- [ ] **Step 2: Run flow test to verify failure**

Run:

```bash
cargo test --test simulated_flow simulated_dkg_sign_and_aggregate_flow_returns_standard_size_signature
```

Expected: FAIL with unresolved `SimulatedDkg`, `ThresholdKeyGeneration`, `SignatureAggregator`, or `SimulatedAggregator`.

- [ ] **Step 3: Implement simulated DKG**

Create `src/dkg.rs` with:

```rust
//! Simulated DKG API boundary.

use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};

use crate::{
    collections::ValidatedDkgShares,
    errors::ThresholdError,
    types::{Commitment, SessionId, ThresholdPublicKey, MLDSA65_PUBLICKEY_BYTES},
};

/// Public DKG interface.
pub trait ThresholdKeyGeneration {
    /// Error returned by DKG operations.
    type Error;

    /// Generate this node's DKG commitment.
    fn generate_share_commitment(
        session: SessionId,
        nodes: u16,
    ) -> Result<Commitment, Self::Error>;

    /// Finalize a joint public key from verified DKG shares.
    fn finalize_public_key(
        verified_shares: ValidatedDkgShares,
    ) -> Result<ThresholdPublicKey, Self::Error>;
}

/// Deterministic simulated DKG engine.
pub struct SimulatedDkg;

impl ThresholdKeyGeneration for SimulatedDkg {
    type Error = ThresholdError;

    fn generate_share_commitment(
        session: SessionId,
        nodes: u16,
    ) -> Result<Commitment, Self::Error> {
        if nodes == 0 {
            return Err(ThresholdError::InvalidThresholdParameters {
                threshold: 1,
                total_nodes: nodes,
            });
        }
        let mut hasher = Shake256::default();
        hasher.update(b"simulated-dkg-commitment");
        hasher.update(&session);
        hasher.update(&nodes.to_be_bytes());
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        Ok(Commitment(out))
    }

    fn finalize_public_key(
        verified_shares: ValidatedDkgShares,
    ) -> Result<ThresholdPublicKey, Self::Error> {
        let mut hasher = Shake256::default();
        hasher.update(b"simulated-threshold-public-key");
        for (id, commitment) in verified_shares.iter() {
            hasher.update(&id.0.to_be_bytes());
            hasher.update(&commitment.0);
        }
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; MLDSA65_PUBLICKEY_BYTES];
        reader.read(&mut out);
        Ok(ThresholdPublicKey(out))
    }
}
```

- [ ] **Step 4: Implement aggregation API**

Create `src/aggregation.rs` with:

```rust
//! Signature aggregation API boundary.

use crate::{
    backend::{Mldsa65Backend, SimulatedBackend},
    collections::PartialShareSet,
    errors::ThresholdError,
    transcript::ThresholdSigningTranscript,
    types::ThresholdSignature,
};

/// Public aggregation interface.
pub trait SignatureAggregator {
    /// Error returned by aggregation.
    type Error;

    /// Aggregate validated partial shares into a standard-size signature.
    fn aggregate_shares(
        transcript: ThresholdSigningTranscript,
        partial_shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error>;
}

/// Aggregator backed by the deterministic simulation backend.
pub struct SimulatedAggregator;

impl SignatureAggregator for SimulatedAggregator {
    type Error = ThresholdError;

    fn aggregate_shares(
        transcript: ThresholdSigningTranscript,
        partial_shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error> {
        SimulatedBackend::aggregate(transcript.public_key(), &transcript, partial_shares)
    }
}
```

- [ ] **Step 5: Run simulated flow test**

Run:

```bash
cargo test --test simulated_flow simulated_dkg_sign_and_aggregate_flow_returns_standard_size_signature
```

Expected: PASS.

- [ ] **Step 6: Run all tests**

Run:

```bash
cargo test
```

Expected: PASS.

- [ ] **Step 7: Commit DKG and aggregation**

```bash
git add src/dkg.rs src/aggregation.rs tests/simulated_flow.rs
git commit -m "feat: add simulated DKG and aggregation APIs"
```

## Task 8: Add Versioned Serialization Helpers

**Files:**
- Create: `src/serialization.rs`
- Modify: `tests/validation.rs`

- [ ] **Step 1: Add failing serialization tests**

Append to `tests/validation.rs`:

```rust
use lattice_aggregation::serialization::{decode_commitment_payload, encode_commitment_payload};

#[test]
fn commitment_payload_round_trips_with_version_and_validator() {
    let encoded = encode_commitment_payload([5; 32], ValidatorId(9), Commitment([7; 32]));
    let decoded = decode_commitment_payload(&encoded).unwrap();
    assert_eq!(decoded.0, [5; 32]);
    assert_eq!(decoded.1, ValidatorId(9));
    assert_eq!(decoded.2, Commitment([7; 32]));
}

#[test]
fn commitment_payload_rejects_bad_version() {
    let mut encoded = encode_commitment_payload([5; 32], ValidatorId(9), Commitment([7; 32]));
    encoded[0] = 2;
    assert!(matches!(
        decode_commitment_payload(&encoded),
        Err(ThresholdError::MalformedSerialization { reason: "unsupported version" })
    ));
}
```

- [ ] **Step 2: Run serialization tests to verify failure**

Run:

```bash
cargo test --test validation commitment_payload
```

Expected: FAIL with unresolved serialization functions.

- [ ] **Step 3: Implement commitment payload encoding**

Create `src/serialization.rs` with:

```rust
//! Explicit versioned wire encodings for public protocol payloads.

use crate::{
    errors::ThresholdError,
    types::{Commitment, SessionId, ValidatorId, COMMITMENT_BYTES, SESSION_ID_BYTES},
};

const WIRE_VERSION: u8 = 1;
const MSG_COMMITMENT: u8 = 1;
const COMMITMENT_PAYLOAD_LEN: usize = 1 + 1 + SESSION_ID_BYTES + 2 + 4 + COMMITMENT_BYTES;

/// Encode a signing commitment payload.
pub fn encode_commitment_payload(
    session_id: SessionId,
    validator: ValidatorId,
    commitment: Commitment,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMMITMENT_PAYLOAD_LEN);
    out.push(WIRE_VERSION);
    out.push(MSG_COMMITMENT);
    out.extend_from_slice(&session_id);
    out.extend_from_slice(&validator.0.to_be_bytes());
    out.extend_from_slice(&(COMMITMENT_BYTES as u32).to_be_bytes());
    out.extend_from_slice(&commitment.0);
    out
}

/// Decode a signing commitment payload.
pub fn decode_commitment_payload(
    bytes: &[u8],
) -> Result<(SessionId, ValidatorId, Commitment), ThresholdError> {
    if bytes.len() != COMMITMENT_PAYLOAD_LEN {
        return Err(ThresholdError::MalformedSerialization { reason: "invalid length" });
    }
    if bytes[0] != WIRE_VERSION {
        return Err(ThresholdError::MalformedSerialization { reason: "unsupported version" });
    }
    if bytes[1] != MSG_COMMITMENT {
        return Err(ThresholdError::MalformedSerialization { reason: "unexpected message type" });
    }
    let mut session = [0u8; SESSION_ID_BYTES];
    session.copy_from_slice(&bytes[2..34]);
    let validator = ValidatorId(u16::from_be_bytes([bytes[34], bytes[35]]));
    let payload_len = u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
    if payload_len != COMMITMENT_BYTES as u32 {
        return Err(ThresholdError::MalformedSerialization { reason: "invalid payload length" });
    }
    let mut commitment = [0u8; COMMITMENT_BYTES];
    commitment.copy_from_slice(&bytes[40..72]);
    Ok((session, validator, Commitment(commitment)))
}
```

- [ ] **Step 4: Run serialization tests**

Run:

```bash
cargo test --test validation commitment_payload
```

Expected: PASS.

- [ ] **Step 5: Commit serialization**

```bash
git add src/serialization.rs tests/validation.rs
git commit -m "feat: add versioned commitment serialization"
```

## Task 9: Add Type-State Compile-Fail Tests

**Files:**
- Create: `tests/type_state.rs`
- Create: `tests/ui/type_state_invalid_partial.rs`
- Create: `tests/ui/type_state_invalid_aggregate.rs`

- [ ] **Step 1: Add trybuild harness**

Create `tests/type_state.rs` with:

```rust
#[test]
fn invalid_type_state_calls_do_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/type_state_invalid_partial.rs");
    tests.compile_fail("tests/ui/type_state_invalid_aggregate.rs");
}
```

- [ ] **Step 2: Add invalid partial-sign call fixture**

Create `tests/ui/type_state_invalid_partial.rs` with:

```rust
use lattice_aggregation::{
    CommitmentSet, PrivateKeyShare, SigningSession, ThresholdPublicKey, ValidatorId,
};

fn main() {
    let validators = vec![ValidatorId(1), ValidatorId(2)];
    let session = SigningSession::new(
        [1; 32],
        1,
        validators.clone(),
        ThresholdPublicKey([1; 1952]),
        PrivateKeyShare::new(ValidatorId(1), b"share".to_vec()),
    )
    .unwrap();
    let commitments = CommitmentSet::new(validators, 1, vec![]).unwrap();
    let _ = SigningSession::generate_partial_signature(session, commitments, b"message");
}
```

- [ ] **Step 3: Add invalid aggregation-state fixture**

Create `tests/ui/type_state_invalid_aggregate.rs` with:

```rust
use lattice_aggregation::{
    CommitmentSet, PrivateKeyShare, SigningSession, ThresholdPublicKey, ValidatorId,
};

fn main() {
    let validators = vec![ValidatorId(1), ValidatorId(2)];
    let session = SigningSession::new(
        [1; 32],
        1,
        validators.clone(),
        ThresholdPublicKey([1; 1952]),
        PrivateKeyShare::new(ValidatorId(1), b"share".to_vec()),
    )
    .unwrap();
    let commitments = CommitmentSet::new(validators, 1, vec![]).unwrap();
    let _ = lattice_aggregation::SigningSession::generate_partial_signature(
        session,
        commitments,
        b"message",
    );
}
```

- [ ] **Step 4: Run trybuild test and accept stderr fixtures**

Run:

```bash
cargo test --test type_state
```

Expected: FAIL once, with `wip/*.stderr` generated by `trybuild`.

Move the generated stderr fixtures:

```bash
mkdir -p tests/ui
mv wip/type_state_invalid_partial.stderr tests/ui/type_state_invalid_partial.stderr
mv wip/type_state_invalid_aggregate.stderr tests/ui/type_state_invalid_aggregate.stderr
```

- [ ] **Step 5: Re-run trybuild test**

Run:

```bash
cargo test --test type_state
```

Expected: PASS with both compile-fail fixtures accepted.

- [ ] **Step 6: Commit type-state tests**

```bash
git add tests/type_state.rs tests/ui
git commit -m "test: prove invalid signing rounds do not compile"
```

## Task 10: Add Cryptographic Model Document and Final Verification

**Files:**
- Create: `docs/cryptography/phase-1-noise-bound-model.md`

- [ ] **Step 1: Write the scoped cryptographic model document**

Create `docs/cryptography/phase-1-noise-bound-model.md` with:

```markdown
# Phase 1 Threshold ML-DSA-65 Noise-Bound Model

Date: 2026-05-22

## Scope

This document records the mathematical constraints the crate API is designed to preserve. It does not prove production security for the simulation backend.

## ML-DSA-65 Constraint

ML-DSA-65 signatures rely on Fiat-Shamir with aborts. Any threshold construction must preserve the distribution and norm bounds of the effective masking vector `y` and response vector `z`.

## Threshold Signing Requirement

Participants must commit to local masking contributions before the challenge is derived. The transcript must bind the protocol version, session ID, validator set, public key, message, and ordered commitments.

## Rejection Requirement

A real backend must reject local or aggregate partial shares when the backend-specific bounds for `z`, hint vectors, or challenge consistency fail. The simulation backend exercises API behavior only and has no ML-DSA security claim.

## Production Gates

The crate cannot be used for production consensus signing until a concrete threshold ML-DSA protocol is selected, the noise-bound proof is completed for ML-DSA-65 parameters, a standard verifier accepts aggregate signatures, timing tests are run on the concrete backend, and an external cryptographic review is complete.
```

- [ ] **Step 2: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits successfully with no output or formatted Rust files.

- [ ] **Step 3: Run all tests**

Run:

```bash
cargo test
```

Expected: PASS for validation, transcript, simulated flow, and type-state tests.

- [ ] **Step 4: Run lint check**

Run:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: PASS with no warnings.

- [ ] **Step 5: Review production guardrails**

Run:

```bash
rg -n "production-ready|standard ML-DSA|simulation backend|hazmat|audited|cryptographic review" src docs tests
```

Expected: output shows guardrail language in crate docs and cryptography docs, and no text claims the simulation backend produces real ML-DSA signatures.

- [ ] **Step 6: Commit final docs and verification fixes**

```bash
git add docs/cryptography/phase-1-noise-bound-model.md Cargo.toml src tests
git commit -m "docs: record phase 1 threshold ML-DSA guardrails"
```

## Self-Review

- Spec coverage: The plan covers public types, type-state signing, transcript construction, DKG boundary, aggregation boundary, simulation backend, serialization, validation errors, compile-fail tests, and non-production cryptographic guardrails.
- Intentional gap: Real threshold ML-DSA polynomial arithmetic and standard verifier integration are not implemented in this plan because the approved design requires those to remain behind audited backend gates.
- Placeholder scan: The plan uses concrete file paths, code blocks, commands, and expected results for each step.
- Type consistency: Public names match the design spec: `SigningSession`, `ThresholdSigner`, `ThresholdKeyGeneration`, `SignatureAggregator`, `CommitmentSet`, `PartialShareSet`, `ThresholdSigningTranscript`, and `SimulatedBackend`.
