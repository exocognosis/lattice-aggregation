# Production Threshold ML-DSA Coordinator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a gated coordinator-assisted ML-DSA-65 production-candidate path that starts with a standard verifier/provider boundary, then builds typed preprocessing, transcript, coordinator, and wire surfaces without changing the default simulation backend.

**Architecture:** The current deterministic simulation backend remains the default and keeps its current claims. New production-candidate code lives behind non-default gates and is split into provider, transcript, preprocessing, coordinator, policy, and evidence modules. The first milestone produces typed, testable surfaces and mandatory standard-verifier gates; threshold math and external audit evidence remain blocked by explicit policy until the reviewed backend is wired.

**Tech Stack:** Rust 2021, existing `sha3`, `thiserror`, `serde`, `zeroize`, `tokio`, `trybuild`; optional `ml-dsa` provider dependency behind `hazmat-real-mldsa`; future fuzzing with `cargo-fuzz`; future side-channel harnesses with dudect/ctgrind equivalents.

---

## Scope And Guardrails

This plan implements the production-candidate skeleton and verification gates needed before adding real threshold arithmetic. It does not claim production threshold ML-DSA security. The first executable milestone must prove that:

- production profile code is unavailable unless explicit non-default gates are enabled;
- the simulator cannot satisfy production-labeled APIs;
- context, attempts, active signer sets, and final verification are typed and testable;
- every successful coordinator aggregate path must pass a standard ML-DSA verification gate before returning a `ThresholdSignature`.

The implementation must not replace `SimulatedBackend` or weaken current docs.

## File Structure

- Modify `Cargo.toml`: add feature gates and optional provider dependencies.
- Modify `src/lib.rs`: expose gated production modules.
- Modify `src/errors.rs`: add production policy, attempt, attestation, and verifier error variants.
- Create `src/production.rs`: top-level gated production module exports.
- Create `src/production/types.rs`: typed context wrappers.
- Create `src/production/policy.rs`: profile and policy gate checks.
- Create `src/production/provider.rs`: standard ML-DSA provider trait and gated provider implementation.
- Create `src/production/transcript.rs`: production transcript binding.
- Create `src/production/preprocess.rs`: one-time preprocessing attempt model.
- Create `src/production/coordinator.rs`: coordinator profile trait and request wrappers.
- Create `src/production/evidence.rs`: non-secret production diagnostic records.
- Create `src/adapter/production_wire.rs`: v2 coordinator frame definitions.
- Modify `src/adapter.rs`: export `production_wire` behind the coordinator gate.
- Create `tests/production_policy.rs`: feature/policy gate tests.
- Create `tests/production_provider.rs`: standard verifier provider tests.
- Create `tests/production_transcript.rs`: transcript determinism and mismatch tests.
- Create `tests/production_preprocess.rs`: attempt-use tests.
- Create `tests/production_coordinator.rs`: coordinator request/aggregate gate tests.
- Create `tests/production_wire.rs`: v2 wire golden and malformed-input tests.
- Create `tests/ui/production_simulated_backend_rejected.rs`: compile-fail guard when the simulator is used as a production backend.
- Modify `tests/type_state.rs`: include production compile-fail tests.
- Modify `tests/proof_documentation_manifest.rs`: add stable anchors for production profile docs once docs are updated.
- Modify docs listed in the design spec when each implementation task changes claim boundaries.

## Task 1: Add Production Feature Gates And Module Shell

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/lib.rs`
- Create: `src/production.rs`
- Create: `tests/production_policy.rs`

- [ ] **Step 1: Write the failing feature-gate test**

Create `tests/production_policy.rs`:

```rust
#[test]
fn production_module_is_not_exported_without_gate() {
    assert!(!cfg!(feature = "coordinator-assisted"));
}
```

- [ ] **Step 2: Run the test**

Run:

```bash
cargo test --test production_policy production_module_is_not_exported_without_gate
```

Expected: PASS. This confirms the default feature set does not enable the production coordinator profile.

- [ ] **Step 3: Add feature gates**

Modify `Cargo.toml`:

```toml
[features]
default = ["simulated"]
simulated = []
hazmat = []
hazmat-real-mldsa = ["hazmat", "dep:ml-dsa"]
coordinator-assisted = []
production-mldsa65-coordinator = ["coordinator-assisted", "hazmat-real-mldsa"]

[dependencies]
async-trait = "0.1"
ml-dsa = { version = "0.1.1", optional = true, default-features = false }
serde = { version = "1", features = ["derive"] }
sha3 = "0.10"
thiserror = "1"
tokio = { version = "1", features = ["macros", "rt", "sync", "time"] }
zeroize = { version = "1", features = ["derive"] }
```

- [ ] **Step 4: Export the gated module**

Modify `src/lib.rs`:

```rust
#[cfg(feature = "coordinator-assisted")]
pub mod production;
```

- [ ] **Step 5: Create the production module shell**

Create `src/production.rs`:

```rust
//! Coordinator-assisted production-candidate ML-DSA-65 profile.
//!
//! This module is gated and does not make a production-readiness claim. It
//! contains typed boundaries for future reviewed ML-DSA-65 threshold signing.

pub mod coordinator;
pub mod evidence;
pub mod policy;
pub mod preprocess;
pub mod provider;
pub mod transcript;
pub mod types;
```

Create empty module files with module-level docs:

```rust
//! Production profile policy gates.
```

Use that pattern for `coordinator.rs`, `evidence.rs`, `preprocess.rs`, `provider.rs`, `transcript.rs`, and `types.rs`, changing the sentence to match each file.

- [ ] **Step 6: Verify default and gated builds**

Run:

```bash
cargo test --test production_policy
cargo check --features coordinator-assisted
```

Expected: both PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml src/lib.rs src/production.rs src/production tests/production_policy.rs
git commit -m "chore: scaffold coordinator production profile"
```

## Task 2: Add Production Error Variants And Policy Gate

**Files:**
- Modify: `src/errors.rs`
- Create: `src/production/policy.rs`
- Modify: `tests/production_policy.rs`

- [ ] **Step 1: Add failing policy tests**

Append to `tests/production_policy.rs`:

```rust
#[cfg(feature = "coordinator-assisted")]
use lattice_aggregation::{production::policy::ProductionPolicy, ThresholdError};

#[cfg(feature = "coordinator-assisted")]
#[test]
fn production_policy_rejects_unreviewed_profile() {
    let err = ProductionPolicy::hazmat_unreviewed().require_production_release().unwrap_err();
    assert_eq!(
        err,
        ThresholdError::ProductionPolicyBlocked {
            reason: "coordinator profile has not passed production release gates",
        }
    );
}

#[cfg(feature = "production-mldsa65-coordinator")]
#[test]
fn production_feature_still_requires_runtime_release_gate() {
    let err = ProductionPolicy::hazmat_unreviewed().require_production_release().unwrap_err();
    assert!(err.to_string().contains("production release gates"));
}
```

- [ ] **Step 2: Run the tests and verify failure**

Run:

```bash
cargo test --features coordinator-assisted --test production_policy production_policy_rejects_unreviewed_profile
```

Expected: FAIL because `ProductionPolicy` and `ProductionPolicyBlocked` do not exist.

- [ ] **Step 3: Add error variants**

Modify `src/errors.rs` by adding variants before `StandardVerificationFailed`:

```rust
    /// Production profile is blocked by policy gates.
    #[error("production policy blocked: {reason}")]
    ProductionPolicyBlocked {
        /// Static reason the policy gate blocked the operation.
        reason: &'static str,
    },

    /// Coordinator attestation failed.
    #[error("coordinator attestation failed: {reason}")]
    CoordinatorAttestationFailed {
        /// Static reason the attestation was rejected.
        reason: &'static str,
    },

    /// Preprocessed attempt was stale, reused, or unknown.
    #[error("invalid preprocessed attempt: {reason}")]
    InvalidPreprocessedAttempt {
        /// Static reason the attempt was rejected.
        reason: &'static str,
    },
```

- [ ] **Step 4: Implement production policy**

Replace `src/production/policy.rs`:

```rust
//! Production profile policy gates.

use crate::ThresholdError;

/// Release status for the coordinator-assisted profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorReleaseStatus {
    /// Feature is available only for hazmat and conformance work.
    HazmatUnreviewed,
    /// Feature has evidence-backed production approval.
    ProductionApproved,
}

/// Runtime policy for the coordinator-assisted profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionPolicy {
    status: CoordinatorReleaseStatus,
}

impl ProductionPolicy {
    /// Construct the default unreviewed hazmat policy.
    pub fn hazmat_unreviewed() -> Self {
        Self {
            status: CoordinatorReleaseStatus::HazmatUnreviewed,
        }
    }

    /// Construct an approved policy for audited release builds.
    pub fn production_approved() -> Self {
        Self {
            status: CoordinatorReleaseStatus::ProductionApproved,
        }
    }

    /// Require production release gates to have passed.
    pub fn require_production_release(self) -> Result<(), ThresholdError> {
        match self.status {
            CoordinatorReleaseStatus::HazmatUnreviewed => Err(
                ThresholdError::ProductionPolicyBlocked {
                    reason: "coordinator profile has not passed production release gates",
                },
            ),
            CoordinatorReleaseStatus::ProductionApproved => Ok(()),
        }
    }

    /// Return the configured release status.
    pub fn status(self) -> CoordinatorReleaseStatus {
        self.status
    }
}
```

- [ ] **Step 5: Run policy tests**

Run:

```bash
cargo test --features coordinator-assisted --test production_policy
cargo test --features production-mldsa65-coordinator --test production_policy
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/errors.rs src/production/policy.rs tests/production_policy.rs
git commit -m "feat: add coordinator production policy gate"
```

## Task 3: Add Typed Production Context Wrappers

**Files:**
- Create/replace: `src/production/types.rs`
- Create: `tests/production_transcript.rs`

- [ ] **Step 1: Write failing typed-context tests**

Create `tests/production_transcript.rs`:

```rust
#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::production::types::{
    ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
    ProtocolProfile, ValidatorSetDigest,
};
use lattice_aggregation::ValidatorId;

#[test]
fn production_context_types_have_stable_bytes() {
    assert_eq!(ProtocolProfile::coordinator_assisted_v1().as_bytes(), b"mldsa65-coordinator-v1");
    assert_eq!(EpochId(7).to_be_bytes(), 7u64.to_be_bytes());
    assert_eq!(KeyId([1; 32]).as_bytes(), &[1; 32]);
    assert_eq!(AttemptId([2; 32]).as_bytes(), &[2; 32]);
    assert_eq!(ValidatorSetDigest([3; 32]).as_bytes(), &[3; 32]);
    assert_eq!(DkgTranscriptDigest([4; 32]).as_bytes(), &[4; 32]);
    assert_eq!(MessageBinding([5; 64]).as_bytes(), &[5; 64]);
}

#[test]
fn active_signer_set_is_canonical() {
    let active = ActiveSignerSet::new(vec![ValidatorId(3), ValidatorId(1), ValidatorId(2)]).unwrap();
    assert_eq!(active.as_slice(), &[ValidatorId(1), ValidatorId(2), ValidatorId(3)]);
}

#[test]
fn active_signer_set_rejects_duplicates() {
    let err = ActiveSignerSet::new(vec![ValidatorId(1), ValidatorId(1)]).unwrap_err();
    assert!(err.to_string().contains("duplicate validator 1"));
}
```

- [ ] **Step 2: Run the tests and verify failure**

Run:

```bash
cargo test --features coordinator-assisted --test production_transcript
```

Expected: FAIL because the types do not exist.

- [ ] **Step 3: Implement typed wrappers**

Replace `src/production/types.rs`:

```rust
//! Typed production profile context wrappers.

use crate::{collections::set_from_validators, ThresholdError, ValidatorId};

/// Coordinator-assisted profile identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolProfile(&'static [u8]);

impl ProtocolProfile {
    /// Profile label for the first coordinator-assisted ML-DSA-65 profile.
    pub fn coordinator_assisted_v1() -> Self {
        Self(b"mldsa65-coordinator-v1")
    }

    /// Return profile label bytes.
    pub fn as_bytes(self) -> &'static [u8] {
        self.0
    }
}

/// Epoch identifier for a validator set and key epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EpochId(pub u64);

impl EpochId {
    /// Return big-endian bytes.
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// Threshold key identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct KeyId(pub [u8; 32]);

impl KeyId {
    /// Borrow the digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Single-use preprocessing attempt identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AttemptId(pub [u8; 32]);

impl AttemptId {
    /// Borrow the digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Digest of the canonical validator set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ValidatorSetDigest(pub [u8; 32]);

impl ValidatorSetDigest {
    /// Borrow the digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Digest of the DKG transcript or external share ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DkgTranscriptDigest(pub [u8; 32]);

impl DkgTranscriptDigest {
    /// Borrow the digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// ML-DSA message binding, such as `mu`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MessageBinding(pub [u8; 64]);

impl MessageBinding {
    /// Borrow the binding bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Canonical active signer set for one attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveSignerSet {
    validators: Vec<ValidatorId>,
}

impl ActiveSignerSet {
    /// Construct and canonicalize an active signer set.
    pub fn new(validators: Vec<ValidatorId>) -> Result<Self, ThresholdError> {
        let validators = set_from_validators(validators)?.into_iter().collect();
        Ok(Self { validators })
    }

    /// Borrow canonical validators.
    pub fn as_slice(&self) -> &[ValidatorId] {
        &self.validators
    }

    /// Number of active signers.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Return true when no active signers are present.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}
```

- [ ] **Step 4: Run typed context tests**

Run:

```bash
cargo test --features coordinator-assisted --test production_transcript
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/production/types.rs tests/production_transcript.rs
git commit -m "feat: add production context types"
```

## Task 4: Add Production Transcript Binding

**Files:**
- Create/replace: `src/production/transcript.rs`
- Modify: `tests/production_transcript.rs`

- [ ] **Step 1: Add failing transcript tests**

Append to `tests/production_transcript.rs`:

```rust
use lattice_aggregation::production::transcript::{
    CommitmentDigest, ProductionSigningTranscript, ProductionTranscriptInput,
};
use lattice_aggregation::{SessionId, ThresholdPublicKey};

fn transcript_input(attempt_byte: u8, commitments: Vec<(ValidatorId, [u8; 32])>) -> ProductionTranscriptInput {
    ProductionTranscriptInput {
        session_id: [9; 32],
        epoch: EpochId(11),
        key_id: KeyId([12; 32]),
        validator_set_digest: ValidatorSetDigest([13; 32]),
        dkg_transcript_digest: DkgTranscriptDigest([14; 32]),
        active_signers: ActiveSignerSet::new(vec![ValidatorId(2), ValidatorId(1)]).unwrap(),
        threshold: 2,
        public_key: ThresholdPublicKey([15; 1952]),
        message_binding: MessageBinding([16; 64]),
        attempt_id: AttemptId([attempt_byte; 32]),
        coordinator_attestation_digest: [17; 32],
        retry_counter: 0,
        commitment_digests: commitments
            .into_iter()
            .map(|(validator, digest)| (validator, CommitmentDigest(digest)))
            .collect(),
    }
}

#[test]
fn production_transcript_is_order_independent() {
    let a = ProductionSigningTranscript::new(transcript_input(
        21,
        vec![(ValidatorId(2), [2; 32]), (ValidatorId(1), [1; 32])],
    ))
    .unwrap();
    let b = ProductionSigningTranscript::new(transcript_input(
        21,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(2), [2; 32])],
    ))
    .unwrap();
    assert_eq!(a.challenge_digest(), b.challenge_digest());
}

#[test]
fn production_transcript_binds_attempt_id() {
    let a = ProductionSigningTranscript::new(transcript_input(
        21,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(2), [2; 32])],
    ))
    .unwrap();
    let b = ProductionSigningTranscript::new(transcript_input(
        22,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(2), [2; 32])],
    ))
    .unwrap();
    assert_ne!(a.challenge_digest(), b.challenge_digest());
}

#[test]
fn production_transcript_rejects_commitment_from_inactive_signer() {
    let err = ProductionSigningTranscript::new(transcript_input(
        21,
        vec![(ValidatorId(1), [1; 32]), (ValidatorId(3), [3; 32])],
    ))
    .unwrap_err();
    assert!(err.to_string().contains("transcript mismatch"));
}
```

- [ ] **Step 2: Run transcript tests and verify failure**

Run:

```bash
cargo test --features coordinator-assisted --test production_transcript
```

Expected: FAIL because transcript types do not exist.

- [ ] **Step 3: Implement production transcript**

Replace `src/production/transcript.rs`:

```rust
//! Production coordinator transcript binding.

use std::collections::BTreeMap;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{ThresholdError, ThresholdPublicKey, ValidatorId};

use super::types::{
    ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
    ProtocolProfile, ValidatorSetDigest,
};

/// Digest of a production commitment statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CommitmentDigest(pub [u8; 32]);

/// Fully bound production transcript input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionTranscriptInput {
    /// Protocol session ID.
    pub session_id: crate::SessionId,
    /// Validator/key epoch.
    pub epoch: EpochId,
    /// Threshold key ID.
    pub key_id: KeyId,
    /// Digest of canonical validator set.
    pub validator_set_digest: ValidatorSetDigest,
    /// DKG transcript or external share ceremony digest.
    pub dkg_transcript_digest: DkgTranscriptDigest,
    /// Active signer set for this attempt.
    pub active_signers: ActiveSignerSet,
    /// Signing threshold.
    pub threshold: u16,
    /// Threshold public key.
    pub public_key: ThresholdPublicKey,
    /// ML-DSA message binding.
    pub message_binding: MessageBinding,
    /// Single-use attempt ID.
    pub attempt_id: AttemptId,
    /// Digest of coordinator attestation quote.
    pub coordinator_attestation_digest: [u8; 32],
    /// Retry counter for this session.
    pub retry_counter: u32,
    /// Commitment digests by validator.
    pub commitment_digests: Vec<(ValidatorId, CommitmentDigest)>,
}

/// Bound production signing transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionSigningTranscript {
    input: ProductionTranscriptInput,
    challenge_digest: [u8; 32],
}

impl ProductionSigningTranscript {
    /// Construct a production transcript and derive its challenge digest.
    pub fn new(mut input: ProductionTranscriptInput) -> Result<Self, ThresholdError> {
        if input.threshold == 0 || input.threshold as usize > input.active_signers.len() {
            return Err(ThresholdError::InvalidThresholdParameters {
                threshold: input.threshold,
                total_nodes: input.active_signers.len() as u16,
            });
        }

        let mut commitments = BTreeMap::new();
        for (validator, digest) in input.commitment_digests.drain(..) {
            if !input.active_signers.as_slice().contains(&validator) {
                return Err(ThresholdError::TranscriptMismatch);
            }
            if commitments.insert(validator, digest).is_some() {
                return Err(ThresholdError::DuplicateValidator { validator });
            }
        }

        if commitments.len() < input.threshold as usize {
            return Err(ThresholdError::InsufficientCommitments {
                required: input.threshold,
                received: commitments.len(),
            });
        }

        input.commitment_digests = commitments.into_iter().collect();
        let challenge_digest = derive_challenge_digest(&input);
        Ok(Self {
            input,
            challenge_digest,
        })
    }

    /// Return the derived challenge digest.
    pub fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }

    /// Borrow transcript input.
    pub fn input(&self) -> &ProductionTranscriptInput {
        &self.input
    }
}

fn derive_challenge_digest(input: &ProductionTranscriptInput) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(ProtocolProfile::coordinator_assisted_v1().as_bytes());
    hasher.update(&1u16.to_be_bytes());
    hasher.update(&input.session_id);
    hasher.update(&input.epoch.to_be_bytes());
    hasher.update(input.key_id.as_bytes());
    hasher.update(input.validator_set_digest.as_bytes());
    hasher.update(input.dkg_transcript_digest.as_bytes());
    hasher.update(&(input.active_signers.len() as u16).to_be_bytes());
    for validator in input.active_signers.as_slice() {
        hasher.update(&validator.0.to_be_bytes());
    }
    hasher.update(&input.threshold.to_be_bytes());
    hasher.update(&input.public_key.0);
    hasher.update(input.message_binding.as_bytes());
    hasher.update(input.attempt_id.as_bytes());
    hasher.update(&input.coordinator_attestation_digest);
    hasher.update(&input.retry_counter.to_be_bytes());
    hasher.update(&(input.commitment_digests.len() as u16).to_be_bytes());
    for (validator, digest) in &input.commitment_digests {
        hasher.update(&validator.0.to_be_bytes());
        hasher.update(&digest.0);
    }

    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}
```

- [ ] **Step 4: Run production transcript tests**

Run:

```bash
cargo test --features coordinator-assisted --test production_transcript
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/production/transcript.rs tests/production_transcript.rs
git commit -m "feat: bind production coordinator transcripts"
```

## Task 5: Add One-Time Preprocessing Attempts

**Files:**
- Create/replace: `src/production/preprocess.rs`
- Create: `tests/production_preprocess.rs`

- [ ] **Step 1: Write failing preprocessing tests**

Create `tests/production_preprocess.rs`:

```rust
#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        preprocess::{PreprocessedAttempt, PreprocessingStore},
        types::AttemptId,
    },
    ThresholdError,
};

#[test]
fn preprocessing_store_consumes_attempt_once() {
    let attempt = PreprocessedAttempt::new(AttemptId([7; 32]), vec![1, 2, 3]).unwrap();
    let mut store = PreprocessingStore::default();
    store.insert(attempt).unwrap();

    let first = store.consume(AttemptId([7; 32])).unwrap();
    assert_eq!(first.attempt_id(), AttemptId([7; 32]));

    let err = store.consume(AttemptId([7; 32])).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::InvalidPreprocessedAttempt {
            reason: "attempt is unknown or already consumed",
        }
    );
}

#[test]
fn preprocessing_attempt_rejects_empty_secret() {
    let err = PreprocessedAttempt::new(AttemptId([8; 32]), Vec::new()).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::InvalidPreprocessedAttempt {
            reason: "attempt secret material is empty",
        }
    );
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test --features coordinator-assisted --test production_preprocess
```

Expected: FAIL because preprocessing types do not exist.

- [ ] **Step 3: Implement preprocessing attempts**

Replace `src/production/preprocess.rs`:

```rust
//! One-time preprocessing attempt state.

use std::collections::HashMap;

use zeroize::Zeroize;

use crate::ThresholdError;

use super::types::AttemptId;

/// Single-use preprocessed attempt material.
#[derive(Clone, Eq, PartialEq)]
pub struct PreprocessedAttempt {
    attempt_id: AttemptId,
    secret_material: Vec<u8>,
}

impl core::fmt::Debug for PreprocessedAttempt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreprocessedAttempt")
            .field("attempt_id", &self.attempt_id)
            .field("secret_material_redacted", &true)
            .finish()
    }
}

impl Drop for PreprocessedAttempt {
    fn drop(&mut self) {
        self.secret_material.zeroize();
    }
}

impl PreprocessedAttempt {
    /// Construct attempt state.
    pub fn new(attempt_id: AttemptId, secret_material: Vec<u8>) -> Result<Self, ThresholdError> {
        if secret_material.is_empty() {
            return Err(ThresholdError::InvalidPreprocessedAttempt {
                reason: "attempt secret material is empty",
            });
        }
        Ok(Self {
            attempt_id,
            secret_material,
        })
    }

    /// Return attempt ID.
    pub fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Borrow secret material for backend use.
    pub(crate) fn secret_material(&self) -> &[u8] {
        &self.secret_material
    }
}

/// In-memory one-time attempt store.
#[derive(Debug, Default)]
pub struct PreprocessingStore {
    attempts: HashMap<AttemptId, PreprocessedAttempt>,
}

impl PreprocessingStore {
    /// Insert one attempt.
    pub fn insert(&mut self, attempt: PreprocessedAttempt) -> Result<(), ThresholdError> {
        let attempt_id = attempt.attempt_id();
        if self.attempts.insert(attempt_id, attempt).is_some() {
            return Err(ThresholdError::InvalidPreprocessedAttempt {
                reason: "attempt already exists",
            });
        }
        Ok(())
    }

    /// Consume an attempt exactly once.
    pub fn consume(&mut self, attempt_id: AttemptId) -> Result<PreprocessedAttempt, ThresholdError> {
        self.attempts
            .remove(&attempt_id)
            .ok_or(ThresholdError::InvalidPreprocessedAttempt {
                reason: "attempt is unknown or already consumed",
            })
    }
}
```

- [ ] **Step 4: Run preprocessing tests**

Run:

```bash
cargo test --features coordinator-assisted --test production_preprocess
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/production/preprocess.rs tests/production_preprocess.rs
git commit -m "feat: add one-time preprocessing attempts"
```

## Task 6: Add Standard ML-DSA Provider Boundary

**Files:**
- Create/replace: `src/production/provider.rs`
- Create: `tests/production_provider.rs`

- [ ] **Step 1: Add failing provider boundary tests**

Create `tests/production_provider.rs`:

```rust
#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::provider::{StandardMldsa65Provider, UnavailableMldsa65Provider},
    ThresholdError, ThresholdPublicKey, ThresholdSignature,
};

#[test]
fn unavailable_provider_fails_closed() {
    let public_key = ThresholdPublicKey([0; 1952]);
    let signature = ThresholdSignature([0; 3309]);
    let err = UnavailableMldsa65Provider::verify(&public_key, b"msg", &signature).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::BackendUnavailable {
            reason: "standard ML-DSA provider is not enabled",
        }
    );
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test --features coordinator-assisted --test production_provider
```

Expected: FAIL because provider types do not exist.

- [ ] **Step 3: Implement provider boundary**

Replace `src/production/provider.rs`:

```rust
//! Standard ML-DSA-65 provider boundary.

use crate::{ThresholdError, ThresholdPublicKey, ThresholdSignature};

/// Standard ML-DSA-65 verification provider.
pub trait StandardMldsa65Provider {
    /// Verify a standard ML-DSA-65 signature.
    fn verify(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError>;
}

/// Fail-closed provider used when real ML-DSA is not enabled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnavailableMldsa65Provider;

impl StandardMldsa65Provider for UnavailableMldsa65Provider {
    fn verify(
        _public_key: &ThresholdPublicKey,
        _message: &[u8],
        _signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "standard ML-DSA provider is not enabled",
        })
    }
}

/// Hazmat provider wrapper for the optional ML-DSA implementation.
#[cfg(feature = "hazmat-real-mldsa")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HazmatMldsa65Provider;

#[cfg(feature = "hazmat-real-mldsa")]
impl StandardMldsa65Provider for HazmatMldsa65Provider {
    fn verify(
        _public_key: &ThresholdPublicKey,
        _message: &[u8],
        _signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "hazmat ML-DSA provider wrapper requires KAT-backed implementation",
        })
    }
}
```

- [ ] **Step 4: Run provider tests**

Run:

```bash
cargo test --features coordinator-assisted --test production_provider
cargo check --features hazmat-real-mldsa
```

Expected: PASS. The hazmat provider remains fail-closed until KAT-backed implementation is added in Task 7.

- [ ] **Step 5: Commit**

```bash
git add src/production/provider.rs tests/production_provider.rs
git commit -m "feat: add standard ML-DSA provider boundary"
```

## Task 7: Wire A KAT-Backed Standard Provider

**Files:**
- Modify: `src/production/provider.rs`
- Modify: `tests/production_provider.rs`
- Create: `tests/fixtures/mldsa65_provider_smoke.json`

- [ ] **Step 1: Add a provider smoke fixture**

Create `tests/fixtures/mldsa65_provider_smoke.json`:

```json
{
  "name": "mldsa65-provider-smoke",
  "message_hex": "6c6174746963652d6167677265676174696f6e2d6d6c64736136352d736d6f6b65",
  "note": "This smoke fixture is not a FIPS KAT. Replace or extend it with ACVP/FIPS vectors before release promotion."
}
```

- [ ] **Step 2: Add a failing hazmat-provider test**

Append to `tests/production_provider.rs`:

```rust
#[cfg(feature = "hazmat-real-mldsa")]
#[test]
fn hazmat_provider_is_explicitly_not_release_approved() {
    use lattice_aggregation::production::provider::HazmatMldsa65Provider;

    let public_key = ThresholdPublicKey([0; 1952]);
    let signature = ThresholdSignature([0; 3309]);
    let err = HazmatMldsa65Provider::verify(&public_key, b"msg", &signature).unwrap_err();
    assert!(err.to_string().contains("KAT-backed implementation"));
}
```

- [ ] **Step 3: Run the hazmat provider test**

Run:

```bash
cargo test --features hazmat-real-mldsa --test production_provider hazmat_provider_is_explicitly_not_release_approved
```

Expected: PASS before real provider code is introduced. This test is a guard that the hazmat wrapper cannot be mistaken for release approval.

- [ ] **Step 4: Add the real-provider implementation behind a separate review change**

In this task, do not hand-code ML-DSA arithmetic. Wrap the selected provider crate only after reading its API and security notes. The wrapper must:

```rust
#[cfg(feature = "hazmat-real-mldsa")]
impl StandardMldsa65Provider for HazmatMldsa65Provider {
    fn verify(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError> {
        verify_with_selected_provider(public_key, message, signature)
    }
}
```

The helper `verify_with_selected_provider` must return `Ok(true)` only when the provider accepts the exact standard ML-DSA-65 public key, message, and signature bytes. It must return `Ok(false)` for verifier rejection and `Err(ThresholdError::MalformedSerialization { reason })` for malformed byte conversions.

- [ ] **Step 5: Add release-blocking KAT tests**

Add test names in `tests/production_provider.rs` before implementing release promotion:

```rust
#[cfg(feature = "hazmat-real-mldsa")]
#[test]
#[ignore = "requires checked-in ACVP/FIPS ML-DSA-65 vectors"]
fn hazmat_provider_verifies_mldsa65_kats() {
    panic!("ACVP/FIPS ML-DSA-65 vectors must be checked in before production promotion");
}
```

- [ ] **Step 6: Commit**

```bash
git add src/production/provider.rs tests/production_provider.rs tests/fixtures/mldsa65_provider_smoke.json
git commit -m "feat: gate hazmat ML-DSA provider verification"
```

## Task 8: Add Coordinator Request Types And Final Verification Gate

**Files:**
- Create/replace: `src/production/coordinator.rs`
- Create: `tests/production_coordinator.rs`

- [ ] **Step 1: Write failing coordinator gate tests**

Create `tests/production_coordinator.rs`:

```rust
#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        coordinator::{AggregateAttemptRequest, CoordinatorAggregateGate},
        policy::ProductionPolicy,
        provider::UnavailableMldsa65Provider,
        transcript::{ProductionSigningTranscript, ProductionTranscriptInput, CommitmentDigest},
        types::{
            ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
            ValidatorSetDigest,
        },
    },
    ThresholdError, ThresholdPublicKey, ThresholdSignature, ValidatorId,
};

fn transcript() -> ProductionSigningTranscript {
    ProductionSigningTranscript::new(ProductionTranscriptInput {
        session_id: [1; 32],
        epoch: EpochId(2),
        key_id: KeyId([3; 32]),
        validator_set_digest: ValidatorSetDigest([4; 32]),
        dkg_transcript_digest: DkgTranscriptDigest([5; 32]),
        active_signers: ActiveSignerSet::new(vec![ValidatorId(1), ValidatorId(2)]).unwrap(),
        threshold: 2,
        public_key: ThresholdPublicKey([6; 1952]),
        message_binding: MessageBinding([7; 64]),
        attempt_id: AttemptId([8; 32]),
        coordinator_attestation_digest: [9; 32],
        retry_counter: 0,
        commitment_digests: vec![
            (ValidatorId(1), CommitmentDigest([1; 32])),
            (ValidatorId(2), CommitmentDigest([2; 32])),
        ],
    })
    .unwrap()
}

#[test]
fn aggregate_gate_requires_standard_verification() {
    let request = AggregateAttemptRequest {
        transcript: transcript(),
        candidate_signature: ThresholdSignature([0; 3309]),
        policy: ProductionPolicy::production_approved(),
    };

    let err = CoordinatorAggregateGate::<UnavailableMldsa65Provider>::finalize(request).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::BackendUnavailable {
            reason: "standard ML-DSA provider is not enabled",
        }
    );
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test --features coordinator-assisted --test production_coordinator
```

Expected: FAIL because coordinator types do not exist.

- [ ] **Step 3: Implement coordinator aggregate gate**

Replace `src/production/coordinator.rs`:

```rust
//! Coordinator-assisted aggregate finalization gate.

use core::marker::PhantomData;

use crate::{ThresholdError, ThresholdSignature};

use super::{
    policy::ProductionPolicy,
    provider::StandardMldsa65Provider,
    transcript::ProductionSigningTranscript,
};

/// Aggregate finalization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateAttemptRequest {
    /// Bound production transcript.
    pub transcript: ProductionSigningTranscript,
    /// Candidate signature assembled by the coordinator profile.
    pub candidate_signature: ThresholdSignature,
    /// Runtime release policy.
    pub policy: ProductionPolicy,
}

/// Final standard-verifier gate for coordinator aggregates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoordinatorAggregateGate<P> {
    _provider: PhantomData<P>,
}

impl<P> CoordinatorAggregateGate<P>
where
    P: StandardMldsa65Provider,
{
    /// Finalize a candidate signature only after policy and standard verification pass.
    pub fn finalize(request: AggregateAttemptRequest) -> Result<ThresholdSignature, ThresholdError> {
        request.policy.require_production_release()?;
        let public_key = &request.transcript.input().public_key;
        let message = request.transcript.input().message_binding.as_bytes();
        if !P::verify(public_key, message, &request.candidate_signature)? {
            return Err(ThresholdError::StandardVerificationFailed);
        }
        Ok(request.candidate_signature)
    }
}
```

- [ ] **Step 4: Run coordinator tests**

Run:

```bash
cargo test --features coordinator-assisted --test production_coordinator
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/production/coordinator.rs tests/production_coordinator.rs
git commit -m "feat: require standard verification for coordinator aggregates"
```

## Task 9: Add Production Wire V2 Frames

**Files:**
- Modify: `src/adapter.rs`
- Create: `src/adapter/production_wire.rs`
- Create: `tests/production_wire.rs`

- [ ] **Step 1: Write failing wire tests**

Create `tests/production_wire.rs`:

```rust
#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::adapter::production_wire::{ProductionWireDecodeError, ProductionWireMsg};

#[test]
fn coordinator_challenge_wire_encoding_is_golden() {
    let msg = ProductionWireMsg::CoordinatorChallenge {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        active_set_digest: [3; 32],
        challenge_digest: [4; 32],
    };
    let encoded = msg.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(encoded[1], 3);
    assert_eq!(ProductionWireMsg::decode(&encoded).unwrap(), msg);
}

#[test]
fn production_wire_rejects_trailing_bytes() {
    let mut frame = ProductionWireMsg::CoordinatorAbort {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        reason_code: 9,
    }
    .encode();
    frame.push(0);
    assert_eq!(
        ProductionWireMsg::decode(&frame).unwrap_err(),
        ProductionWireDecodeError::InvalidLength
    );
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cargo test --features coordinator-assisted --test production_wire
```

Expected: FAIL because production wire module does not exist.

- [ ] **Step 3: Export production wire module**

Modify `src/adapter.rs`:

```rust
#[cfg(feature = "coordinator-assisted")]
pub mod production_wire;
```

- [ ] **Step 4: Implement minimal v2 frames**

Create `src/adapter/production_wire.rs`:

```rust
//! Version 2 coordinator-assisted production wire frames.

use crate::SessionId;

const WIRE_VERSION: u8 = 2;
const MSG_COORDINATOR_CHALLENGE: u8 = 3;
const MSG_COORDINATOR_ABORT: u8 = 4;

/// Decode failure for production wire frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionWireDecodeError {
    /// Frame length is invalid.
    #[error("invalid production wire length")]
    InvalidLength,
    /// Wire version is unsupported.
    #[error("unsupported production wire version")]
    UnsupportedVersion,
    /// Message type is unknown.
    #[error("unknown production wire message type")]
    UnknownMessageType,
}

/// Production coordinator wire messages.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProductionWireMsg {
    /// Coordinator challenge broadcast.
    CoordinatorChallenge {
        /// Session ID.
        session_id: SessionId,
        /// Epoch.
        epoch: u64,
        /// Attempt ID.
        attempt_id: [u8; 32],
        /// Active signer set digest.
        active_set_digest: [u8; 32],
        /// Challenge digest.
        challenge_digest: [u8; 32],
    },
    /// Coordinator abort notice.
    CoordinatorAbort {
        /// Session ID.
        session_id: SessionId,
        /// Epoch.
        epoch: u64,
        /// Attempt ID.
        attempt_id: [u8; 32],
        /// Public abort reason code.
        reason_code: u16,
    },
}

impl ProductionWireMsg {
    /// Encode canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::CoordinatorChallenge {
                session_id,
                epoch,
                attempt_id,
                active_set_digest,
                challenge_digest,
            } => {
                let mut out = Vec::with_capacity(138);
                out.push(WIRE_VERSION);
                out.push(MSG_COORDINATOR_CHALLENGE);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(attempt_id);
                out.extend_from_slice(active_set_digest);
                out.extend_from_slice(challenge_digest);
                out
            }
            Self::CoordinatorAbort {
                session_id,
                epoch,
                attempt_id,
                reason_code,
            } => {
                let mut out = Vec::with_capacity(76);
                out.push(WIRE_VERSION);
                out.push(MSG_COORDINATOR_ABORT);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(attempt_id);
                out.extend_from_slice(&reason_code.to_be_bytes());
                out
            }
        }
    }

    /// Decode canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionWireDecodeError> {
        if bytes.len() < 2 {
            return Err(ProductionWireDecodeError::InvalidLength);
        }
        if bytes[0] != WIRE_VERSION {
            return Err(ProductionWireDecodeError::UnsupportedVersion);
        }
        match bytes[1] {
            MSG_COORDINATOR_CHALLENGE => decode_challenge(bytes),
            MSG_COORDINATOR_ABORT => decode_abort(bytes),
            _ => Err(ProductionWireDecodeError::UnknownMessageType),
        }
    }
}

fn decode_challenge(bytes: &[u8]) -> Result<ProductionWireMsg, ProductionWireDecodeError> {
    if bytes.len() != 138 {
        return Err(ProductionWireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&bytes[34..42]);
    let mut attempt_id = [0u8; 32];
    attempt_id.copy_from_slice(&bytes[42..74]);
    let mut active_set_digest = [0u8; 32];
    active_set_digest.copy_from_slice(&bytes[74..106]);
    let mut challenge_digest = [0u8; 32];
    challenge_digest.copy_from_slice(&bytes[106..138]);
    Ok(ProductionWireMsg::CoordinatorChallenge {
        session_id,
        epoch: u64::from_be_bytes(epoch),
        attempt_id,
        active_set_digest,
        challenge_digest,
    })
}

fn decode_abort(bytes: &[u8]) -> Result<ProductionWireMsg, ProductionWireDecodeError> {
    if bytes.len() != 76 {
        return Err(ProductionWireDecodeError::InvalidLength);
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes[2..34]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&bytes[34..42]);
    let mut attempt_id = [0u8; 32];
    attempt_id.copy_from_slice(&bytes[42..74]);
    let reason_code = u16::from_be_bytes([bytes[74], bytes[75]]);
    Ok(ProductionWireMsg::CoordinatorAbort {
        session_id,
        epoch: u64::from_be_bytes(epoch),
        attempt_id,
        reason_code,
    })
}
```

- [ ] **Step 5: Run production wire tests**

Run:

```bash
cargo test --features coordinator-assisted --test production_wire
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/adapter.rs src/adapter/production_wire.rs tests/production_wire.rs
git commit -m "feat: add coordinator production wire frames"
```

## Task 10: Add Production Compile-Fail Guard

**Files:**
- Modify: `tests/type_state.rs`
- Create: `tests/ui/production_simulated_backend_rejected.rs`
- Create: `tests/ui/production_simulated_backend_rejected.stderr`

- [ ] **Step 1: Add compile-fail fixture**

Create `tests/ui/production_simulated_backend_rejected.rs`:

```rust
use lattice_aggregation::{
    production::coordinator::{AggregateAttemptRequest, CoordinatorAggregateGate},
    production::provider::StandardMldsa65Provider,
    SimulatedBackend,
};

fn assert_provider<P: StandardMldsa65Provider>() {}

fn main() {
    assert_provider::<SimulatedBackend>();
    let _ = core::any::type_name::<AggregateAttemptRequest>();
    let _ = core::any::type_name::<CoordinatorAggregateGate<SimulatedBackend>>();
}
```

- [ ] **Step 2: Extend trybuild harness**

Modify `tests/type_state.rs`:

```rust
#[test]
fn invalid_signing_state_calls_do_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/type_state_invalid_partial.rs");
    tests.compile_fail("tests/ui/type_state_invalid_aggregate.rs");
    #[cfg(feature = "coordinator-assisted")]
    tests.compile_fail("tests/ui/production_simulated_backend_rejected.rs");
}
```

- [ ] **Step 3: Run compile-fail test and capture stderr**

Run:

```bash
TRYBUILD=overwrite CARGO_TARGET_DIR=/tmp/lattice-aggregation-trybuild-production \
  cargo test --features coordinator-assisted --test type_state invalid_signing_state_calls_do_not_compile -- --nocapture
```

Expected: FAIL first if the stderr file is absent, then write `tests/ui/production_simulated_backend_rejected.stderr`.

- [ ] **Step 4: Review generated stderr**

Open `tests/ui/production_simulated_backend_rejected.stderr` and ensure it contains an error equivalent to:

```text
the trait bound `SimulatedBackend: StandardMldsa65Provider` is not satisfied
```

- [ ] **Step 5: Rerun compile-fail test**

Run:

```bash
CARGO_TARGET_DIR=/tmp/lattice-aggregation-trybuild-production \
  cargo test --features coordinator-assisted --test type_state invalid_signing_state_calls_do_not_compile -- --nocapture
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add tests/type_state.rs tests/ui/production_simulated_backend_rejected.rs tests/ui/production_simulated_backend_rejected.stderr
git commit -m "test: reject simulator as production provider"
```

## Task 11: Update Claim-Boundary Documentation

**Files:**
- Modify: `docs/cryptography/claims-matrix.md`
- Modify: `docs/cryptography/proof-implementation-crosswalk.md`
- Modify: `docs/cryptography/protocol-code-crosswalk.md`
- Modify: `docs/audit/attack-surface.md`
- Modify: `docs/audit/tcb.md`
- Modify: `docs/benchmarks/release-readiness-checklist.md`
- Modify: `tests/proof_documentation_manifest.rs`

- [ ] **Step 1: Add failing doc-manifest anchors**

Add a test to `tests/proof_documentation_manifest.rs`:

```rust
#[test]
fn production_coordinator_docs_keep_claim_boundary() {
    assert_contains_all(
        "docs/cryptography/claims-matrix.md",
        &[
            "coordinator-assisted ML-DSA-65 profile",
            "hazmat conformance only",
            "standard-verifier-compatible only after KAT and audit gates",
        ],
    );
    assert_contains_all(
        "docs/benchmarks/release-readiness-checklist.md",
        &[
            "FIPS/ACVP-style ML-DSA-65 provider KATs",
            "coordinator-assisted threshold KATs",
            "fuzz targets for production coordinator frames",
        ],
    );
}
```

- [ ] **Step 2: Run manifest test and verify failure**

Run:

```bash
CARGO_TARGET_DIR=/tmp/lattice-aggregation-doc-manifest cargo test --test proof_documentation_manifest production_coordinator_docs_keep_claim_boundary
```

Expected: FAIL because the new anchors are not present.

- [ ] **Step 3: Update docs with exact non-claims**

Add a row to `docs/cryptography/claims-matrix.md`:

```markdown
| Coordinator-assisted ML-DSA-65 profile | Non-default coordinator profile types, policy gates, transcript bindings, preprocessing attempts, and provider boundaries may exist behind `coordinator-assisted` or `hazmat-real-mldsa`. | `production-threshold-mldsa-coordinator-design.md`, FST-L5, Noise Lemma F | hazmat conformance only | Must not claim production threshold ML-DSA security; standard-verifier-compatible only after KAT and audit gates. |
```

Add a production-coordinator section to `docs/cryptography/proof-implementation-crosswalk.md` and `docs/cryptography/protocol-code-crosswalk.md` that maps:

```markdown
- `src/production/provider.rs`
- `src/production/transcript.rs`
- `src/production/preprocess.rs`
- `src/production/coordinator.rs`
- `src/adapter/production_wire.rs`
- `tests/production_provider.rs`
- `tests/production_transcript.rs`
- `tests/production_preprocess.rs`
- `tests/production_coordinator.rs`
- `tests/production_wire.rs`
```

Add production review targets to `docs/audit/attack-surface.md` and `docs/audit/tcb.md`.

Add the following checklist items to `docs/benchmarks/release-readiness-checklist.md`:

```markdown
- FIPS/ACVP-style ML-DSA-65 provider KATs.
- Coordinator-assisted threshold KATs for fixed 2-of-3 and 3-of-5 fixtures.
- Fuzz targets for production coordinator frames, transcripts, evidence records, and partial-response parsing.
```

- [ ] **Step 4: Run manifest test**

Run:

```bash
CARGO_TARGET_DIR=/tmp/lattice-aggregation-doc-manifest cargo test --test proof_documentation_manifest
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/cryptography/claims-matrix.md docs/cryptography/proof-implementation-crosswalk.md docs/cryptography/protocol-code-crosswalk.md docs/audit/attack-surface.md docs/audit/tcb.md docs/benchmarks/release-readiness-checklist.md tests/proof_documentation_manifest.rs
git commit -m "docs: add production coordinator claim boundaries"
```

## Task 12: Final Verification

**Files:**
- Verify all modified files.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt --check
```

Expected: PASS.

- [ ] **Step 2: Run Clippy**

Run:

```bash
CARGO_INCREMENTAL=0 cargo clippy --all-targets --all-features -- -D warnings
```

Expected: PASS with no warnings. If Cargo incremental metadata fails, keep `CARGO_INCREMENTAL=0` and rerun once before changing source.

- [ ] **Step 3: Run full tests**

Run:

```bash
CARGO_INCREMENTAL=0 cargo test --all-features
```

Expected: PASS. The `trybuild` target may run for several minutes; do not interrupt only because it prints “has been running for over 60 seconds.”

- [ ] **Step 4: Run isolated doc manifest**

Run:

```bash
CARGO_TARGET_DIR=/tmp/lattice-aggregation-prod-docs CARGO_INCREMENTAL=0 cargo test --test proof_documentation_manifest
```

Expected: PASS.

- [ ] **Step 5: Run targeted feature tests**

Run:

```bash
cargo test --features coordinator-assisted --test production_policy
cargo test --features coordinator-assisted --test production_transcript
cargo test --features coordinator-assisted --test production_preprocess
cargo test --features coordinator-assisted --test production_provider
cargo test --features coordinator-assisted --test production_coordinator
cargo test --features coordinator-assisted --test production_wire
```

Expected: all PASS.

- [ ] **Step 6: Confirm status**

Run:

```bash
git status --short --branch
```

Expected: only intended files are modified before staging, or clean after the final commit.

## Self-Review Checklist

- The simulator remains the default backend.
- `production-mldsa65-coordinator` remains non-default and policy-gated.
- The first provider boundary fails closed without a reviewed standard verifier.
- Attempt reuse is rejected by `PreprocessingStore`.
- Production transcript binds epoch, key ID, validator digest, DKG digest, active signers, attempt, message binding, commitment digests, and coordinator attestation digest.
- Coordinator finalization calls a `StandardMldsa65Provider` before returning a signature.
- Production wire uses version 2 and rejects trailing bytes.
- Documentation states hazmat conformance only until KAT, fuzzing, side-channel, proof, and audit gates pass.
- No task claims FIPS validation, production DKG/VSS, production slashing, adaptive security, or completed threshold ML-DSA security.
