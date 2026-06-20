# Epsilon Prefilter Guardrails Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add conformance-layer epsilon accounting, blinded pre-filter gating, hint-routing frames, and DKG hot-path isolation docs without claiming production threshold ML-DSA security.

**Architecture:** Add small production modules under the existing `coordinator-assisted` gate. `epsilon.rs` owns deterministic Renyi-budget accounting, `prefilter.rs` owns abort/pass capability tokens and zeroization flow, `hints.rs` owns public hint-routing wrappers, and `production_wire.rs` carries the new v2 public frames. Existing transcript and final verifier gates remain the production boundary.

**Tech Stack:** Rust 2021, cargo test, sha3/zeroize already in use, non-default `coordinator-assisted` feature.

---

## File Structure

- Create `src/production/epsilon.rs`: fixed-point epsilon ledger and noise-flooding parameter validation.
- Create `src/production/prefilter.rs`: blinded pre-filter request/outcome types and `PreFilterPassed` token.
- Create `src/production/hints.rs`: conformance-only hint-routing request, response, and decision types.
- Modify `src/production/preprocess.rs`: add explicit abort-and-zeroize consumption path.
- Modify `src/production.rs`: export new modules behind `coordinator-assisted`.
- Modify `src/errors.rs`: add pre-filter/noise/hint validation error variants.
- Modify `src/adapter/production_wire.rs`: add pre-filter and hint-routing frames.
- Create `tests/production_epsilon.rs`: ledger and noise parameter tests.
- Create `tests/production_prefilter.rs`: abort/pass/zeroization and share-release token tests.
- Create `tests/production_hints.rs`: hint-routing type tests.
- Modify `tests/production_wire.rs`: golden and malformed-frame tests for new v2 frames.
- Modify proof docs and `tests/proof_documentation_manifest.rs`: track Renyi and conformance-only anchors.

### Task 1: Epsilon Ledger And Noise Parameters

**Files:**
- Create: `src/production/epsilon.rs`
- Modify: `src/production.rs`
- Modify: `src/errors.rs`
- Test: `tests/production_epsilon.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::epsilon::{EpsilonLedger, EpsilonUnit, NoiseFloodingParameters},
    ThresholdError,
};

#[test]
fn epsilon_ledger_starts_at_zero_and_increments_independent_components() {
    let mut ledger = EpsilonLedger::default();
    assert_eq!(ledger.epsilon_mask(), EpsilonUnit::ZERO);
    assert_eq!(ledger.epsilon_rej(), EpsilonUnit::ZERO);
    assert_eq!(ledger.epsilon_withhold(), EpsilonUnit::ZERO);

    ledger.increment_mask(EpsilonUnit::from_units(3));
    ledger.increment_rejection(EpsilonUnit::from_units(5));
    ledger.increment_withholding(EpsilonUnit::from_units(7));

    assert_eq!(ledger.epsilon_mask(), EpsilonUnit::from_units(3));
    assert_eq!(ledger.epsilon_rej(), EpsilonUnit::from_units(5));
    assert_eq!(ledger.epsilon_withhold(), EpsilonUnit::from_units(7));
}

#[test]
fn noise_flooding_rejects_sigma_above_beta_quarter() {
    let err = NoiseFloodingParameters::new(100, 26, EpsilonUnit::from_units(1)).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::InvalidNoiseFloodingParameters {
            reason: "gaussian sigma bound exceeds beta / 4",
        }
    );
}

#[test]
fn noise_flooding_records_renyi_budget_when_valid() {
    let params = NoiseFloodingParameters::new(100, 25, EpsilonUnit::from_units(9)).unwrap();
    assert_eq!(params.beta(), 100);
    assert_eq!(params.gaussian_sigma_bound(), 25);
    assert_eq!(params.renyi_epsilon_increment(), EpsilonUnit::from_units(9));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --features coordinator-assisted --test production_epsilon`

Expected: compile failure because `production::epsilon`, `EpsilonLedger`, `EpsilonUnit`, `NoiseFloodingParameters`, and `InvalidNoiseFloodingParameters` do not exist.

- [ ] **Step 3: Implement minimal code**

Add `src/production/epsilon.rs`:

```rust
//! Epsilon residual accounting for coordinator-assisted conformance gates.

use crate::ThresholdError;

/// Deterministic fixed-point epsilon unit used in tests and transcripts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EpsilonUnit(u64);

impl EpsilonUnit {
    /// Zero epsilon budget.
    pub const ZERO: Self = Self(0);

    /// Construct from deterministic ledger units.
    pub const fn from_units(units: u64) -> Self {
        Self(units)
    }

    /// Return raw deterministic ledger units.
    pub const fn units(self) -> u64 {
        self.0
    }
}

/// Residual ledger for public conformance accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EpsilonLedger {
    epsilon_mask: EpsilonUnit,
    epsilon_rej: EpsilonUnit,
    epsilon_withhold: EpsilonUnit,
}

impl EpsilonLedger {
    /// Return the Renyi-divergence masking residual budget.
    pub const fn epsilon_mask(self) -> EpsilonUnit {
        self.epsilon_mask
    }

    /// Return the rejection/abort residual budget.
    pub const fn epsilon_rej(self) -> EpsilonUnit {
        self.epsilon_rej
    }

    /// Return the withholding residual budget.
    pub const fn epsilon_withhold(self) -> EpsilonUnit {
        self.epsilon_withhold
    }

    /// Increment the Renyi-divergence masking residual.
    pub fn increment_mask(&mut self, amount: EpsilonUnit) {
        self.epsilon_mask = EpsilonUnit(self.epsilon_mask.0.saturating_add(amount.0));
    }

    /// Increment the public rejection residual.
    pub fn increment_rejection(&mut self, amount: EpsilonUnit) {
        self.epsilon_rej = EpsilonUnit(self.epsilon_rej.0.saturating_add(amount.0));
    }

    /// Increment the public withholding residual.
    pub fn increment_withholding(&mut self, amount: EpsilonUnit) {
        self.epsilon_withhold =
            EpsilonUnit(self.epsilon_withhold.0.saturating_add(amount.0));
    }
}

/// Conformance parameters for asymmetric noise flooding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoiseFloodingParameters {
    beta: u32,
    gaussian_sigma_bound: u32,
    renyi_epsilon_increment: EpsilonUnit,
}

impl NoiseFloodingParameters {
    /// Construct parameters, enforcing `sigma <= beta / 4`.
    pub fn new(
        beta: u32,
        gaussian_sigma_bound: u32,
        renyi_epsilon_increment: EpsilonUnit,
    ) -> Result<Self, ThresholdError> {
        if gaussian_sigma_bound > beta / 4 {
            return Err(ThresholdError::InvalidNoiseFloodingParameters {
                reason: "gaussian sigma bound exceeds beta / 4",
            });
        }
        Ok(Self {
            beta,
            gaussian_sigma_bound,
            renyi_epsilon_increment,
        })
    }

    /// Return beta bound.
    pub const fn beta(self) -> u32 {
        self.beta
    }

    /// Return configured Gaussian sigma upper bound.
    pub const fn gaussian_sigma_bound(self) -> u32 {
        self.gaussian_sigma_bound
    }

    /// Return the Renyi epsilon increment supplied by the reviewed backend.
    pub const fn renyi_epsilon_increment(self) -> EpsilonUnit {
        self.renyi_epsilon_increment
    }
}
```

Add to `src/production.rs`:

```rust
#[cfg(feature = "coordinator-assisted")]
pub mod epsilon;
```

Add to `src/errors.rs`:

```rust
    /// Noise-flooding parameters failed conformance validation.
    #[error("invalid noise flooding parameters: {reason}")]
    InvalidNoiseFloodingParameters {
        /// Static reason the parameters were rejected.
        reason: &'static str,
    },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --features coordinator-assisted --test production_epsilon`

Expected: all three tests pass.

### Task 2: Blinded Pre-Filter Gate And Attempt Zeroization

**Files:**
- Create: `src/production/prefilter.rs`
- Modify: `src/production.rs`
- Modify: `src/production/preprocess.rs`
- Modify: `src/errors.rs`
- Test: `tests/production_prefilter.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        epsilon::{EpsilonLedger, EpsilonUnit},
        prefilter::{BlindedCommitmentSummary, BlindedPreFilter, PreFilterOutcome},
        preprocess::PreprocessedAttempt,
        types::AttemptId,
    },
    ValidatorId,
};

#[test]
fn prefilter_pass_returns_share_release_token() {
    let mut ledger = EpsilonLedger::default();
    let summaries = vec![
        BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 40),
        BlindedCommitmentSummary::new(ValidatorId(2), [2; 32], 45),
    ];

    let outcome = BlindedPreFilter::evaluate(100, EpsilonUnit::from_units(2), summaries, &mut ledger)
        .unwrap();

    match outcome {
        PreFilterOutcome::Passed(token) => {
            assert_eq!(token.clearance_boundary(), 100);
            assert_eq!(ledger.epsilon_rej(), EpsilonUnit::ZERO);
        }
        PreFilterOutcome::Aborted(_) => panic!("expected pass"),
    }
}

#[test]
fn prefilter_abort_increments_rejection_budget() {
    let mut ledger = EpsilonLedger::default();
    let summaries = vec![BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 101)];

    let outcome = BlindedPreFilter::evaluate(100, EpsilonUnit::from_units(2), summaries, &mut ledger)
        .unwrap();

    match outcome {
        PreFilterOutcome::Passed(_) => panic!("expected abort"),
        PreFilterOutcome::Aborted(abort) => {
            assert_eq!(abort.aggregate_infinity_norm(), 101);
            assert_eq!(ledger.epsilon_rej(), EpsilonUnit::from_units(2));
        }
    }
}

#[test]
fn abort_and_zeroize_consumes_attempt_secret_material() {
    let mut attempt = PreprocessedAttempt::new(AttemptId([7; 32]), vec![9, 8, 7]).unwrap();
    attempt.abort_and_zeroize();
    assert_eq!(attempt.secret_material_for_test(), &[0, 0, 0]);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --features coordinator-assisted --test production_prefilter`

Expected: compile failure because `production::prefilter`, the new types, and `abort_and_zeroize` do not exist.

- [ ] **Step 3: Implement minimal code**

Add `src/production/prefilter.rs`:

```rust
//! Blinded pre-filter gate for conformance-only share release ordering.

use crate::{ThresholdError, ValidatorId};

use super::epsilon::{EpsilonLedger, EpsilonUnit};

/// Public digest and bound summary for one blinded commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindedCommitmentSummary {
    validator: ValidatorId,
    commitment_digest: [u8; 32],
    infinity_norm: u32,
}

impl BlindedCommitmentSummary {
    /// Construct a public blinded commitment summary.
    pub const fn new(
        validator: ValidatorId,
        commitment_digest: [u8; 32],
        infinity_norm: u32,
    ) -> Self {
        Self {
            validator,
            commitment_digest,
            infinity_norm,
        }
    }

    /// Return the validator that supplied this summary.
    pub const fn validator(self) -> ValidatorId {
        self.validator
    }

    /// Return the commitment digest.
    pub const fn commitment_digest(self) -> [u8; 32] {
        self.commitment_digest
    }

    /// Return the declared infinity norm summary.
    pub const fn infinity_norm(self) -> u32 {
        self.infinity_norm
    }
}

/// Capability token proving blinded pre-filter success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreFilterPassed {
    clearance_boundary: u32,
    aggregate_infinity_norm: u32,
}

impl PreFilterPassed {
    /// Return the clearance boundary.
    pub const fn clearance_boundary(self) -> u32 {
        self.clearance_boundary
    }

    /// Return the accepted aggregate infinity norm summary.
    pub const fn aggregate_infinity_norm(self) -> u32 {
        self.aggregate_infinity_norm
    }
}

/// Public abort record for a failed pre-filter gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreFilterAborted {
    clearance_boundary: u32,
    aggregate_infinity_norm: u32,
}

impl PreFilterAborted {
    /// Return the clearance boundary.
    pub const fn clearance_boundary(self) -> u32 {
        self.clearance_boundary
    }

    /// Return the rejected aggregate infinity norm summary.
    pub const fn aggregate_infinity_norm(self) -> u32 {
        self.aggregate_infinity_norm
    }
}

/// Pre-filter result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreFilterOutcome {
    /// Share release may proceed.
    Passed(PreFilterPassed),
    /// Attempt must abort before share release.
    Aborted(PreFilterAborted),
}

/// Stateless blinded pre-filter evaluator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlindedPreFilter;

impl BlindedPreFilter {
    /// Evaluate public blinded commitment summaries.
    pub fn evaluate(
        clearance_boundary: u32,
        rejection_increment: EpsilonUnit,
        summaries: Vec<BlindedCommitmentSummary>,
        ledger: &mut EpsilonLedger,
    ) -> Result<PreFilterOutcome, ThresholdError> {
        if summaries.is_empty() {
            return Err(ThresholdError::InvalidPreFilter {
                reason: "no blinded commitment summaries supplied",
            });
        }

        let aggregate_infinity_norm = summaries
            .iter()
            .map(|summary| summary.infinity_norm())
            .max()
            .unwrap_or(0);

        if aggregate_infinity_norm > clearance_boundary {
            ledger.increment_rejection(rejection_increment);
            Ok(PreFilterOutcome::Aborted(PreFilterAborted {
                clearance_boundary,
                aggregate_infinity_norm,
            }))
        } else {
            Ok(PreFilterOutcome::Passed(PreFilterPassed {
                clearance_boundary,
                aggregate_infinity_norm,
            }))
        }
    }
}
```

Add to `src/production.rs`:

```rust
#[cfg(feature = "coordinator-assisted")]
pub mod prefilter;
```

Add to `src/errors.rs`:

```rust
    /// Blinded pre-filter input failed conformance validation.
    #[error("invalid pre-filter input: {reason}")]
    InvalidPreFilter {
        /// Static reason the input was rejected.
        reason: &'static str,
    },
```

Add to `src/production/preprocess.rs`:

```rust
    /// Zeroize attempt-local secret material after an abort gate.
    pub fn abort_and_zeroize(&mut self) {
        self.secret_material.zeroize();
    }

    /// Borrow secret material for tests that verify explicit zeroization.
    #[cfg(test)]
    pub(crate) fn secret_material_for_test(&self) -> &[u8] {
        &self.secret_material
    }
```

If integration tests need the test accessor, expose it under
`#[cfg(any(test, feature = "coordinator-assisted"))]` as `pub`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --features coordinator-assisted --test production_prefilter`

Expected: all three tests pass.

### Task 3: Hint-Routing Types And Production Wire Frames

**Files:**
- Create: `src/production/hints.rs`
- Modify: `src/production.rs`
- Modify: `src/adapter/production_wire.rs`
- Test: `tests/production_hints.rs`
- Test: `tests/production_wire.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        hints::{HintRoutingDecision, HintRoutingRequest, HintRoutingResponse},
        types::AttemptId,
    },
    ValidatorId,
};

#[test]
fn hint_routing_request_binds_public_context() {
    let request = HintRoutingRequest::new([1; 32], AttemptId([2; 32]), [3; 32], [4; 32], [5; 32]);
    assert_eq!(request.session_id(), &[1; 32]);
    assert_eq!(request.attempt_id(), AttemptId([2; 32]));
    assert_eq!(request.active_set_digest(), &[3; 32]);
    assert_eq!(request.challenge_digest(), &[4; 32]);
    assert_eq!(request.near_boundary_commitment_digest(), &[5; 32]);
}

#[test]
fn hint_routing_response_binds_validator_without_raw_hint_material() {
    let response = HintRoutingResponse::new(ValidatorId(9), [8; 32]);
    assert_eq!(response.validator(), ValidatorId(9));
    assert_eq!(response.response_digest(), &[8; 32]);
}

#[test]
fn hint_routing_decision_records_complete_or_abort() {
    assert_eq!(HintRoutingDecision::Completed.hint_routing_completed(), true);
    assert_eq!(HintRoutingDecision::AbortBeforeShareRelease.hint_routing_completed(), false);
}
```

Add wire tests to `tests/production_wire.rs`:

```rust
#[test]
fn hint_routing_wire_encoding_is_golden() {
    let msg = ProductionWireMsg::HintRoutingRequest {
        session_id: [1; 32],
        epoch: 7,
        attempt_id: [2; 32],
        active_set_digest: [3; 32],
        challenge_digest: [4; 32],
        near_boundary_commitment_digest: [5; 32],
    };
    let encoded = msg.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(encoded[1], 7);
    assert_eq!(encoded.len(), 170);
    assert_eq!(ProductionWireMsg::decode(&encoded).unwrap(), msg);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --features coordinator-assisted --test production_hints --test production_wire`

Expected: compile failure because hint types and wire variants do not exist.

- [ ] **Step 3: Implement minimal code**

Add `src/production/hints.rs` with public digest-only wrappers and accessors.

In `src/adapter/production_wire.rs`, add message tags:

```rust
const MSG_PREFILTER_ABORT: u8 = 5;
const MSG_PREFILTER_PASS: u8 = 6;
const MSG_HINT_ROUTING_REQUEST: u8 = 7;
const MSG_HINT_ROUTING_RESPONSE: u8 = 8;
```

Add enum variants for pre-filter pass/abort and hint routing request/response.
Encode fixed-width frames only, reject exact-length mismatches, and include no
raw low bits, raw hints, raw response scalars, or secret material.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --features coordinator-assisted --test production_hints --test production_wire`

Expected: all hint and production wire tests pass.

### Task 4: Transcript And Share-Release Capability Boundary

**Files:**
- Modify: `src/production/coordinator.rs`
- Modify: `src/production/prefilter.rs`
- Test: `tests/production_prefilter.rs`
- Test: `tests/production_coordinator.rs`

- [ ] **Step 1: Write failing tests for token-gated release**

Add to `tests/production_prefilter.rs`:

```rust
#[test]
fn share_release_request_requires_prefilter_pass_token() {
    let mut ledger = EpsilonLedger::default();
    let outcome = BlindedPreFilter::evaluate(
        100,
        EpsilonUnit::from_units(1),
        vec![BlindedCommitmentSummary::new(ValidatorId(1), [1; 32], 50)],
        &mut ledger,
    )
    .unwrap();
    let token = match outcome {
        PreFilterOutcome::Passed(token) => token,
        PreFilterOutcome::Aborted(_) => panic!("expected pass"),
    };

    let request = token.into_share_release_authorization(AttemptId([9; 32]));
    assert_eq!(request.attempt_id(), AttemptId([9; 32]));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --features coordinator-assisted --test production_prefilter`

Expected: compile failure because `into_share_release_authorization` does not exist.

- [ ] **Step 3: Implement minimal token-gated authorization**

Add to `src/production/prefilter.rs`:

```rust
use super::types::AttemptId;

/// Capability required before response-share release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareReleaseAuthorization {
    attempt_id: AttemptId,
    prefilter: PreFilterPassed,
}

impl ShareReleaseAuthorization {
    /// Return the authorized attempt.
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Return the pre-filter pass token.
    pub const fn prefilter(self) -> PreFilterPassed {
        self.prefilter
    }
}

impl PreFilterPassed {
    /// Convert the pass token into share-release authorization for one attempt.
    pub const fn into_share_release_authorization(
        self,
        attempt_id: AttemptId,
    ) -> ShareReleaseAuthorization {
        ShareReleaseAuthorization {
            attempt_id,
            prefilter: self,
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --features coordinator-assisted --test production_prefilter`

Expected: all pre-filter tests pass.

### Task 5: Documentation And Manifest Claim Boundary

**Files:**
- Modify: `docs/cryptography/noise-rejection-proof-plan.md`
- Modify: `docs/cryptography/phase-1-noise-bound-model.md`
- Modify: `docs/cryptography/claims-matrix.md`
- Modify: `docs/cryptography/proof-obligations.md`
- Modify: `docs/cryptography/proof-implementation-crosswalk.md`
- Modify: `docs/cryptography/protocol-code-crosswalk.md`
- Modify: `docs/audit/attack-surface.md`
- Modify: `docs/audit/tcb.md`
- Modify: `docs/benchmarks/release-readiness-checklist.md`
- Modify: `tests/proof_documentation_manifest.rs`

- [ ] **Step 1: Write failing manifest expectations**

Add required anchors to `tests/proof_documentation_manifest.rs` under
`production_coordinator_docs_keep_claim_boundary`:

```rust
"EpsilonLedger",
"blinded pre-filter",
"Renyi divergence",
"hint-routing conformance",
"DKG setup-only boundary",
```

- [ ] **Step 2: Run manifest test to verify it fails**

Run: `cargo test --test proof_documentation_manifest production_coordinator_docs_keep_claim_boundary`

Expected: failure naming missing anchors.

- [ ] **Step 3: Update docs with conservative wording**

Update the listed docs to include the anchors and these statements:

- `EpsilonLedger` is conformance accounting, not proof completion.
- `epsilon_mask` drift is tracked using Renyi divergence wording.
- Blinded pre-filter abort happens before response-share release.
- Hint routing is digest-only conformance state until real ML-DSA equations are
  selected and reviewed.
- DKG is setup-only for block production; signing binds `DkgTranscriptDigest`
  and does not run a live DKG loop.

- [ ] **Step 4: Run manifest test to verify it passes**

Run: `cargo test --test proof_documentation_manifest production_coordinator_docs_keep_claim_boundary`

Expected: pass.

### Task 6: Focused Verification

**Files:**
- All files changed by prior tasks.

- [ ] **Step 1: Run coordinator feature tests**

Run:

```bash
cargo test --features coordinator-assisted --test production_epsilon --test production_prefilter --test production_hints --test production_wire --test production_transcript --test production_coordinator
```

Expected: pass.

- [ ] **Step 2: Run docs manifest test**

Run:

```bash
cargo test --test proof_documentation_manifest
```

Expected: pass.

- [ ] **Step 3: Run formatting check**

Run:

```bash
cargo fmt --check
```

Expected: pass.

## Self-Review

- Spec coverage: tasks cover epsilon accounting, noise parameter validation,
  pre-filter pass/abort, zeroization, share-release capability tokens,
  hint-routing state, production wire frames, DKG setup-only docs, and manifest
  anchors.
- Placeholder scan: no task relies on unspecified code names or deferred
  behavior.
- Type consistency: `EpsilonUnit`, `EpsilonLedger`, `BlindedPreFilter`,
  `PreFilterPassed`, `ShareReleaseAuthorization`, `HintRoutingRequest`, and
  `HintRoutingResponse` are introduced before later tasks use them.
