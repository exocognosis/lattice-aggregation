# Threshold Reconstruction Backend Run Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `emit-backend-capture` produce an executable threshold-controlled aggregate run using Shamir reconstruction of the ML-DSA-65 seed, while preserving blockers for true theorem closure until ML-DSA partial `z_i` signing exists.

**Architecture:** Add a transitional core mode separate from centralized smoke and strict partial aggregation. The run splits the 32-byte seed into 6,667 active Shamir shares over ML-DSA q, reconstructs the seed at the coordinator, signs with the standard ML-DSA provider, verifies with the unmodified verifier, and emits transcript evidence that explicitly says this is seed reconstruction rather than partial ML-DSA signing.

**Tech Stack:** Rust `src/bin/threshold_backend_p1.rs`, Python script tests, existing artifact pipeline.

---

### Task 1: Failing CLI Test

**Files:**
- Modify: `script_tests/test_threshold_backend_p1.py`

- [x] Add a test that `emit-backend-capture` succeeds and emits `threshold_seed_reconstruction_mldsa65_provider`.
- [x] Assert the capture has `standard_verifier_compatible_output: true`, `threshold_seed_reconstruction_sharing: true`, and `partial_signing_over_secret_shares: false`.
- [x] Run the test and verify it fails because `emit-backend-capture` currently fails closed.

### Task 2: Transitional Core Implementation

**Files:**
- Modify: `src/bin/threshold_backend_p1.rs`

- [x] Add Shamir reconstruction helpers over q=8380417 for 32 seed bytes and active x coordinates `1..=6667`.
- [x] Implement `emit_backend_capture` using reconstructed seed signing rather than the smoke command.
- [x] Emit transcript fields for reconstruction share count, active signer digest, share commitment root, reconstructed seed digest, and closure boundary.
- [x] Keep `partial_signing_over_secret_shares`, `partial_z_i_hint_aggregation`, and `fips204_rejection_loop_over_threshold_partials` false.

### Task 3: Gate/Artifact Synchronization

**Files:**
- Modify: `scripts/stage_external_backend_emission_capture.py` if needed
- Modify: `scripts/build_p1_external_backend_cryptographic_closure_candidate.py` if needed
- Modify: affected tests

- [x] Ensure the transitional mode stages as evidence but remains blocked from theorem closure.
- [x] Regenerate backend/evidence artifacts from `emit-backend-capture`.

### Task 4: Verification and Publication

- [x] Run focused Python tests.
- [x] Run `cargo test --all-features` and clippy.
- [x] Regenerate closure/hypothesis artifacts.
- [ ] Commit and push the scoped branch.
