# Core Backend Requirements Ledger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an executable backend evidence ledger for the six core backend requirement classes: threshold key material, distributed nonce path, partial signing, aggregation, FIPS 204 rejection loop, and standard verifier compatibility.

**Architecture:** The current backend can emit a threshold seed-reconstruction ML-DSA-65 capture and standard verifier evidence, but it does not yet implement true ML-DSA partial signing over secret shares. This plan adds a machine-readable `backend_requirement_evidence` ledger to the backend transcript and `cryptographic_core` accounting so each requirement has explicit evidence, blockers, and closure flags without falsely claiming theorem closure.

**Tech Stack:** Rust `src/bin/threshold_backend_p1.rs`, Python `script_tests/test_threshold_backend_p1.py`, existing artifact generation scripts.

---

### Task 1: Failing Ledger Test

**Files:**
- Modify: `script_tests/test_threshold_backend_p1.py`

- [x] Add assertions to `test_backend_capture_emits_threshold_reconstruction_run_without_closure_claim` requiring `cryptographic_core["backend_requirement_evidence"]`.
- [x] Assert the ledger contains exactly these keys: `threshold_key_material`, `distributed_nonce_path`, `partial_signing`, `aggregation`, `fips204_rejection_loop`, and `standard_verifier_compatibility`.
- [x] Assert threshold key material records `validator_count=10000`, `threshold=6667`, one public key, DKG/VSS unavailable, TEE/HSM trust record present, and no exposed ML-DSA secret key.
- [x] Assert distributed nonce path records commit-before-reveal, aggregate commitment evidence, abort accountability, and no centralized nonce oracle, while marking live distributed nonce generation false.
- [x] Assert partial signing and FIPS 204 rejection loop remain not implemented with concrete blockers.
- [x] Run the focused test and verify it fails before implementation.

### Task 2: Backend Ledger Implementation

**Files:**
- Modify: `src/bin/threshold_backend_p1.rs`

- [x] Add `backend_requirement_evidence()` for the reconstruction path.
- [x] Include the ledger in `reconstruction_backend_core_accounting()`.
- [x] Include the ledger in `reconstruction_backend_transcript_core_accounting()`.
- [x] Include per-attempt evidence objects in the backend transcript for nonce path, partial signing, aggregation, rejection loop, and verifier compatibility.
- [x] Keep strict closure flags false for missing DKG/VSS, partial signing over shares, partial hint aggregation, and rejection loop over threshold partials.

### Task 3: Artifact Regeneration

**Files:**
- Regenerate: `artifacts/backend-emission-capture/latest/*`
- Regenerate: `artifacts/p1-external-backend-cryptographic-closure-candidate/latest/*`
- Regenerate: `artifacts/p1-external-backend-evidence-attempt/latest/*`
- Regenerate: `artifacts/hypothesis/latest/*`
- Regenerate: `artifacts/theorem-closure-readiness/latest/*`

- [x] Emit a fresh backend capture.
- [x] Stage the capture through the external backend intake script.
- [x] Rebuild candidate, evidence-attempt, hypothesis, and theorem-readiness artifacts.

### Task 4: Verification

- [x] Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest script_tests.test_threshold_backend_p1`.
- [x] Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest script_tests.test_run_backend_emission_capture script_tests.test_stage_external_backend_emission_capture`.
- [x] Run `cargo check --features raw-real-mldsa --bin threshold_backend_p1`.
- [x] Run `cargo clippy --all-features -- -D warnings`.
