# Full Cryptographic Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the merged research artifact into a proof-carrying threshold ML-DSA-65 project with explicit theorem statements, correctness lemmas, adversary assumptions, VSS/DKG proof obligations, and implementation conformance tests.

**Architecture:** The proof work is split into independent documentation and manifest-test tracks so parallel agents can work without file conflicts. Each track produces a reviewable artifact with clear claims, dependencies, and limitations; later batches will replace scaffold assumptions with production proof backends.

**Tech Stack:** Rust, Cargo integration tests, FIPS 204 ML-DSA-65 terminology, Shamir/Lagrange algebra over `Z_q`, markdown proof documents, text-based manifest tests.

---

## Current Baseline

The repository is merged and tagged as `v0.1.0`. It contains a strong research artifact with hazmat ML-DSA-65 internals, threshold protocol scaffolding, actor simulations, transcript binding, evidence schemas, and reproducibility docs.

The full cryptographic theorem is not yet proven. The next phase must avoid overstating the claim: this phase defines the theorem, proof assumptions, ideal functionality, lemma structure, and code/proof crosswalk needed for rigorous review.

## Parallel Batch 1: Proof Surface Definition

### Task 1: Formal Theorem And Ideal Functionality

**Files:**
- Create: `docs/cryptography/formal-security-theorem.md`
- Create: `docs/cryptography/ideal-functionality.md`

- [x] Define the main threshold ML-DSA-65 theorem.
- [x] Define assumptions for ML-DSA EUF-CMA security, random oracle programmability, VSS binding/hiding/extractability, and transcript collision resistance.
- [x] Define `F_TMLDSA` with setup, DKG, signing, output, and attributable abort behavior.
- [x] State exactly which theorem parts are proven by existing tests and which remain proof obligations.
- [x] Include stable anchors for later crosswalk tests:
  - `theorem-tmldsa-euf-cma`
  - `assumptions`
  - `ideal-functionality-ftmldsa`
  - `limitations`

### Task 2: Correctness And Noise/Rejection Lemmas

**Files:**
- Create: `docs/cryptography/correctness-lemmas.md`
- Create: `docs/cryptography/noise-rejection-proof-plan.md`

- [x] Formalize Shamir/Lagrange reconstruction over `Z_q`.
- [x] Formalize aggregation correctness for threshold response terms.
- [x] State the standard-verification compatibility lemma.
- [x] State infinity-norm and rejection-sampling proof obligations.
- [x] Identify the exact distribution-equivalence gap that must be closed before publication as a proven cryptographic construction.
- [x] Include stable anchors:
  - `lemma-lagrange-reconstruction`
  - `lemma-standard-verification`
  - `noise-bound-obligations`
  - `rejection-sampling-gap`

### Task 3: VSS/DKG And Active Adversary Model

**Files:**
- Create: `docs/cryptography/vss-dkg-security-plan.md`
- Create: `docs/cryptography/active-adversary-model.md`

- [x] Define static and adaptive adversary variants.
- [x] Define rushing behavior and synchrony assumptions.
- [x] Define VSS binding, hiding, extractability, complaint, and evidence properties.
- [x] Define DKG key-bias resistance and public-key uniqueness obligations.
- [x] Identify which current modules are scaffold/backends and which production proofs must replace them.
- [x] Include stable anchors:
  - `active-adversary-model`
  - `vss-security-properties`
  - `dkg-key-bias-resistance`
  - `production-replacement-obligations`

### Task 4: Proof-To-Code Crosswalk And Manifest Test

**Files:**
- Create: `docs/cryptography/proof-implementation-crosswalk.md`
- Create: `tests/proof_documentation_manifest.rs`

- [x] Map theorem/lemma areas to code modules and integration tests.
- [x] Add an integration test that checks proof documents exist and expose required anchors.
- [x] Ensure manifest test is robust, text-based, and does not require network access.
- [x] Run:

```bash
cargo test -j1 proof_documentation_manifest --all-features
```

## Integration Batch 1

- [x] Review all new proof docs for consistent theorem names and assumptions.
- [x] Ensure crosswalk points to all newly created docs.
- [x] Run:

```bash
cargo fmt --check
cargo test -j1 proof_documentation_manifest --all-features
cargo test -j1 --all-features
```

- [x] Commit:

```bash
git add docs/cryptography docs/superpowers/plans tests/proof_documentation_manifest.rs
git commit -m "Add full cryptographic proof plan surface"
```

## Parallel Batch 2: Proof Hardening

Started after Batch 1 landed cleanly.

### Task 5: Proof Obligation Matrix Update

**Files:**
- Modify: `docs/cryptography/proof-obligations.md`
- Modify: `docs/cryptography/claims-matrix.md`

- [x] Add a matrix row for each theorem/lemma from Batch 1.
- [x] Mark each row with conservative proof-surface status language.
- [x] Prevent any wording that says the active-adversary theorem is complete.

### Task 6: Transcript And Random Oracle Game

**Files:**
- Create: `docs/cryptography/random-oracle-game.md`
- Modify: `docs/cryptography/formal-threshold-mldsa-transcript.md`

- [x] Define the random oracle queries used for `mu`, `w`, challenge `c`, and contribution proofs.
- [x] Define transcript collision and domain-separation obligations.
- [x] Map each query to concrete Rust transcript encodings.

### Task 7: Side-Channel And Constant-Time Boundary

**Files:**
- Create: `docs/cryptography/side-channel-boundary.md`
- Modify: `docs/audit/attack-surface.md`

- [x] Define the leakage model assumed by the proof.
- [x] Separate mathematical security claims from implementation side-channel claims.
- [x] Identify operations that still need dudect/ctgrind-style empirical validation.

## Publication Gate

The project may claim "proof-oriented research artifact" after Batch 1.

The project may claim "cryptographically proven construction" only after all of the following hold:

- [ ] A complete correctness proof is written and reviewed.
- [ ] A complete active-adversary security reduction is written and reviewed.
- [ ] VSS/DKG backend is no longer scaffolded or the theorem explicitly assumes an ideal VSS/DKG functionality.
- [ ] Rejection-sampling distribution equivalence is proven for the threshold protocol.
- [ ] External lattice/PQ cryptography review has been completed.

## Parallel Batch 3: Proof Body Expansion

### Task 8: Correctness Proof Expansion

**Files:**
- Modify: `docs/cryptography/correctness-lemmas.md`
- Modify: `tests/proof_documentation_manifest.rs`

- [x] Strengthen field inversion, Lagrange basis, coefficient-lane Shamir
  reconstruction, canonical collection, transcript binding, aggregation,
  standard verification, and norm-preservation proof sketches.
- [x] Add explicit preconditions and current-evidence boundaries.
- [x] Add manifest anchors for strengthened correctness sections.

### Task 9: Rejection-Sampling Hybrid Proof

**Files:**
- Create: `docs/cryptography/rejection-sampling-hybrid-proof.md`
- Modify: `docs/cryptography/noise-rejection-proof-plan.md`
- Modify: `tests/proof_documentation_manifest.rs`

- [x] Define hybrids from centralized ML-DSA to accepted threshold aggregate
  output.
- [x] Track commit-before-challenge, partial response reconstruction, aggregate
  rejection, and accepted-signature distribution gaps.
- [x] Add manifest anchors for the hybrid proof.

### Task 10: VSS Backend Selection Framework

**Files:**
- Create: `docs/cryptography/vss-backend-selection.md`
- Modify: `docs/cryptography/vss-dkg-security-plan.md`
- Modify: `docs/cryptography/production-vss-backend.md`
- Modify: `tests/proof_documentation_manifest.rs`

- [x] Compare candidate backend families and their proof assumptions.
- [x] Add a conservative no-backend-selected decision record unless a candidate
  is justified.
- [x] Add manifest anchors for backend-selection criteria.

### Task 11: Real/Ideal Simulator Skeleton

**Files:**
- Create: `docs/cryptography/real-ideal-simulator.md`
- Modify: `docs/cryptography/ideal-functionality.md`
- Modify: `docs/cryptography/formal-security-theorem.md`
- Modify: `tests/proof_documentation_manifest.rs`

- [x] Define simulator state, oracle programming points, DKG simulation,
  signing simulation, abort/evidence simulation, and hybrid sequence.
- [x] Link simulator skeleton from theorem and ideal-functionality documents.
- [x] Add manifest anchors for the simulator skeleton.
