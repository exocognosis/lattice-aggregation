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

- [ ] Define the main threshold ML-DSA-65 theorem.
- [ ] Define assumptions for ML-DSA EUF-CMA security, random oracle programmability, VSS binding/hiding/extractability, and transcript collision resistance.
- [ ] Define `F_TMLDSA` with setup, DKG, signing, output, and attributable abort behavior.
- [ ] State exactly which theorem parts are proven by existing tests and which remain proof obligations.
- [ ] Include stable anchors for later crosswalk tests:
  - `theorem-tmldsa-euf-cma`
  - `assumptions`
  - `ideal-functionality-ftmldsa`
  - `limitations`

### Task 2: Correctness And Noise/Rejection Lemmas

**Files:**
- Create: `docs/cryptography/correctness-lemmas.md`
- Create: `docs/cryptography/noise-rejection-proof-plan.md`

- [ ] Formalize Shamir/Lagrange reconstruction over `Z_q`.
- [ ] Formalize aggregation correctness for threshold response terms.
- [ ] State the standard-verification compatibility lemma.
- [ ] State infinity-norm and rejection-sampling proof obligations.
- [ ] Identify the exact distribution-equivalence gap that must be closed before publication as a proven cryptographic construction.
- [ ] Include stable anchors:
  - `lemma-lagrange-reconstruction`
  - `lemma-standard-verification`
  - `noise-bound-obligations`
  - `rejection-sampling-gap`

### Task 3: VSS/DKG And Active Adversary Model

**Files:**
- Create: `docs/cryptography/vss-dkg-security-plan.md`
- Create: `docs/cryptography/active-adversary-model.md`

- [ ] Define static and adaptive adversary variants.
- [ ] Define rushing behavior and synchrony assumptions.
- [ ] Define VSS binding, hiding, extractability, complaint, and evidence properties.
- [ ] Define DKG key-bias resistance and public-key uniqueness obligations.
- [ ] Identify which current modules are scaffold/backends and which production proofs must replace them.
- [ ] Include stable anchors:
  - `active-adversary-model`
  - `vss-security-properties`
  - `dkg-key-bias-resistance`
  - `production-replacement-obligations`

### Task 4: Proof-To-Code Crosswalk And Manifest Test

**Files:**
- Create: `docs/cryptography/proof-implementation-crosswalk.md`
- Create: `tests/proof_documentation_manifest.rs`

- [ ] Map theorem/lemma areas to code modules and integration tests.
- [ ] Add an integration test that checks proof documents exist and expose required anchors.
- [ ] Ensure manifest test is robust, text-based, and does not require network access.
- [ ] Run:

```bash
cargo test -j1 proof_documentation_manifest --all-features
```

## Integration Batch 1

- [ ] Review all new proof docs for consistent theorem names and assumptions.
- [ ] Ensure crosswalk points to all newly created docs.
- [ ] Run:

```bash
cargo fmt --check
cargo test -j1 proof_documentation_manifest --all-features
cargo test -j1 --all-features
```

- [ ] Commit:

```bash
git add docs/cryptography docs/superpowers/plans tests/proof_documentation_manifest.rs
git commit -m "Add full cryptographic proof plan surface"
```

## Parallel Batch 2: Proof Hardening

Start Batch 2 only after Batch 1 lands cleanly.

### Task 5: Proof Obligation Matrix Update

**Files:**
- Modify: `docs/cryptography/proof-obligations.md`
- Modify: `docs/cryptography/claims-matrix.md`

- [ ] Add a matrix row for each theorem/lemma from Batch 1.
- [ ] Mark each row as `Proven by tests`, `Proof sketch only`, `External theorem dependency`, or `Open`.
- [ ] Prevent any wording that says the active-adversary theorem is complete.

### Task 6: Transcript And Random Oracle Game

**Files:**
- Create: `docs/cryptography/random-oracle-game.md`
- Modify: `docs/cryptography/formal-threshold-mldsa-transcript.md`

- [ ] Define the random oracle queries used for `mu`, `w`, challenge `c`, and contribution proofs.
- [ ] Define transcript collision and domain-separation obligations.
- [ ] Map each query to concrete Rust transcript encodings.

### Task 7: Side-Channel And Constant-Time Boundary

**Files:**
- Create: `docs/cryptography/side-channel-boundary.md`
- Modify: `docs/audit/attack-surface.md`

- [ ] Define the leakage model assumed by the proof.
- [ ] Separate mathematical security claims from implementation side-channel claims.
- [ ] Identify operations that still need dudect/ctgrind-style empirical validation.

## Publication Gate

The project may claim "proof-oriented research artifact" after Batch 1.

The project may claim "cryptographically proven construction" only after all of the following hold:

- [ ] A complete correctness proof is written and reviewed.
- [ ] A complete active-adversary security reduction is written and reviewed.
- [ ] VSS/DKG backend is no longer scaffolded or the theorem explicitly assumes an ideal VSS/DKG functionality.
- [ ] Rejection-sampling distribution equivalence is proven for the threshold protocol.
- [ ] External lattice/PQ cryptography review has been completed.
