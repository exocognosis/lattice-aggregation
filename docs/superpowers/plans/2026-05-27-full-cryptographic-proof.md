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

## Parallel Batch 4: Proof Reduction Worksheets

### Task 12: Rejection-Sampling Bounds Worksheet

**Files:**
- Create: `docs/cryptography/rejection-sampling-bounds.md`

- [x] Define symbolic ML-DSA-65 bounds and inequalities for accepted threshold
  responses.
- [x] Decompose selective-abort advantage into masking, commitment, aggregate
  rejection, and withholding terms.
- [x] Map each bound to current evidence and remaining proof work.

### Task 13: VSS Idealization And Backend Selection

**Files:**
- Create: `docs/cryptography/vss-idealization-and-selection.md`

- [x] Define an ideal `F_VSS_DKG` for proof staging.
- [x] State when `F_TMLDSA` may cite ideal VSS/DKG.
- [x] Add a decision tree for idealization versus concrete lattice/vector
  commitment selection.

### Task 14: Simulator Hybrid Reductions

**Files:**
- Create: `docs/cryptography/simulator-hybrid-reductions.md`

- [x] Convert S0..S8 into transition lemmas.
- [x] Map each transition to a reduction target or explicit assumption.
- [x] Decompose simulator failure events and identify hardest reductions.

### Task 15: Proof Bibliography And Citation Map

**Files:**
- Create: `docs/cryptography/proof-bibliography.md`

- [x] Map external theorem needs to proof documents.
- [x] Add conservative citation placeholders instead of invented citations.
- [x] Add a citation closure checklist for reviewer/audit readiness.

## Parallel Batch 5: Proof Closure Assumption Tightening

### Task 16: Citation Closure Pass

**Files:**
- Modify: `docs/cryptography/proof-bibliography.md`

- [x] Replace high-confidence citation placeholders with primary or
  authoritative sources for FIPS 204, ACVP ML-DSA vectors, Dilithium design
  background, Fiat-Shamir with aborts, QROM Fiat-Shamir context, dudect, and
  ctgrind.
- [x] Group unresolved threshold-signing, VSS/DKG, commitment, proof-system,
  and side-channel proof citations under an explicit unresolved list instead
  of inventing unsupported references.

### Task 17: Ideal VSS Theorem Route

**Files:**
- Modify: `docs/cryptography/formal-security-theorem.md`
- Modify: `docs/cryptography/vss-idealization-and-selection.md`
- Modify: `docs/cryptography/proof-obligations.md`
- Modify: `docs/cryptography/claims-matrix.md`

- [x] Add `FST-T1-IdealVSS` as an intermediate theorem path under ideal
  `F_VSS_DKG`.
- [x] State that idealization can isolate setup from the signing proof but
  cannot prove production VSS/DKG security.
- [x] Keep production `FST-T1` and `FST-T2` blocked until concrete VSS/DKG and
  real/ideal realization proofs are completed.

### Task 18: Rejection-Sampling Bound Equation

**Files:**
- Modify: `docs/cryptography/rejection-sampling-bounds.md`
- Modify: `docs/cryptography/rejection-sampling-hybrid-proof.md`

- [x] Add the conditional bound
  `Delta_accept <= eps_mask + eps_rej + eps_withhold + eps_ro + eps_commit`.
- [x] Define sub-lemma obligations for mask distribution, aggregate rejection,
  and selective withholding.
- [x] Map H2 through H6 hybrid transitions to the corresponding epsilon terms.

### Task 19: Simulator Advantage Equation

**Files:**
- Modify: `docs/cryptography/simulator-hybrid-reductions.md`
- Modify: `docs/cryptography/real-ideal-simulator.md`

- [x] Add named `eps_*` loss terms for the real/ideal simulator worksheet.
- [x] Tighten S6 to S7 and S7 to S8 transition dependencies.
- [x] Add a theorem-style consolidated `Adv_real_ideal(A,Z)` bound while
  keeping `eps_classify` as an explicit unresolved classifier gap.

## Parallel Batch 6: Proof Gap Closure Routes

### Task 20: Epsilon Closure Routes

**Files:**
- Modify: `docs/cryptography/rejection-sampling-bounds.md`
- Modify: `docs/cryptography/rejection-sampling-hybrid-proof.md`

- [x] Add `epsilon-closure-dependency-graph` linking H1 through H6 proof
  dependencies.
- [x] Add conservative theorem-style closure routes for `eps_mask`,
  `eps_rej`, and `eps_withhold`.
- [x] State acceptance criteria and exact blockers for making each term
  negligible or carrying an explicit symbolic bound.

### Task 21: Contribution Soundness Relation Target

**Files:**
- Create: `docs/cryptography/contribution-soundness-relation.md`
- Modify: `docs/cryptography/proof-obligations.md`
- Modify: `docs/cryptography/claims-matrix.md`
- Modify: `docs/cryptography/proof-implementation-crosswalk.md`

- [x] Define the production public statement, witness relation, soundness game,
  extraction target, witness-hiding/simulation target, context-binding
  requirements, and non-claims.
- [x] Link the worksheet into the proof obligation, claims, and crosswalk
  surfaces while preserving scaffold-only status for current contribution
  proofs.

### Task 22: Unauthorized Output Classifier Route

**Files:**
- Modify: `docs/cryptography/simulator-hybrid-reductions.md`

- [x] Decompose `eps_classify` into named classifier cases.
- [x] Add totality and disjointness obligations for mapping every unauthorized
  accepting output to a base ML-DSA forgery or named threshold-side assumption
  violation.
- [x] Keep `eps_cls_unmapped` explicit until a production verification grammar
  proves no accepting output remains unclassified.

### Task 23: Manifest Integration

**Files:**
- Modify: `tests/proof_documentation_manifest.rs`

- [x] Add the contribution soundness worksheet to the required proof document
  manifest.
- [x] Add stable anchors for epsilon closure routes and unauthorized-output
  classifier obligations.

## Parallel Batch 7: `eps_rej` Predicate Equivalence Route

### Task 24: Rejection Predicate Code Audit

**Files:**
- Read-only audit of `src/low_level/mldsa65.rs`
- Read-only audit of hazmat tests

- [x] Map threshold finalization checks for `z`, low bits, `ct0`, hints,
  challenge sampling, signature packing, standard verification, and active-set
  consistency to current code and tests.
- [x] Identify missing boundary coverage for low-bit, `ct0`, active-set, and
  byte-level equivalence proofs.

### Task 25: Rejection Predicate Equivalence Worksheet

**Files:**
- Create: `docs/cryptography/rejection-predicate-equivalence.md`
- Modify: `docs/cryptography/rejection-sampling-bounds.md`
- Modify: `docs/cryptography/rejection-sampling-hybrid-proof.md`
- Modify: `docs/cryptography/proof-obligations.md`

## Parallel Batch 8: `eps_mask` and `eps_withhold` Route Decomposition

### Task 27: Mask Distribution Equivalence Worksheet

**Files:**
- Create: `docs/cryptography/mask-distribution-equivalence.md`
- Modify: `docs/cryptography/rejection-sampling-bounds.md`
- Modify: `docs/cryptography/rejection-sampling-hybrid-proof.md`
- Modify: `docs/cryptography/proof-obligations.md`
- Modify: `docs/cryptography/proof-implementation-crosswalk.md`
- Modify: `docs/cryptography/claims-matrix.md`

- [x] Promote the `eps_mask` closure route into a dedicated worksheet with a
  theorem target, candidate protocol families, bad-event decomposition, code
  crosswalk, acceptance criteria, and non-claims.
- [x] Keep the route explicitly open until a production mask-generation family
  is selected and proven against centralized ML-DSA-65 mask sampling.

### Task 28: Withholding and Abort Bound Worksheet

**Files:**
- Create: `docs/cryptography/withholding-abort-bound.md`
- Modify: `docs/cryptography/rejection-sampling-bounds.md`
- Modify: `docs/cryptography/rejection-sampling-hybrid-proof.md`
- Modify: `docs/cryptography/proof-obligations.md`
- Modify: `docs/cryptography/proof-implementation-crosswalk.md`
- Modify: `docs/cryptography/claims-matrix.md`

- [x] Promote the `eps_withhold` closure route into a dedicated worksheet with
  a simulator target, abort-observable taxonomy, symbolic decomposition, code
  crosswalk, acceptance criteria, and non-claims.
- [x] Keep liveness/availability separate from accepted-signature
  distribution, and prevent withholding from absorbing `eps_mask` or
  `eps_rej` gaps.

### Task 29: Manifest Integration for Route Worksheets

**Files:**
- Modify: `tests/proof_documentation_manifest.rs`

- [x] Add stable anchors for the mask-distribution and withholding-abort
  worksheets to the required proof document manifest.

## Parallel Batch 9: Contribution Backend and Classifier Routes

### Task 30: Contribution Backend Instantiation Route

**Files:**
- Create: `docs/cryptography/contribution-backend-instantiation.md`
- Modify: `docs/cryptography/contribution-soundness-relation.md`
- Modify: `docs/cryptography/proof-obligations.md`
- Modify: `docs/cryptography/proof-implementation-crosswalk.md`
- Modify: `docs/cryptography/claims-matrix.md`

- [x] Add a backend declaration target, backend-family split, theorem target,
  epsilon accounting, acceptance criteria, code crosswalk, and non-claims for
  `eps_contrib`.
- [x] Preserve the boundary that transcript-hash proofs and backend
  declarations are not production contribution soundness.

### Task 31: Unauthorized Output Classifier Closure Route

**Files:**
- Create: `docs/cryptography/unauthorized-output-classifier-closure.md`
- Modify: `docs/cryptography/simulator-hybrid-reductions.md`
- Modify: `docs/cryptography/formal-security-theorem.md`
- Modify: `docs/cryptography/ideal-functionality.md`
- Modify: `docs/cryptography/proof-obligations.md`
- Modify: `docs/cryptography/proof-implementation-crosswalk.md`
- Modify: `docs/cryptography/claims-matrix.md`

- [x] Add a classifier input tuple, ordered case grammar, totality and
  disjointness targets, reduction map, acceptance criteria, and non-claims for
  eliminating `eps_cls_unmapped`.
- [x] Keep `eps_classify` open until the production verifier grammar and
  per-case reductions prove `eps_cls_unmapped = 0`.

### Task 32: Manifest Integration for Backend and Classifier Routes

**Files:**
- Modify: `tests/proof_documentation_manifest.rs`

- [x] Add stable anchors for contribution backend instantiation and
  unauthorized-output classifier closure routes.
- Modify: `docs/cryptography/claims-matrix.md`
- Modify: `docs/cryptography/proof-implementation-crosswalk.md`

- [x] Add the `rpe-theorem-target` for `Reject_T = Reject_0` on the same
  reconstructed candidate except named bad events.
- [x] Add `rpe-predicate-map`, `rpe-bad-events`, `rpe-code-fips-crosswalk`,
  and `rpe-non-claims`.
- [x] Link the worksheet into the rejection-sampling, claims, proof
  obligation, and crosswalk surfaces without claiming `eps_rej` is closed.

### Task 26: Hazmat Rejection Boundary Tests

**Files:**
- Modify: `tests/hazmat_mldsa65.rs`

- [x] Add `z` exact-bound and verifier-boundary tests.
- [x] Add hint weight at `omega`, weight above `omega`, and noncanonical hint
  decoding tests.
- [x] Keep remaining low-bit, `ct0`, and active-set exact-bound coverage as
  open work unless a future harness makes those candidates easy to construct.

### Task 27: Manifest Integration

**Files:**
- Modify: `tests/proof_documentation_manifest.rs`

- [x] Add `rejection-predicate-equivalence.md` to the required proof document
  manifest.
- [x] Add stable anchors for the new `rpe-*` sections and crosswalk row.
