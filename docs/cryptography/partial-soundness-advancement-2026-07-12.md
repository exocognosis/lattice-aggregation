# Criterion 4 Advancement — Partial Contribution Soundness

Status: `partially_met` (unchanged). This document records one increment of
executable evidence for the SOUNDNESS leg of Criterion 4,
`partial_contribution_soundness`. It does not promote the criterion, does not
change the overall `partially_proven` verdict, and does not flip any closure,
`claims_*`, or `production_approved` flag.

Date: 2026-07-12

## Criterion Chosen and Why It Is Fork-Independent

The five hypothesis criteria are:

1. `aggregate_mask_distribution` — BLOCKED behind the unresolved `epsilon_mask`
   fork.
2. `aggregate_rejection_equivalence` — BLOCKED behind the same `epsilon_mask`
   fork (accepted-output distribution vs centralized ML-DSA-65).
3. `abort_retry_bias`.
4. `partial_contribution_soundness` — **chosen**.
5. `unauthorized_aggregate_reduction`.

This increment advances **Criterion 4**. It is the most legitimately
advanceable criterion this turn with *real* (not simulated) executable checks,
and it does not depend on the `epsilon_mask` fork:

- Criteria 1 and 2 are the two forks explicitly gated on the aggregate
  mask-distribution / rejection-distribution decision. They are off-limits.
- Criterion 4 is about **local partial-share validity**: whether each accepted
  partial response is well-formed against its own share, mask, and challenge,
  and whether it satisfies the per-partial acceptance bound. That decision is a
  function of one partial's own algebraic relation (`z_i = y_i + c · s1_i` over
  `R_q^L`) and its centered infinity norm (`‖z_i‖_∞ < γ₁ − β`). It is decided
  *before* and *independently of* how aggregate masks are distributed, so it
  needs no `epsilon_mask` value to evaluate.
- The only place `epsilon_mask` appears anywhere near this criterion's surface
  is the caller-supplied `LeakageLimits.epsilon_mask` **budget ceiling** in
  `src/production/partial_soundness.rs`. That is a comparison against a
  caller-chosen bound, not the fork decision, and the new gate added here does
  not read, set, or depend on it.
- Stack B already contains genuine module-vector partial arithmetic
  (`src/backend/module_partial.rs`), so Criterion 4 can be advanced with real
  ring math rather than more digest plumbing. Criteria 3 and 5, by contrast,
  are closer to distribution/proof-manifest work whose real content is
  out-of-band.

## What Evidence Now Exists (New This Increment)

### 1. A real local partial-share validity gate (library code)

`src/backend/module_partial.rs` gains:

- `ModulePartialLocalValidity` — a typed result carrying the checked signer,
  evaluation point, the centered infinity norm of the response, and a SHA3-256
  `local_validity_digest` minted only after the checks below pass.
- `verify_module_partial_local_validity(partial, opened_y_i, opened_s1_i, c)` —
  recomputes `z_i = y_i + c · s1_i` over `R_q^L` using the repository's
  negacyclic ring arithmetic (`compute_z`), compares it to the claimed response
  under canonical `R_q` equality, and enforces the ML-DSA-65 acceptance bound
  `‖z_i‖_∞ < γ₁ − β` (`Z_BOUND`, i.e. `2^19 − 196`).

The gate rejects, with typed `ThresholdError` values, four **real** fault
classes (all covered by tests):

| Fault injected | Real cause modeled | Rejection |
| --- | --- | --- |
| One response coefficient flipped | tampered / malformed partial | `PartialShareVerificationFailed` |
| Verified against a different challenge | stale, cross-context, or rebound challenge | `PartialShareVerificationFailed` |
| A different signer's opened share/mask | share not bound to `(signer)` | `PartialShareVerificationFailed` |
| A coefficient just under `γ₁` (relation still holds) | out-of-bound response | `RejectionSamplingFailed` |

The algebraic-relation check runs before the norm check, so a response that is
both mis-formed and out of bound is reported as a verification failure.

### 2. Executable tests

- Unit tests in `src/backend/module_partial.rs`
  (`local_validity_gate_accepts_honest_partial_and_rebinds_a_real_digest`,
  `local_validity_gate_rejects_out_of_bound_response`).
- Integration test `tests/partial_soundness_real_local_verifier.rs` (gated on
  `production-mldsa65-coordinator`, which enables both Stack B's real partials
  and the coordinator-assisted evidence surface): honest accept, the four fault
  rejections above, digest determinism, and a binding test.

### 3. Binding to the existing criterion-4 evidence surface

The binding test shows the gate's **real** `local_validity_digest` flowing into
the typed `PartialContributionSoundnessEvidence` surface as the
`local_bounds_proof_digest`. This is stronger than the previous state, where
that slot held an opaque digest never checked against any arithmetic. Crucially,
the test then asserts the honest boundary: the typed surface still classifies
the evidence as `EvidenceClass::ScaffoldDigestOnly` /
`PartialSoundnessClosureStatus::ConformanceOnly`, and a
`PartialEvidenceRequirement::ProofBackedOnly` check **rejects** it. Real
soundness arithmetic is not, and is not presented as, proof-backed hiding
evidence.

## What Criterion 4 Still Requires for Closure (Out of Band)

This increment closes none of the following. Each is out of band for repository
code alone and is required before Criterion 4 can be reviewed as `met`:

1. **Zero-knowledge / hiding.** The gate consumes `y_i` and `s1_i` in the clear.
   A production partial verifier must check correct formation **without** seeing
   the secret share or one-time mask. That is the `ProofBacked` local verifier
   (a reviewed ZK proof system) that `src/production/partial_soundness.rs` still
   only accepts as a digest label. Until it is fed by an audited proof verifier,
   the hiding/leakage obligation is open.
2. **Real DKG-produced shares and CAVP-identical expanders.** The module-vector
   expanders are domain-separated SHAKE256 research expanders sized for
   ML-DSA-65; they are not claimed bit-identical to FIPS 204
   `ExpandS`/`ExpandMask`, and the shares here are not produced by a
   malicious-secure DKG.
3. **VSS/DKG binding proof and formal leakage model.** The closure-package
   digests in `PartialSoundnessClosurePackage`
   (`vss_dkg_binding_proof_digest`, `hiding_leakage_proof_digest`,
   `audited_local_verifier_digest`, `external_review_digest`) remain
   placeholders identifying required artifacts, not validated proofs.
4. **Aggregate-path enforcement.** Accepted-partial soundness evidence is not
   yet required on every aggregate acceptance path.
5. **External cryptographic review** of the local verifier soundness, leakage
   model, and simulator obligations referenced by
   `docs/cryptography/noise-rejection-proof-plan.md` and
   `docs/cryptography/partial-soundness-evidence.md`.

## Why This Does NOT Constitute "Met"

Per `docs/cryptography/hypothesis-outcome-taxonomy.md`, a criterion is `met`
only when implementation evidence, proof artifacts, validation/backend
artifacts, claim-boundary documentation, **and** external review all point at
the same assumption set. This increment supplies executable **soundness**
evidence (real algebraic-relation and norm-bound checking with genuine
fault rejection) — a strengthening of the implementation-evidence leg only. The
hiding proof, VSS/DKG binding proof, formal leakage model, and external review
remain open, and the gate is explicitly non-zero-knowledge.

Accordingly:

- Criterion 4 stays `partially_met`.
- The overall verdict stays `partially_proven`.
- No closure flag, `claims_*` boolean, or `production_approved` boolean was
  flipped; no machine-readable proof-payload or assessment artifact was
  promoted.

The safe claim boundary for this work is: *the repository can now execute a real
local partial-share validity check over Stack B module-vector partials and
reject genuine malformed, mis-challenged, mis-bound, and out-of-bound partials,
and can bind that real check into the criterion-4 evidence surface as
digest-only scaffold evidence.* It is not a claim of production partial
verification, hiding, extractability, or local acceptance soundness.

## Files Touched

- `src/backend/module_partial.rs` — new `ModulePartialLocalValidity`,
  `verify_module_partial_local_validity`, `module_partial_validity_digest`, and
  two unit tests.
- `tests/partial_soundness_real_local_verifier.rs` — new integration test
  (honest accept, four fault rejections, digest determinism, typed-evidence
  binding with the honest boundary asserted).
- `docs/cryptography/partial-soundness-advancement-2026-07-12.md` — this note.

## Verification

- `cargo test --features production-mldsa65-coordinator --test partial_soundness_real_local_verifier` — 6 passed.
- `cargo test --features raw-real-mldsa --lib backend::module_partial` — 5 passed.
- `cargo test --all-features` — all binaries `0 failed`.
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
