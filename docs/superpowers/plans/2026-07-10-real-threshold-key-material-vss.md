# Real Threshold Key Material (VSS/DKG) Implementation Plan

> **For agentic workers:** implement task-by-task. Steps use checkbox (`- [ ]`)
> syntax for tracking. This plan builds backend requirement class **#1
> (threshold key material)** from the core backend requirements ledger.

**Goal:** Replace the deterministic VSS/DKG scaffold (`src/crypto/vss.rs` toy
masks; `src/dkg.rs` hash-derived commitments) with a real, verifiable secret
sharing and distributed key generation construction over
`R_q = Z_q[X]/(X^256 + 1)` that produces a threshold ML-DSA-65 key with **no
single party ever holding the full secret key**.

**Claim boundary (unchanged by this plan until every increment closes):** this
work delivers *correct and verifiable* secret-sharing arithmetic. It does not by
itself close any hypothesis criterion, does not claim malicious-secure DKG, and
does not claim production threshold ML-DSA security. Each increment documents
exactly which security property it does and does not provide.

**Design reference:** `docs/cryptography/vss-dkg-security-plan.md` (Production
Replacement Checklist items 1–10).

**Tech stack:** Rust, `src/low_level/poly.rs`, `src/crypto/`, `sha3` (already a
dependency). No new crates.

---

### Increment 1: Real ring arithmetic + CSPRNG-seeded verifiable VSS

Satisfies checklist item 1 (CSPRNG-sampled degree-`< tau` sharing polynomials)
and part of item 2 (typed coefficient commitments + verifiable shares).

**Files:**
- Modify: `src/low_level/poly.rs`
- Create: `src/crypto/vss_real.rs`
- Modify: `src/crypto.rs`

- [x] Add negacyclic (`mod X^256 + 1`) schoolbook multiplication, subtraction,
  integer-scalar multiplication, and canonical reduction to `Poly`, with
  property tests (`X^256 = -1`, distributivity, commutativity, identity).
- [x] Add SHAKE256 rejection-sampling of uniform `R_q` elements from a
  domain-separated seed (FIPS 204 style: 23-bit candidates, reject `>= Q`).
- [x] Implement `deal_secret`: sample non-constant coefficients from a dealer
  seed (CSPRNG-modeled), evaluate shares at receiver indices, emit
  Feldman-style coefficient commitments `C_j = g * c_j`.
- [x] Implement `verify_share`: homomorphic check `g * P(i) == sum_j C_j * i^j`.
- [x] Implement `reconstruct` over `>= tau` verified shares (reuse
  `crypto::interpolation`).
- [x] Tests: reconstruction correctness, subset-agreement, tampered-share
  rejection, sub-threshold non-recovery, parameter validation.
- [x] Document the property gap: perfectly binding relative to `g` (invertible
  w.h.p.), **not hiding** — a module-SIS (Ajtai/BDLOP) hiding commitment is
  Increment 2.

### Increment 2: Hiding commitment (module-SIS / BDLOP)

- [x] Replace the Feldman map with a BDLOP module-lattice commitment
  (`C = (A1 r, <a2,r> + m)`, short `r`) in `src/crypto/bdlop.rs`, giving
  computational hiding under a stated Module-LWE assumption and MSIS-binding for
  short openings (`verify_opening`). Parameters `KAPPA=4`, `K=12`, ternary
  randomness are a chosen set pending lattice-estimator validation.
- [x] Module-lattice arithmetic + sampling in `src/crypto/module_lattice.rs`.
- [x] Hiding verifiable secret sharing (`src/crypto/vss_bdlop.rs`) with
  homomorphic share verification, replacing the leaky Feldman path for hiding.
- [x] Adversarial review (implementation + design subagents); fixes applied for
  `i32::MIN` norm-check overflow, non-canonical aggregated randomness, and
  non-canonical opening comparison. Binding/hiding claims reworded to match what
  the code enforces.

**Honesty note (from review):** `verify_share` enforces no norm bound on the
aggregated randomness (which is legitimately non-short), so it provides
homomorphic consistency, not malicious-dealer binding. This is documented in the
module and captured by `verify_share_does_not_enforce_randomness_shortness`.

### Increment 2b: Malicious-dealer binding + encrypted transport

- [ ] Per-share validity proofs: a relaxed-norm opening bound
  `beta ~ sum_j i^j` on `rho(i)` reducing share-binding to `MSIS_{2 beta}`,
  giving malicious-dealer binding and extractability (security plan
  Binding/Extractability).
- [ ] Encrypted per-receiver share transport (checklist item 2).

### Increment 3: Module structure and the ML-DSA key relation

- [x] `src/crypto/mldsa_module.rs`: lift from single `Poly` to ML-DSA-65 module
  vectors `s1 in R_q^L` (L=5), `s2 in R_q^K` (K=6), with `eta=4` sampling
  (FIPS 204 RejBoundedPoly distribution), matrix `A` expanded from `rho`, and the
  key relation `t = A s1 + s2`.
- [x] Threshold sharing of the whole secret key: each of the `L + K` component
  polynomials is dealt with the hiding VSS (`vss_bdlop`) under a
  component-separated seed; `verify` / `reconstruct` recover the key and confirm
  the public `t` recomputes.
- [x] Adversarial review (subagent); fixes applied for a fail-closed
  `reconstruct` (rejects duplicate/unknown/insufficient index sets rather than
  returning a silently-wrong key) and a non-canonical `t`.

**Claim boundary:** `A` is uniform over `R_q` (byte-exact FIPS 204 `ExpandA`
deferred); the `eta` distribution is FIPS-correct but not asserted bit-identical
to `ExpandS`; `Power2Round` (t1/t0) and public-key encoding are deferred. So this
is the ML-DSA-65 module key *structure and relation*, not a wire-format FIPS 204
key. Multi-dealer DKG is Increment 4; malicious-dealer binding is the inherited
Increment 2b gap.

### Increment 4: DKG state machine

- [x] `src/crypto/mldsa_dkg.rs`: multi-dealer DKG. Each dealer VSS-shares an
  independent random contribution and publishes `t^(d) = A s1^(d) + s2^(d)`;
  `finalize` accepts dealers whose shares all verify (complaint rule), sums the
  accepted contributions into the joint key, and derives per-validator shares by
  homomorphic aggregation (`mldsa_module::aggregate`). Deterministic, id-sorted
  accepted-dealer set (output agreement); joint shares verify against summed
  commitments; reconstruction from `>= threshold` shares recomputes the joint
  `t`.
- [x] Adversarial review (subagent): confirmed the aggregation homomorphism,
  determinism, seed separation, and panic/overflow safety. Fixed two honesty
  over-claims (secrecy scoped to sub-threshold *validator* coalitions since
  shares are unencrypted here; commit digest labelled computable-but-inert).

**Deferred (Increment 5 / 2b):** complaint *adjudication* with public evidence,
binding `t^(d)` to the VSS commitments (Increment 2b validity proofs), rushing /
last-mover key-bias resistance, and encrypted per-receiver share transport. This
is an honest-but-verifiable DKG, not yet malicious-secure.

### Increment 5: Key-bias resistance, evidence, negative tests

- [x] `src/crypto/mldsa_dkg.rs`: committing round + public fault evidence.
  `DkgCoordinator::contribution_digest` is a session-bound commit digest (folds
  `rho`, threshold, validator count, dealer id, `t^(d)`, and the VSS commitment
  digest); `collect_commitments` freezes an id-sorted, dedup'd commit vector
  (round 1); `finalize_with_evidence` (round 2) opens each commit and emits a
  [`DealerFault`] per excluded committed dealer, with a deterministic id-ordered
  accepted set and a `transcript_digest` binding the round. `verify_fault`
  re-checks any fault from public state only (anti-framing), and the original
  one-shot `finalize` is retained for back-compat.
- [x] Fault classes are restricted to the publicly *recomputable* ones —
  `CommitMismatch`, `InvalidShareRelation`, `InvalidCommitmentProof`
  (`DealerFaultClass`) — with an over-claim guard test. No `DealerEquivocation`
  class exists: proving equivocation-across-receivers needs signed dealer frames
  this synchronous in-memory model does not have.
- [x] Negative / property tests: anti-framing (no forged fault verifies against an
  honest dealer), order-independent acceptance, commit-binding rejects a
  post-commit swap, genuine bad share/proof yield a re-verifiable fault,
  verifier uses no private state, missing reveal is exclusion-not-fault,
  transcript-digest binds the outcome.

**Honest boundary (this increment does *not* reach malicious security):** the
fault records are **diagnostic, not slashing-grade** (no signed frames ⇒ not
cryptographically attributable to a dealer key); the commit round stops
**adaptive-choice** bias but **not last-mover abort** bias (a final dealer can
still abort after seeing others' reveals); a **missing reveal is a silent
exclusion, not a fault**; and binding `t^(d)` to the VSS commitments plus
encrypted per-receiver transport remain deferred (Increment 2b). It closes no
hypothesis criterion.

---

**Verification per increment:** `cargo test`, `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features -- -D warnings`.
