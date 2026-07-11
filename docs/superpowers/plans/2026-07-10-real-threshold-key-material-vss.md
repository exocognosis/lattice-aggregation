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

- [ ] Replace `SimulatedDkg` with commit -> share -> complaint -> response ->
  adjudicate -> finalize phases (checklist 3), typed DKG transcript
  (checklist 4), and joint-key derivation with output agreement.

### Increment 5: Key-bias resistance, evidence, negative tests

- [ ] Commit-before-share binding, deterministic accepted-dealer rule, and the
  publicly checkable evidence records (`InvalidDealerShare`,
  `DealerEquivocation`, ...) from the security plan (checklist 6, 10).

---

**Verification per increment:** `cargo test`, `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features -- -D warnings`.
