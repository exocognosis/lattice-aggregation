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

- [ ] Replace the Feldman map with an Ajtai/BDLOP commitment `C = A r + [msg]`
  with short randomness `r`, giving computational hiding + binding under a
  stated module-SIS assumption with selected parameters.
- [ ] Encrypted per-receiver shares + per-share validity proofs (checklist 2).

### Increment 3: Module structure and the ML-DSA key relation

- [ ] Lift from single `Poly` to module vectors `s1 in R_q^l`, `s2 in R_q^k`
  with `eta`-bounded sampling, matrix `A = ExpandA(rho)`, and the key relation
  `t = A s1 + s2`, so the shared object is a real ML-DSA-65 secret key.

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
