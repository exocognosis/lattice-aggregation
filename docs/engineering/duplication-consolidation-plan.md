# Duplication consolidation plan (Roadmap Item 5)

**Status:** MAP + PLAN only. No source file is modified by this document, and the
consolidation is **not** executed. Consolidating the wrong primitive would retire
merged, reviewed work, so every unification below is gated behind an explicit,
behavior-preserving test.

**Scope:** the four primitive families named in the roadmap item — `SampleInBall`,
`Decompose`/`HighBits`/`LowBits`/`Power2Round`, `NTT`/`inverse-NTT`, and Shamir
secret sharing / Lagrange interpolation / share reconstruction — across the two
stacks:

- **Stack A** (`src/crypto/` + `src/low_level/`) — always compiled, the
  distributed VSS/DKG path. Coefficients are carried **centered** (`{-1, 0, +1}`,
  `r0 ∈ (-α/2, α/2]`). Internal `R_q` multiply uses a **non-FIPS-ordered** NTT.
- **Stack B** (`src/backend/`, feature `raw-real-mldsa`) — the coordinator-assisted
  FIPS-wire path. Coefficients are carried **canonical** (`[0, Q)`, `-1` as `Q-1`).
  Its `fips_sign` NTT is **FIPS-ordered** so the public key / NTT-domain wire bytes
  are byte-equal to the `ml-dsa` crate.

Both stacks store polynomials in the **same** underlying type
`low_level::poly::Poly` (`{ coeffs: [i32; 256] }`); `crypto::poly::Poly` is a
re-export of it (`src/crypto.rs:7-9`). The `[u32]` that the roadmap note refers to
is an **internal NTT intermediate** inside `fips_sign` (its `ntt()` returns
`[u32; N]`), not a distinct `Poly` type. The load-bearing split is therefore a
**coefficient-representation convention** (centered vs canonical) plus the
**FIPS transform ordering**, not two different container types.

---

## 1. What was actually found vs the memory estimate

| Primitive family | Memory estimate | Actual distinct implementations found |
|---|---|---|
| SampleInBall | ×3 | **3** (2 of them byte-identical) |
| Decompose family (decompose/high/low/power2round) | ×2 | **2** (HighBits identical; LowBits differ only by representation) |
| NTT / inverse-NTT | ×2 | **2** (genuinely divergent — FIPS ordering) |
| Shamir / Lagrange / reconstruction | ×5 | **5 Shamir-split sites**, plus a Lagrange-coefficient kernel duplicated **4×** (1 shared `i32` + 2 byte-identical `u64` + 1 specialized), a share-reconstruction kernel already unified (1 shared + 4 thin wrappers), 2 byte-seed reconstructors, and a Horner poly-eval kernel copied **8×** |

The memory's "Shamir ×5" is exactly the count of **secret-splitting** call sites; the
Lagrange/reconstruct/eval sub-primitives underneath fan out further than the estimate.

---

## 2. Master table

Columns: **primitive | locations (file:line) | domain | divergence | classification | action**

### 2a. SampleInBall

| primitive | locations (file:line) | domain | divergence | classification | action |
|---|---|---|---|---|---|
| SampleInBall (Stack A) | `src/crypto/mldsa_primitives.rs:111` `sample_in_ball(seed)` | `Poly[i32]`, **centered** `{-1,+1}`, τ=49 fixed | Same SHAKE256 stream + inside-out shuffle as Stack B; **differs only in the representation of −1** (centered `-1` vs canonical `Q-1`). Signature omits `tau`. | **SAFE-TO-UNIFY (mod representation)** — semantically equal mod Q | Migrate to a shared core returning canonical coeffs, wrap with a centered adapter. Medium priority. |
| SampleInBall (Stack B, module) | `src/backend/module_partial.rs:138` `sample_in_ball(rho, tau)` | `Poly[i32]`, **canonical** `{1,Q-1}` | — (reference for the pair below) | **SAFE-TO-UNIFY** | Keep as the canonical shared impl; delete the `fips_sign` twin. |
| SampleInBall (Stack B, fips_sign) | `src/backend/fips_sign.rs:740` `sample_in_ball_poly(rho, tau)` | `Poly[i32]`, **canonical** `{1,Q-1}` | **Byte-for-byte identical** to `module_partial::sample_in_ball` (same body, same XOF sign-bit indexing `s[(i+τ-256)/8] >> ((i+τ-256)%8)`). | **SAFE-TO-UNIFY (identical)** | **Highest-value / lowest-risk unify.** Replace with `module_partial::sample_in_ball`. |

Verified equivalence detail: all three read the same 8 sign-bytes then run the same
`(256-τ)..256` Fisher–Yates rejection shuffle over the same XOF byte stream. The
sign-bit consumption order is identical (LSB-first, sequential). The only difference
across the three is whether a `−1` coefficient is stored as centered `-1` (Stack A)
or canonical `Q-1` (Stack B). Because arithmetic canonicalizes mod Q, the three
produce congruent challenge polynomials.

### 2b. Decompose family

| primitive | locations (file:line) | domain | divergence | classification | action |
|---|---|---|---|---|---|
| Decompose / HighBits / LowBits / Power2Round (Stack A) | `src/crypto/mldsa_primitives.rs:65` `power2round`, `:75` `decompose`, `:90` `high_bits`, `:95` `low_bits`, `:100` `high_bits_poly` | scalar/`Poly[i32]`, **centered** low bits (`mod_pm`) | HighBits identical to Stack B; **LowBits kept centered** (`r0 ∈ (-α/2, α/2]`). No `make_hint`. | **SAFE-TO-UNIFY (HighBits) / representation-divergent (LowBits)** | Extract a shared `decompose` core; expose centered vs canonical `low_bits` via thin wrappers. Medium priority. |
| Decompose / HighBits / LowBits / Power2Round + MakeHint (Stack B) | `src/backend/fips_sign.rs:669` `decompose`, `:684` `high_bits_poly`, `:692` `low_bits_poly`, `:700` `power2round_poly`, `:731` `make_hint` | scalar/`Poly[i32]` with `[u32]` field ops, **canonical** low bits (`to_can(...)`) | Same boundary correction (`diff == Q-1 → r1=0`) and same HighBits as Stack A; **LowBits canonicalized** to `[0,Q)`. Adds `make_hint` (Stack A has none). | **SAFE-TO-UNIFY (core) — representation is the ε_mask boundary** | Unify the decompose core; keep the canonical `low_bits_poly`/`make_hint` as Stack-B wrappers. |

The centered-vs-canonical LowBits split **is** the ε_mask stack boundary: the
distributed stack composes centered residuals into the mask budget, the wire stack
must emit canonical `[0,Q)` bytes. Congruent mod Q; not interchangeable at the byte
level.

### 2c. NTT / inverse-NTT — **LOAD-BEARING, LEAVE DUPLICATED**

| primitive | locations (file:line) | domain | divergence | classification | action |
|---|---|---|---|---|---|
| Forward/inverse NTT + NTT multiply (Stack A) | `src/low_level/ntt.rs:48` `ntt`, `:70` `inv_ntt`, `:100` `ntt_mul` (root `ZETA=1753`, `:21`) | `[i32;N]`, `i64` modular arithmetic | Runtime-built twiddle table `ζ^bitrev8(i)`; Cooley–Tukey forward + Gentleman–Sande inverse. **Butterfly/coefficient ordering is self-consistent but explicitly NOT FIPS-ordered** (`src/low_level/ntt.rs:12-14`). Only ever used **inside `ntt_mul`**, fully round-tripped, so the ordering is invisible to callers. | **LOAD-BEARING** | **Leave duplicated.** |
| Forward/inverse NTT + pointwise (Stack B) | `src/backend/fips_sign.rs:524` `ntt`, `:551` `ntt_inverse`, `:582` `ntt_pointwise`, table `ZETA_POW_BITREV` (`:52`) | `[u32;N]` field arithmetic | Precomputed **FIPS 204 / `ml-dsa` zeta table** with the FIPS BitRev8 layer order. Emits NTT-domain `t1`/`w1` bytes that must be **byte-equal to the `ml-dsa` crate**. | **LOAD-BEARING (FIPS byte-ordering)** | **Leave duplicated.** |

Why not unify: the two are both correct negacyclic NTTs over the same ring but at
**different transform-boundary orderings**. Stack B's ordering is dictated by FIPS
204 wire interop and is pinned by KAT-level gates; Stack A's ordering is a private
implementation detail that only has to round-trip. A single shared NTT would have to
adopt the FIPS ordering for both — a change that risks silently corrupting either
Stack A's `R_q` products or Stack B's wire bytes. This is exactly the "consolidating
wrong retires reviewed work" hazard; do not merge.

### 2d. Shamir / Lagrange / reconstruction

| primitive | locations (file:line) | domain | divergence | classification | action |
|---|---|---|---|---|---|
| Lagrange coeff @ 0 (shared scaffold) | `src/crypto/interpolation.rs:33` `compute_lagrange_coefficient` (+ `:13` `modular_inverse`) | `i32` over Q, general `xs` | Canonical shared impl. Consumers: `fips_wire.rs:212`, `algebraic_partial.rs:158`, `module_partial.rs:267,337`. | **SHARED (target module)** | Keep. Make it the single home. |
| Lagrange coeff @ 0 (feldman) | `src/crypto/feldman_vss.rs:345` `lagrange_at_zero` | `u64` over Q, general `xs` | **Byte-identical** to `backend/real.rs` twin. | **SAFE-TO-UNIFY** | Fold into `interpolation` (add a `u64` variant or reuse the `i32` one). |
| Lagrange coeff @ 0 (real backend) | `src/backend/real.rs:553` `lagrange_at_zero` | `u64` over Q, general `xs` | **Byte-identical** to feldman twin. | **SAFE-TO-UNIFY** | Same target. |
| Lagrange coeffs @ 0 (P1 binary) | `src/bin/threshold_backend_p1.rs:1874` `lagrange_coefficients_at_zero` | `u64` over Q, **consecutive points x=1..t** | Different algorithm: combinatorial recurrence assuming consecutive evaluation points; returns full vector. Lives in a `bin/` (separate crate target). | **LOAD-BEARING (specialized) / low-priority** | Leave, or optionally expose the lib kernel to the binary later. Flag as leave-for-now. |
| Reconstruct secret Poly @ 0 (shared) | `src/crypto/interpolation.rs:54` `reconstruct_secret_poly` | `Poly[i32]` over Q | Canonical shared impl. | **SHARED** | Keep. |
| ↳ wrapper | `src/backend/algebraic_partial.rs:234` `reconstruct_secret_poly` | delegates → interpolation | thin wrapper | **ALREADY UNIFIED** | No action. |
| ↳ wrapper | `src/crypto/vss_real.rs:166` `reconstruct` | delegates → interpolation | thin wrapper | **ALREADY UNIFIED** | No action. |
| ↳ wrapper | `src/crypto/vss_bdlop.rs:197` `reconstruct` | delegates → interpolation | thin wrapper | **ALREADY UNIFIED** | No action. |
| ↳ wrapper | `src/crypto/mldsa_module.rs:456` `reconstruct_components` | per-component → `vss_bdlop::reconstruct` | thin wrapper | **ALREADY UNIFIED** | No action. |
| Reconstruct byte-seed secret | `src/crypto/feldman_vss.rs:277` `reconstruct_secret` ([u8;32]) | per-byte `u64` over Q | Same per-byte Lagrange loop as `real.rs`. | **SAFE-TO-UNIFY** | Share the per-byte reconstruct once the `u64` Lagrange kernel is shared. |
| Reconstruct byte-seed secret | `src/backend/real.rs:469` `reconstruct_seed_from_partials` (POLY_SEED_BYTES) | per-byte `u64` over Q | Near-identical to feldman; adds full-seed short-circuit + x-dedup. | **SAFE-TO-UNIFY (core)** | Share the per-byte core; keep the short-circuit as a Stack-B wrapper. |
| Shamir split — Poly, test fixtures | `src/crypto/vss.rs:48` `split_secret_poly` (+ `:22` `evaluate_polynomial_at`) | `Poly[i32]` over Q | Deterministic mask fixtures (test/research). | **SAFE-TO-UNIFY (eval kernel)** | Share Horner kernel; keep split wrapper. |
| Shamir split — Poly, CSPRNG | `src/crypto/vss_real.rs` `split` (+ `:176` `evaluate_poly`) | `Poly[i32]` over Q | CSPRNG-seeded coeffs; own Horner copy. | **SAFE-TO-UNIFY (eval kernel)** | Share Horner kernel. |
| Shamir split — Poly, hiding/BDLOP | `src/crypto/vss_bdlop.rs` `split` (+ `:224` `evaluate_poly`) | `Poly[i32]` over Q | Adds BDLOP commitments; own Horner copy. | **SAFE-TO-UNIFY (eval kernel)** | Share Horner kernel; keep commitment logic. |
| Shamir split — Poly, algebraic | `src/backend/algebraic_partial.rs:181` `split_secret_poly_shamir` | `Poly[i32]` over Q | Inline Horner; domain-separated `mask_seed`. | **SAFE-TO-UNIFY (eval kernel)** | Share Horner kernel; keep domain tag. |
| Shamir split — module vector | `src/backend/module_partial.rs:182` `split_module_vector_shamir` (+ `:524` `eval_poly_coeffs`) | `ModuleVecL` (L polys) over Q | Splits each of L component polys; domain-separated `mask_seed`. | **SAFE-TO-UNIFY (eval kernel)** | Reuse the shared per-poly kernel across L; keep the module wrapper + domain tag. |
| Byte-domain Horner eval | `src/crypto/feldman_vss.rs:333` `eval_poly` (u64); `src/backend/real.rs:517` `evaluate_seed_share_poly` (u64) | `u64` per-byte | Byte-domain twins. | **SAFE-TO-UNIFY** | Share a `u64` Horner helper. |

**Domain-separation caveat (load-bearing detail):** each split site derives its
higher-degree mask/randomness coefficients under a **distinct SHAKE/SHA3 domain tag**
(e.g. `module_partial.rs:407` `".../module-partial/shamir-mask/v1"`, feldman's
`"feldman-vss-coeff-sample:v1"`). Those domain strings are **intentional** and must
**not** be collapsed — unifying the split sites means sharing the *evaluation kernel*
(Horner over `R_q`) and the *Lagrange kernel*, while each caller keeps its own
domain-separated coefficient derivation.

---

## 3. Classification summary

- **Distinct implementations across the 4 families:** 3 (SampleInBall) + 2 (decompose)
  + 2 (NTT) + [4 Lagrange-coeff + 5 Shamir-split + 2 byte-reconstruct + 8 Horner-eval,
  minus the already-shared reconstruct kernel] — i.e. the Shamir family is the bulk of
  the surface.
- **SAFE-TO-UNIFY:**
  - SampleInBall: the `module_partial`/`fips_sign` pair (identical) + the Stack-A one
    (mod representation).
  - Decompose: the shared core + HighBits (LowBits behind representation wrappers).
  - Lagrange: the two identical `u64` copies (`feldman_vss`, `real`).
  - Byte-seed reconstruct: the `feldman_vss`/`real` pair.
  - Horner eval: all 8 copies behind two kernels (`Poly` over R_q, and `u64` per-byte).
- **LOAD-BEARING / LEAVE DUPLICATED:**
  - **Both NTTs** (FIPS byte-ordering vs internal ordering) — the primary do-not-merge.
  - The **centered vs canonical LowBits/`−1` representation** (the ε_mask boundary) —
    keep as documented thin wrappers over a shared core, never collapse the convention.
  - The **P1 binary's specialized `lagrange_coefficients_at_zero`** (consecutive-point
    recurrence, separate crate target) — leave for now.
  - Per-site **domain-separation tags** in the split functions.
- **ALREADY UNIFIED (no action):** `reconstruct_secret_poly` and its four wrappers
  (`algebraic_partial`, `vss_real`, `vss_bdlop`, `mldsa_module`).

**Highest-value single consolidation:** delete
`backend/fips_sign.rs:740 sample_in_ball_poly` and call
`backend/module_partial.rs:138 sample_in_ball` instead. The two bodies are
byte-identical, both under the `raw-real-mldsa` feature, both on the same
`low_level::poly::Poly`, so the change is provably behavior-preserving and carries the
lowest risk of any item here. (The broadest de-duplication is the 8-copy Horner
eval kernel, but it touches more files and each carries a domain tag; the SampleInBall
pair is the cleanest first move.)

---

## 4. Migration order and verification gates

Each step must be **behavior-preserving**: run the cited property tests **before** and
**after**, byte-for-byte green, with **no test edits** in the same change.

**Step 0 — Baseline.** Record green runs of the full suite in both configurations:
`cargo test` (default / Stack A) and `cargo test --features raw-real-mldsa` (Stack B),
including `tests/validator_10000_standard_verifier_gate.rs` and the ACVP fixture
(`tests/fixtures/acvp_mldsa65_sigver_fips204_sample.json`).

**Step 1 (lowest risk) — SampleInBall, Stack B pair.**
Replace `fips_sign::sample_in_ball_poly` with `module_partial::sample_in_ball`.
- Guarding tests: `module_partial.rs:554 sample_in_ball_has_weight_tau`,
  `fips_sign.rs:871 keygen_public_key_matches_ml_dsa`,
  `fips_sign.rs:884 self_contained_sign_verifies_with_ml_dsa_verifier`,
  `fips_wire.rs:384` (`standard_verifier_accepted`), and the ACVP/verifier gate.
  The ml-dsa verifier acceptance is the byte-equality gate — if the challenge bytes
  drifted, these fail.

**Step 2 — Shamir Horner-eval kernel.**
Extract one `eval_poly_coeffs(&[Poly], x) -> Poly` (R_q) and one `u64` per-byte helper;
point `vss`, `vss_real`, `vss_bdlop`, `algebraic_partial`, `module_partial`,
`feldman_vss`, `real` at them. **Do not touch the per-site domain tags.**
- Guarding tests: `crypto/interpolation.rs:106 test_end_to_end_vss_interpolation_reconstruction`,
  `crypto/vss.rs:80/97`, `feldman_vss.rs:440 deal_reconstruct_round_trip`,
  `module_partial.rs:562 module_partial_algebraic_identity_holds`,
  `algebraic_partial` round-trip tests (`:297`, `:303`), and `tests/real_backend.rs`.

**Step 3 — Lagrange `u64` kernel + byte-seed reconstruct.**
Fold the identical `feldman_vss::lagrange_at_zero` and `real::lagrange_at_zero` into
`crypto::interpolation` (as a `u64` variant); share the per-byte reconstruct core,
keeping `real`'s full-seed short-circuit and x-dedup as a wrapper.
- Guarding tests: `feldman_vss.rs:440`, the `real` backend reconstruction tests, and
  `tests/threshold_core.rs` / `tests/real_backend.rs`.

**Step 4 (highest risk — do last, or defer) — Decompose/SampleInBall core across
stacks.** Introduce a single `decompose`/`sample_in_ball` core returning canonical
coeffs, and expose Stack A's centered `low_bits`/challenge via a thin `centered_*`
wrapper. Keep `make_hint` in Stack B.
- Guarding tests (both must stay green independently):
  Stack A — `mldsa_primitives.rs:172 decompose_reconstructs_modulo_q`,
  `:185 power2round_reconstructs_modulo_q`, `:196 mod_pm_is_centered`,
  `:206 sample_in_ball_has_weight_tau_and_signs`, `:222 sample_in_ball_is_deterministic`,
  `distributed_nonce.rs:311 high_bits_is_non_linear`.
  Stack B — `fips_sign.rs:871/884`, `fips_wire.rs:384`, ACVP fixture, 10000-validator gate.
- If any centered/canonical wrapper cannot be shown byte-preserving on both sides,
  **abort this step and leave the two implementations duplicated** — the representation
  split is load-bearing.

**Never attempt:** merging the two NTTs (`low_level/ntt.rs` vs
`backend/fips_sign.rs`). Their transform orderings are contractually different
(FIPS wire vs internal). Leave duplicated.

---

## 5. Explicit "leave duplicated" list (do not consolidate)

1. **`low_level::ntt` vs `fips_sign` NTT** — FIPS byte-ordering vs internal ordering.
   Guarded by, respectively, the round-trip/schoolbook tests (`low_level/ntt.rs:178-235`,
   `low_level/poly.rs:221`) and the ml-dsa byte-equality gates. Merging risks retiring
   reviewed wire-interop work.
2. **Centered vs canonical LowBits / `−1` representation** — the ε_mask stack boundary.
   Unify the *core* only; keep centered/canonical as documented wrappers.
3. **`bin/threshold_backend_p1.rs::lagrange_coefficients_at_zero`** — specialized
   consecutive-point recurrence in a separate crate target; low value to share.
4. **Per-split-site domain-separation tags** — security-relevant; must stay distinct.
