# ε_mask Fork — Decision Memo (Item 1)

Status: **RATIFIED (direction of work) — 2026-07-12.** Not a criterion closure
and not a thesis change. Date: 2026-07-12.

> **Ratified decision (2026-07-12):** The layered recommendation is adopted as
> the project's direction. (1) Stack B (`src/backend/`, coordinator-assisted) is
> the production / standard-verifier track, reframed honestly as **TEE/HSM
> coordinator seed-reconstruction under a no-export assumption — NOT cryptographic
> no-single-holder**; the "no single party holds the key" claim is restricted to
> Stack A. (2) A **scoped heavy-MPC effort** (small committee, n≈5–20) is the one
> route authorized to actually drive ε_mask→0 while keeping both the standard
> verifier and no-single-holder. (3) Raccoon (option a) is demoted to a documented
> fallback comparator. (4) Open-ended dual-track (option d) is rejected as a
> permanent posture. This adopts a *direction*, not a result: ε_mask remains
> open, C1/C2 remain `partially_met`, and the reframing of Stack B's public
> claims and the heavy-MPC increment plan are follow-on work, not done here.

## Claim boundary (read first)

This memo analyzes a strategic fork and **recommends** a direction. It does
**not** close any of the five hypothesis criteria, does not promote any
criterion beyond `partially_met`, does not change the thesis statement, and does
not claim any security level, standard-verifier compatibility, or
distribution-preservation result. Every "closes", "buys", or "would" below is
conditional on external proof and audit that this repository does not contain.
Nothing here may be cited as evidence that ε_mask is closed. The overall verdict
remains `partially_proven`; all five criteria remain `partially_met`. Ratifying
this memo means adopting a *direction of work*, not asserting a result.

The five tracked criteria (per `scripts/assess_lattice_hypothesis.py`):
`aggregate_mask_distribution` (C1), `aggregate_rejection_equivalence` (C2),
`abort_retry_bias` (C3), `partial_contribution_soundness` (C4),
`unauthorized_aggregate_reduction` (C5).

---

## 1. The ε_mask obstruction, restated with the concrete parameters

### 1.1 Parameters (from code)

ML-DSA-65, as fixed in the crate:

| Symbol | Value | Source |
| --- | --- | --- |
| `N` | 256 | `src/low_level/poly.rs:13` |
| `Q` | 8 380 417 | `src/low_level/poly.rs:15` |
| `γ₁` (`GAMMA1`) | 2¹⁹ = 524 288 | `src/crypto/mldsa_primitives.rs:42` |
| `γ₂` (`GAMMA2`) | (Q−1)/32 = 261 888 | `src/crypto/mldsa_primitives.rs:44` |
| `τ` (`TAU`) | 49 | `src/crypto/mldsa_primitives.rs:46` |
| `η` | 4 | (ML-DSA-65) |
| `β` (`BETA` = τ·η) | 196 | `src/crypto/mldsa_primitives.rs:48` |
| `K`, `L` (module) | 6, 5 | `src/crypto/mldsa_module.rs:46,48` |
| `Z_BOUND` (= γ₁ − β) | 524 092 | `src/backend/module_partial.rs:56` |

The per-signer mask is sampled coefficient-wise **uniform** on `(−γ₁, γ₁]`
(20-bit unpack, `2·γ₁ = 2²⁰`, no rejection) —
`sample_gamma1_poly` / `src/crypto/mldsa_primitives.rs:139–154`, called from
`distributed_nonce::commit` (`src/crypto/distributed_nonce.rs:128–130`).

### 1.2 The centralized (target) behavior

In standard ML-DSA the response is `z = y + c·s1` with a **single**
`y ← ExpandMask` (each coeff uniform on `(−γ₁, γ₁]`) and `‖c·s1‖_∞ ≤ β`. The
verifier accepts only if `‖z‖_∞ < γ₁ − β` (`Z_BOUND`; enforced at
`src/backend/fips_sign.rs:280` and `src/backend/module_partial.rs:238,274`).
Fiat-Shamir-with-aborts **rejection-samples** `y` until `z` lands in the box, and
the accepted `z` is then uniform on that box **and statistically independent of
`s1`**. This independence is the entire hiding argument, and it makes
`ε_mask = 0`.

### 1.3 The distributed (actual) behavior on Stack A

Stack A's no-dealer nonce forms the joint mask as the **plain additive sum**
`y = Σ_{i=1}^{s} y_i` of `s` independent uniform masks (FROST-style; the aggregate
`w = Σ wᵢ` is the image `A·y`, see `distributed_nonce.rs:177–200` and the test
`joint_commitment_is_a_times_joint_mask`, lines 275–289). A sum of `s`
independent uniforms is **not** uniform:

- **Support widens** to `(−s·γ₁, s·γ₁]`; the density is the `s`-fold convolution
  (bell-shaped, Irwin–Hall-like), with per-coefficient standard deviation
  `γ₁·√(s/3)`.
- For the minimal non-trivial case `s = 2`, the per-coefficient law is
  **triangular** on `(−2γ₁, 2γ₁]`, and `P(|coeff| > γ₁) = 1/4`. Over the
  `L·N = 5·256 = 1280` mask coefficients, the probability that **at least one**
  exceeds `γ₁` is `≈ 1 − (3/4)^1280 ≈ 1`. This is exactly what the honesty test
  `aggregate_mask_exceeds_gamma1_epsilon_mask_open`
  (`distributed_nonce.rs:366–388`) pins OPEN.

Two independent, catastrophic consequences follow — both intrinsic, neither a bug:

- **ε_rej (verifier rejection).** With `‖y‖_∞` routinely `> γ₁`, we get
  `‖z‖_∞ > γ₁ − β = 524 092`, so `check_z_bound(Z_BOUND)` fails and the standard
  verifier rejects. You cannot "just rejection-sample" this away: forcing all
  `1280` coefficients into the box has acceptance probability
  `≈ (P_in-box)^{1280} → 0` for `s ≥ 2`.
- **ε_mask (distribution / hiding).** Even conditioned on the rare acceptance,
  the accepted `z` is a **truncated bell**, not the ExpandMask uniform. So the
  accepted response is statistically dependent on the aggregate, the
  `z ⟂ s1` independence that the with-aborts proof needs is lost, and the
  construction leaks about `s1`. `ε_mask ≠ 0`, and it is not small.

### 1.4 The root tension (why this is hard, not just unfinished)

ML-DSA's mask distribution (**uniform + rejection**) is **not additively
homomorphic**: you cannot linearly combine per-party uniform masks and remain
ExpandMask-uniform. Any construction must therefore either (i) make the
aggregate mask *exactly* ExpandMask (requires securely sampling a single uniform
mask no party knows → MPC), or (ii) change the mask distribution to one that
*is* additively friendly, which changes the verifier (Raccoon). This is the
`epsilon_mask` boundary that the two-stack ADR
(`threshold-stack-architecture.md`) names as "the genuinely hard, open research
problem this project studies."

---

## 2. Decision matrix

Scoring is qualitative and **conditional** — no option closes any criterion
without external proof + audit. "Closable" = the option removes the *structural*
obstruction so the criterion *could* be proved; "re-opens/retires" = the option
invalidates or moots a criterion as currently written.

| Dimension | (a) Raccoon-style | (b) Heavy MPC | (c) Adopt Stack B | (d) Status quo / dual-track |
| --- | --- | --- | --- | --- |
| **Which of C1–C5 it moves** | Makes **C1** closable via a Rényi/hint-MLWE bound on a sum-of-Gaussians mask; largely **dissolves C3** (no rejection loop) but adds smudging-noise leakage to bound; **retires/re-scopes C2** (no ML-DSA rejection to be equivalent to); shifts **C5**'s base to Raccoon's assumption (replaces FST-A1); **C4** unchanged. | Can in principle close **C1 exactly** (`ε_mask = 0`, aggregate *is* ExpandMask) and **C2** (rejection identical by construction) **while keeping the standard verifier**; makes **C3 acute** but provable with a fixed abort/restart policy; **C4/C5** stay in scope and become provable against a real construction (FST-A1 preserved). Only option that closes C1/C2 *and* keeps both target properties. | **C1** trivially met at construction (a real ExpandMask sample) pending its proof slot; **C2** already has real recomputation + standard-verifier acceptance (strongest current evidence); **C3** uses real FIPS FS-with-aborts on reconstructed `rnd`; **C4/C5** have real code + evidence gates. All become closable inside **one** coherent assumption set — none close without external proof+audit. Does **not** address ε_mask for a distributed mask; it sidesteps it. | Closes/re-opens nothing; both stacks stay `partially_met`. Preserves honest surfacing of ε_mask via the negative test. |
| **Engineering cost** | High: new scheme, verifier, packing, parameters — but Raccoon is published / NIST-submitted, so portable. | **Very high**: distributed uniform sampling + oblivious `‖z‖_∞<γ₁−β` / `‖r0‖` accept-check + per-attempt MPC rounds; 10 000-validator fan-in likely infeasible without committee reduction. | **Low marginal**: already built (`fips_sign.rs`) and already the selected backend (`production/selected_backend.rs`). Remaining work is proof / KAT / audit, not new crypto. | Zero new cost; ongoing duplication/drift debt (tracked in the ADR). |
| **Cryptographic risk** | Medium–high: Raccoon has an external analysis, but a newer, less-battle-tested assumption base; you inherit its parameters and its own leakage argument. | High **engineering / composition** risk (MPC soundness, side channels, abort leakage), but **low novelty risk on the target** — goal is byte-identical ML-DSA, base assumption unchanged. | Low on the **signature** (standard ML-DSA, verified vs `ml-dsa`); risk is **entirely in the trust assumption** (coordinator reconstructs the key). | Low (nothing new claimed); real risk is **stagnation** — the appearance of progress while the crux stays open. |
| **Thesis-scope impact** | **Severe**: contradicts the defining output target (standard ML-DSA verifier, 3309-byte sig); requires a *new* thesis. | **Fully aligned**: this *is* the thesis crux; cost is a long, research-grade timeline. | **Matches** the thesis's own Profile P1 statement (coordinator-assisted, TEE/HSM); but demotes "no single holder" to a Stack-A-only property. | Neutral; but it is an **avoidance** of the crux, not a resolution. |
| **Standard-verifier compatibility** | **No** — Raccoon verifier ≠ ML-DSA verifier; larger signatures, different pk. | **Yes** — the whole point is to keep the ordinary ML-DSA-65 verifier and 3309-byte signature. | **Yes** — already accepted by the standard `ml-dsa` verifier in CI. | Mixed/unchanged — Stack B yes, Stack A no. |
| **Distribution / no-single-holder** | **Yes** — additive masks are native; no party holds the key. `ε_mask` gets a real (non-zero) bound. | **Yes** — no party knows `y` or the key; `ε_mask = 0` exactly. | **No cryptographic no-single-holder** — the coordinator reconstructs seed + nonce in the clear (protected only by TEE/HSM). `ε_mask = 0`. | Unchanged — Stack A yes (ε_mask open) / Stack B no. |

Reading the matrix: **(b) is the only option that keeps the standard verifier
AND the no-single-holder property AND drives `ε_mask → 0`** — it is the "correct"
answer to the literal thesis, and also the most expensive and slowest. **(a)**
buys the distributed property by surrendering the thesis's defining upside.
**(c)** already delivers the standard verifier today but only by surrendering the
distributed property to a hardware trust assumption. **(d)** decides nothing.

---

## 3. Recommendation

**Recommended (a layered decision, for ratification):**

1. **Ratify Stack B (option c) as the production / standard-verifier track**,
   with an explicit, honest reframing: its "threshold" is **coordinator
   seed-reconstruction under a TEE/HSM no-export assumption**, *not* a
   cryptographic no-single-holder property. Restrict the "no single party holds
   the key" claim to Stack A only. (This is the *already selected* backend and
   the thesis's *own* Profile P1 statement — ratifying it is low marginal cost
   and over-claims nothing new.)
2. **Charter a scoped-down heavy-MPC effort (option b) as the single research
   route authorized to close the ε_mask crux** — distributed sampling of one
   ExpandMask-distributed mask no party knows, with an oblivious norm-bound
   accept-check, for a **small committee** (e.g. n ≈ 5–20), explicitly *not* the
   10 000-validator fan-in. Treat it as `evaluate / prototype`, not closure.
3. **Demote Raccoon (option a) to a documented fallback comparator**, alongside
   the existing Falcon/LaBRADOR proof-wrapper fallback trigger in
   `thesis-operating-parameters.md`. It stays a named alternative, not the
   primary direction, precisely because it discards standard-ML-DSA-verifier
   compatibility — the thesis's reason to exist.
4. **Reject open-ended status quo (option d) as an *outcome*.** Keeping both
   stacks is the right *interim posture*, but only when upgraded from "the split
   is deliberate" to "here is the ratified role of each stack **and the one route
   (b) we are actually investing in to close the crux**." Dual-track as a
   permanent end-state is avoidance.

### Justification

- The thesis's defining, differentiating upside over the Falcon/LaBRADOR
  fallback is *the standard ML-DSA-65 verifier and a standard-sized signature*
  (`claims-matrix.md` "Related Work Comparator"; `thesis-operating-parameters.md`
  §Thesis Statement). Option (a) throws exactly that away, so it cannot be the
  primary direction without abandoning the thesis.
- Under the repo's fail-closed honesty discipline, the honest position is: the
  *only* route that closes the literal crux (standard verifier + no-single-holder
  + `ε_mask = 0`) is (b), and (b) is not a near-term deliverable. So ship the
  honestly-scoped valid-signature answer now (c), and fund the crux route as
  research (b) — rather than pretending either (a) or (d) resolves the crux.
- (c) is not new risk surface: Stack B already emits `ml-dsa`-verified signatures
  (`blocker-closure-status.md`), so ratifying it converts an implicit selection
  into an explicit, honestly-bounded one and frees the ε_mask question to live
  entirely inside the Stack A research route.

### Single biggest risk of the recommendation

**The Stack B production track has a single point of total key compromise.**
Its security rests entirely on the TEE/HSM no-export assumption; the coordinator
reconstructs the full secret-key seed and nonce in the clear
(`threshold-stack-architecture.md` §Stack B; `blocker-closure-status.md`
"Must not say: coordinator no-export security is proved"). If that hardware
assumption fails or is bypassed, the "threshold" collapses to a **centralized
key with no cryptographic fallback** — there is zero distributed protection
underneath. This residual must be recorded explicitly (see step 1 below) and
must never be described as cryptographic threshold security. (Secondary risk:
the research route (b) may prove infeasible at any useful committee size, in
which case the crux stays permanently open and only (a) or the Falcon/LaBRADOR
fallback remain — which is why (a) is retained as a documented comparator, not
deleted.)

---

## 4. First three engineering steps the recommendation implies

These are the concrete next actions **after** ratification. None of them close a
criterion; each stays inside the honesty boundary.

1. **Pin the ratified division of roles + the Stack B residual.** Supersede /
   extend `threshold-stack-architecture.md` with a ratified ADR that names Stack B
   the production/standard-verifier track under the explicit "coordinator
   seed-reconstruction, TEE/HSM no-export trust" statement, and Stack A the
   distributed research track that owns the (open) `ε_mask` boundary. Record a
   new **"coordinator = single point of key compromise"** residual in the Epsilon
   Residual Ledger / `blocker-closure-status.md` "Residual" list. Keep all five
   criteria at `partially_met`.

2. **Scope the crux route into a reviewable plan.** Write
   `docs/cryptography/distributed-mask-mpc-feasibility.md` specifying the target
   for a small committee (n ≈ 5–20): distributed sampling of one
   ExpandMask-uniform mask on `(−γ₁, γ₁]` that no party knows, secure/committed
   `w = A·y`, **oblivious** evaluation of the `‖z‖_∞ < γ₁−β` and `‖r0‖ ≤ γ₂−β`
   accept predicates, and a per-attempt restart policy — with an enumerated MPC
   primitive list and a round/bandwidth cost estimate that acts as an explicit
   go/no-go gate. This converts the ADR's "heavy MPC" hand-wave into a concrete,
   externally-reviewable research charter.

3. **Turn the ε_mask negative test into a quantitative honesty ledger.** Extend
   `distributed_nonce::aggregate_mask_exceeds_gamma1_epsilon_mask_open` into a
   measurement harness that, for `s = 2..N` signers, records (i) the empirical
   per-coefficient `P(|Σ yᵢ| > γ₁)`, (ii) the aggregate acceptance probability
   under `Z_BOUND`, and (iii) a statistical/Rényi distance of the
   accepted-conditional `z` from the ExpandMask-uniform target — logged as
   **evidence, not closure** into `mask-distribution-evidence.md`. This gives the
   user hard numbers to justify the demotion of (a), to size the committee in
   step 2, and to seed a future C1 Rényi-bound review, without promoting any
   criterion.

---

## 5. Cross-references

- Obstruction pinned: `src/crypto/distributed_nonce.rs:26–53, 366–388`
- Two-stack ADR: `docs/cryptography/threshold-stack-architecture.md`
- Thesis / output target: `docs/cryptography/thesis-operating-parameters.md`
- C1 / C2 proof payloads: `docs/cryptography/criterion-1-proof-substance.md`,
  `docs/cryptography/criterion-2-proof-substance.md`
- Outcome vocabulary: `docs/cryptography/hypothesis-outcome-taxonomy.md`
- Stack B capability: `src/backend/fips_sign.rs`, `src/backend/module_partial.rs`,
  `docs/cryptography/blocker-closure-status.md`
</content>
</invoke>
