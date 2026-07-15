# ε_mask Fork ↔ Boundary Theorems — Reconciliation Note

Status: reconciliation of `epsilon-mask-fork-decision.md` (ratified 2026-07-12)
against `design-space-boundary-theorems.md` (FST-T4/T5, 2026-07-14).
Date: 2026-07-14.

## Verdict: consistent. The ratified fork survives FST-T5.

The concern that prompted this check — "did FST-T5 just invalidate the ratified
ε_mask decision?" — resolves **no**. The two documents were written
independently (the fork memo from the code parameters, the boundary theorems
from a clean-room model) and reach the **same** structural conclusion by two
routes. The ratified option (b), scoped heavy-MPC on a small committee, *is*
FST-T5's Exit 1. Nothing in the ratified direction needs to change. Two
alignments and one correction follow.

## 1. Where they agree (independently)

| Question | Fork memo (from code) | FST-T5 (from model) |
| --- | --- | --- |
| Additive/plain-sum masking at standard params | §1.3: `P(‖y‖_∞ > γ₁) ≈ 1` at `s=2`; "catastrophic, intrinsic, not a bug" | Branch (b): additive family, `E(2)≈23`, `exp(Θ(t))` growth |
| Can rejection-sampling rescue it | §1.3: forcing all 1280 coeffs into box has acceptance `→ 0` for `s≥2` | Branch (b): same `exp(Θ(t))` wall, `t_max≈6–8` |
| Pure flooding at standard params | (not separately modeled) | Branch (a): dead at **any** `t` for `Q_s≥2^20` |
| The only route keeping standard verifier + no-single-holder | §2–3: option (b) heavy-MPC, and *only* (b) | DSB-4.6: Exit 1 (computational hiding / committee), and *only* Exit 1 |
| Scale that route is viable at | Rec. 2: "small committee, n ≈ 5–20, explicitly NOT 10 000 fan-in" | DSB-4.6 Exit 1 + DSB-3.5: committee `k << n`, reshare from the `(t,n)` sharing |

The fork memo is the **concrete instance** of FST-T5 on this repo's actual code
paths (`distributed_nonce.rs`), with the real parameters read from the crate.
FST-T5 is the **general statement** that covers the whole additive family, so it
also rules out designs the memo did not enumerate (e.g. Lagrange-weighted
Shamir masks, which DSB-4.5 notes are strictly worse than plain additive).
They are the same finding at two altitudes.

## 2. What FST-T5 adds beyond the fork memo

1. **Flooding is dead at any `t`, not just large `t`.** The memo analyzes the
   additive-sum and per-party-rejection routes but does not separately close off
   pure statistical flooding. FST-T5 branch (a) does: at the NIST base-scheme
   query bound (`Q_s = 2^64`) the required mask width exceeds the verifier
   budget by ~5×10⁶, so *no* validator count works. This removes flooding as a
   candidate more completely than the memo's demotion of Raccoon (option a),
   which was about the verifier-incompatibility of Raccoon's *own* parameters,
   not about flooding at standard params.
2. **A named positive result to pair with the negative one.** The memo says (b)
   "can in principle close C1 exactly" but leaves existence as an assertion.
   FST-T4 upgrades that to a proof-sketch corollary of MPC completeness:
   existence is settled for all `t`, and the open question is cost. This gives
   the ratified charter (Rec. 2 / memo step 2, the
   `distributed-mask-mpc-feasibility.md` plan) a theorem to cite as its
   foundation rather than an open assertion.
3. **A quantitative `t_max`.** The memo says the additive route fails "for
   `s ≥ 2`." FST-T5 branch (b) sharpens this to a cost curve
   (`E(2)≈23`, `E(4)≈4.1e3`, `E(6)≈2.2e6`, hopeless past `t≈8`) that is
   externally calibrated against the published 6-party frontier. This is the
   hard number memo step 3 asked for to "size the committee."

## 3. Correction to the boundary-theorems doc (from reading the code)

FST-T5 branch (b) modeled the additive family with **per-party local
rejection** producing box-uniform `z_i`. The fork memo (§1.1) documents that
this repo's Stack A actually samples the mask **without** rejection —
`sample_gamma1_poly` is a plain 20-bit uniform unpack (`2γ₁ = 2^20`), summed
additively in `distributed_nonce.rs`. So the deployed code is even further from
acceptable than branch (b): its aggregate is an un-rejected `s`-fold
convolution, matching the memo's `P(‖y‖_∞ > γ₁) ≈ 1`. Branch (b) is the
*best-case* additive design; the current code is the *naive* one. Both fail;
the code fails harder. `design-space-boundary-theorems.md` DSB-4.1 should note
that its box-uniform `z_i` is an idealization more favorable than the shipped
Stack A sampler.

## 4. The C1-distribution point both documents imply but neither states outright

A simulation while writing this note makes the ε_mask (C1) obstruction sharper
than "the support widens." Take the *best* additive design — `t=2` with each
party locally rejection-sampling into the optimal box (`g≈169869`) so every
accepted `z_i` is genuinely secret-independent and uniform — and condition on
the aggregate passing the standard bound. The accepted aggregate coefficient is
**still not** ExpandMask-uniform:

```
accepted-conditional band mass (|z|<B/3, B/3..2B/3, >2B/3): [0.766, 0.234, 0.000]
ExpandMask-uniform target:                                  [0.333, 0.333, 0.333]
```

The accepted aggregate is a truncated triangular law, heavily center-massed,
with zero mass in the outer third. So even in the additive family's best case,
and even ignoring the `exp(Θ(t))` cost of *reaching* acceptance, C1
(`aggregate_mask_distribution`) **cannot** close: the conditional distribution
is bounded away from uniform, hence bounded away from `s1`-independence, hence
`ε_mask` is bounded below by a constant, not merely nonzero. This strengthens
the memo's §1.3 ε_mask paragraph from "is a truncated bell, not uniform" to "is
quantifiably far from uniform even under ideal per-party hiding," and it
independently confirms the memo's core claim that only Exit 1 / option (b) —
where no `z_i` is ever exposed and the mask is sampled as a single ExpandMask
draw inside MPC — can drive `ε_mask → 0`. (Numbers reproducible; the snippet is
in the reconciliation commit message / `scripts/` alongside the model.)

## 5. Net effect on the ratified decision

- **No change to the ratified direction.** Option (b) / Exit 1 stands as the one
  authorized crux route; Stack B stays the honestly-reframed production track;
  Raccoon stays a demoted comparator; dual-track stays rejected as an end-state.
- **Two upgrades to its evidentiary basis**, both usable immediately:
  - Cite **FST-T4** as the existence foundation of the
    `distributed-mask-mpc-feasibility.md` charter (memo step 2).
  - Cite **FST-T5 branch (b)** + the §4 C1 simulation as the quantitative
    honesty ledger for the ε_mask negative test (memo step 3), and as the
    justification for the `n ≈ 5–20` committee sizing.
- **One doc edit queued:** annotate `design-space-boundary-theorems.md` DSB-4.1
  per §3 above (box-uniform `z_i` is more favorable than shipped Stack A).
- **One open decision unchanged and still pending:** the committee size `k` and
  the go/no-go bandwidth gate remain to be produced by the FST-L12 cost model,
  which is the natural next artifact after this reconciliation.

## Cross-references

- `docs/cryptography/epsilon-mask-fork-decision.md` (ratified memo)
- `docs/cryptography/design-space-boundary-theorems.md` (FST-T4/T5)
- `src/crypto/distributed_nonce.rs:26–53, 128–130, 366–388` (obstruction pinned in code)
- `scripts/model_fst_t5_boundaries.py` (branch (a)/(b) tables)
