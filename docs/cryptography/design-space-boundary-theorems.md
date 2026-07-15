# Design-Space Boundary Theorems for Threshold ML-DSA-65

Status: draft for review. FST-T4 is a proof sketch reducible to external
theorems. FST-T5 is a heuristic boundary model with explicit model assumptions;
it is not yet a formal impossibility lemma.

Date: 2026-07-14

## DSB-0. Scope and Reading Notes

This document adds two boundary results to the theorem set of
`docs/cryptography/formal-security-theorem.md`. Together they fence the design
space in which any protocol satisfying FST-T1 through FST-T3 must live:

- **FST-T4 (positive boundary):** exact threshold ML-DSA-65 *exists* for every
  threshold `t <= n`, including `n = 10000`, as a corollary of secure
  multiparty computation (MPC) completeness. Existence is therefore settled and
  is not a research question of this project. Cost is.
- **FST-T5 (negative boundary):** within the *additive-response family* of
  protocols (defined in DSB-4.1) — the family containing every
  lightweight/flooding-style and per-party-rejection design — the standard
  ML-DSA-65 parameter set caps practical participation at roughly
  `t <= 6..8` active signers, and pure statistical flooding fails at *any* `t`
  under NIST-level query bounds. The `t = 10000` target is unreachable inside
  this family. Any protocol meeting
  `docs/cryptography/validator-10000-standard-verifier-gate.md` must exit the
  family via one of the three exits in DSB-4.6.

Consequence for the epsilon ledger: FST-T4 shows all five criteria
(`epsilon_mask`, `epsilon_rej`, `epsilon_withhold`, `epsilon_contrib`,
`epsilon_classify`) are *simultaneously closable* at any `t` (at unquantified
cost, and with the `epsilon_withhold` condition FST-A12). FST-T5 shows
`epsilon_mask` and `epsilon_rej` *cannot both close* inside the additive family
at the target scale. The open question of this project is therefore not
whether, but at what cost, and with which architecture.

Numerical tables in this document were produced by the reproducible model
script referenced in DSB-7 and use exact FIPS 204 ML-DSA-65 parameters. They
enforce only the `||z||_inf < gamma1 - beta` check; the `gamma2` low-bits and
hint predicates required by FIPS 204 would only tighten every bound stated
here.

## DSB-1. Objects and Notation

Notation follows `formal-security-theorem.md` section FST-1. Additionally:

- `gamma1 = 2^19 = 524288`, `tau = 49`, `eta = 4`, `beta = tau * eta = 196`,
  `ell = 5`, `k = 6`, `q = 8380417` (ML-DSA-65, FIPS 204).
- `B = gamma1 - beta = 524092`: the response bound enforced by the unmodified
  verifier.
- `D = 256 * ell = 1280`: the number of coefficients in the response vector
  `z`.
- `A`: the active signer set for a session, `|A| = t_act` (we write `t` for
  `t_act` where unambiguous).
- `Q_s`: the number of signing sessions an adversary may observe for a fixed
  key epoch (NIST guidance for the base scheme: up to `2^64`).
- `Delta_i = c * shat_i`: the secret-dependent shift contributed by party `i`
  to its response share, where `shat_i` is party `i`'s effective (possibly
  Lagrange-weighted) secret share.

## DSB-2. Additional Assumptions

These extend FST-A1 through FST-A9. Both are external theorem dependencies in
the sense of `claims-matrix.md`.

- **FST-A10 (MPC completeness).** For every polynomial-size circuit `C` there
  exists a protocol securely computing `C` on secret-shared inputs against
  static malicious corruption of up to `t - 1` of `n` parties: with
  computational security for dishonest majority (GMW-style, assuming oblivious
  transfer), and with information-theoretic security and guaranteed output
  delivery for `t - 1 < n/2` (BGW-style, assuming secure channels).
- **FST-A11 (joint randomness).** Secure coin-tossing into shares is available
  inside the MPC envelope, so the mask `y` of each signing attempt is jointly
  generated, uniformly distributed, and secret-shared without any party
  learning it.
- **FST-A12 (output-delivery discipline).** Either (a) the MPC provides
  guaranteed output delivery (honest-majority setting), or (b) the protocol
  enforces an externally auditable bound `R` on abort-triggered retries per
  `(epoch, m)` pair. This is the condition under which `epsilon_withhold`
  closes in FST-T4; see DSB-3.4.

## DSB-3. Theorem FST-T4 (Existence of Exact Threshold ML-DSA-65)

### DSB-3.1 Statement

> **Theorem FST-T4.** Assume FST-A1, FST-A10, and FST-A11. For every `n` and
> every threshold `t <= n`, there exists an interactive protocol `Pi_MPC`
> among `n` parties holding a `(t, n)` secret sharing of an ML-DSA-65 signing
> key `sk` such that:
>
> (i) *Exactness.* For every message `m`, the output of `Pi_MPC` is
> distributed **identically** to `MLDSA65.Sign(sk, m)` — not statistically
> close, identical — and in particular is 3309 bytes and satisfies
> `MLDSA65.Verify(pk, m, sigma) = accept` with the unmodified FIPS 204
> verifier.
>
> (ii) *Security.* Any probabilistic polynomial-time adversary statically
> corrupting at most `t - 1` parties learns nothing beyond `(m, sigma)`, the
> public transcript metadata, and the per-session rejection iteration count
> `kappa`. Formally, `Pi_MPC` UC-realizes `F_TMLDSA`
> (`docs/cryptography/ideal-functionality.md`) in the corruption model of
> FST-T2, with the `epsilon_withhold` caveat of DSB-3.4.

### DSB-3.2 Proof sketch

The FIPS 204 signing algorithm — mask expansion, `w = A*y`, decomposition,
challenge derivation, `z = y + c*s1`, both rejection predicates, hint
computation, encoding — is a fixed polynomial-size circuit `C_Sign`. Share
`sk` with the `(t, n)` scheme already analyzed in
`correctness-lemmas.md` (Lemma 3). Generate each attempt's mask `y` by
FST-A11. Evaluate `C_Sign` inside the MPC envelope of FST-A10, iterating the
rejection loop *inside* the envelope and revealing only the accepted
`sigma` and the iteration count `kappa`.

Exactness (i) is immediate: the protocol computes the single-signer
functionality on the true `(sk, y)` distribution, so the output *is* the
single-signer distribution. Security (ii) reduces to the security of the MPC:
the simulator for `Pi_MPC` is the MPC simulator composed with `F_TMLDSA`.
Revealing `kappa` leaks nothing beyond the single-signer baseline, because
FIPS 204 already treats the iteration count as public for a lone signer
(signing time reveals it).

### DSB-3.3 Epsilon-ledger corollary

Within `Pi_MPC`:

| Criterion | Status inside FST-T4 | Condition |
|---|---|---|
| `epsilon_mask` | 0 (exact) | FST-A11 |
| `epsilon_rej` | 0 (exact; loop inside envelope) | FST-A10 |
| `epsilon_contrib` | inherited from MPC security | FST-A10 |
| `epsilon_classify` | reduces to FST-A1 via FST-T4(ii) | FST-A1, FST-A10 |
| `epsilon_withhold` | 0 under FST-A12(a); bounded by `log2(R)` bits of selection under FST-A12(b) | FST-A12 |

### DSB-3.4 The `epsilon_withhold` caveat

In dishonest-majority MPC (no guaranteed output delivery), an adversary who
learns the output first can abort and force a retry, selecting among candidate
signatures for the same `(epoch, m)`. Each permitted retry grants at most a
one-of-`R` selection over honest output candidates. Under FST-A12(a) this
channel does not exist; under FST-A12(b) it is bounded and auditable. This is
the same abort/retry surface tracked in `abort-retry-bias-evidence.md`, and it
does not disappear merely because the envelope is MPC.

### DSB-3.5 What FST-T4 does and does not establish

- It settles **existence** for all `t`, including 10000, unconditionally
  modulo external theorems. The project's headline question is therefore a
  **cost** question.
- It is silent on cost. Direct MPC among `n = 10000` parties has
  communication growing at least quadratically in `n` for the nonlinear
  gates of `C_Sign` and is impractical as stated. The nonlinear core is,
  however, small: the linear algebra (`A*y`, `y + c*s1`) is local on shares,
  and the challenge hash operates on data that becomes public in the
  signature, so only `Decompose`/`HighBits`, the two rejection comparisons,
  and `MakeHint` need secure evaluation — on the order of a few thousand
  secure comparisons per attempt, times an expected ~4 attempts.
- It does not provide identifiable aborts (FST-A6) natively, and does not
  cover adaptive corruption (consistent with limitation FST-X5).

## DSB-4. Theorem FST-T5 (Additive-Family Infeasibility at Standard Parameters)

### DSB-4.1 The additive-response family `F`

Implementation note (added 2026-07-14 during fork reconciliation): the
box-uniform `z_i` idealization used in DSB-4.4 branch (b) is *more favorable*
than this repository's shipped Stack A sampler, which draws `sample_gamma1_poly`
as a plain 20-bit uniform with **no** per-party rejection
(`src/crypto/distributed_nonce.rs:128-130`) and sums additively. The deployed
code therefore fails harder than branch (b) predicts; see
`epsilon-mask-fork-reconciliation.md` section 3.

A threshold protocol `Pi` belongs to family `F` if, in each signing session
with active set `A`:

1. Each party `i in A` publishes (or makes adversarially reconstructible,
   e.g. via attributable partial-signature evidence per FST-A6) a response
   share `z_i = yhat_i + Delta_i`, where `Delta_i = c * shat_i` is its
   secret-dependent shift and `yhat_i` is a mask sampled independently by
   party `i`.
2. The aggregate response is coordinate-wise: `z = sum_{i in A} z_i` in
   `R_q^ell` (Lagrange weights, if any, are absorbed into `yhat_i, shat_i`).
3. Hiding of each honest `Delta_i` given the published `z_i` is
   **statistical**: the security argument bounds the divergence between the
   distributions of `z_i` under adjacent admissible secrets, accumulated over
   `Q_s` sessions.

Note that FST-A6 (attributable partial signatures), as currently stated,
places a protocol in condition 1 unless attribution is achieved without
revealing `z_i` (e.g. zero-knowledge attestation). This is a design choice
with direct security consequences; see DSB-4.6.

### DSB-4.2 Model assumptions

- **FST-M1 (independence).** Honest masks `yhat_i` are independent across
  parties; aggregate coefficient distributions are approximated as Gaussian
  (sums of `t` independent bounded terms; Berry–Esseen regime for `t >= 3`).
- **FST-M2 (z-check only).** Only `||z||_inf < B` is enforced. The `gamma2`
  low-bits and hint predicates are ignored; they strictly tighten every bound.
- **FST-M3 (visibility).** The adversary observes individual `z_i` for
  corrupted-adjacent sessions, per family condition 1.
- **FST-M4 (flooding requirement).** A statistical-hiding argument for
  condition 3 over `Q_s` sessions requires per-party mask standard deviation
  `sigma >= ||Delta_i||_2 * sqrt(lambda_R * Q_s)` with `lambda_R >= 1`
  (Renyi-divergence accounting; `lambda_R = 1` is the most protocol-favorable
  constant and understates every published concrete instantiation).

Estimate used below: `||Delta_i||_2 = ||c * s1_i||_2 ~ 647` for ML-DSA-65
(challenge weight `tau = 49`, `s1` coefficients uniform on `[-eta, eta]`,
`D = 1280` coordinates).

### DSB-4.3 Statement

> **Theorem FST-T5 (model-level).** Under FST-M1 through FST-M4, at the exact
> ML-DSA-65 parameter set, for any `Pi in F`:
>
> **(a) Flooding branch.** If hiding is by flooding alone (no per-party
> rejection), then for `Q_s >= 2^20` the required per-party mask width
> exceeds the total verifier budget `B` — `sigma_min > B` — so the aggregate
> response fails the standard verifier with overwhelming probability at
> **every** `t >= 1`. Pure flooding at standard parameters is infeasible
> independent of the validator count.
>
> **(b) Per-party-rejection branch.** If instead each party locally rejection
> -samples `z_i` into a box of width `g` (perfect per-party hiding), the
> expected number of full interactive signing attempts satisfies
> `E(t) = min_g [ exp(D * beta * t / g) / P_agg(t, g) ]`, which grows as
> `exp(Theta(t))`. Concretely (see DSB-4.4): `E(2) ~ 23`, `E(4) ~ 4.1e3`,
> `E(6) ~ 2.2e6`, `E(8) ~ 3.3e9`; for `t >= ~10` no choice of `g` yields
> nonvanishing acceptance.
>
> In particular no `Pi in F` satisfies the acceptance criterion of
> `validator-10000-standard-verifier-gate.md` with `t_act = 10000` (nor
> `t_act = 100`).

### DSB-4.4 Computed boundaries

Branch (a), most-protocol-favorable constants (`lambda_R = 1`):

| `Q_s` (sessions per epoch) | required `sigma_min` | `sigma_min / B` | verdict |
|---|---|---|---|
| `2^64` (NIST base-scheme bound) | `2.8e12` | `5.3e6` | dead at any `t` |
| `2^45` | `3.8e9` | `7.3e3` | dead at any `t` |
| `2^30` | `2.1e7` | `40` | dead at any `t` |
| `2^20` | `6.6e5` | `1.3` | dead at any `t` |
| `2^10` (1024 sigs/epoch) | `2.1e4` | `0.04` | `t_max ~ 59` |

Even under an aggressive 1024-signature epoch-rotation policy — itself
requiring a fresh `n = 10000` DKG per epoch — the flooding branch tops out
near `t ~ 59`, two orders of magnitude below target.

Branch (b), optimal local box width `g` per `t`:

| `t` | best `g` | `alpha_loc^t` | `P_agg` | `E[attempts]` |
|---|---|---|---|---|
| 2 | 169869 | `5.2e-2` | 0.82 | 23 |
| 3 | 144703 | `5.5e-3` | 0.69 | 262 |
| 4 | 129499 | `4.3e-4` | 0.56 | `4.1e3` |
| 5 | 119537 | `2.8e-5` | 0.42 | `8.5e4` |
| 6 | 111673 | `1.4e-6` | 0.32 | `2.2e6` |
| 8 | 104857 | `4.9e-9` | 0.06 | `3.3e9` |
| 10 | 104857 | `4.1e-11` | ~0 | `6.1e13` |
| 100, 10000 | — | — | — | infeasible |

External consistency check: this model, built independently of the
literature, reproduces the published frontier — exact-output threshold
ML-DSA schemes top out around 6 parties (NIST PQC 2025, "Efficient Threshold
ML-DSA up to 6 parties"), and Threshold Raccoon obtains `t` up to 1024 only
by abandoning the standard parameter set (`q ~ 2^49`, 13 KiB signatures).
The model is calibrated, not merely pessimistic.

### DSB-4.5 Proof sketch

(a) By FST-M4 the flooding width must satisfy
`sigma >= 647 * sqrt(Q_s)`. A single party's published `z_i` already has
coefficient scale `sigma`; the verifier requires every coefficient of the
*sum* to lie under `B = 524092 < sigma` for all `Q_s >= 2^20`. Acceptance
probability is then bounded by `(2B/sigma)^D`-type terms, vanishing at any
`t`.

(b) Per-party rejection into a box of width `g` gives per-party acceptance
`alpha_loc ~ exp(-D * beta / g)` (the single-signer FIPS 204 z-check formula
applied locally), so all `t` parties jointly accept with `alpha_loc^t =
exp(-D * beta * t / g)`. The accepted `z_i` are box-uniform, so the aggregate
coefficient standard deviation is `(g - beta) * sqrt(t/3)`, and the aggregate
passes the standard verifier with `P_agg = (1 - 2Q(B / sigma_t))^D`. Raising
`g` improves local acceptance but widens the aggregate; lowering `g` does the
reverse; the optimum trades `exp(D beta t / g)` against `P_agg` and grows
exponentially in `t`. Lagrange-weighted (Shamir) recombination with
unstructured validator indices multiplies `||yhat_i||` by weights of size up
to `~q/2` (see `mask-distribution-evidence.md` and the regime-2 computation in
the model script), and is therefore strictly worse than the additive case
analyzed here.

### DSB-4.6 Corollary: the three exits

Any protocol meeting the 10000-validator gate must break at least one family
condition:

1. **Exit the visibility condition (1/3): computational hiding.** Individual
   `z_i` never exist in the clear; secret contributions meet the response
   only inside an MPC or commitment envelope. This is the FST-T4 route. Its
   scalable form is committee delegation: `n = 10000` parties hold the
   `(t, n)` sharing and reshare per epoch to a rotating committee of size
   `k << n` (sortition), which executes the nonlinear core of `C_Sign`.
   Corruption tolerance is inherited from the `(t, n)` sharing; cost scales
   with `k`, not `n`. Attribution (FST-A6) must then be met by attestation
   rather than by publishing `z_i`.
2. **Exit the parameter set: Raccoon route.** Larger `q`, `gamma1`, and
   signature size restore the flooding budget. This forfeits the unmodified
   FIPS 204 verifier and is out of scope for this project's gate.
3. **Exit the aggregation shape: reduce `t_act`.** Keep `t_act <= ~6` actual
   signers (per branch (b)) representing the stake of 10000 — a degenerate
   form of exit 1 without its security inheritance. Not recommended: trust
   concentrates in the few signers.

Exit 1 is the only one compatible with the project thesis.

## DSB-5. Claims-Matrix Delta

Proposed new rows for `claims-matrix.md`, using the existing status
vocabulary:

| Claim | Status |
|---|---|
| FST-T4 existence of exact threshold ML-DSA-65 for all `t` | proof sketch only (reduces to external theorem dependencies FST-A10/A11) |
| FST-T4 epsilon-ledger closure table (DSB-3.3) | proof sketch only |
| FST-A10 MPC completeness (GMW/BGW) | external theorem dependency |
| FST-T5(a) flooding infeasibility at standard parameters | heuristic model; needs formal lemma (FST-L10) |
| FST-T5(b) `exp(Theta(t))` attempt growth, `t_max ~ 6..8` | heuristic model; needs formal lemma (FST-L11); externally consistent with published 6-party frontier |
| Exit-1 committee architecture achieves the 10000 gate | open |

No row above claims completed active-adversary security or production
threshold ML-DSA security.

## DSB-6. Upgrade Path to Formal Status

- **FST-L10 (flooding lower bound).** Replace FST-M4 with a theorem-grade
  statement: for the concrete Renyi order used in the chosen proof framework,
  derive `sigma_min(Q_s, lambda)` exactly and conclude
  `Pr[accept] <= f(sigma_min, B, D)` with explicit constants. Removes the
  `lambda_R = 1` generosity.
- **FST-L11 (attempt-growth lower bound).** Replace the Gaussian
  approximation with exact convolution of box-uniform distributions (or
  Berry–Esseen with explicit constants) to make branch (b) a lemma. The
  optimization over `g` is one-dimensional and can be bounded analytically.
- **FST-L12 (committee-delegation cost model).** For exit 1: count secure
  comparisons per signing attempt for ML-DSA-65 (`Decompose`, two rejection
  predicates, `MakeHint`), instantiate a concrete MPC (honest-majority,
  `k in {32, 64, 128}`), and derive rounds/bandwidth per signature under WAN
  latency. This converts FST-T4 from existence to an engineering budget and
  is the natural successor document.

## DSB-7. References and Reproducibility

- FIPS 204 (ML-DSA), parameter set ML-DSA-65.
- Goldreich–Micali–Wigderson (STOC 1987); Ben-Or–Goldwasser–Wigderson
  (STOC 1988): FST-A10.
- del Pino, Espitau, Katsumata, Maller, Mouhartem, Prest et al., *Threshold
  Raccoon*, EUROCRYPT 2024 (eprint 2024/184): parameter-exit exemplar.
- *Efficient Threshold ML-DSA up to 6 parties*, NIST PQC Standardization
  Conference 2025: branch-(b) frontier consistency.
- *Quorus: Efficient, Scalable Threshold ML-DSA Signatures from MPC*
  (eprint 2025/1163); *Threshold Signatures Reloaded* (eprint 2025/1166):
  exit-1 exemplars.
- *FIPS 204-Compatible Threshold ML-DSA via Masked Lagrange Reconstruction*
  (arXiv 2601.20917): closest known prior art to this project's stated
  approach; must be differentiated against before publication.
- Model scripts (committed alongside this document):
  `scripts/model_fst_t5_boundaries.py` (branch (a)/(b) tables, exact
  ML-DSA-65 parameters) and `scripts/model_fst_algebra_check.py`
  (verification-identity linearity; Lagrange norm-blowup regimes). Both are
  deterministic and reproduce every number in DSB-4.4.
