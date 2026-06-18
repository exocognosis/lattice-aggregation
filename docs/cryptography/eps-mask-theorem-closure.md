# eps_mask Theorem Closure Batch
<a id="eps-mask-theorem-closure"></a>

Status: theorem-closure batch for `eps_mask`, not a completed
mask-distribution proof.

This document refines the `RSTC-3` route from
[rejection-sampling-theorem-closure.md](rejection-sampling-theorem-closure.md).
It states the exact obligations required before the threshold aggregate mask
distribution can be treated as centralized ML-DSA-65 mask sampling or charged
to a visible `eps_mask_bound`.

It does not select a production mask protocol. It does not prove
`eps_mask = 0`, and implementation evidence is not cryptographic proof.

## EMTC-0. Scope and Non-Claim
<a id="emtc-scope-non-claim"></a>

The route covers the pre-rejection H1 -> H2 transition. It must be discharged
before accepted-output conditioning and before any selective-abort analysis
can claim distribution preservation.

The theorem target is intentionally conditional on one fixed production
`CombineMask` family. Until that family is selected and proved, `eps_mask`
remains a symbolic term in `Delta_accept` and `FST-T1-IdealVSS`.

## EMTC-1. CombineMask Selection
<a id="emtc-combinemask-selection"></a>

The production proof must select exactly one family:

| Family | Candidate equation | Status |
| --- | --- | --- |
| Additive | `Y_T = sum_{i in A} y_i` | Unselected; requires distribution proof for the sum. |
| Lagrange-weighted | `Y_T = sum_{i in A} lambda_i(A) * y_i` | Unselected; requires scaling and active-set distribution proof. |
| MPC/ideal | `Y_T = F_mask(ctx, A)` | Unselected; requires ideal-realization or explicit ideal boundary. |
| Dealer-aided | `Y_T` reconstructed from committed dealer material | Unselected; requires dealer consistency and anti-bias proof. |

The chosen equation must be bound into the production transcript grammar and
must not change across retries, active sets, or proof sections.

## EMTC-2. Theorem Statement
<a id="emtc-theorem-statement"></a>

Formalization route: see
[eps-mask-formalization.md](eps-mask-formalization.md) for the game/interface
shape and `Theorem M1-combine-mask-game` roadmap that precede this closure
target.

Target statement:

```text
Theorem M-close-mask-distribution.
For every public key pk, message binding mu, active set A, retry context rho,
and selected production CombineMask protocol, let

Y_T  <- threshold mask generation for (pk, mu, A, rho)
Y_0  <- centralized ML-DSA-65 mask sampling
WT_1 = HighBits(A_matrix * Y_T)
W0_1 = HighBits(A_matrix * Y_0).

Then either

Delta((Y_T, WT_1, rho), (Y_0, W0_1, rho)) = 0

or

Delta((Y_T, WT_1, rho), (Y_0, W0_1, rho))
  <= eps_mask_bound(lambda, A, rho).
```

The zero form is valid only under exact distribution equality. Otherwise
`eps_mask_bound` remains visible in the accepted-distribution theorem.

## EMTC-3. Coefficient Distribution Proof
<a id="emtc-coefficient-distribution-proof"></a>

The proof must cover every coefficient in the ML-DSA-65 mask vector:

```text
Y_T in R_q^L_65
L_65 = 5
N = 256
q = 8380417
```

Closure obligations:

- `eps_mask_support`: threshold masks must stay inside the centralized
  ML-DSA-65 support.
- `eps_mask_entropy`: honest mask material must be fresh and unpredictable.
- coefficient weights must match the selected centralized sampler or be
  charged to `eps_mask_bound`.
- module dimensions, coefficient centering, seed expansion, and retry context
  must be fixed for all `L_65 * N` coefficients.

Tests may demonstrate selected arithmetic behavior, but they do not prove
coefficient-distribution equality.

## EMTC-4. HighBits Coupling
<a id="emtc-highbits-coupling"></a>

The public challenge input depends on:

```text
W_1 = HighBits(A_matrix * Y)
```

The mask theorem must show that the pair `(Y_T, WT_1)` is coupled to
`(Y_0, W0_1)`, not only that `Y_T` has plausible coefficient ranges.

If the `HighBits` map introduces an additional mismatch, it must appear as:

```text
eps_mask_highbits
```

and remain visible until discharged.

## EMTC-5. Active-Set Binding
<a id="emtc-active-set-binding"></a>

The active set `A` used by `CombineMask` must be identical to the active set
used by:

- mask commitments and openings;
- challenge derivation;
- contribution validation;
- Lagrange or additive reconstruction;
- aggregate rejection checks;
- release records and final output.

Any mismatch is charged to:

```text
eps_mask_active_set
```

or to the collection-soundness term `eps_collect` if the production theorem
chooses that accounting. The same mismatch must not be counted twice.

## EMTC-6. Retry Freshness
<a id="emtc-retry-freshness"></a>

Each rejected or aborted attempt must use a fresh typed context:

```text
rho = Enc(domain, session_id, block_height, attempt, active_set, message_hash)
```

Required properties:

- retry identifiers are injective;
- mask seeds and opened mask values are not reused;
- challenge oracle inputs are domain separated across attempts;
- rejected attempts do not condition future masks except through the displayed
  `eps_mask_retry_freshness` term.

## EMTC-7. Corrupted Prechallenge Bias
<a id="emtc-corrupt-bias-boundary"></a>

Corrupted parties may choose malformed or biased prechallenge mask material.
The proof must classify this behavior before the challenge `H_c` is evaluated:

```text
eps_mask_corrupt_bias
```

This term covers prechallenge bias only. Postchallenge withholding, timeout
behavior, and retry forcing must be accounted for in `eps_withhold`, not hidden
inside `eps_mask`.

## EMTC-8. Epsilon Final Form
<a id="emtc-epsilon-final-form"></a>

The route exports:

```text
eps_mask
 <= eps_mask_support
  + eps_mask_entropy
  + eps_mask_highbits
  + eps_mask_active_set
  + eps_mask_retry_freshness
  + eps_mask_corrupt_bias
```

or, after one production family is selected:

```text
eps_mask <= eps_mask_bound(lambda, A, rho).
```

The final theorem may set `eps_mask = 0` only if exact equality of
`(Y_T, WT_1, rho)` and `(Y_0, W0_1, rho)` is proved.

## EMTC-9. Code Crosswalk
<a id="emtc-code-crosswalk"></a>

Current evidence:

- `src/low_level/mldsa65.rs` contains hazmat masking contribution paths.
- `tests/hazmat_mldsa65_threshold_bridge.rs` exercises selected aggregate
  consistency paths.
- `tests/hazmat_mldsa65_hardening.rs` rejects malformed masking encodings.
- actor and simulation-grid tests exercise ordering and modeled retries.

These artifacts are regression evidence only. They do not prove `MDE-1` or
`Theorem M-close-mask-distribution`.

## EMTC-10. Acceptance Criteria
<a id="emtc-acceptance-criteria"></a>

This batch is acceptable only if it:

- keeps `eps_mask_bound` visible unless exact equality is proved;
- states that no production `CombineMask` family is selected by this document;
- separates prechallenge corruption bias from postchallenge withholding;
- covers coefficient support, `HighBits` coupling, active-set binding, and
  retry freshness;
- says implementation evidence is not cryptographic proof.

## EMTC-11. Non-Claims
<a id="emtc-non-claims"></a>

This document does not claim:

- `eps_mask = 0`;
- `eps_mask` is negligible;
- the current hazmat aggregation path samples centralized ML-DSA-65 masks;
- production randomness quality is proved;
- accepted threshold signatures are distributed as centralized ML-DSA-65
  signatures;
- the repository is production-ready.

## EMTC-12. Manifest Anchors
<a id="emtc-manifest-anchors"></a>

Stable anchors and text markers:

- `# eps_mask Theorem Closure Batch`
- `eps-mask-theorem-closure`
- `Status: theorem-closure batch for eps_mask`
- `EMTC-0. Scope and Non-Claim`
- `EMTC-1. CombineMask Selection`
- `EMTC-2. Theorem Statement`
- `EMTC-3. Coefficient Distribution Proof`
- `EMTC-4. HighBits Coupling`
- `EMTC-5. Active-Set Binding`
- `EMTC-6. Retry Freshness`
- `EMTC-7. Corrupted Prechallenge Bias`
- `EMTC-8. Epsilon Final Form`
- `EMTC-9. Code Crosswalk`
- `EMTC-10. Acceptance Criteria`
- `EMTC-11. Non-Claims`
- `EMTC-12. Manifest Anchors`
- `eps-mask-formalization-route`
- `Theorem M1-combine-mask-game`
- `Theorem M-close-mask-distribution`
- `CombineMask`
- `HighBits(A_matrix * Y_T)`
- `eps_mask_bound`
- `eps_mask_support`
- `eps_mask_entropy`
- `eps_mask_highbits`
- `eps_mask_active_set`
- `eps_mask_retry_freshness`
- `eps_mask_corrupt_bias`
- `implementation evidence is not cryptographic proof`
- `not a completed mask-distribution proof`
- `not production-ready`
