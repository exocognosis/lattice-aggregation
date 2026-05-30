# eps_mask Formalization Route
<a id="eps-mask-formalization-route"></a>

Status: formalization roadmap for eps_mask, not a completed proof and not a
production mask-distribution theorem.

This document gives the game shape and proof obligations needed to formalize
the aggregate mask distribution route. It is a route for closing the residual
term, not evidence that the residual is zero, negligible, or already closed.

## EMFR-0. Scope
<a id="emfr-scope"></a>

The route covers the pre-rejection mask-distribution step that compares a
threshold aggregate mask to centralized ML-DSA-65 mask sampling. It fixes the
interface names that later proof work must instantiate and keeps all mismatch
terms visible until a selected production `CombineMask` family discharges them.

The proof object must reason about the joint distribution:

```text
(Y_T, HighBits(A_matrix * Y_T), T, retry_index, public_context)
```

and not only about isolated coefficient ranges or implementation tests.

## EMFR-1. Game Interface
<a id="emfr-game-interface"></a>

The formal game is parameterized by:

```text
lambda        security parameter
pk            public key or public verification context
mu            message binding used by the ML-DSA challenge route
A_matrix      public ML-DSA matrix derived from pk context
T             active signer set for this attempt
retry_index   monotonically increasing attempt identifier
rho           typed retry context
Corrupt       adversarial corrupted-contribution interface
CombineMask   selected aggregate-mask protocol family
```

The retry context is part of the sampled object:

```text
rho = Enc(domain, session_id, pk_id, mu, T, retry_index)
```

`retry_index` must be injective within one session and must bind into every
mask seed, opening, contribution validation statement, challenge-oracle input,
and aggregate transcript record that can affect the mask route.

The active set `T` is the set of signers whose mask contributions are accepted
for this attempt. The same `T` must be used by `CombineMask`, contribution
validation, challenge derivation, rejection checks, release records, and final
output metadata. If a different document uses `A` for the active set, this
roadmap treats that `A` as the same object as `T`.

## EMFR-2. CombineMask Shape
<a id="emfr-combinemask-shape"></a>

`CombineMask` is an explicit probabilistic or deterministic interface:

```text
CombineMask(pk, mu, A_matrix, T, rho, retry_index, Open_T, Corrupt)
  -> Y_T or reject
```

where:

```text
Open_T = { open_i : i in T and i is honest or accepted }
```

and `Corrupt` exposes exactly the corrupted prechallenge contribution surface:

```text
Corrupt.choose(ctx, T, rho, retry_index, commitments, validation_rules)
  -> corrupted openings, malformed encodings, omissions, or abort markers
```

The interface boundary is prechallenge only. Postchallenge withholding,
timeouts, retry forcing, and selective release are not hidden inside
`CombineMask`; they must be routed to their own residual terms.

Candidate instantiations may be additive, Lagrange-weighted, MPC/ideal, or
dealer-aided, but this document does not select one. A production proof must
select one exact equation or ideal functionality before claiming closure.

## EMFR-3. Sampled Variables
<a id="emfr-sampled-variables"></a>

The threshold game samples or receives accepted mask material, then computes:

```text
Y_T = CombineMask(pk, mu, A_matrix, T, rho, retry_index, Open_T, Corrupt)
W_T = HighBits(A_matrix * Y_T)
```

The centralized reference game samples:

```text
Y_0 <- ML-DSA-65 centralized mask sampler for (pk, mu, rho)
W_0 = HighBits(A_matrix * Y_0)
```

The comparison object is:

```text
View_T = (Y_T, W_T, T, retry_index, rho)
View_0 = (Y_0, W_0, T, retry_index, rho)
```

The proof must account for all `L_65 * N` coefficients of `Y_T`, the module
dimensions, coefficient centering, support bounds, seed expansion, and the
deterministic `HighBits(A_matrix * Y_T)` map.

## EMFR-4. Theorem Target
<a id="emfr-theorem-target"></a>

```text
Theorem M1-combine-mask-game.
For every admissible pk, mu, A_matrix, active set T, retry_index, rho,
adversary-controlled corrupted contribution interface Corrupt, and selected
production CombineMask family, the statistical distance between the threshold
view and centralized reference view satisfies

Delta(View_T, View_0) <= eps_mask(lambda, T, rho, retry_index, Corrupt)

where

eps_mask
 <= eps_mask_support
  + eps_mask_entropy
  + eps_mask_highbits
  + eps_mask_active_set
  + eps_mask_retry_freshness
  + eps_mask_corrupt_bias.
```

The theorem is a target statement. This document does not prove it.

## EMFR-5. Residual Decomposition
<a id="emfr-residual-decomposition"></a>

The residual must remain decomposed into visible subterms:

- `eps_mask_support`: `Y_T` may leave the centralized ML-DSA-65 support, use
  different centering, or expose invalid coefficient/module dimensions.
- `eps_mask_entropy`: honest contribution material may fail freshness,
  independence, unpredictability, or sampler-equivalence requirements.
- `eps_mask_highbits`: even if `Y_T` is close in coefficient distribution,
  the joint pair `(Y_T, HighBits(A_matrix * Y_T))` may diverge from the
  centralized pair.
- `eps_mask_active_set`: the active set used by contribution acceptance,
  aggregation, challenge derivation, retry context, and output records may be
  inconsistent.
- `eps_mask_retry_freshness`: retries may reuse seeds, openings, transcript
  inputs, or challenge domains, or may condition later masks on rejected
  attempts.
- `eps_mask_corrupt_bias`: corrupted parties may bias prechallenge mask
  material through malformed openings, selective valid contributions, or
  contribution choices that remain inside validation but skew the aggregate.

The final accounting may map these subterms to a single
`eps_mask_bound(lambda, T, rho, retry_index)` only after a selected
`CombineMask` family proves the mapping.

## EMFR-6. Closure Acceptance Criteria
<a id="emfr-closure-acceptance-criteria"></a>

To actually close `eps_mask`, later proof work must provide:

- one selected production `CombineMask` family and a fixed transcript grammar;
- a coefficient-level distribution proof for all ML-DSA-65 mask coordinates;
- a support proof matching the centralized sampler, including centering and
  module dimensions;
- an entropy and independence proof for honest mask material under typed
  retry contexts;
- a coupling proof for `(Y_T, HighBits(A_matrix * Y_T))`, not only `Y_T`;
- active-set identity across commitments, openings, aggregation, challenge
  derivation, rejection checks, release records, and final output;
- retry freshness and injectivity proofs for `retry_index` and `rho`;
- a corrupted prechallenge contribution boundary and bias bound;
- explicit accounting showing how each visible subterm is discharged or added
  to the final accepted-distribution theorem;
- a statement preserving `eps_mask` or `eps_mask_bound` unless exact
  distribution equality is proved.

## EMFR-7. Non-Claims
<a id="emfr-non-claims"></a>

This document makes these non-claims:

- no centralized-distribution claim is made by this roadmap;
- the threshold aggregate mask has the centralized ML-DSA-65 distribution;
- `eps_mask = 0`;
- `eps_mask` is negligible;
- the route is production-ready or production-ready evidence;
- implementation evidence is not cryptographic proof;
- tests, simulations, or hazmat bridge checks close any residual subterm;
- postchallenge withholding or retry forcing can be charged to
  `eps_mask_corrupt_bias`.

## EMFR-8. Manifest Anchors
<a id="emfr-manifest-anchors"></a>

Stable strings:

- `# eps_mask Formalization Route`
- `eps-mask-formalization-route`
- `Status: formalization roadmap for eps_mask`
- `EMFR-0. Scope`
- `EMFR-1. Game Interface`
- `EMFR-2. CombineMask Shape`
- `EMFR-3. Sampled Variables`
- `EMFR-4. Theorem Target`
- `EMFR-5. Residual Decomposition`
- `EMFR-6. Closure Acceptance Criteria`
- `EMFR-7. Non-Claims`
- `EMFR-8. Manifest Anchors`
- `Theorem M1-combine-mask-game`
- `CombineMask`
- `Y_T`
- `HighBits(A_matrix * Y_T)`
- `T`
- `retry_index`
- `Corrupt`
- `eps_mask_support`
- `eps_mask_entropy`
- `eps_mask_highbits`
- `eps_mask_active_set`
- `eps_mask_retry_freshness`
- `eps_mask_corrupt_bias`
- `no centralized-distribution claim`
- `implementation evidence is not cryptographic proof`
- `not production-ready`
