# FST-L5 Aggregation Correctness Worksheet
<a id="fst-l5-aggregation-correctness"></a>

Date: 2026-05-28

Status: reduction worksheet for `FST-L5`, not a completed aggregation
correctness proof.

## FSTL5-0. Scope and Non-Claim
<a id="fstl5-scope-non-claim"></a>

This worksheet expands the `FST-L5` aggregation correctness lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It connects
threshold recombination, rejection-predicate equivalence, and standard
ML-DSA-65 verification compatibility.

This document does not prove accepted threshold outputs verify under the
unmodified ML-DSA-65 verifier. It does not close `eps_rej`, `eps_verify`,
`eps_mask`, or `eps_collect`.

## FSTL5-1. Theorem Context
<a id="fstl5-theorem-context"></a>

`FST-L5` is consumed by the S6 to S7 authorized signature replacement step.
That transition replaces accepted threshold aggregates on authorized messages
with signatures released by `F_TMLDSA`, paying the rejection-sampling and
release residuals when aggregation does not match centralized ML-DSA-65.

The immediate IdealVSS lemma skeleton records the open residual:

```text
eps_rej + eps_verify
```

## FSTL5-2. Inputs and Candidate Values
<a id="fstl5-inputs-candidate-values"></a>

Inputs include `PartialShareSet`, `AggregateOutputRecord`, the active set,
`ChallengeRecord`, message or `mu`, `pk_epoch`, contribution statements,
Lagrange coefficients, aggregate candidate values, final `c_tilde`, `z`, and
hint `h`.

The threshold rejection predicate is written `Reject_T`; the centralized
ML-DSA predicate is written `Reject_0`. `FST-L5` must prove these predicates
agree on the same candidate values or carry the mismatch in `eps_rej` and
`eps_verify`.

## FSTL5-3. Aggregation-Correctness Statement
<a id="fstl5-lemma-statement"></a>
<a id="fstl5-aggregation-correctness-statement"></a>

Target lemma:

```text
FST-L5:
  If at least t valid partial shares are accepted for the same transcript,
  aggregation outputs sigma such that
  MLDSA65.Verify(pk_epoch, M, sigma) = accept,
  except through eps_rej, eps_verify, eps_collect, or named upstream terms.
```

The statement is conditional on `FST-L1` through `FST-L4`, the IdealVSS setup
boundary, canonical active-set equality, and selected contribution validity.

## FSTL5-4. Reconstruction Obligations
<a id="fstl5-reconstruction-obligations"></a>

### Aggregation Input Invariants
<a id="fstl5-aggregation-input-invariants"></a>

Before aggregation, the proof must establish:

- all counted contributions are unique, in-set, and threshold sufficient;
- every contribution binds the same `SigningContext`, `ChallengeRecord`,
  `dkg_digest`, public key, message representative, and active set;
- all contribution statements pass `FST-L4` validity;
- the Lagrange active set used in recombination is the active set committed in
  the challenge and aggregate output;
- malformed encodings and stale attempts are rejected before recombination.

### Recombination Correctness Target
<a id="fstl5-recombination-correctness-target"></a>

The algebraic target is coefficientwise reconstruction over the ML-DSA-65
module components:

```text
AggregatePartial(A, {partial_i}_{i in A})
  = centralized_response(sk_epoch, y, c)
```

for the same challenge `c`, aggregate mask `y`, epoch secret represented by
`F_VSS_DKG`, and active set `A`.

This requires Lagrange interpolation correctness, coefficient-domain and NTT
domain consistency where applicable, canonical coefficient reduction, and
active-set equality across all polynomial and vector components.

## FSTL5-5. Rejection-Predicate and Bound Obligations
<a id="fstl5-rejection-predicate-bound-obligations"></a>

### Rejection Predicate Equivalence
<a id="fstl5-rejection-predicate-equivalence"></a>

The accepted aggregate must satisfy the same rejection predicates as
centralized ML-DSA-65 on the same candidate values. The route is:

```text
eps_rej
  <= eps_bound_encoding
   + eps_z_bound
   + eps_lowbits
   + eps_ct0
   + eps_hint
   + eps_challenge
   + eps_active_set
   + eps_malformed
   + eps_verify_mismatch
```

The final theorem must decide whether `eps_verify_mismatch` is absorbed into
`eps_rej` or carried as a separate `eps_verify` term.

## FSTL5-6. Standard Verification Compatibility
<a id="fstl5-standard-verification-compatibility"></a>

The final output must be a standard-size ML-DSA-65 signature and must verify
through the unmodified verifier:

```text
MLDSA65.Verify(pk_epoch, M, sigma) = accept
```

The proof must fix whether the theorem is stated over an external message `M`,
internal `mu`, or a proved consistent pair. It must also prove byte-level
signature layout, challenge encoding, hint encoding, high-bit reconstruction,
and verifier-side malformed input rejection.

## FSTL5-7. Implementation Evidence Crosswalk
<a id="fstl5-implementation-evidence-crosswalk"></a>

Relevant implementation evidence includes:

- `src/aggregation.rs` for aggregate assembly boundaries;
- `src/crypto/interpolation.rs` and `src/crypto/vss.rs` for Lagrange and
  coefficient-lane reconstruction scaffolding;
- `src/collections.rs` for canonical collection evidence;
- `SimulatedBackend` for non-production protocol flow tests;
- `src/low_level/mldsa65.rs` and hazmat tests for standard-size verifier
  compatibility experiments.

These artifacts are evidence inputs only. The implementation tests are
evidence only, not proof.

## FSTL5-8. Residual Terms
<a id="fstl5-residual-terms"></a>

Direct residuals are `eps_rej` and `eps_verify`.

Related prerequisites that must stay visible are `eps_collect`, `eps_contrib`,
`eps_ro_prior`, `eps_ro_replay`, `eps_commit_context`, `eps_mask`, and
`implementation_residual`. They cannot be silently absorbed into aggregation
success.

### Bad Events and Accounting
<a id="fstl5-bad-events-accounting"></a>

The worksheet tracks:

- `BadAggCorrect`: an aggregate is accepted but does not correspond to the
  centralized ML-DSA verification relation.
- `BadRejectDist`: the threshold accepted-signature distribution differs from
  centralized ML-DSA beyond the rejection-sampling bound.
- `BadVerifyMismatch`: final bytes pass the threshold predicate but fail the
  standard verifier.
- `BadActiveSetRebind`: recombination uses a different active set from the
  transcript.
- `BadMalformedAggregate`: malformed contribution or output bytes are accepted.

Each failure is charged to `eps_rej`, `eps_verify`, `eps_collect`,
`eps_contrib`, `eps_ro`, or `eps_mask`, not hidden inside implementation
success tests.

## FSTL5-9. Proof Skeleton
<a id="fstl5-proof-skeleton"></a>

The intended proof is:

1. Use `FST-L3` and `FST-L4` to restrict aggregation inputs to valid, bound,
   threshold-sufficient contributions.
2. Apply Lagrange reconstruction to the selected active set.
3. Prove aggregate candidate values equal the centralized candidate values.
4. Prove threshold and centralized rejection predicates match on those values.
5. Prove emitted bytes verify under the unmodified ML-DSA-65 verifier.

## FSTL5-10. Dependencies
<a id="fstl5-dependencies"></a>

`FST-L5` depends on:

- `FST-L1` transcript injectivity;
- `FST-L2` challenge binding;
- `FST-L3` collection and active-set soundness;
- `FST-L4` contribution validity;
- coefficient-lane Shamir reconstruction;
- rejection predicate equivalence;
- standard verifier compatibility.

## FSTL5-11. Acceptance Criteria
<a id="fstl5-acceptance-criteria"></a>

Before `FST-L5` can be treated as proved:

- the recombination equation is stated for every ML-DSA-65 module component;
- active-set equality is proved across transcript and interpolation inputs;
- aggregate and centralized rejection predicates are proved equivalent;
- the final verifier theorem fixes `M` versus `mu`;
- `eps_verify` is either eliminated, absorbed into `eps_rej` with proof, or
  carried visibly.

## FSTL5-12. Non-Claims
<a id="fstl5-non-claims"></a>

This worksheet does not claim aggregation correctness is proved. It does not
prove distributional equivalence of aggregate masks, rejection-sampling
preservation, standard-verifier compatibility, or production readiness.

## FSTL5-13. Manifest Anchors
<a id="fstl5-manifest-anchors"></a>

- `# FST-L5 Aggregation Correctness Worksheet`
- `fst-l5-aggregation-correctness`
- `FSTL5-0. Scope and Non-Claim`
- `FSTL5-1. Theorem Context`
- `FSTL5-2. Lemma Statement`
- `FSTL5-2. Inputs and Candidate Values`
- `FSTL5-3. Aggregation-Correctness Statement`
- `FSTL5-4. Reconstruction Obligations`
- `FSTL5-5. Rejection-Predicate and Bound Obligations`
- `FSTL5-6. Standard Verification Compatibility`
- `FSTL5-7. Implementation Evidence Crosswalk`
- `FSTL5-8. Residual Terms`
- `FSTL5-9. Proof Skeleton`
- `FSTL5-10. Dependencies`
- `FSTL5-11. Acceptance Criteria`
- `FSTL5-12. Non-Claims`
- `FST-L5`
- `AggregateOutputRecord`
- `PartialShareSet`
- `SimulatedBackend`
- `Reject_T`
- `Reject_0`
- `AggregatePartial`
- `MLDSA65.Verify(pk_epoch, M, sigma) = accept`
- `eps_rej`
- `eps_verify`
- `eps_collect`
- `eps_mask`
- `BadAggCorrect`
- `BadRejectDist`
- `BadVerifyMismatch`
- `BadActiveSetRebind`
- `eps_verify_mismatch`
- `implementation tests are evidence only, not proof`
