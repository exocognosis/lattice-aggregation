# FST-L5 Aggregation Correctness Worksheet
<a id="fst-l5-aggregation-correctness"></a>

Date: 2026-05-28

Status: theorem-closure worksheet for `FST-L5`, not a completed aggregation
correctness proof.

## FSTL5-0. Scope and Non-Claim
<a id="fstl5-scope-non-claim"></a>

This worksheet expands the `FST-L5` aggregation correctness lemma from
[formal-security-theorem.md](formal-security-theorem.md) and
[idealvss-lemma-skeleton.md](idealvss-lemma-skeleton.md). It connects
threshold recombination, rejection-predicate equivalence, and standard
ML-DSA-65 verification compatibility.

This document states a conditional aggregation-correctness route. It is not an
accepted-distribution proof, not a production verifier proof, and not a claim
that accepted threshold outputs always verify under every deployment verifier.
It does not close `eps_rej`, `eps_verify`, `eps_mask`, or `eps_collect`.

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

Definitions used by the closure route:

- `PartialShareSet` is the canonical, threshold-sufficient set of accepted
  per-signer contribution records selected for one transcript. Each entry
  includes the signer identifier, contribution bytes, contribution validity
  evidence, and bindings to the same `ChallengeRecord`, message representative,
  `pk_epoch`, `dkg_digest`, and active set.
- The active set `A` is the ordered set of signer identifiers committed by the
  accepted transcript and used to compute Lagrange coefficients. Equality of
  active sets is byte-canonical equality, not set equality after local sorting
  or deduplication.
- `AggregatePartial(A, {partial_i}_{i in A})` is the deterministic
  recombination algorithm that consumes exactly the shares indexed by `A`,
  applies the Lagrange coefficients for `A`, and emits aggregate candidate
  values before final byte encoding.
- `AggregateOutputRecord` is the deterministic aggregate record emitted from an
  accepted `PartialShareSet` and `ChallengeRecord`. It contains the committed
  active set, aggregate candidate values, reconstructed `z`, hint `h`,
  `c_tilde`, encoded signature bytes `sigma`, and enough transcript bindings to
  re-check the challenge, rejection predicates, and byte layout.

The threshold rejection predicate is written `Reject_T`; the centralized
ML-DSA predicate is written `Reject_0`. `FST-L5` must prove these predicates
agree on the same candidate values or carry the mismatch in `eps_rej` and
`eps_verify`.

`Reject_T` is the threshold-side decision predicate over aggregate candidate
values and transcript bindings before release. `Reject_0` is the corresponding
centralized ML-DSA-65 rejection predicate over the reconstructed candidate
values. Predicate compatibility is conditional on both predicates being
evaluated on the same challenge, active set, message representative, candidate
`z`, high-bit value, and hint.

## FSTL5-3. Aggregation-Correctness Statement
<a id="fstl5-lemma-statement"></a>
<a id="fstl5-aggregation-correctness-statement"></a>

Conditional theorem statement:

```text
FST-L5:
  Given an accepted PartialShareSet P and accepted ChallengeRecord C for
  pk_epoch and message representative mu, there is a unique
  AggregateOutputRecord O = AggregatePartial(active(C), P) such that O's
  reconstructed z, h, challenge c or c_tilde, and signature bytes sigma match
  the accepted active set and transcript.

  If O does not match the centralized ML-DSA-65 candidate relation for the same
  pk_epoch, mu, challenge, and active set, then one named bad event fires:
  BadAggCorrect, BadRejectDist, BadVerifyMismatch, BadActiveSetRebind, or a
  named residual charged to eps_rej, eps_verify, eps_collect, eps_mask, or
  eps_verify_mismatch.
```

The statement is conditional on `FST-L1` through `FST-L4`, the IdealVSS setup
boundary, canonical active-set equality, and selected contribution validity.
It proves a conditional aggregation-correctness route for accepted inputs; it
does not prove that the accepted-output distribution is identical to centralized
ML-DSA-65, and it does not certify a production verifier implementation.

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

If any item fails for an accepted input, the route exits through
`BadAggCorrect`, `BadActiveSetRebind`, `eps_collect`, or an upstream collection
residual rather than continuing as a successful aggregation proof.

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

Uniqueness follows from deterministic canonicalization: for fixed accepted
`PartialShareSet`, `ChallengeRecord`, and active set `A`, there is one ordered
share vector, one Lagrange coefficient vector, one aggregate candidate tuple,
and one byte encoding. A second accepted `AggregateOutputRecord` for the same
inputs must therefore have byte-identical `z`, `h`, `c_tilde`, `sigma`, and
active-set binding, or it triggers `BadAggCorrect` or
`BadActiveSetRebind`.

## FSTL5-5. Rejection-Predicate and Bound Obligations
<a id="fstl5-rejection-predicate-bound-obligations"></a>

### Rejection Predicate Equivalence
<a id="fstl5-rejection-predicate-equivalence"></a>

The accepted aggregate must satisfy the same rejection predicates as
centralized ML-DSA-65 on the same candidate values. The route is conditional:
prove `Reject_T(candidate) = Reject_0(candidate)`, or charge the mismatch
explicitly. The accounting route is:

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

The compatibility boundary is the standard ML-DSA-65 verification relation over
the emitted bytes:

```text
MLDSA65.Verify(pk_epoch, M, sigma) = accept
```

This worksheet does not prove the production verifier. It requires a theorem
that the aggregate output bytes are standard-size ML-DSA-65 signature bytes for
the same `pk_epoch` and a proved-consistent external message `M` or internal
`mu`. It must also prove byte-level signature layout, challenge encoding, hint
encoding, high-bit reconstruction, and verifier-side malformed input rejection.
If those byte-level obligations are not met, the route exits through
`BadVerifyMismatch`, `eps_verify`, or `eps_verify_mismatch`.

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
`implementation_residual`. The verifier-compatibility residual
`eps_verify_mismatch` also stays visible until explicitly absorbed by a proved
predicate-equivalence or verifier-compatibility lemma. These terms cannot be
silently absorbed into aggregation success.

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
`eps_contrib`, `eps_ro`, `eps_mask`, or `eps_verify_mismatch`, not hidden
inside implementation success tests.

## FSTL5-9. Proof Skeleton
<a id="fstl5-proof-skeleton"></a>

The intended proof is:

1. Use `FST-L3` and `FST-L4` to restrict aggregation inputs to valid, bound,
   threshold-sufficient contributions.
2. Apply Lagrange reconstruction to the selected active set.
3. Prove aggregate candidate values equal the centralized candidate values.
4. Prove threshold and centralized rejection predicates match on those values.
5. Prove emitted bytes verify under the unmodified ML-DSA-65 verifier.

Required case split:

- Lagrange coefficient mismatch: if coefficients are not exactly those for the
  accepted active set, reconstruction is not the theorem target and the run is
  charged to `BadAggCorrect` or `BadActiveSetRebind`.
- Duplicate or missing share: if canonical collection accepts two shares for
  one signer, omits a signer in `A`, or includes an out-of-set signer, the run
  exits through `eps_collect` or `BadAggCorrect`.
- Wrong active set: if recombination, challenge binding, output binding, and
  contribution statements do not name the same ordered `A`, charge
  `BadActiveSetRebind`.
- Challenge mismatch: if any accepted contribution or output uses a different
  `ChallengeRecord`, `c_tilde`, message representative, or transcript digest,
  charge the challenge-binding residual from `FST-L2` or `BadAggCorrect`.
- Rejection predicate mismatch: if `Reject_T` and `Reject_0` disagree on the
  same candidate tuple, charge `eps_rej`, `eps_verify`, or
  `eps_verify_mismatch`; do not treat the aggregate as closed.
- Byte-layout mismatch: if the reconstructed tuple does not encode to the
  claimed standard ML-DSA-65 signature bytes, charge `BadVerifyMismatch` or
  `eps_verify_mismatch`.
- High-bit or hint mismatch: if verifier-side high-bit reconstruction or hint
  decoding differs from threshold-side candidate construction, charge
  `eps_rej`, `BadVerifyMismatch`, or `eps_verify_mismatch`.
- Standard verifier mismatch: if the threshold predicate accepts but
  `MLDSA65.Verify(pk_epoch, M, sigma) = accept` is false for the
  proved-consistent message, charge `BadVerifyMismatch` and carry
  `eps_verify`.

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
- uniqueness of `AggregateOutputRecord` is proved for each accepted
  `PartialShareSet` and `ChallengeRecord`;
- active-set equality is proved across transcript and interpolation inputs;
- aggregate and centralized rejection predicates are proved equivalent;
- the final verifier theorem fixes `M` versus `mu`;
- `eps_verify` is either eliminated, absorbed into `eps_rej` with proof, or
  carried visibly.

## FSTL5-12. Non-Claims
<a id="fstl5-non-claims"></a>

This worksheet does not claim aggregation correctness is proved. It does not
prove accepted-output distributional equivalence, distributional equivalence of
aggregate masks, rejection-sampling preservation, standard-verifier
compatibility, or production readiness.

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
