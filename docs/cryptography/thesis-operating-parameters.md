# Thesis and Operating Parameters

Status: formalized research boundary, pending theorem-closure review.

Date: 2026-06-25

## Scope and Claim Boundary

This document formalizes the current thesis, operating parameters, promotion
criteria, failure criteria, and fallback trigger for the native threshold
ML-DSA-65 path. It is a `research scaffold evidence` contract for reviewer
orientation and assessment tooling.

The thesis identifier is `native-threshold-mldsa65-aggregation-p1`. Current
repository status remains `partially_proven`, with all five hypothesis criteria
still `partially_met`. This document is requires selected-backend proof closure evidence, not
production threshold ML-DSA security, requires CAVP/ACVTS validation evidence, not FIPS
validation, requires rejection-distribution preservation proof, and not a completed
standard-verifier compatibility proof.

The machine-readable companion is
[`thesis-operating-parameters.json`](thesis-operating-parameters.json). That
manifest is a claim-boundary source document, not generated benchmark evidence
and not a production configuration file.

## Thesis Statement

The working thesis is that Profile P1, an ML-DSA-65 coordinator-assisted Shamir
nonce DKG path with a TEE/HSM coordinator assumption, may be able to produce one
native aggregate output that has the shape of one standard-sized ML-DSA-65
signature if proven.

The upside target is standard verifier compatibility: a successful construction
would use the ordinary ML-DSA-65 public key and standard ML-DSA-65 verifier, and
would emit one standard-sized ML-DSA-65 signature if proven. The risk is higher
than proof-wrapper aggregation because the threshold protocol itself must
preserve mask distribution, rejection behavior, partial contribution soundness,
abort/retry bounds, and threshold unforgeability.

## Operating Parameters

- Selected profile: `ML-DSA-65 coordinator-assisted Shamir nonce DKG P1`.
- Feature gate under review: `production-mldsa65-coordinator`.
- Parameter set: `ML-DSA-65`.
- Public key size target: `1952` bytes.
- Signature size target: `3309` bytes.
- Security parameter notation: `lambda`.
- Validator count notation: `n`.
- Threshold notation: `t`, with `1 <= t <= n`.
- Validator set notation: `V`.
- Base corruption model: static corruption of at most `t - 1` validators.
- Output target: one standard-sized ML-DSA-65 signature if proven.

The Batch 4 dependency boundary is the selected-backend proof-closure artifact
package gate. That gate is conformance/proof-review evidence. It is not
selected-backend proof closure and does not promote any criterion by itself.

## Promotion Criteria

Each criterion remains `partially_met` until proof artifacts, backend evidence,
validation evidence, and external review close the criterion-specific blockers.
The current criteria are:

- `aggregate_mask_distribution`: requires a selected-backend mask-generation
  proof artifact, reviewed Renyi divergence bound for `epsilon_mask`, and
  distribution comparison evidence linked from the closure package.
- `aggregate_rejection_equivalence`: requires real threshold aggregate
  recomputation artifacts, standard-verifier compatibility artifact digest and
  reviewer sign-off, and accepted-output rejection-distribution review linked
  to provider evidence.
- `abort_retry_bias`: requires retry transcript domain separation proof,
  selective-abort leakage model and bias bound, and accepted-signature
  distribution analysis across retries.
- `partial_contribution_soundness`: requires production `LocalAccept`
  proof-backed verifier evidence, VSS/DKG binding and hiding proof artifacts,
  and context-binding plus leakage review for accepted partials.
- `unauthorized_aggregate_reduction`: requires a threshold unforgeability
  reduction proof, base ML-DSA theorem dependency and concrete assumption
  mapping, and simulator plus hybrid-bound artifacts with external review.

Promotion is operating-parameter review only until those artifacts are checked
in, linked from the assessment report, and externally reviewed.

## Failure Criteria

The native threshold path should be treated as failed or blocked if any of the
following cannot be repaired inside the Profile P1 assumptions:

- Aggregate masks are distinguishable from the centralized ML-DSA-65 sampling
  model beyond the reviewed bound.
- Accepted threshold outputs fail standard ML-DSA-65 verification or require a
  non-standard verifier.
- Retry timing, abort behavior, or attempt binding biases accepted signatures
  beyond the reviewed proof bound.
- Stale, cross-context, malformed, or leaking partial contributions can pass
  local or aggregate acceptance.
- An unauthorized accepting aggregate cannot be classified as a base ML-DSA
  forgery or a named threshold-side assumption violation.

Failure is not determined by this document alone. It requires reviewed evidence
showing that a criterion cannot be satisfied under the selected assumptions.

## Fallback Trigger

Falcon/LaBRADOR-style proof aggregation is the fallback architecture to
evaluate if native threshold ML-DSA proof closure stalls. It is `evaluate only`;
it is not a selected backend, not a production path, and not a release path.

Any pivot to proof-wrapper aggregation requires separate scheme selection,
prover and verifier benchmarks, audit review, consensus-latency analysis, and
claim-boundary docs. A proof-wrapper path would prove many independent
signatures, while the native threshold thesis targets one standard-verifier
compatible threshold signature.

## Batch 4 Dependency Boundary

Batch 4 added the selected-backend proof-closure artifact package gate. That
gate binds threshold-output, recomputation, provider KAT, rejection behavior,
standard-verifier-compatibility artifact digest, theorem-linkage artifact
digest, and reviewed source-package digest into proof-review evidence.

This evidence is useful for review but remains necessary and not sufficient. It
records remaining theorem review requirements, does not claim production threshold ML-DSA security,
and does not claim that the standard-verifier compatibility target is complete.

## Manifest Anchors

The companion manifest pins:

- `native-threshold-mldsa65-aggregation-p1`
- `research scaffold evidence`
- `ML-DSA-65 coordinator-assisted Shamir nonce DKG P1`
- `one standard-sized ML-DSA-65 signature if proven`
- `partially_proven`
- `partially_met`
- requires selected-backend proof closure evidence
- requires production threshold ML-DSA security evidence
- requires CAVP/ACVTS validation evidence
- requires FIPS validation evidence
- `Falcon/LaBRADOR-style proof aggregation`
- `evaluate only`
