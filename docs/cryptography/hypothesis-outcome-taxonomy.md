# Hypothesis Outcome Taxonomy

Status: reviewer-facing outcome vocabulary, not theorem closure.

Date: 2026-06-30

## Scope

This document defines what failure, partial success, and full success mean for
the lattice aggregation hypothesis tracked by
[`thesis-operating-parameters.md`](thesis-operating-parameters.md),
[`claims-matrix.md`](claims-matrix.md), and
[`scripts/assess_lattice_hypothesis.py`](../../scripts/assess_lattice_hypothesis.py).

The taxonomy applies to the Profile P1 thesis
`native-threshold-mldsa65-aggregation-p1`: an ML-DSA-65 coordinator-assisted
Shamir nonce DKG path that targets one standard-sized ML-DSA-65 signature if
proven. It is a grant-review and proof-planning guide. It does not replace the
assessment script, cryptographic review, release-readiness checklist, or
criterion-specific proof artifacts.

The current repository state is `partially_proven`, with all five tracked
criteria `partially_met`. That means the package is useful as a research-preview
and grant-submission artifact, but it is not selected-backend proof closure,
production threshold ML-DSA security, CAVP/ACVTS validation, FIPS validation, or
a completed standard-verifier-compatible threshold signature scheme.

## Outcome Vocabulary

`completely_proven` means all five hypothesis criteria are `met`, the required
proof artifacts and backend evidence are checked in, external cryptographic
review has accepted the criterion-specific arguments, and the assessment report
can reproduce the result from the repository. This closes the research
hypothesis under the documented assumptions only.

`partially_proven` means at least one criterion has reviewable scaffold,
conformance, proof-slot, or evidence-gate progress and no criterion has been
reviewed as failed. The repository can support grant submissions, technical
review, and research-preview publication when the claim boundary remains
explicit. It cannot support production cryptography claims.

`partially_disproven` means one or more criteria are reviewed as `failed`, but
the failure is not total across the thesis. This is a pivot state: the native
path may need a changed operating profile, a narrower theorem, or evaluation of
Falcon/LaBRADOR-style proof-wrapper aggregation.

`completely_disproven` means all five criteria fail under the stated assumptions
or one reviewed impossibility result invalidates the top-level native threshold
ML-DSA-65 aggregation target. In that state, the native thesis should no longer
be presented as an open route without a materially new assumption set.

## Criterion Status Vocabulary

`met` means the criterion has implementation evidence, proof artifacts,
validation or backend artifacts where applicable, claim-boundary documentation,
and external review sufficient to promote the criterion.

`partially_met` means the repository contains useful typed gates, fixtures,
proof-substance documents, manifests, or assessor-visible evidence, but one or
more proof, backend, validation, or review obligations remain open.

`blocked` means required evidence is absent, dependent artifacts are missing, or
the criterion cannot be evaluated yet from the checked-in material. A blocked
criterion is not a proof failure by itself.

`failed` means reviewed evidence contradicts the criterion under the current
Profile P1 assumptions. A failed criterion should name the contradicted
assumption, the evidence source, and whether the issue is repairable inside P1.

## Failure

Failure means the native threshold path cannot satisfy one or more required
security surfaces under the selected Profile P1 assumptions. A CI failure,
missing artifact, or unreviewed proof gap is not enough by itself; failure
requires reviewed evidence that the criterion is false or cannot be repaired
inside the stated assumptions.

Examples of failure include:

- accepted aggregate outputs cannot verify as standard ML-DSA-65 signatures
  under the same public key and message;
- aggregate masks are distinguishable from centralized ML-DSA-65 masks beyond
  the reviewed `epsilon_mask` bound;
- accepted threshold outputs pass conditions that centralized ML-DSA-65 would
  reject;
- retry timing, abort behavior, or attempt binding biases accepted signatures
  beyond the reviewed bound;
- stale, cross-context, malformed, or leaking partial contributions can be
  accepted;
- an unauthorized accepting aggregate cannot be reduced to a base ML-DSA forgery
  or a named threshold-side assumption violation.

If a failure is repairable by narrowing assumptions, changing parameters, or
replacing a subprotocol, the status is usually `partially_disproven` until the
new profile is documented and reassessed.

## Partial Success

Partial success means the repository is doing useful research work before
theorem closure. In this state, the project may have executable evidence gates,
fixture-backed manifests, proof-substance checklists, claim-boundary docs, and a
reproducible assessment report, while still lacking the final proof artifacts or
review needed for full promotion.

The current repository is in this category. It is appropriate to use for grant
submissions, cryptographer review, technical roadmap discussions, and
research-preview tagging when every public claim says the work is
`partially_proven` / `partially_met` and not production cryptography.

Partial success must not be described as:

- completed theorem closure;
- production threshold ML-DSA security;
- selected-backend proof closure;
- CAVP/ACVTS validation or FIPS validation;
- completed standard-verifier compatibility;
- deployment-ready consensus signing.

## Full Success

Full success means the top-level thesis is closed under the documented
assumptions. All five criteria must be `met`, the assessment verdict must be
`completely_proven`, and the proof package must connect the implementation,
backend artifacts, validation evidence, and external review to the same Profile
P1 assumptions.

Full success for the research hypothesis still does not automatically mean the
software is deployable. The rule is explicit: full hypothesis success is not production release readiness.
Production release language additionally requires malicious-secure DKG review,
side-channel and constant-time review, randomness and erasure review,
FIPS/CAVP-style validation where claimed, operational integration review, and
the gates in the
[`Release Readiness Checklist`](../benchmarks/release-readiness-checklist.md).

## Per-Criterion Outcome Guide

| Criterion | Partial success | Full success | Failure |
| --- | --- | --- | --- |
| `aggregate_mask_distribution` | Mask-distribution evidence gates, Criterion 1 proof-substance payload, selected mask construction slots, and assessor-visible `partially_met` status are present. | Reviewed aggregate-vs-centralized distribution argument, accepted `epsilon_mask` Renyi bound, min-entropy review, selected-backend mask artifact, and external review are complete. | Aggregate masks are distinguishable beyond the reviewed bound or the selected mask construction cannot satisfy the centralized ML-DSA-65 distribution target. |
| `aggregate_rejection_equivalence` | Criterion 2 proof slots, threshold-output certificate fixtures, recomputation slots, standard-verifier compatibility slots, and theorem-linkage artifacts are present as conformance/proof-review evidence. | Real threshold recomputation, accepted-output rejection-distribution review, completed standard-verifier compatibility proof, full validation artifacts, and external review are complete. | Accepted aggregate outputs fail the standard verifier, require a non-standard verifier, or accept outputs outside centralized ML-DSA-65 rejection predicates. |
| `abort_retry_bias` | Retry-domain, leakage, accepted-sample, threshold, and review artifact gates are present. | A concrete retry and timeout policy has a reviewed accepted-sample distribution bound showing aborts and retries do not bias accepted signatures beyond the allowed bound. | Abort timing, retry behavior, or attempt binding lets participants bias accepted outputs beyond the reviewed proof bound. |
| `partial_contribution_soundness` | Typed `LocalAccept`, `AggregateAccept`, accepted-partial evidence, proof-backed verifier scaffolds, and context-binding tests are present. | Production partial-verification predicates, VSS/DKG binding and hiding proofs, leakage review, and local acceptance soundness are complete and externally reviewed. | Stale, cross-context, malformed, or leaking partial contributions can be accepted locally or into an aggregate. |
| `unauthorized_aggregate_reduction` | Reduction cases, classifier slots, simulator slots, and proof-obligation manifests name the required threshold-side assumptions. | Every unauthorized accepting output is covered by a total reduction to base ML-DSA forgery or a named threshold-side assumption violation. | An unauthorized accepting aggregate exists outside all reduction cases or depends on an unnamed/unreviewed assumption. |

## Decision Rules

Use `partially_proven` language for grant submissions and research-preview
materials while any criterion remains `partially_met`, `blocked`, or unreviewed.

Promote a criterion to `met` only when the criterion-specific document,
machine-readable artifacts, implementation evidence, validation or backend
evidence, and external review all point at the same assumption set.

Treat an unrepaired `failed` criterion as a stop condition for native-thesis
promotion. If repair requires new assumptions, document a new profile before
claiming renewed progress.

Treat Falcon/LaBRADOR-style proof-wrapper aggregation as an evaluation fallback,
not as a hidden replacement for the native threshold thesis.
