# Criterion 1 Proof Substance

Status: `formalized_open_proof_payload`, not criterion closure.

Date: 2026-06-30

## Scope and Claim Boundary

This document defines the proof payload still required for Criterion 1,
`aggregate_mask_distribution`. It turns the existing mask-distribution evidence
gate and closure-package framework into a reviewer-facing proof-substance
checklist. It does not change the criterion status.

The current criterion status remains `partially_met`, and the overall
assessment remains `partially_proven`. This contract is not selected-backend proof closure, not production threshold ML-DSA security, not CAVP/ACVTS validation, not FIPS validation, not rejection-distribution preservation, and not a completed mask-distribution proof.

The machine-readable companion is
[`criterion-1-proof-substance.json`](criterion-1-proof-substance.json). Its
report status is `criterion1_proof_payload_formalized`.

## Proof Payload Statement

Criterion 1 closes only if the selected Profile P1 proof package establishes a
reviewed bound between the aggregate-mask behavior and the centralized ML-DSA-65
mask distribution.

The centralized target is:

```text
centralized ML-DSA-65 mask distribution
```

The aggregate target is:

```text
selected Profile P1 aggregate mask distribution
```

The distance measure required for the first proof package is:

```text
Renyi divergence bound for epsilon_mask
```

Digest plumbing and framework readiness are not enough. The proof payload must
bind the selected construction, distribution artifacts, Renyi-divergence
argument, min-entropy review, parameter selection, and external review over the
same assumptions.

## Required Artifact Slots

The Criterion 1 proof payload requires these slots before any promotion:

- `selected_mask_construction_digest`: `required_unclosed` from
  `p1_criterion1_mask_construction_artifact_gate`
  (`p1_criterion1_proof_payload_package`).
- `centralized_distribution_artifact_digest`: `required_unclosed` from
  `p1_criterion1_centralized_distribution_artifact_gate`
  (`p1_criterion1_proof_payload_package`).
- `aggregate_distribution_artifact_digest`: `required_unclosed` from
  `p1_criterion1_aggregate_distribution_artifact_gate`
  (`p1_criterion1_proof_payload_package`).
- `renyi_bound_proof_digest`: `required_unclosed` from
  `p1_criterion1_renyi_bound_proof_artifact_gate`
  (`p1_criterion1_proof_payload_package`).
- `min_entropy_review_digest`: `required_unclosed` from
  `p1_criterion1_min_entropy_review_artifact_gate`
  (`p1_criterion1_proof_payload_package`).
- `parameter_selection_digest`: `required_unclosed` from
  `p1_criterion1_parameter_selection_artifact_gate`
  (`p1_criterion1_proof_payload_package`).
- `external_review_digest`: `required_unclosed` from
  `p1_criterion1_external_review_artifact_gate`
  (`p1_criterion1_proof_payload_package`).

Every slot remains `required_unclosed`. The existing
`MaskDistributionEvidence`, `AcceptedMaskDistributionCertificate`, and
`MaskDistributionClosurePackage` surfaces are useful conformance and
proof-review scaffolding, but they do not provide the real Renyi-bound artifact
or external review needed for criterion promotion. The slot claim boundary is
`conformance/proof-review evidence only`.

## Theorem Links

The proof payload must link the artifact package to the theorem and lemma
surfaces that actually carry Criterion 1:

- `Noise Lemma B`: aggregate mask distribution.
- `Noise Lemma H`: accepted-signature distribution.
- `Correctness Lemma 8`: norm, hint, and challenge-bound preservation.
- `FST-L7`: abort and rejection compatibility.

## Promotion Requirements

Criterion 1 remains `partially_met` until all of the following are reviewed and
linked:

- selected aggregate-mask construction and parameter family;
- centralized ML-DSA-65 reference distribution artifact;
- selected Profile P1 aggregate-mask distribution artifact;
- reviewed Renyi-divergence proof for `epsilon_mask`;
- reviewed aggregate-mask min-entropy argument;
- external cryptographic review of the exact digests and assumptions.

The existing mask-distribution closure package is necessary but not sufficient
for criterion-1 promotion. `is_closure_ready()` means the framework has a
complete shape for proof review; it does not mean the construction has been
proved against centralized ML-DSA-65 masks.

## Failure Conditions

Criterion 1 fails or remains blocked if either condition is observed and cannot
be repaired within the selected Profile P1 assumptions:

- aggregate masks are distinguishable from centralized ML-DSA-65 masks beyond
  the accepted `epsilon_mask` bound;
- aggregate-mask min-entropy is below the selected security threshold.

These failure conditions are proof-review conditions, not claims that the
native path has already failed.

## Assessment Boundary

The assessor may report `criterion1_proof_payload_formalized` when this
contract and its manifest are present and internally consistent. That report
field does not change `aggregate_mask_distribution` from `partially_met`, does
not change the overall verdict from `partially_proven`, and does not close the
theorem.
