# Criterion 3 Proof Substance

Status: `formalized_open_proof_payload`, not criterion closure.

Date: 2026-06-30

## Scope and Claim Boundary

This document defines the proof payload still required for Criterion 3,
`abort_retry_bias`. It turns the existing abort-bias audit scaffolding into a
reviewer-facing proof-substance checklist for retry transcript binding,
observable abort leakage, and accepted-signature distribution preservation. It
does not change the criterion status.

The current criterion status remains `partially_met`, and the overall
assessment remains `partially_proven`. This contract requires selected-backend proof closure evidence, requires production threshold ML-DSA security evidence, requires CAVP/ACVTS validation evidence, requires FIPS validation evidence, requires accepted-signature distribution preservation proof, requires a completed Fiat-Shamir-with-aborts preservation proof, and
requires a completed abort/retry-bias proof.

The machine-readable companion is
[`criterion-3-proof-substance.json`](criterion-3-proof-substance.json). Its
report status is `criterion3_proof_payload_formalized`.

## Proof Payload Statement

Criterion 3 closes only if the selected Profile P1 proof package establishes
that aborts, timeouts, and retries cannot bias accepted threshold signatures
beyond the reviewed bound.

The retry domain that must be bound into the transcript is:

```text
session_id + attempt_id + retry_counter
```

The accepted-signature target is:

```text
accepted threshold signatures remain unbiased under the reviewed abort and retry policy
```

Digest plumbing, local deterministic checks, and audit scaffolding are not
enough. The proof payload must bind retry-domain separation, a formal abort
leakage model, accepted-signature distribution proof, adversarial abort-policy
corpus, sample-size and bucket rationale, timeout/retry policy, and external
review over the same selected assumptions.

## Required Artifact Slots

The Criterion 3 proof payload requires these slots before any promotion:

- `retry_domain_separation_proof_digest`: `required_unclosed` from
  `p1_criterion3_retry_domain_separation_artifact_gate`
  (`p1_criterion3_proof_payload_package`).
- `formal_abort_leakage_model_digest`: `required_unclosed` from
  `p1_criterion3_abort_leakage_model_artifact_gate`
  (`p1_criterion3_proof_payload_package`).
- `accepted_signature_distribution_proof_digest`: `required_unclosed` from
  `p1_criterion3_accepted_signature_distribution_artifact_gate`
  (`p1_criterion3_proof_payload_package`).
- `adversarial_abort_policy_corpus_digest`: `required_unclosed` from
  `p1_criterion3_adversarial_abort_policy_corpus_artifact_gate`
  (`p1_criterion3_proof_payload_package`).
- `sample_size_bucket_rationale_digest`: `required_unclosed` from
  `p1_criterion3_sample_size_bucket_rationale_artifact_gate`
  (`p1_criterion3_proof_payload_package`).
- `timeout_retry_policy_digest`: `required_unclosed` from
  `p1_criterion3_timeout_retry_policy_artifact_gate`
  (`p1_criterion3_proof_payload_package`).
- `external_review_digest`: `required_unclosed` from
  `p1_criterion3_external_review_artifact_gate`
  (`p1_criterion3_proof_payload_package`).

Every slot remains `required_unclosed`. The existing `AbortBiasEvidence`,
`AbortRetryBiasProofPackage`, and `AbortBiasClosureReport` surfaces are useful
conformance and proof-review scaffolding, but they do not provide the real
Fiat-Shamir-with-aborts preservation proof or external review needed for
criterion promotion. The slot claim boundary is
`conformance/proof-review evidence`.

## Theorem Links

The proof payload must link the artifact package to the theorem and lemma
surfaces that actually carry Criterion 3:

- `Noise Lemma G`: abort and retry bias.
- `Noise Lemma H`: accepted-signature distribution.
- `FST-L7`: abort and rejection compatibility.
- `FST-L9`: retry transcript and domain-separation compatibility.

## Promotion Requirements

Criterion 3 remains `partially_met` until all of the following are reviewed and
linked:

- retry transcript domain separation over `session_id`, `attempt_id`, and
  `retry_counter`;
- formal abort leakage model matching the public observable set;
- accepted-signature distribution proof under the reviewed abort and retry
  policy;
- adversarial abort-policy corpus covering rushing, selective abort, malformed
  commitment, omitted partial, and retry-exhaustion policies;
- sample-size bucket rationale for the reviewed evidence corpus;
- timeout and retry policy bound to the production transcript;
- external cryptographic review of the exact digests and assumptions.

The existing abort-bias closure package is necessary but not sufficient for
criterion-3 promotion. Audit scaffolding means the framework has a complete
shape for proof review; it does not mean the construction has been proved to
preserve ML-DSA Fiat-Shamir accepted-signature behavior under aborts and
retries.

## Failure Conditions

Criterion 3 fails or remains blocked if any condition is observed and cannot be
repaired within the selected Profile P1 assumptions:

- retry timing or attempt identifiers let participants bias accepted outputs
  beyond the reviewed bound;
- local aborts reveal secret-dependent information that is not public or
  simulatable;
- accepted-sample evidence exceeds the reviewed bias bound.

These failure conditions are proof-review conditions, not claims that the
native path has already failed.

## Assessment Boundary

The assessor may report `criterion3_proof_payload_formalized` when this
contract and its manifest are present and internally consistent. That report
field keeps `abort_retry_bias` at `partially_met`, keeps the overall verdict at
`partially_proven`, and records the remaining theorem review requirements.
