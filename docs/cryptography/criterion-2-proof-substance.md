# Criterion 2 Proof Substance

Status: `formalized_open_proof_payload`, not criterion closure.

Date: 2026-06-25

## Scope and Claim Boundary

This document defines the proof payload still required for Criterion 2,
`aggregate_rejection_equivalence`. It turns the existing Batch 4 artifact slots
into a reviewer-facing proof-substance checklist. It does not change the
criterion status.

The current criterion status remains `partially_met`, and the overall
assessment remains `partially_proven`. This contract is not selected-backend proof closure, not production threshold ML-DSA security, not CAVP/ACVTS validation, not FIPS validation, not rejection-distribution preservation, and not a completed standard-verifier compatibility proof.

The machine-readable companion is
[`criterion-2-proof-substance.json`](criterion-2-proof-substance.json). Its
report status is `criterion2_proof_payload_formalized`.

## Proof Payload Statement

Criterion 2 closes only if the selected Profile P1 proof package establishes
both emitted-output compatibility and rejection-distribution substance.

For emitted-output compatibility, the proof payload must show that the accepted
selected-backend threshold output binds the same public key, message, signer
set, attempt, transcript, and accepted signature through standard verifier and
rejection-equivalence evidence. The central verifier target is:

```text
MLDSA65.Verify(pk, m, sigma) = accept
```

The aggregate acceptance target is:

```text
AggregateAccept(...) = true only when standard ML-DSA verification,
or checks proven equivalent to it, accepts the aggregate output.
```

For rejection-distribution substance, the payload must show that accepted
threshold signatures are indistinguishable from ordinary ML-DSA-65 signatures
under the reviewed rejection-distribution argument. Digest plumbing alone is
not enough.

## Required Artifact Slots

The Criterion 2 proof payload requires these slots before any promotion:

- `threshold_output_certificate_digest`: `evidence_present_unclosed` from
  `p1_criterion2_threshold_output_certificate_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
  Checked threshold-output certificate fixture:
  `tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json`.
- `real_recomputation_evidence_digest`: `evidence_present_unclosed` from
  `p1_criterion2_real_recomputation_evidence_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
  Checked recomputation fixture:
  `tests/fixtures/p1_real_recomputation_artifact_fixture.json`.
- `standard_verifier_compatibility_artifact_digest`:
  `evidence_present_unclosed` from
  `p1_standard_verifier_compatibility_artifact_gate`
  (`p1_standard_verifier_compatibility_artifact_package`); this is
  conformance/proof-review evidence only.
  Checked standard-verifier compatibility fixture:
  `tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json`.
- `full_kat_validation_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_full_kat_validation_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `rejection_distribution_review_digest`: `evidence_present_unclosed` from
  `p1_criterion2_rejection_distribution_review_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `norm_bound_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_norm_bound_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `hint_bound_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_hint_bound_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `challenge_bound_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_challenge_bound_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `transcript_binding_evidence_digest`: `evidence_present_unclosed` from
  `p1_criterion2_transcript_binding_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `theorem_linkage_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_theorem_linkage_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `external_review_digest`: `evidence_present_unclosed` from
  `p1_criterion2_external_review_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).

Typed Criterion 2 proof-slot artifact packages provide deterministic package
shape, digest binding, review metadata, and proof-review claim boundaries for
all listed slots, including the threshold-output certificate and real
recomputation predecessor evidence. `evidence_present_unclosed` means the slot
has typed evidence for review; `evidence_present_unclosed only` does not mean
Criterion 2 is met, selected-backend proof closure is complete,
rejection-distribution preservation is proven, or the theorem is closed. The
slot claim boundary is `conformance/proof-review evidence only`.

All Criterion 2 proof slots now have typed `evidence_present_unclosed` wrappers.
The accepted proof-closure artifact certificate also carries durable certificate evidence for the threshold-output certificate and real recomputation
predecessor slot artifact digests through
`P1SelectedBackendProofClosureArtifactCertificate::threshold_output_certificate_artifact_digest`
and
`P1SelectedBackendProofClosureArtifactCertificate::real_recomputation_evidence_artifact_digest`.
The threshold-output certificate slot is now backed by the checked
`tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json`
fixture so reviewers can inspect the bound threshold-output source package,
source digest, predecessor aggregate certificate digest, transcript binding,
accepted output digests, and typed slot artifact digest without relying only on
in-memory test construction.
The real recomputation predecessor slot is now backed by the checked
`tests/fixtures/p1_real_recomputation_artifact_fixture.json` fixture so
reviewers can inspect the bound source evidence, review digest, transcript
binding, predecessor threshold-output certificate, and typed slot artifact
digest without relying only on in-memory test construction.
The standard-verifier compatibility slot is also backed by the checked
`tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json`
fixture so reviewers can inspect the bound verifier payload, provider identity,
accepted result, predecessor certificate digest, transcript binding, and
standard-verifier compatibility artifact digest without promoting the slot
beyond `evidence_present_unclosed`.
Batch 4 proof-closure artifact packages, typed Criterion 2 proof-slot artifact
packages, and the P1 standard-verifier compatibility artifact gate are inputs
to this payload, not proof closure by themselves.

## Theorem Links

The proof payload must link the artifact package to the theorem and lemma
surfaces that actually carry Criterion 2:

- `Correctness Lemma 7`: standard verification compatibility.
- `Correctness Lemma 8`: ML-DSA-65 module-vector norm, hint, and challenge
  bounds.
- `Noise Lemma D`: aggregate rejection bound preservation.
- `Noise Lemma F`: aggregate rejection soundness and standard verification.
- `Noise Lemma H`: accepted-signature distribution.
- `FST-L5`: aggregation correctness for a standard-valid ML-DSA signature.
- `FST-L7`: abort and rejection compatibility.

## Promotion Requirements

Criterion 2 remains `partially_met` until all of the following are reviewed and
linked:

- reviewed proof payload tying threshold-output, recomputation, bounds,
  rejection behavior, and standard verification;
- full KAT/validation artifact package;
- reviewed rejection-distribution preservation argument;
- reviewed standard-verifier compatibility argument;
- theorem-linkage review.

The existing selected-backend proof-closure artifact package gate is necessary
but not sufficient for criterion-2 promotion. `ClosureReady` and
`ArtifactReady` mean the relevant framework has all typed evidence digests
needed for proof review; they do not mean those artifacts have been
independently validated in this repository.

## Failure Conditions

Criterion 2 fails or remains blocked if either condition is observed and cannot
be repaired within the selected Profile P1 assumptions:

- accepted threshold outputs fail standard ML-DSA-65 verification;
- aggregate rejection accepts outputs outside centralized ML-DSA-65 predicates.

These failure conditions are proof-review conditions, not claims that the
native path has already failed.

## Assessment Boundary

The assessor may report `criterion2_proof_payload_formalized` when this
contract and its manifest are present and internally consistent. That report
field does not change `aggregate_rejection_equivalence` from `partially_met`,
does not change the overall verdict from `partially_proven`, and does not close
the theorem.
