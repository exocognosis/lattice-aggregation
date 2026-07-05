# Theorem Closure Assessment Readiness

Status: fail-closed readiness preflight, not theorem closure.

## Scope

This document defines the preflight for deciding whether theorem-closure
assessment can begin. The preflight is implemented by
`scripts/assess_theorem_closure_readiness.py` and writes
`artifacts/theorem-closure-readiness/latest/manifest.json`.

The preflight does not prove Criterion 2, does not prove
rejection-distribution preservation, does not claim selected-backend proof
closure, and does not claim production threshold ML-DSA security. Its claim
boundary is `readiness preflight only; not theorem closure`.

## Preflight Inputs

The preflight consumes the existing Criterion 2 and external-evidence surfaces:

- `docs/cryptography/criterion-2-proof-substance.json`;
- `artifacts/hypothesis/latest/assessment.json`;
- `artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json`;
- `artifacts/p1-external-backend-evidence-attempt/latest/manifest.json`;
- `artifacts/theorem-closure-review/latest/manifest.json`.

The final input is intentionally absent until reviewers produce a separate
theorem-closure review package. The expected review schema is
`lattice-aggregation:theorem-closure-review:v1`, and its ready status is
`theorem_closure_review_ready`.

## Readiness Checks

The checked readiness status is either
`blocked_before_theorem_closure_assessment` or
`ready_for_theorem_closure_assessment`.

The preflight remains blocked unless all external evidence checks pass:

- the Batch 7 external-backend closure candidate exists and has
  `close_candidate = true`;
- the Batch 8 grouped external-evidence attempt exists and has
  `attempt_status = external_evidence_close_candidate_ready`;
- the Batch 9 reviewed external evidence package binds all inputs with
  `review_package_binds_inputs = true`;
- source exclusions pass for hazmat, simulation, localnet, fixture, single-key,
  and repo-reference capture sources.

The preflight also remains blocked until the theorem review manifest marks
these review flags true:

- `proof_payload_reviewed`;
- `full_kat_validation_reviewed`;
- `rejection_distribution_preservation_reviewed`;
- `standard_verifier_compatibility_reviewed`;
- `theorem_linkage_reviewed`.

## Blocker Groups

The manifest groups blockers under stable keys so reviewers can route work
without rereading every artifact:

- `external_backend_evidence`;
- `proof_payload_review`;
- `validation`;
- `rejection_distribution_review`;
- `standard_verifier_review`;
- `theorem_linkage_review`;
- `criterion2_manifest`;
- `hypothesis_assessment`;
- `claim_boundary`.

The current checked artifact is expected to remain blocked while the actual
external nonce capture, real threshold backend emission capture,
rejection-distribution comparison, reviewed external evidence package, and
theorem review package are absent.

## Non-Claims

The preflight keeps these flags false in every output:

- `claims_theorem_closure`;
- `claims_criterion_met`;
- `claims_selected_backend_proof_closure`;
- `claims_rejection_distribution_preservation`;
- `claims_standard_verifier_compatibility_complete`;
- `claims_production_threshold_mldsa_security`;
- `claims_cavp_acvts_validation`;
- `claims_fips_validation`.

Even a future `ready_for_theorem_closure_assessment` result only means that
the repository has enough reviewed input material to start theorem-closure
assessment. It does not mean the theorem has closed.
