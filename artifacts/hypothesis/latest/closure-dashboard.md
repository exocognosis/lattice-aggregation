# Current Closure Dashboard

Overall verdict: `partially_proven`
Claim boundary: `research scaffold only`
Branch: `codex/p1-real-external-evidence-attempt`
Commit: `bfa8cecebcbff4676e068ac33e57d3a4a316a918`

## Criteria

- `aggregate_mask_distribution`: `partially_met` (3 evidence entries, 3 blockers)
- `aggregate_rejection_equivalence`: `partially_met` (28 evidence entries, 10 blockers)
- `abort_retry_bias`: `partially_met` (3 evidence entries, 2 blockers)
- `partial_contribution_soundness`: `partially_met` (5 evidence entries, 2 blockers)
- `unauthorized_aggregate_reduction`: `partially_met` (3 evidence entries, 2 blockers)

## Proof Artifact Slots

### criterion_1
- Status: `criterion1_proof_payload_formalized`
- `required_unclosed`: aggregate_distribution_artifact_digest, centralized_distribution_artifact_digest, external_review_digest, min_entropy_review_digest, parameter_selection_digest, renyi_bound_proof_digest, selected_mask_construction_digest

### criterion_2
- Status: `criterion2_proof_payload_formalized`
- `evidence_present_unclosed`: challenge_bound_artifact_digest, distributed_nonce_producer_artifact_digest, external_backend_cryptographic_closure_candidate, external_backend_evidence_attempt, external_review_digest, full_kat_validation_artifact_digest, hint_bound_artifact_digest, norm_bound_artifact_digest, real_recomputation_evidence_digest, real_threshold_backend_emission_artifact_digest, rejection_distribution_review_digest, standard_verifier_compatibility_artifact_digest, theorem_linkage_artifact_digest, threshold_output_certificate_digest, transcript_binding_evidence_digest

### criterion_3
- Status: `criterion3_proof_payload_formalized`
- `required_unclosed`: accepted_signature_distribution_proof_digest, adversarial_abort_policy_corpus_digest, external_review_digest, formal_abort_leakage_model_digest, retry_domain_separation_proof_digest, sample_size_bucket_rationale_digest, timeout_retry_policy_digest

## Non-Closure Guards

- not theorem closure
- not selected-backend proof closure
- not production threshold ML-DSA security
- not CAVP/ACVTS validation
- not FIPS validation
- not rejection-distribution preservation
