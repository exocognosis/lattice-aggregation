# Current Closure Dashboard

Overall verdict: `partially_proven`
Claim boundary: `closure-run implementation track`
Branch: `codex/p1-validation-proof-packages`
Commit: `b5932fcc5c665486fbc11a6450f4ccbd5e5a275a`

## Criteria

- `aggregate_mask_distribution`: `partially_met` (3 evidence entries, 2 blockers)
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
- `blocker_inputs_satisfied`: theorem_closure_blocker_requests
- `evidence_present_unclosed`: challenge_bound_artifact_digest, distributed_nonce_producer_artifact_digest, external_backend_cryptographic_closure_candidate, external_backend_evidence_attempt, external_review_digest, full_kat_validation_artifact_digest, hint_bound_artifact_digest, norm_bound_artifact_digest, real_recomputation_evidence_digest, real_threshold_backend_emission_artifact_digest, rejection_distribution_review_digest, standard_verifier_compatibility_artifact_digest, theorem_linkage_artifact_digest, threshold_output_certificate_digest, transcript_binding_evidence_digest

### criterion_3
- Status: `criterion3_proof_payload_formalized`
- `required_unclosed`: accepted_signature_distribution_proof_digest, adversarial_abort_policy_corpus_digest, external_review_digest, formal_abort_leakage_model_digest, retry_domain_separation_proof_digest, sample_size_bucket_rationale_digest, timeout_retry_policy_digest

## Non-Closure Guards

- pending theorem-closure review
- requires selected-backend proof closure evidence
- requires production threshold ml-dsa security evidence
- requires cavp/acvts validation evidence
- requires fips validation evidence
- requires rejection-distribution preservation proof
