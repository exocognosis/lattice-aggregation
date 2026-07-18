# Current Closure Dashboard

Overall verdict: `partially_proven`
Claim boundary: `closure-run implementation track`
Branch: `codex/post-119-crypto-evidence`
Commit: `9999744b66bac4a94c3ab874f55edfba1462dff6`

## Criteria

- `aggregate_mask_distribution`: `partially_met` (5 evidence entries, 4 blockers)
- `aggregate_rejection_equivalence`: `partially_met` (31 evidence entries, 12 blockers)
- `abort_retry_bias`: `partially_met` (4 evidence entries, 3 blockers)
- `partial_contribution_soundness`: `partially_met` (6 evidence entries, 3 blockers)
- `unauthorized_aggregate_reduction`: `partially_met` (4 evidence entries, 3 blockers)

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

## Post-119 Crypto Evidence

- Status: `post_119_crypto_substrate_indexed`
- Evidence status: `evidence_present_unclosed`
- Boundary: evidence_present_unclosed; not theorem closure
- `design_space_boundary_gate`: `True`
- `distributed_mask_mpc_feasibility_gate`: `True`
- `distributed_nonce_epsilon_mask_gate`: `True`
- `mldsa_primitive_gate`: `True`
- `partial_local_validity_gate`: `True`
- `real_dkg_vss_stack_a_gate`: `True`
- `two_stack_adr_gate`: `True`
- `claims_theorem_closure`: `False`
- `claims_criterion_met`: `False`
- `claims_selected_backend_proof_closure`: `False`
- `claims_rejection_distribution_preservation`: `False`
- `claims_mask_distribution_proven`: `False`
- `claims_standard_verifier_compatibility_complete`: `False`
- `claims_production_threshold_mldsa_security`: `False`
- `claims_cavp_acvts_validation`: `False`
- `claims_fips_validation`: `False`
- `claims_epsilon_mask_closed`: `False`

## Non-Closure Guards

- pending theorem-closure review
- requires selected-backend proof closure evidence
- requires production threshold ml-dsa security evidence
- requires cavp/acvts validation evidence
- requires fips validation evidence
- requires rejection-distribution preservation proof
