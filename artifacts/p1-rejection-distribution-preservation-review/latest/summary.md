# P1 Rejection-Distribution Preservation Review

This package records whether reviewed rejection-distribution and abort bounds are bound to the current rejection batch.

- Review status: `blocked_rejection_distribution_preservation_review`
- Claim boundary: `conformance/proof-review evidence`

Checks:
- `accepted_distribution_distance_bound_reviewed`: `true`
- `threshold_accepted_distribution_reviewed`: `true`
- `centralized_mldsa_reference_distribution_reviewed`: `true`
- `rejection_sampling_conditioning_reviewed`: `true`
- `selective_abort_withholding_bound_reviewed`: `true`
- `restart_leakage_bound_reviewed`: `true`
- `concurrency_model_reviewed`: `true`
- `concrete_loss_bound_nonvacuous`: `true`
- `binds_rejection_batch_digest`: `true`
- `binds_distribution_abort_review_digest`: `false`
- `external_reviewer_digest_present`: `true`

Blockers:
- `binds_distribution_abort_review_digest`

Proof package:
- `accepted_threshold_output_distribution_vs_centralized_mldsa_distribution`: `reviewed=true`
- `concrete_distance_loss_bound`: `reviewed=true`
- `concurrency_model`: `reviewed=true`
- `rejection_sampling_conditioning`: `reviewed=true`
- `restart_leakage_bound`: `reviewed=true`
- `reviewer_signoff_digest`: `reviewed=true`, digest `8198cf8c6a693d2114540bf0ac3d60b1a28d0c79cfd1dd165536c1088593376d`
- `selective_abort_withholding_bound`: `reviewed=true`
