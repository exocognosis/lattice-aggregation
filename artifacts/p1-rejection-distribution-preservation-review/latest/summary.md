# P1 Rejection-Distribution Preservation Review

This package records whether reviewed rejection-distribution and abort bounds are bound to the current rejection batch.

- Review status: `blocked_rejection_distribution_preservation_review`
- Claim boundary: `conformance/proof-review evidence`

Checks:
- `accepted_distribution_distance_bound_reviewed`: `false`
- `threshold_accepted_distribution_reviewed`: `true`
- `centralized_mldsa_reference_distribution_reviewed`: `true`
- `rejection_sampling_conditioning_reviewed`: `true`
- `selective_abort_withholding_bound_reviewed`: `true`
- `restart_leakage_bound_reviewed`: `true`
- `concurrency_model_reviewed`: `true`
- `concrete_loss_bound_nonvacuous`: `false`
- `binds_rejection_batch_digest`: `true`
- `binds_distribution_abort_review_digest`: `true`
- `external_reviewer_digest_present`: `false`

Blockers:
- `accepted_distribution_distance_bound_reviewed`
- `concrete_loss_bound_nonvacuous`
- `external_reviewer_digest_present`
