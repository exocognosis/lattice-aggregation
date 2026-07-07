# Theorem Closure Evidence Components

Status: `external_components_required`

This inventory records the evidence components still needed before theorem
closure readiness flags can be computed as ready. It does not assert theorem
closure, rejection-distribution preservation, CAVP/ACVTS validation, or FIPS
validation.

## Rejection Distribution Preservation

- Component requirements:
  `artifacts/p1-rejection-distribution-proof-input/latest/component-requirements.json`
- Draft input:
  `artifacts/p1-rejection-distribution-proof-input/latest/evidence.json`
- Missing ready checks:
  `accepted_distribution_distance_bound_reviewed`,
  `concrete_loss_bound_nonvacuous`, and
  `external_reviewer_digest_present`.

## Full KAT/CAVP Validation

- Component requirements:
  `artifacts/p1-full-kat-cavp-validation-input/latest/component-requirements.json`
- Draft input:
  `artifacts/p1-full-kat-cavp-validation-input/latest/evidence.json`
- Missing ready checks:
  `provider_kat_vectors_passed`, `fips204_mldsa65_kat_passed`,
  `acvts_or_cavp_campaign_reviewed`, and
  `external_reviewer_digest_present`.
