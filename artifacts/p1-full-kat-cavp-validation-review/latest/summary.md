# P1 Full KAT/CAVP Validation Review

This package records whether reviewed ML-DSA-65 KAT/CAVP validation evidence is bound to the current backend capture.

- Review status: `blocked_full_kat_cavp_validation_review`
- Claim boundary: `conformance/proof-review evidence`

Checks:
- `provider_kat_vectors_passed`: `false`
- `fips204_mldsa65_kat_passed`: `false`
- `acvts_or_cavp_campaign_reviewed`: `false`
- `signing_verification_vectors_reviewed`: `true`
- `mutation_negative_vectors_reviewed`: `true`
- `public_key_signature_length_vectors_reviewed`: `true`
- `implementation_digest_bound`: `true`
- `binds_backend_capture_digest`: `true`
- `binds_backend_manifest_digest`: `true`
- `external_reviewer_digest_present`: `false`

Blockers:
- `provider_kat_vectors_passed`
- `fips204_mldsa65_kat_passed`
- `acvts_or_cavp_campaign_reviewed`
- `external_reviewer_digest_present`
