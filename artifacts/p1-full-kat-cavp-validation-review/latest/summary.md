# P1 Full KAT/CAVP Validation Review

This package records whether reviewed ML-DSA-65 KAT/CAVP validation evidence is bound to the current backend capture.

- Review status: `reviewed_full_kat_cavp_validation_ready`
- Claim boundary: `conformance/proof-review evidence`

Checks:
- `provider_kat_vectors_passed`: `true`
- `fips204_mldsa65_kat_passed`: `true`
- `acvts_or_cavp_campaign_reviewed`: `true`
- `signing_verification_vectors_reviewed`: `true`
- `mutation_negative_vectors_reviewed`: `true`
- `public_key_signature_length_vectors_reviewed`: `true`
- `implementation_digest_bound`: `true`
- `binds_backend_capture_digest`: `true`
- `binds_backend_manifest_digest`: `true`
- `external_reviewer_digest_present`: `true`

Blockers:
- none

Validation package:
- `acvts_cavp_campaign_transcript`: `reviewed=true`
- `fips204_mldsa65_kat_vectors`: `reviewed=true`
- `keygen_siggen_sigver_coverage`: `reviewed=true`
- `provider_kat_vectors`: `reviewed=true`
- `reviewer_signoff_digest`: `reviewed=true`, digest `6e35fd8bc1d51e584b02b729084d47d05535a81d975bc07b1e4c7d3c2cb317e6`
