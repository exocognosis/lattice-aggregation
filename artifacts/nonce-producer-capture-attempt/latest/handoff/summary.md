# Executable P1 Nonce-Producer Handoff Replay

This artifact builds the current repo request and replays the capture/import handoff through the external-command runner. It is evidence_present_unclosed conformance/proof-review evidence.

- Request schema: `lattice-aggregation:p1-distributed-nonce-producer-request:v1`
- Capture schema: `lattice-aggregation:p1-distributed-nonce-producer-capture:v1`
- Request: `p1-reviewed-nonce-producer-request-001`
- Request SHA-256: `dd2928e0755b7f61dddcf0942fd67412479a6471fc582db9c3d21ab5f3018685`
- Capture SHA-256: `9316a197b7b793b26b5bae9ed8abc9b692eac6cdc4fafe25b54507554b28cbf7`
- Producer evidence: `p1_shamir_nonce_dkg_tee_external_capture`
- Backend readiness: `backend_candidate_admissible_pending_capture`
- Backend package: `lattice-aggregation`
- Handoff source profile: `repo_reference_cli_capture`
- Quarantine: `reference CLI handoff replay; requires actual backend evidence and requires Criterion 2 closure evidence`

This replay requires Criterion 2 proof review, rejection-distribution preservation, production threshold ML-DSA security, CAVP/ACVTS validation, FIPS validation, or theorem closure.
