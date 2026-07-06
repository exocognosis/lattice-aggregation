# Executable P1 Nonce-Producer Handoff Replay

This artifact builds the current repo request and replays the capture/import handoff through the external-command runner. It is evidence_present_unclosed conformance/proof-review evidence.

- Request schema: `lattice-aggregation:p1-distributed-nonce-producer-request:v1`
- Capture schema: `lattice-aggregation:p1-distributed-nonce-producer-capture:v1`
- Request: `p1-reviewed-nonce-producer-request-001`
- Request SHA-256: `d0c5eb664cc2e562d8c50f5fb2c698c60295b7e450bfb86765b9d78a6c6ff4e2`
- Capture SHA-256: `66aa746ad641dde437c299bf624340b61b2901eb3cb40b494bbf9584268f1a64`
- Producer evidence: `p1_shamir_nonce_dkg_tee_external_capture`
- Backend readiness: `backend_candidate_admissible_pending_capture`
- Backend package: `lattice-aggregation`
- Handoff source profile: `repo_reference_cli_capture`
- Quarantine: `reference CLI handoff replay only; requires actual backend evidence; requires Criterion 2 closure evidence`

This replay requires Criterion 2 proof review, rejection-distribution preservation, production threshold ML-DSA security, CAVP/ACVTS validation, FIPS validation, or theorem closure.
