# Executable P1 Nonce-Producer Handoff Replay

This artifact builds the current repo request and replays the capture/import handoff through the external-command runner. It is evidence_present_unclosed conformance/proof-review evidence only.

- Request schema: `lattice-aggregation:p1-distributed-nonce-producer-request:v1`
- Capture schema: `lattice-aggregation:p1-distributed-nonce-producer-capture:v1`
- Request: `p1-reviewed-nonce-producer-request-001`
- Request SHA-256: `8e9dd7c33e9af31f3c40a8b3c54ad0737a48972ce128c596ecc70420b16a7253`
- Capture SHA-256: `20594e85cb9bd296db1addc7a84d70a8d1f80f8365b27f71d7c00b6e30011015`
- Producer evidence: `p1_shamir_nonce_dkg_tee_external_capture`
- Backend readiness: `backend_candidate_admissible_pending_capture`
- Backend package: `lattice-aggregation`
- Handoff source profile: `repo_reference_cli_capture`
- Quarantine: `reference CLI handoff replay only; not actual backend evidence; not Criterion 2 closure evidence`

This replay does not prove Criterion 2, rejection-distribution preservation, production threshold ML-DSA security, CAVP/ACVTS validation, FIPS validation, or theorem closure.
