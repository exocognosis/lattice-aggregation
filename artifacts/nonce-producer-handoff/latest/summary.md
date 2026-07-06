# Executable P1 Nonce-Producer Handoff Replay

This artifact builds the current repo request and replays the capture/import handoff through the external-command runner. It is evidence_present_unclosed conformance/proof-review evidence only.

- Request schema: `lattice-aggregation:p1-distributed-nonce-producer-request:v1`
- Capture schema: `lattice-aggregation:p1-distributed-nonce-producer-capture:v1`
- Request: `p1-reviewed-nonce-producer-request-001`
- Request SHA-256: `527fd72113f2c52cd3c3154ab9126435081388b6518866eccb0cfd24403c1047`
- Capture SHA-256: `66aa746ad641dde437c299bf624340b61b2901eb3cb40b494bbf9584268f1a64`
- Producer evidence: `p1_shamir_nonce_dkg_tee_external_capture`
- Handoff source profile: `quarantined_local_schema_replay`
- Quarantine: `quarantined local schema/importer replay only`

This replay does not prove Criterion 2, rejection-distribution preservation, production threshold ML-DSA security, CAVP/ACVTS validation, FIPS validation, or theorem closure.
