# P1 Nonce-Producer Backend CLI Contract

## Scope

This is the executable handoff contract between this repo and an external P1
distributed nonce-producer backend for the selected profile
`ML-DSA-65 coordinator-assisted Shamir nonce DKG P1`.

The contract is `evidence_present_unclosed` conformance/proof-review evidence
only. A conforming capture does not prove Criterion 2, rejection-distribution
preservation, production threshold ML-DSA security, CAVP/ACVTS validation, FIPS
validation, or theorem closure.

## Request Input

The repo generates the backend request with:

```bash
python3 scripts/run_nonce_producer_handoff_replay.py \
  --root . \
  --out artifacts/nonce-producer-handoff/latest
```

For a real external backend, pass the backend command after
`--backend-command`. The backend command must read the request JSON path supplied
by its own arguments and must write only canonical capture JSON to stdout:

```bash
python3 scripts/run_nonce_producer_handoff_replay.py \
  --root . \
  --out artifacts/nonce-producer-handoff/latest \
  --backend-command /opt/p1-nonce-producer emit \
    --request artifacts/nonce-producer-handoff/latest/request/request.json
```

The request JSON schema is:

```text
lattice-aggregation:p1-distributed-nonce-producer-request:v1
```

The request binds:

- request `name`
- request SHA-256 over canonical sorted JSON
- selected profile binding digest
- threshold-output certificate digest
- standard-verifier compatibility artifact digest
- required capture schema
- required producer evidence class
- required material classes
- proof-review-only claim boundary

## Capture Output

The backend command must write a single JSON object to stdout with schema:

```text
lattice-aggregation:p1-distributed-nonce-producer-capture:v1
```

The capture must include:

- `request.schema`
- `request.name`
- `request.request_sha256`
- `predecessors.selected_profile_binding_digest_hex`
- `predecessors.threshold_output_certificate_digest_hex`
- `predecessors.standard_verifier_compatibility_artifact_digest_hex`
- `producer_evidence = p1_shamir_nonce_dkg_tee_external_capture`
- `claim_boundary = conformance/proof-review evidence only`
- `capture.reviewed = true`
- byte objects for `source_reference`, `backend_implementation`,
  `coordinator_attestation`, `shamir_nonce_dkg_transcript`,
  `pairwise_mask_seed_commitments`, `nonce_share_commitments`,
  `abort_accountability`, and `external_review`
- expected package digests for every material class and the final
  `distributed_nonce_producer_artifact_digest_hex`

Byte objects must be either:

```json
{"encoding": "utf8", "value": "..."}
```

or:

```json
{"encoding": "hex", "value": "..."}
```

## Rejection Rules

`scripts/run_nonce_producer_capture.py` rejects commands or captures that use
known scaffold sources:

- localnet
- deterministic or simulated paths
- fixture harnesses
- hazmat PRF-output oracles
- centralized expanded-secret-key helpers
- ordinary single-key standard-provider output

It also rejects missing, stale, or mismatched request digests; missing
predecessor digests; missing expected digests; unknown capture fields; empty
byte material; unsupported byte encodings; and unreviewed captures.

## Checked Replay

The checked replay path is:

- `scripts/run_nonce_producer_handoff_replay.py`
- `scripts/emit_reviewed_nonce_producer_capture.py`
- `artifacts/nonce-producer-handoff/latest/manifest.json`
- `artifacts/nonce-producer-handoff/latest/request/request.json`
- `artifacts/nonce-producer-handoff/latest/capture/capture.json`

The checked replay emitter exists so CI and reviewers can verify the executable
request/capture/import handoff. It is not a production threshold backend and it
does not replace the required externally generated reviewed P1 nonce-producer
material.

It does not replace the required externally generated reviewed P1 nonce-producer material.

The replay manifest records `request_sha256`, `capture_sha256`,
`backend_command_sha256`, command metadata, logs, checksums, and the imported
capture path.
