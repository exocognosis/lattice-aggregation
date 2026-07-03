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

The checked replay can generate the current request artifacts:

```bash
python3 scripts/run_nonce_producer_handoff_replay.py \
  --root . \
  --out artifacts/nonce-producer-handoff/latest
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

## Backend Readiness Preflight

Before attempting to promote a backend capture, run the candidate source through
the readiness preflight against the exact generated request:

```bash
python3 scripts/check_nonce_producer_backend_readiness.py \
  --request artifacts/nonce-producer-handoff/latest/request/request.json \
  --backend-crate /path/to/backend-crate \
  --backend-label reviewed-backend-candidate \
  --out artifacts/nonce-producer-backend-readiness/latest
```

The preflight records the request SHA-256, source-tree checksums, Cargo package
metadata, detected distributed nonce-PRF interfaces, source-level blocker
diagnostics, and an ordered remediation list. A backend is not admissible for
this handoff while the report detects hazmat features, simulated defaults,
centralized nonce-PRF oracles, deterministic test-vector plumbing,
localnet/simulation markers, or missing reviewed external capture contract
material.

The current checked readiness artifact is:

- `artifacts/nonce-producer-backend-readiness/latest/manifest.json`

It marks the local `dytallix-pq-threshold` candidate
`backend_detected_not_admissible`; that is useful boundary evidence, not
reviewed external nonce-producer evidence.

## Capture Attempt Orchestrator

The preferred external-backend attempt path is the readiness-gated orchestrator:

```bash
python3 scripts/run_admissible_nonce_producer_capture_attempt.py \
  --root . \
  --out artifacts/nonce-producer-capture-attempt/latest \
  --backend-crate /path/to/backend-crate \
  --backend-label reviewed-backend-candidate \
  --backend-command /opt/p1-nonce-producer emit --request {request}
```

The `{request}` placeholder is mandatory. The orchestrator generates the exact
request under `handoff/request/request.json`, substitutes that path into the
backend command, runs the readiness preflight against the same request, and
writes a top-level attempt manifest. If readiness is blocked, it records
`backend_readiness_blocked`, writes the readiness artifacts, and does not
execute the backend command. If readiness is admissible, it reuses the same
request in `scripts/run_nonce_producer_handoff_replay.py` and records
`capture_promoted`. If readiness is admissible but the backend command fails
or emits invalid capture JSON, the attempt still writes a durable top-level
manifest with `capture_execution_failed` or `capture_validation_failed`,
including the command failure phase and available command output.

The current checked attempt artifact is:

- `artifacts/nonce-producer-capture-attempt/latest/manifest.json`

It is boundary evidence only. A blocked attempt proves the repo failed closed
before capture; it does not prove Criterion 2, production threshold ML-DSA
security, rejection-distribution preservation, or theorem closure.

## Real Backend Handoff

For a real external backend, `scripts/run_nonce_producer_handoff_replay.py`
requires an admissible backend-readiness manifest before it will run an
explicit `--backend-command`. Use `--reuse-request` so the handoff runner does
not regenerate a different request SHA-256 after the readiness preflight:

```bash
python3 scripts/run_nonce_producer_handoff_replay.py \
  --root . \
  --out artifacts/nonce-producer-handoff/latest \
  --reuse-request \
  --backend-readiness artifacts/nonce-producer-backend-readiness/latest/manifest.json \
  --backend-command /opt/p1-nonce-producer emit \
    --request artifacts/nonce-producer-handoff/latest/request/request.json
```

The backend command must read the request JSON path supplied by its own
arguments and must write only canonical capture JSON to stdout. The handoff
manifest records the accepted readiness schema, readiness SHA-256, package
name, source-tree SHA-256, readiness status, and request SHA-256.

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
