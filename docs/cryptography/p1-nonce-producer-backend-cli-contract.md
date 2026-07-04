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

The checked replay can generate the current request artifacts. This default
path is a quarantined local schema/importer replay, not actual external
backend evidence:

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

It marks the checked backend profile
`backend_candidate_admissible_pending_capture` with no detected blockers; that
is useful boundary evidence, not reviewed external nonce-producer evidence.

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

It is boundary evidence only. The checked Batch 2 artifact uses
`scripts/p1_nonce_producer_reference_cli.py` and records `capture_promoted`
with handoff source profile `repo_reference_cli_capture`. That reference CLI
proves the request-bound external process, capture JSON, provenance, and Rust
import path are wired. It is quarantined as not actual backend evidence and
does not prove Criterion 2, production threshold ML-DSA security,
rejection-distribution preservation, or theorem closure.

## Reference CLI Replay

The repo-owned reference CLI can exercise the exact command contract without
requiring the final external backend binary:

```bash
python3 scripts/run_admissible_nonce_producer_capture_attempt.py \
  --root . \
  --out artifacts/nonce-producer-capture-attempt/latest \
  --backend-crate . \
  --backend-label lattice-aggregation-reference-cli \
  --backend-command python3 scripts/p1_nonce_producer_reference_cli.py \
    emit --request {request} --root .
```

The resulting handoff source profile is `repo_reference_cli_capture`, not
`admissible_external_backend_capture`. This replay is suitable for CI and
reviewing the executable handoff contract, but it cannot replace an
independently generated reviewed threshold nonce-producer capture.

## Actual External Gate

Batch 3 adds a separate gate for the actual external backend slot:

```bash
python3 scripts/verify_actual_nonce_producer_capture.py \
  --root . \
  --attempt artifacts/nonce-producer-capture-attempt/latest/manifest.json \
  --out artifacts/nonce-producer-actual-external-gate/latest
```

The gate accepts only a promoted handoff whose source profile is
`admissible_external_backend_capture` and whose quarantine record is false. The
current checked artifact is `actual_external_capture_missing` because the
promoted handoff is `repo_reference_cli_capture`. Use `--strict` when a real
external backend is available and CI should fail until the actual external slot
is ready.

Batch 7 consumes this gate through
`scripts/build_p1_external_backend_cryptographic_closure_candidate.py`:

```bash
python3 scripts/build_p1_external_backend_cryptographic_closure_candidate.py \
  --root . \
  --nonce-gate artifacts/nonce-producer-actual-external-gate/latest/manifest.json \
  --backend-manifest artifacts/backend-emission-capture/latest/manifest.json \
  --backend-capture artifacts/backend-emission-capture/latest/capture.json \
  --rejection-batch artifacts/p1-rejection-equivalence-batch/latest/batch.json \
  --out artifacts/p1-external-backend-cryptographic-closure-candidate/latest
```

That builder computes `close_candidate`; it does not accept a manual closure
claim and it keeps `claims_theorem_closure`,
`claims_rejection_distribution_preservation`, and
`claims_selected_backend_proof_closure` false.

## External Command-Origin Guard

Batch 4 hardens the external-command boundary. The capture runner records
`backend_command_origin` and rejects an unmarked repo-local backend wrapper
before it can be classified as `admissible_external_backend_capture`.

Accepted actual-external commands must resolve to
`outside_repo_executable_or_script`; repo-owned emitters remain either
`quarantined_local_schema_replay` or `repo_reference_cli_capture`, and neither
can satisfy the actual external backend slot. This is an intake guard only: a
non-quarantined external command still has to emit a request-bound reviewed
capture whose package digests import through the Rust gate.

## External Capture-File Intake

Batch 5 adds a file-based intake path for reviewed captures already emitted by
an independently operated backend outside the repo:

```bash
python3 scripts/stage_external_nonce_producer_capture.py \
  --root . \
  --request artifacts/nonce-producer-handoff/latest/request/request.json \
  --readiness artifacts/nonce-producer-backend-readiness/latest/manifest.json \
  --capture-file /path/outside/repo/p1-nonce-producer-capture.json \
  --review-manifest /path/outside/repo/p1-nonce-producer-review.json \
  --out artifacts/nonce-producer-external-capture-intake/latest

python3 scripts/verify_actual_nonce_producer_capture.py \
  --root . \
  --attempt artifacts/nonce-producer-external-capture-intake/latest/manifest.json \
  --out artifacts/nonce-producer-actual-external-gate/latest \
  --strict
```

Batch 6 hardens this path with an external review dossier. The intake now
rejects repo-local capture files, repo-local review manifests, missing review
manifests, mismatched capture/readiness bindings, and failed review checks. The
review manifest schema is:

```text
lattice-aggregation:p1-external-nonce-producer-capture-review:v1
```

The review must carry `reviewed_external_capture_ready`, bind the request
SHA-256, canonical capture SHA-256, capture-file SHA-256, readiness manifest
SHA-256, backend source-tree SHA-256, reviewer/operator/environment/command
digests, and explicit checks excluding hazmat PRF oracles, centralized
expanded-secret-key helpers, fixture harnesses, localnet/deterministic
simulation, and single-key standard-provider output.

The intake validates the exact request digest and capture schema through the
same capture runner checks, then writes an attempt-compatible handoff with
`preexisting_external_capture_file` provenance and
`outside_repo_review_manifest` evidence. This still does not prove Criterion 2;
it only gives a strict path for a real external capture file plus review dossier
to occupy the actual backend slot.

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

The backend command must be an explicit external command, must read the request
JSON path supplied by its own arguments, and must write only canonical capture
JSON to stdout. The local checked replay emitter is rejected on this path as a
quarantined local replay source. The handoff manifest records the accepted
readiness schema, readiness SHA-256, package name, source-tree SHA-256,
readiness status, request SHA-256, and whether the source profile is an
`admissible_external_backend_capture` or a quarantined local replay.

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
- the local checked replay emitter when used as an explicit external backend

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
request/capture/import handoff. It is not a production threshold backend, and
does not replace the required externally generated reviewed P1 nonce-producer material.

The replay manifest records `quarantined_local_schema_replay`,
`request_sha256`, `capture_sha256`, `backend_command_sha256`, command metadata,
logs, checksums, and the imported capture path.
