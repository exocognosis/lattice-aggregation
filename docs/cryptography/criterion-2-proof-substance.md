# Criterion 2 Proof Substance

Status: `formalized_open_proof_payload`, not criterion closure.

Date: 2026-06-25

## Scope and Claim Boundary

This document defines the proof payload still required for Criterion 2,
`aggregate_rejection_equivalence`. It turns the existing Batch 4 artifact slots
into a reviewer-facing proof-substance checklist. It does not change the
criterion status.

The current criterion status remains `partially_met`, and the overall
assessment remains `partially_proven`. This contract requires selected-backend proof closure evidence, requires production threshold ML-DSA security evidence, requires CAVP/ACVTS validation evidence, requires FIPS validation evidence, requires rejection-distribution preservation proof, requires real threshold backend implementation evidence, and requires a completed standard-verifier compatibility proof.

The machine-readable companion is
[`criterion-2-proof-substance.json`](criterion-2-proof-substance.json). Its
report status is `criterion2_proof_payload_formalized`.

## Proof Payload Statement

Criterion 2 closes only if the selected Profile P1 proof package establishes
both emitted-output compatibility and rejection-distribution substance.

For emitted-output compatibility, the proof payload must show that the accepted
selected-backend threshold output binds the same public key, message, signer
set, attempt, transcript, and accepted signature through standard verifier and
rejection-equivalence evidence. The central verifier target is:

```text
MLDSA65.Verify(pk, m, sigma) = accept
```

The aggregate acceptance target is:

```text
AggregateAccept(...) = true only when standard ML-DSA verification,
or checks proven equivalent to it, accepts the aggregate output.
```

For rejection-distribution substance, the payload must show that accepted
threshold signatures are indistinguishable from ordinary ML-DSA-65 signatures
under the reviewed rejection-distribution argument. Digest plumbing alone is
not enough.

## Required Artifact Slots

The Criterion 2 proof payload requires these slots before any promotion:

- `threshold_output_certificate_digest`: `evidence_present_unclosed` from
  `p1_criterion2_threshold_output_certificate_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
  Checked threshold-output certificate fixture:
  `tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json`.
- `real_recomputation_evidence_digest`: `evidence_present_unclosed` from
  `p1_criterion2_real_recomputation_evidence_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
  Checked recomputation fixture:
  `tests/fixtures/p1_real_recomputation_artifact_fixture.json`.
- `distributed_nonce_producer_artifact_digest`: `evidence_present_unclosed`
  from
  `p1_criterion2_distributed_nonce_producer_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`). This is the producer slot
  that must replace the current hazmat PRF-output oracle behind
  `derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key`.
  The P1 nonce producer selection is documented in
  `docs/cryptography/p1-nonce-producer-selection.md` and
  `docs/cryptography/p1-nonce-producer-selection.json` as
  `FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG P1`. The Rust gate
  now accepts only reviewed `ReviewedP1ShamirNonceDkgTee` evidence and rejects
  the hazmat PRF-output oracle, centralized expanded-secret-key helper, fixture
  harnesses, and ordinary single-key standard-provider output. The backend
  output adapter
  `derive_p1_distributed_nonce_producer_artifact_package_from_backend_output`
  converts `Mldsa65DistributedNonceProducerArtifact` byte material into this
  gate package and binds source-reference, backend-implementation,
  coordinator-attestation, Shamir nonce-DKG transcript, active-set,
  pairwise-mask, nonce-share commitment, attempt-binding,
  abort-accountability, standard-verifier bridge, and external-review digests.
  The canonical backend handoff is the capture schema
  `lattice-aggregation:p1-distributed-nonce-producer-capture:v1`, bound to
  request schema
  `lattice-aggregation:p1-distributed-nonce-producer-request:v1`; importer
  `derive_p1_distributed_nonce_producer_artifact_package_from_capture` requires
  request name and `request_sha256`, predecessor certificate digests, decoded
  nonce-producer material classes, and expected package digests before feeding
  the artifact gate. The repo-generated request and runner path is
  `scripts/build_nonce_producer_request.py` plus
  `scripts/run_nonce_producer_capture.py`; the runner loads the request JSON,
  requires the capture to echo the exact request digest, and rejects localnet,
  deterministic, fixture, hazmat, centralized-helper, and ordinary single-key
  provider command sources before writing importable capture artifacts.
  The exact external backend CLI contract is documented in
  `docs/cryptography/p1-nonce-producer-backend-cli-contract.md`. The checked
  replay path `scripts/run_nonce_producer_handoff_replay.py` invokes
  `scripts/emit_reviewed_nonce_producer_capture.py`, writes
  `artifacts/nonce-producer-handoff/latest/manifest.json`, and stores the bound
  request and capture at
  `artifacts/nonce-producer-handoff/latest/request/request.json` and
  `artifacts/nonce-producer-handoff/latest/capture/capture.json`. Rust test
  `checked_nonce_producer_handoff_replay_capture_json_feeds_rust_importer`
  imports that exact capture through
  `derive_p1_distributed_nonce_producer_artifact_package_from_capture`.
  This replay is now marked `quarantined_local_schema_replay`: it proves the
  executable request/capture/import handoff is wired, not that an external
  backend has closed Criterion 2. The explicit external-backend path rejects
  that local replay emitter unless the runner is in quarantined replay mode.
  The backend readiness preflight
  `scripts/check_nonce_producer_backend_readiness.py` inspects candidate
  backend source before capture promotion. Its current artifact
  `artifacts/nonce-producer-backend-readiness/latest/manifest.json` binds the
  repo-generated request SHA-256, records candidate source-tree checksums, and
  confirms the checked backend profile exposes distributed nonce-PRF
  interfaces. It marks the profile
  `backend_candidate_admissible_pending_capture` with no detected blockers.
  This moves the repo past the prior hazmat/simulation/centralized-oracle
  readiness quarantine. The readiness artifact is still only a preflight
  boundary check, not reviewed external nonce-producer evidence.
  The handoff replay now requires an admissible backend-readiness manifest for
  every explicit external backend command, supports `--reuse-request` so the
  readiness manifest binds the exact request SHA-256, and records accepted
  readiness metadata in the handoff manifest.
  The readiness-gated capture-attempt runner
  `scripts/run_admissible_nonce_producer_capture_attempt.py` now generates the
  exact handoff request, runs readiness against that request, requires a
  `{request}`-bound backend command template, and writes
  `artifacts/nonce-producer-capture-attempt/latest/manifest.json`. Its current
  checked artifact is `capture_promoted`: the current backend profile passed
  readiness, the repo reference CLI emitted canonical request-bound capture
  JSON, and the handoff/import path wrote a promoted manifest. The promoted
  source profile is `repo_reference_cli_capture`, with quarantine text stating
  that this is reference CLI handoff replay only, requires actual backend evidence
  and requires Criterion 2 closure evidence. The runner preserves failed backend
  attempts as `capture_execution_failed` or `capture_validation_failed` instead
  of dropping command-output diagnostics. It remains `evidence_present_unclosed`
  until externally generated reviewed P1 nonce-producer material replaces the
  hazmat oracle.
  Batch 3 adds `scripts/verify_actual_nonce_producer_capture.py`, which gates
  the promoted handoff before it can occupy the actual external backend slot.
  Its current artifact
  `artifacts/nonce-producer-actual-external-gate/latest/manifest.json` is
  `actual_external_capture_ready`: it is bound to an
  `admissible_external_backend_capture` with quarantine false. This actual
  external nonce capture promotes the nonce-producer capture into the actual
  external slot, but it remains
  proof-review evidence and does not discharge the real threshold-backend,
  rejection-distribution, or theorem-closure obligations.
  Batch 4 hardens the capture-runner source boundary: accepted external
  captures now record `backend_command_origin =
  outside_repo_executable_or_script`, while unmarked repo-local backend
  wrappers are rejected before they can be classified as
  `admissible_external_backend_capture`. This prevents a repo-local script from
  satisfying the actual external slot, but it still does not supply the missing
  independently generated nonce-DKG/TEE capture.
  Batch 5 adds `scripts/stage_external_nonce_producer_capture.py`, a
  file-based intake for a preexisting `outside_repo_capture_file`. It requires
  admissible readiness, rejects repo-local capture files, validates the exact
  request digest through the capture runner, writes attempt-compatible handoff
  artifacts with `preexisting_external_capture_file` provenance, and can feed
  `scripts/verify_actual_nonce_producer_capture.py --strict` once a real
  outside-repo capture file exists. This is still an intake path only, not the
  missing capture evidence itself.
  Batch 6 hardens that intake with a required
  `outside_repo_review_manifest` using schema
  `lattice-aggregation:p1-external-nonce-producer-capture-review:v1`; the
  review must be `reviewed_external_capture_ready`, bind the request, capture,
  capture-file, readiness, and backend source-tree digests, and record explicit
  checks excluding hazmat, centralized-helper, fixture, localnet/simulation, and
  single-key standard-provider sources.
- `standard_verifier_compatibility_artifact_digest`:
  `evidence_present_unclosed` from
  `p1_standard_verifier_compatibility_artifact_gate`
  (`p1_standard_verifier_compatibility_artifact_package`); this is
  conformance/proof-review evidence.
  Checked standard-verifier compatibility fixture:
  `tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json`.
- `real_threshold_backend_emission_artifact_digest`:
  `evidence_present_unclosed` from `p1_real_threshold_backend_output_gate`
  (`p1_real_threshold_backend_emission_artifact_package` and
  `derive_p1_verified_real_threshold_backend_emission_artifact_package` plus
  `derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture`);
  this is an ingestion gate for provider-verified external backend-emission
  evidence only.
  Canonical backend-emission capture schema/importer:
  `P1RealThresholdBackendEmissionCapture`,
  `P1OwnedRealThresholdBackendEmissionOutput`,
  `lattice-aggregation:p1-real-threshold-backend-emission-capture:v1`, and
  `tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json`.
  The importer binds externally supplied backend source, implementation,
  transcript, public key, message, accepted signature, predecessor certificate
  digests, expected package digests, and mutation-rejection evidence before it
  feeds the provider-verified adapter. Captures also carry the repo request
  schema/name/SHA-256 binding so the capture runner can reject stale, missing,
  or mismatched answers to a request manifest. The schema fixture is blocked
  until actual backend-generated real-threshold emission artifacts replace it.
  Repo-generated backend emission request manifest:
  `lattice-aggregation:p1-real-threshold-backend-emission-request:v1` and
  `scripts/build_backend_emission_request.py`. This request is the P1 challenge
  contract an external backend must answer before capture: it binds the message,
  10,000-validator target, threshold 6,667, predecessor certificate digests,
  required capture schema, external `RealThresholdMldsa` evidence class, and
  mutation-rejection requirements. The capture runner loads this request JSON
  and requires the backend capture to echo the exact request digest before
  writing artifacts. The current checked request is
  `artifacts/backend-emission-request/latest/request.json`, with request
  SHA-256 `804a2549a04010dace167d8f5647635f57a2465520dd087b6c80cc9ae3108ec1`
  recorded in `artifacts/backend-emission-request/latest/manifest.json`. It
  remains `evidence_present_unclosed` and is requires proof-closure evidence.
  Backend emission now also has a file-based intake path:
  `scripts/stage_external_backend_emission_capture.py`. That path stages a
  preexisting `outside_repo_capture_file` into
  `artifacts/backend-emission-capture/latest`, requires a separate
  `outside_repo_review_manifest` with schema
  `lattice-aggregation:p1-external-backend-emission-capture-review:v1`, requires
  review status `reviewed_external_backend_emission_capture_ready`, validates
  the exact request digest through the canonical backend capture runner, records
  `preexisting_external_capture_file` provenance, and rejects repo-local files,
  missing or failed review manifests, stale request bindings,
  localnet/simulation, fixture, and single-key standard-provider sources before
  artifact write. The executable checks are pinned by
  `script_tests/test_stage_external_backend_emission_capture.py`. This is an
  executable intake path only; it does not supply the missing real external
  backend capture, requires Criterion 2 proof review, and does not prove
  rejection-distribution preservation or theorem closure.
  The repo-owned hazmat threshold backend capture adapter
  `scripts/run_hazmat_threshold_backend_capture.py` is the explicit-backend
  bridge for the current 10,000-validator experiment: it requires
  `--backend-crate` or `LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE`, generates a
  temporary Rust emitter for a `dytallix-pq-threshold` hazmat backend, checks
  backend and repo standard-verifier acceptance plus mutation rejection, and
  emits canonical request-bound capture JSON for the runner. It is
  `evidence_present_unclosed` conformance/proof-review infrastructure only.
  Its backend transcript now records the accepted attempt id, attempt count,
  retry count, and `per-attempt-bound-predicates` capability. With the hazmat
  backend predicate transcript API available, the transcript sets
  `rejection_predicate_fields_available = true` and carries an `attempts[]`
  array with `mask_seed_digest_hex`, `challenge_digest_hex`,
  `z_bound_result`, `r0_bound_result`, `ct0_bound_result`,
  `hint_bound_result`, and `accepted_or_rejected` for each signing attempt.
  That turns the previous API blocker into predicate-observability evidence for
  the next reviewed batch comparison against centralized ML-DSA rejection
  behavior.
  The repo-owned comparator
  `scripts/run_hazmat_rejection_equivalence_batch.py` is that first comparison
  path: it generates a Rust emitter that calls centralized and threshold
  per-attempt predicate APIs from the explicit backend, emits
  `threshold_attempts`, `centralized_attempts`, `predicate_mismatches`,
  `challenge_digest_matches`, `accepted_or_rejected_matches`, and
  `close_candidate`, and hard-binds
  `claims_rejection_distribution_preservation = false` plus
  `claims_theorem_closure = false`. A live 3-of-5, 8-attempt smoke batch
  produced artifact digest
  `86115e5e8d50099b08f65ee1944ae996f4b5f80cd2407cd393f9648e0454021f`
  with 17 predicate mismatches, including 8 challenge-digest mismatches and 3
  accepted/rejected outcome mismatches. That is real rejection-sampling
  comparison evidence, but it is not a close candidate.
  A 10,000-validator, threshold-6,667, 1-attempt comparator run produced
  artifact digest
  `51b2e252360dfad0c06d863f41b8d0e5c6c63f39d24b55b77e3577d6a0f1a901`
  with 4 predicate mismatches, including 1 challenge-digest mismatch and 1
  accepted/rejected outcome mismatch; the emitted threshold signature still
  passed both backend and repo standard-verifier checks. This shows the large
  fan-in path can aggregate and compare, but the current sampling path does not
  satisfy rejection-equivalence closure.
  The aligned-mask-domain mode uses backend hazmat helper
  `derive_mldsa65_centralized_domain_masking_contribution_from_share` so the
  threshold aggregate mask is in the centralized `rho_double_prime/kappa`
  domain. A live 3-of-5, 8-attempt aligned batch produced artifact digest
  `3f007157d3a4540ba12ca6797e7efe5efe905920b8d444c983a83d06b1e41660` with
  zero predicate mismatches, accepted and rejected attempt coverage, both
  verifier checks passing, and `close_candidate = true`. A live
  10,000-validator, threshold-6,667, 8-attempt aligned batch produced artifact
  digest
  `e74d8c56dc1f92b762bb42ac41157ac54eb6470062fdd30e8bcc1207b3f29e68` with
  zero predicate mismatches, accepted and rejected attempt coverage, both
  verifier checks passing, and `close_candidate = true`. This is strong
  algebraic closure-candidate evidence for Criterion 2, but it still relies on
  expanded secret-key material to align the mask domain and therefore does not
  replace a reviewed distributed nonce-DKG/PRF construction or close the
  theorem by itself.
  The distributed-nonce-prf-output-shares mode consumes active-set-bound nonce
  PRF output shares on the threshold contribution path instead of calling the
  centralized masking helper. A live 3-of-5, 8-attempt distributed-nonce batch
  produced artifact digest
  `82f55f4f3ce5a76b8935d1b00a9ea2537993b590ca518120c714e5f2cdea20d8` with
  zero predicate mismatches, accepted and rejected attempt coverage, both
  verifier checks passing, and `close_candidate = true`. A live
  10,000-validator, threshold-6,667, 8-attempt distributed-nonce batch produced
  artifact digest
  `5ca4d6d6a7a0f66a9eaca5b008832c96d84a11442c479856fbea378976f952b0` with
  zero predicate mismatches, accepted and rejected attempt coverage, both
  verifier checks passing, and `close_candidate = true`. This moves the
  threshold masking contribution path past the centralized masking helper, but
  the PRF-output oracle still derives the seed from expanded secret-key material
  until a reviewed distributed PRF/MPC producer replaces it. The required
  producer slot is now explicit as
  `distributed_nonce_producer_artifact_digest`; the selected P1 nonce producer
  route is `FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG P1`, and
  the current replacement target is
  `derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key`.
  The actual backend capture runner
  (`derive_p1_verified_real_threshold_backend_emission_capture` and
  `scripts/run_backend_emission_capture.py`) may supply externally generated
  `RealThresholdMldsa` capture material to the canonical importer only after the
  Rust side has an artifact-ready package and the script side rejects known
  localnet/simulation sources plus non-importable capture shapes before artifact
  write. It remains `evidence_present_unclosed` until the reviewed proof
  payload, validation artifacts, rejection-distribution argument, and external
  review are complete.
  checked real-threshold backend emission ingestion fixture harness:
  `tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json`.
  The fixture harness pins source, implementation, transcript, and artifact
  digests, but it is blocked from artifact readiness as `FixtureHarness`; it is
  not a real threshold backend implementation and does not replace actual real
  threshold backend emissions. The checked
  actual single-key ML-DSA-65 negative-control emission fixture:
  `tests/fixtures/p1_standard_provider_single_key_emission_artifact_fixture.json`
  carries an actual `ml-dsa`/`HazmatMldsa65Provider` ML-DSA-65 signature,
  source digest, implementation digest, transcript digest, accepted signature
  digest, and mutation rejection evidence, but it is rejected as
  `StandardProviderSingleKey` because it is not threshold backend provenance.
- `full_kat_validation_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_full_kat_validation_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `rejection_distribution_review_digest`: `evidence_present_unclosed` from
  `p1_criterion2_rejection_distribution_review_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
  Checked rejection-distribution review fixture:
  `tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json`.
- `norm_bound_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_norm_bound_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `hint_bound_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_hint_bound_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `challenge_bound_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_challenge_bound_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `transcript_binding_evidence_digest`: `evidence_present_unclosed` from
  `p1_criterion2_transcript_binding_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
- `theorem_linkage_artifact_digest`: `evidence_present_unclosed` from
  `p1_criterion2_theorem_linkage_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).
  Checked theorem-linkage fixture:
  `tests/fixtures/p1_theorem_linkage_artifact_fixture.json`.
  Live theorem-linkage review package:
  `artifacts/p1-theorem-linkage-review/latest/manifest.json`
  (`reviewed_theorem_linkage_ready`).
- `external_review_digest`: `evidence_present_unclosed` from
  `p1_criterion2_external_review_artifact_gate`
  (`p1_criterion2_proof_slot_artifact_package`).

Typed Criterion 2 proof-slot artifact packages provide deterministic package
shape, digest binding, review metadata, and proof-review claim boundaries for
all listed slots, including the threshold-output certificate, real
recomputation predecessor evidence, and the distributed nonce-producer artifact
slot. `evidence_present_unclosed` means the slot has typed evidence for review;
for the producer slot it specifically means the fail-closed gate exists while a
reviewed backend-generated producer artifact is still required.
`evidence_present_unclosed only` does not mean
Criterion 2 is met, selected-backend proof closure is complete,
rejection-distribution preservation is proven, or the theorem is closed. The
slot claim boundary is `conformance/proof-review evidence`.

All Criterion 2 proof slots now have typed wrappers, while
`distributed_nonce_producer_artifact_digest` remains unclosed until actual
externally generated backend nonce-producer material replaces the hazmat oracle.
The backend-output adapter
`derive_p1_distributed_nonce_producer_artifact_package_from_backend_output`
now hashes submitted `Mldsa65DistributedNonceProducerArtifact` material into
the nonce-producer artifact package, including an explicit
backend-implementation digest. The capture importer
`derive_p1_distributed_nonce_producer_artifact_package_from_capture` imports
canonical `lattice-aggregation:p1-distributed-nonce-producer-capture:v1`
envelopes with request, predecessor, and expected-digest bindings. Request
builder `scripts/build_nonce_producer_request.py` and capture runner
`scripts/run_nonce_producer_capture.py` create the executable handoff path for
actual external nonce-producer captures while remaining
`evidence_present_unclosed`. The precise CLI contract is
`docs/cryptography/p1-nonce-producer-backend-cli-contract.md`, and checked
replay artifacts under `artifacts/nonce-producer-handoff/latest/` bind a
generated request, command metadata, capture logs, checksums, request SHA-256,
and importer-accepted capture JSON for review. The replay manifest now records
`quarantined_local_schema_replay` so this fixture-style path cannot masquerade
as an admissible external backend capture. The accepted
backend readiness artifact at
`artifacts/nonce-producer-backend-readiness/latest/manifest.json` records that
the checked backend profile has distributed nonce-PRF interfaces and is
`backend_candidate_admissible_pending_capture` with no detected blockers.
The handoff replay enforces that a real external
backend command cannot be promoted without an admissible readiness manifest
bound to the reused request SHA-256. The capture-attempt runner
`scripts/run_admissible_nonce_producer_capture_attempt.py` records this
promotion decision as
`artifacts/nonce-producer-capture-attempt/latest/manifest.json`; the current
checked status is `capture_promoted`, with `backend_command_executed = true`
and handoff source profile `repo_reference_cli_capture`. The promoted capture
is quarantined as reference CLI replay only: it exercises the external
process/JSON/import contract but is requires actual backend evidence. The accepted
actual-external gate artifact at
`artifacts/nonce-producer-actual-external-gate/latest/manifest.json` is
`actual_external_capture_ready`, so the distributed nonce-producer slot now has
actual external capture evidence. The Batch 4 command-origin guard rejects
unmarked repo-local backend commands and records
`outside_repo_executable_or_script` for accepted external commands; remaining
Criterion 2 closure work is now on the real threshold backend, reviewed
evidence package, and proof obligations rather than the nonce gate. The Batch 5
file-intake script
`scripts/stage_external_nonce_producer_capture.py` can stage a preexisting
outside-repo capture file into attempt-compatible handoff artifacts only when a
matching Batch 6 `outside_repo_review_manifest` with
`reviewed_external_capture_ready` status binds the capture/readiness evidence,
but no such reviewed external capture file and review dossier are checked in.
The accepted
proof-closure artifact certificate also carries durable certificate evidence
for the threshold-output certificate, real recomputation predecessor, and
distributed nonce-producer artifact digests through
`P1SelectedBackendProofClosureArtifactCertificate::threshold_output_certificate_artifact_digest`
and
`P1SelectedBackendProofClosureArtifactCertificate::real_recomputation_evidence_artifact_digest`,
plus
`P1SelectedBackendProofClosureArtifactCertificate::distributed_nonce_producer_artifact_digest`.
The threshold-output certificate slot is now backed by the checked
`tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json`
fixture so reviewers can inspect the bound threshold-output source package,
source digest, predecessor aggregate certificate digest, transcript binding,
accepted output digests, and typed slot artifact digest without relying only on
in-memory test construction.
The real recomputation predecessor slot is now backed by the checked
`tests/fixtures/p1_real_recomputation_artifact_fixture.json` fixture so
reviewers can inspect the bound source evidence, review digest, transcript
binding, predecessor threshold-output certificate, and typed slot artifact
digest without relying only on in-memory test construction.
The standard-verifier compatibility slot is also backed by the checked
`tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json`
fixture so reviewers can inspect the bound verifier payload, provider identity,
accepted result, predecessor certificate digest, transcript binding, and
standard-verifier compatibility artifact digest without promoting the slot
beyond `evidence_present_unclosed`.
The real-threshold backend emission ingestion artifact is typed through
`P1RealThresholdBackendEmissionArtifactPackage` and
`assess_p1_real_threshold_backend_emission_artifact`. The backend-output adapter
`P1RealThresholdBackendEmissionOutput` plus
`derive_p1_verified_real_threshold_backend_emission_artifact_package` binds
backend source package, implementation, transcript, public key, message, and
aggregate-signature digests to the predecessor threshold-output and
standard-verifier compatibility certificates after standard-provider acceptance.
The canonical backend-emission capture schema/importer
`P1RealThresholdBackendEmissionCapture` plus
`derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture`
is now the JSON handoff for actual external backend captures. It rejects schema
fixtures, decodes owned backend output material, checks predecessor certificate
digests and expected package digests, and then feeds the same provider-verified
adapter. This standardizes the future source digest, implementation digest,
transcript digest, accepted signature, mutation-rejection evidence, and
standard-verifier compatibility binding without implementing a real threshold
backend.
Only an accepted `RealThresholdMldsa` package can feed the threshold verifier
closure contract through `to_verifier_closure_package`.
The checked
`tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json`
fixture pins that capture schema, but it is not actual real threshold backend
emission evidence and is blocked until externally generated threshold emission
artifacts are available.
The checked
`tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json`
fixture harness lets reviewers inspect the bound backend source package,
implementation, transcript, predecessor certificate digests, mutation-rejection
evidence, and raw fixture-package digest, but it is deliberately blocked from
artifact readiness. The checked
`tests/fixtures/p1_standard_provider_single_key_emission_artifact_fixture.json`
negative-control fixture proves that actual single-key ML-DSA provider output
verifies and rejects message, key, and signature mutations, while still being
rejected as non-threshold provenance. These are still not a real threshold
backend implementation, not actual real threshold backend emission evidence,
and requires proof-closure evidence.
The rejection-distribution review slot is now backed by the checked
`tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json`
fixture so reviewers can inspect the bound rejection-distribution review source
evidence, review digest, threshold-output certificate digest, transcript
binding, and typed slot artifact digest without promoting the slot beyond
`evidence_present_unclosed`.
The theorem-linkage slot is now backed by the checked
`tests/fixtures/p1_theorem_linkage_artifact_fixture.json` fixture so reviewers
can inspect the bound theorem-linkage source evidence, review digest,
threshold-output certificate digest, transcript binding, and typed slot artifact
digest without promoting the slot beyond `evidence_present_unclosed`.
The current close-candidate run also has a generated theorem-linkage review at
`artifacts/p1-theorem-linkage-review/latest/manifest.json`; it binds Criterion 2
theorem links, formal theorem/proof-obligation documents, the external
close-candidate attempt, DKG/no-single-secret review, accepted-distribution/abort
review, and rejection-batch predicate evidence while keeping all closure,
distribution-preservation, CAVP/ACVTS, and FIPS claims false.
Batch 7 adds
`P1ExternalBackendCryptographicClosureCandidatePackage` and
`scripts/build_p1_external_backend_cryptographic_closure_candidate.py` as the
first umbrella candidate gate for the actual cryptographic closure attempt. Its
Criterion 2 evidence source is
`p1_external_backend_cryptographic_closure_candidate_gate`, and the package class
is `p1_external_backend_cryptographic_closure_candidate_package`. The gate
composes the strict actual external nonce-producer gate, request-bound
real-threshold backend emission capture, standard-verifier acceptance evidence,
mutation-rejection evidence, and `distributed-nonce-prf-output-shares`
rejection-distribution comparison, plus reviewed production
DKG/no-single-secret evidence and reviewed accepted-distribution/abort evidence,
into
`artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json`.
The current checked artifact is `evidence_present_unclosed` with
`close_candidate = true`: the actual external nonce gate, strict backend
emission capture, standard-verifier acceptance, mutation-rejection,
rejection-batch comparison, production DKG/no-single-secret review, and
accepted-distribution/abort review slots are present. This remains proof-review
evidence only; it does not by itself prove Criterion 2,
rejection-distribution preservation, selected-backend proof closure, or theorem
closure.
Batch 8 adds `scripts/run_p1_external_backend_evidence_attempt.py` as the grouped
external-evidence attempt runner. Its Criterion 2 evidence source is
`p1_external_backend_evidence_attempt_gate`, its artifact package label is
`p1_external_backend_evidence_attempt_artifact`, and it writes
`artifacts/p1-external-backend-evidence-attempt/latest/manifest.json`. The runner
executes the Batch 7 builder over the actual external nonce gate, real-threshold
backend emission capture, standard-verifier acceptance evidence, mutation
rejection evidence, rejection-distribution comparison, production
DKG/no-single-secret review, and accepted-distribution/abort review, then adds
`source_exclusion_passed` to reject hazmat, simulation, localnet, fixture,
test-vector, single-key, repo-reference, and quarantined replay markers before a
close candidate can be treated as external evidence. The current checked attempt
is `external_evidence_close_candidate_ready` with `close_candidate = true`,
source exclusions passed, and no external-evidence blockers. This is the first
grouped attempt harness for the closure run, pending theorem-closure review.
Batch 9 hardens the same grouped attempt with a reviewed external evidence
package gate. The runner now accepts `--review-package` pointing at schema
`lattice-aggregation:p1-external-backend-evidence-package-review:v1`; the
package must have `reviewed_external_backend_evidence_ready` status,
`outside_repo_review_manifest` origin, `admissible_external_backend_capture`
source profile, `review_package_binds_inputs = true` over the actual external
nonce gate, real-threshold backend capture, rejection batch, and Batch 7
candidate digest, production DKG/no-single-secret review, and
accepted-distribution/abort review, plus source-exclusion and review-digest
checks. The checked attempt records `review_package_present = true`,
`review_package_binds_inputs = true`, and valid production-DKG plus
accepted-distribution/abort review-package classes, while Criterion 2 remains
`partially_met`.
The attempt manifest now also exposes the two review-package classes that a
strict external backend closure attempt must carry: `production_dkg_no_single_secret_review`
with route `tee_hsm_no_export`, and `accepted_distribution_abort_review`. The
readiness preflight rejects aggregate ready booleans unless those package
classes and statuses are present alongside a close-candidate strict external
backend attempt and exact input-bound review package.
`scripts/build_theorem_closure_review_manifest.py` writes the current
theorem-review manifest with status `theorem_closure_review_incomplete`. It
marks the proof payload and standard-verifier compatibility review slots
satisfied, but leaves rejection-distribution preservation, full KAT/CAVP
validation, and theorem linkage review unsatisfied.
Batch 4 proof-closure artifact packages, typed Criterion 2 proof-slot artifact
packages, and the P1 standard-verifier compatibility artifact gate are inputs
to this payload, requires proof-closure evidence by themselves.

## Theorem Links

The proof payload must link the artifact package to the theorem and lemma
surfaces that actually carry Criterion 2:

- `Correctness Lemma 7`: standard verification compatibility.
- `Correctness Lemma 8`: ML-DSA-65 module-vector norm, hint, and challenge
  bounds.
- `Noise Lemma D`: aggregate rejection bound preservation.
- `Noise Lemma F`: aggregate rejection soundness and standard verification.
- `Noise Lemma H`: accepted-signature distribution.
- `FST-L5`: aggregation correctness for a standard-valid ML-DSA signature.
- `FST-L7`: abort and rejection compatibility.

## Promotion Requirements

Criterion 2 remains `partially_met` until all of the following are reviewed and
linked:

- reviewed proof payload tying threshold-output, recomputation, bounds,
  rejection behavior, and standard verification;
- full KAT/validation artifact package;
- reviewed rejection-distribution preservation argument;
- reviewed standard-verifier compatibility argument;
- reviewed Batch 7 external-backend closure-candidate bundle populated from
  actual external nonce and real-threshold backend captures;
- reviewed production DKG/no-single-secret package with
  `package_class = production_dkg_no_single_secret_review`,
  `route = tee_hsm_no_export`, no centralized seed, expanded-key split,
  single-key, hazmat, or unreviewed trust setup;
- reviewed accepted-distribution/abort package with
  `package_class = accepted_distribution_abort_review` covering
  rejection-distribution preservation, selective abort/withholding, restart
  leakage, concurrency, and concrete loss bounds;
- reviewed Batch 8 grouped external-evidence attempt with `source_exclusion_passed`
  true and `close_candidate = true`;
- reviewed Batch 9 external evidence package with `review_package_binds_inputs`
  true, source exclusions passed, and review digests present;
- theorem-linkage review. Current status: reviewed for theorem-linkage
  inventory, but Criterion 2 still requires rejection-distribution preservation
  and full KAT/validation before theorem-closure assessment readiness.

`scripts/assess_theorem_closure_readiness.py` records these blockers in
`artifacts/theorem-closure-readiness/latest/manifest.json` before theorem
closure assessment can begin. A future
`ready_for_theorem_closure_assessment` result is only an assessment-entry
preflight; it is not Criterion 2 closure and pending theorem-closure review.

The existing selected-backend proof-closure artifact package gate is necessary
but not sufficient for criterion-2 promotion. `ClosureReady` and
`ArtifactReady` mean the relevant framework has all typed evidence digests
needed for proof review; they do not mean those artifacts have been
independently validated in this repository.

## Failure Conditions

Criterion 2 fails or remains blocked if either condition is observed and cannot
be repaired within the selected Profile P1 assumptions:

- accepted threshold outputs fail standard ML-DSA-65 verification;
- aggregate rejection accepts outputs outside centralized ML-DSA-65 predicates.

These failure conditions are proof-review conditions, not claims that the
native path has already failed.

## Assessment Boundary

The assessor may report `criterion2_proof_payload_formalized` when this
contract and its manifest are present and internally consistent. That report
field keeps `aggregate_rejection_equivalence` at `partially_met`, keeps the
overall verdict at `partially_proven`, and records the remaining theorem
review requirements.
