# Release Readiness Checklist

Date: 2026-06-19

## Scope

This checklist defines the minimum gates that must be satisfied before any
release, publication, or deployment language can describe this repository as
production-ready threshold ML-DSA-65 software. It is intentionally blocking:
No release gate is complete until the evidence is present, reviewed, and linked
from the relevant claim document.

The current repository remains a deterministic research scaffold. Benchmark
and harness output is deterministic research telemetry, useful for regression
review and reproducibility, but not security evidence.

## Required Inputs

Every release review must name the exact commit, feature set, target platforms,
compiler/toolchain, dependency lockfile, backend implementation, proof package,
test results, benchmark artifacts, audit reports, and claim-boundary docs under
review.

The review must explicitly state whether it covers the default simulated
backend, the non-default `coordinator-assisted` profile, the
`hazmat-real-mldsa` production-candidate skeleton, or another backend not
present in this checkout.

For construction-selection review, the current selected production-candidate
backend direction is Profile P1: ML-DSA-65 coordinator-assisted Shamir nonce
DKG with a TEE/HSM-backed coordinator assumption and a standard-verifier
compatibility target. This selection is not evidence of production security,
FIPS validation, completed proof, or release readiness. Profile P2 fully
distributed MPC and TALUS-style optimized threshold ML-DSA remain later
migration candidates that require separate review.

## Cryptography and Proof Gates

- Keep the concrete threshold ML-DSA-65 construction documented as Profile P1:
  coordinator-assisted Shamir nonce DKG with the TEE/HSM coordinator
  assumption, standard-verifier compatibility target, and P2/MPC plus TALUS
  migration candidates.
- Keep the thesis and operating-parameter contract in
  `docs/cryptography/thesis-operating-parameters.md` and
  `docs/cryptography/thesis-operating-parameters.json` aligned with thesis id
  `native-threshold-mldsa65-aggregation-p1`, scope `research scaffold only`,
  all five criteria `partially_met`, and Falcon/LaBRADOR-style proof
  aggregation as `evaluate only`.
- Keep the Criterion 2 proof-substance contract in
  `docs/cryptography/criterion-2-proof-substance.md` and
  `docs/cryptography/criterion-2-proof-substance.json` aligned with
  `aggregate_rejection_equivalence`, status
  `criterion2_proof_payload_formalized`, and Criterion 2 still
  `partially_met` until reviewed proof, compatibility, distribution,
  validation, theorem-linkage, and external-review artifacts are supplied.
- Complete the threshold unforgeability and real/ideal proof package under the
  stated adversary, network, abort, and corruption model.
- Show aggregate output compatibility with a standard ML-DSA verifier.
- Complete VSS/DKG binding, hiding, extractability, complaint soundness, and
  anti-framing arguments.
- Record the external cryptographic review and all unresolved limitations.
- If native threshold ML-DSA proof closure stalls, treat Falcon/LaBRADOR-style
  proof-wrapper aggregation only as a fallback architecture to evaluate. It is
  not a selected backend, not a production release path, and not a claim about
  this repository's current implementation. Any pivot requires separate scheme
  selection, prover and verifier benchmarks, consensus-latency analysis, audit
  review, and updated claim-boundary docs.

## Implementation and Backend Gates

- Implement a production backend behind an explicit feature and policy gate.
- Prove the default simulated backend cannot be selected accidentally for a
  production-labeled API.
- Complete FIPS/ACVP-style ML-DSA-65 provider KATs for the selected provider
  and link the vectors, logs, tool versions, and reviewer sign-off.
- Keep the checked-in NIST ACVP-Server FIPS204 `ML-DSA-sigVer` ML-DSA-65 sample
  fixture passing under `hazmat-real-mldsa`, with source commit and SHA-256
  digests recorded. Treat this as sample-vector conformance only; CAVP/ACVTS
  validation claims require lab/Prod-server vector sets, validation transcripts,
  certificate identifiers, prerequisite validation references, and reviewer
  sign-off.
- Complete coordinator-assisted threshold KATs for profile policy gates,
  transcript binding, preprocessing attempts, final verifier behavior, and
  production coordinator wire frames.
- Treat the checked-in standard-verifier bridge fixture package at
  `tests/fixtures/p1_standard_verifier_bridge_fixture.json` as a
  mandatory criterion-2 release gate. Fixture-backed bridge evidence,
  negative-corpus cases, selected profile binding digest, standard-verifier bridge evidence
  digest, and test-pinned raw fixture-package digest must remain stable before criterion
  promotion. This gate is necessary but not sufficient; it is
  not selected-backend aggregate recomputation,
  not production threshold ML-DSA recomputation, and
  real threshold selected-backend accepted aggregate signatures remain a release blocker.
- Provide production LocalAccept/AggregateAccept evidence for the selected
  backend before any criterion promotion, including rejection cases, logs,
  reviewer sign-off, and linked `tests/production_acceptance.rs` results.
- Tie `LocalAccept` and `AggregateAccept` acceptance to a standard verifier bridge
  and real aggregate recomputation evidence; absent bridge or
  recomputation evidence keeps the predicates conformance-only.
- Require the P1 aggregate recomputation artifact gate before criterion-2
  promotion: selected ML-DSA-65 coordinator-assisted profile binding,
  selected profile binding digest, ACVP/FIPS204-backed provider evidence,
  standard-verifier bridge evidence digest, real threshold recomputation digest,
  norm/hint/challenge/transcript proof artifact digests, negative corpus digest,
  and external review digest must all agree. The P1 gate is framework evidence
  until the real threshold artifacts and reviewed proofs are checked in.
- Require the selected-backend aggregate-output artifact gate before criterion-2
  promotion: `P1SelectedBackendAggregateArtifactPackage`,
  `assess_p1_selected_backend_aggregate_artifact`, and the
  `p1_selected_backend_aggregate_artifact_gate` assessment/report key must bind
  `LocalAccept`/`AggregateAccept` evidence, signer-set digest, attempt-binding
  digest, transcript-binding digest, provider KAT digest, recomputation digest,
  and standard-verifier bridge evidence digest. This gate is
  conformance/proof-review evidence only, necessary but not sufficient,
  criterion-2 remains partial, and the selected-backend aggregate-output
  artifact gate is not selected-backend proof closure,
  not production threshold ML-DSA security, not CAVP/ACVTS validation,
  not FIPS validation, and not a completed standard-verifier compatibility proof.
- Require the real standard-provider aggregate-output package path before
  claiming that the selected-backend artifact package moved beyond fixture-only
  bridge confidence: `derive_p1_selected_backend_aggregate_artifact_package`,
  `derive_p1_real_recomputation_evidence_digest`, and the
  `p1_selected_backend_real_output_package` assessment/report key must derive
  the package from a provider-verified ML-DSA-65 candidate signature,
  `LocalAccept`/`AggregateAccept` tokens, public recomputation transcript, and
  standard-verifier bridge digest evidence. This is still
  conformance/proof-review evidence only; it is not a real threshold aggregate
  signer, production threshold ML-DSA security, CAVP/ACVTS validation, FIPS
  validation, rejection-distribution preservation, or completed
  standard-verifier compatibility proof.
- Require the selected-backend threshold-output artifact gate before claiming
  that Batch 3 moved beyond real standard-provider aggregate-output package
  evidence: `P1SelectedBackendThresholdOutputArtifactPackage`,
  `assess_p1_selected_backend_threshold_output_artifact`,
  `derive_p1_selected_backend_threshold_output_artifact_package`,
  `derive_p1_selected_backend_threshold_output_source_digest`,
  `derive_p1_selected_backend_threshold_output_source_package_digest`,
  `derive_p1_selected_backend_aggregate_certificate_digest`, and the
  `p1_selected_backend_threshold_output_artifact_gate` assessment/report key
  must bind selected-backend threshold-output source evidence to the aggregate
  artifact certificate, signer-set digest, attempt-binding digest,
  transcript-binding digest, public recomputation digest, accepted signature
  digest, standard-verifier bridge evidence digest, and reviewed source-package digest. This is the first Batch 3 threshold-output artifact boundary, not production threshold signing,
  not selected-backend proof closure, not CAVP/ACVTS validation, not FIPS
  validation, not rejection-distribution preservation, and not completed
  standard-verifier compatibility.
- Require the selected-backend proof-closure artifact package gate before
  claiming that Batch 4 moved beyond the threshold-output artifact gate:
  `P1SelectedBackendProofClosureArtifactPackage`,
  `assess_p1_selected_backend_proof_closure_artifact`,
  `derive_p1_selected_backend_proof_closure_artifact_package`,
  `derive_p1_selected_backend_threshold_output_certificate_digest`, and the
  `p1_selected_backend_proof_closure_artifact_gate` assessment/report key must
  bind the accepted threshold-output certificate to selected profile, provider
  KAT, recomputation, standard-verifier bridge evidence, accepted aggregate
  output, reviewed proof artifacts, full KAT/validation artifact slots,
  rejection-distribution review, standard-verifier compatibility evidence, and
  theorem-linkage artifact digest evidence. This is the Batch 4 proof-closure artifact package boundary, not selected-backend proof closure, not production
  threshold ML-DSA security, not CAVP/ACVTS validation, not FIPS validation,
  not rejection-distribution preservation, and not completed standard-verifier
  compatibility.
- Link the five hypothesis blocker evidence gates and closure frameworks before
  any criterion promotion: `tests/production_mask_distribution.rs`,
  `tests/production_rejection_equivalence.rs`,
  `tests/production_abort_bias.rs`, `tests/production_partial_soundness.rs`,
  and `tests/unauthorized_aggregate_reduction_manifest.rs`.
- Treat those evidence gates and closure-package frameworks as partial scaffold
  progress only until the selected backend supplies reviewed Renyi evidence,
  real aggregate recomputation, abort-bias analysis, proof-backed partial
  verification, and a completed unauthorized-aggregate reduction. Framework
  closure does not replace reviewed proof artifacts.
- Link proof/audit linkage for acceptance criteria from
  [claims-matrix.md](../cryptography/claims-matrix.md),
  [proof-implementation-crosswalk.md](../cryptography/proof-implementation-crosswalk.md),
  side-channel review, audit TCB review, and external cryptographic review
  before criterion promotion.
- Verify malformed partials, malformed hints, invalid bounds, transcript
  mismatch, key mismatch, duplicate signer, and unknown signer rejection.
- Link Renyi-divergence proof evidence for any `EpsilonLedger` masking budget
  increment and keep absent evidence classified as a release blocker.
- Keep the simulator compile-fail guard active so the deterministic simulated
  backend cannot satisfy production coordinator contracts.
- Complete a DKG setup-only hot-path review proving per-block signing does not
  start DKG, VSS, or share-ceremony work.
- Isolate `trybuild` compile-fail verification in CI and parallel agent runs
  with a dedicated `CARGO_TARGET_DIR` so lock contention in
  `target/tests/trybuild` cannot be mistaken for a type-state regression.
- Audit randomness, nonce derivation, key handling, zeroization, and error
  behavior for the selected backend.

## Side-Channel and Constant-Time Gates

- Run dudect or an equivalent timing test suite for selected secret-dependent
  arithmetic and encoding paths.
- Run ctgrind or an equivalent dynamic leakage check where the target platform
  supports it.
- Review generated code or compiler output for the selected targets and build
  profiles.
- Confirm logging, panics, retries, aborts, and evidence emission do not leak
  outside the stated side-channel model.
- Document remaining side-channel assumptions in
  [side-channel-boundary.md](../cryptography/side-channel-boundary.md).

## Benchmark and Artifact Gates

- Record the harness configuration, cluster scenarios, seeds, dependency
  versions, hardware, OS, and compiler for every benchmark artifact.
- Keep checked-in deterministic simulation results indexed from
  [simulation-results.md](simulation-results.md), and keep real-world benchmark
  claims blocked by
  [real-world-benchmark-protocol.md](real-world-benchmark-protocol.md) until a
  production backend, external validator deployment, raw logs, checksums, and
  reviewer sign-off exist.
- Keep local validator-network telemetry indexed from
  [localnet-validator-runner.md](localnet-validator-runner.md) and separate it
  from real-world benchmark evidence until production transport, consensus
  safety, authenticated validator deployment, and reviewed backend evidence
  exist.
- Keep local fault-profile telemetry such as `withheld-partial` explicitly
  framed as local fault-injection telemetry, not production liveness,
  consensus-safety, slashing-soundness, or Byzantine-fault-tolerance evidence.
- Keep benchmark output framed as deterministic research telemetry and not
  security evidence.
- Store artifact checksums and regeneration commands.
- Validate that tables, JSONL, CSV, and rendered figures match the checked-in
  source data.
- Add fuzz targets for production coordinator frames, including malformed
  frame tags, length fields, attempt counters, transcript digests, provider
  identifiers, and trailing-byte cases.
- Confirm no benchmark or chart wording implies cryptographic security,
  production liveness, side-channel resistance, or FIPS validation.

## Operational and Consensus Gates

- Document authenticated transport, validator identity binding, replay policy,
  timeout policy, retry limits, and session cleanup.
- Review consensus callbacks, state transitions, finality assumptions, and
  slashing policy against the production chain design.
- Prove or externally review public evidence predicates before any slashing
  integration treats scaffold evidence as authoritative.
- Complete deployment, key-management, incident-response, and rollback plans.
- Treat production consensus signing as blocked until the cryptography,
  implementation, side-channel, operational, and audit gates all pass.

## Documentation and Claim-Drift Gates

- Update [claims-matrix.md](../cryptography/claims-matrix.md),
  [proof-implementation-crosswalk.md](../cryptography/proof-implementation-crosswalk.md),
  [protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md),
  [attack-surface.md](../audit/attack-surface.md), and
  [tcb.md](../audit/tcb.md) in the same change that modifies behavior or
  evidence.
- Keep README, release notes, benchmark docs, and audit docs aligned on current
  claims and non-claims.
- Run documentation link and manifest tests before sign-off.
- Remove stale missing-artifact wording when the named artifact is added.

## Explicit Non-Claims

Until every applicable gate above has passed, the repository does not claim:

- production-ready threshold ML-DSA-65 security;
- active-adversary, adaptive-corruption, or real/ideal security;
- standard ML-DSA verifier compatibility for simulated aggregate signatures;
- production slashing soundness or anti-framing;
- side-channel resistance or constant-time behavior;
- FIPS validation, certification, or certified module status;
- production network liveness, authenticated transport, or consensus safety.

## Sign-Off Rule

Release sign-off requires all gates to be checked with linked evidence, named
reviewers, exact commit identifiers, and explicit residual-risk notes. If any
gate is incomplete, the release must retain research-scaffold wording and must
not claim production consensus signing readiness.
