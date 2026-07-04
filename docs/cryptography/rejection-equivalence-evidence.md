# Aggregate Rejection-Equivalence Evidence

This note records a bounded conformance artifact for blocker 2:
aggregate rejection checks should match centralized ML-DSA rejection checks.
The current artifact does not close the blocker. It separates scaffold-only
digest evidence from evidence that is tied to both a standard-verifier bridge
and a public aggregate recomputation transcript. It also defines a stronger
closure-package framework for the evidence that must exist before blocker 2 can
move from conformance plumbing to proof closure.

## Implemented Gate

`src/production/rejection_equivalence.rs` defines:

- `AggregateRejectionEvidenceStrength::ScaffoldOnly`, for digest-only evidence
  that can support conformance plumbing but cannot satisfy the equivalence gate.
- `AggregateRejectionEvidenceStrength::ProviderRecomputedBridge`, for evidence
  minted only after `StandardVerifierEvidence::verify::<P>` accepts the
  candidate signature and the recomputed aggregate signature digest matches the
  verifier-checked candidate signature digest.
- `AggregateRecomputationTranscript`, a public-output transcript that binds the
  production challenge digest, aggregate-response digest, hint digest, and
  recomputed aggregate-signature digest.
- `AggregateRejectionEquivalenceGate`, which rejects scaffold-only evidence and
  returns bridge evidence only when the standard provider and recomputation
  transcript agree on the candidate signature.
- `derive_standard_verifier_bridge_evidence_digest`, which derives a versioned
  digest from the selected profile binding digest, provider/KAT evidence digest,
  and provider-verified bridge evidence. The digest is an artifact identifier,
  not a production compatibility claim.
- `AggregateRejectionEvidenceDigest`, which tags each digest by artifact class
  so scaffold-only placeholders cannot be supplied where real recomputation or
  KAT evidence is required.
- `AggregateRejectionClosurePackage`, which represents the complete blocker-2
  closure package: real aggregate recomputation evidence, standard verifier
  provider/KAT evidence, norm-bound evidence, hint-bound evidence,
  challenge-bound evidence, transcript-binding evidence, negative test corpus
  evidence, external review evidence, and an explicit conformance boundary.
- `assess_rejection_equivalence_closure`, which returns
  `AggregateRejectionClosureAssessment::ClosureReady` only when the package uses
  the `ClosureCandidate` boundary and every required digest is present,
  non-zero, and classified as the expected non-scaffold artifact.
- `AcvpFips204EvidenceSource`, `Mldsa65ProviderKatEvidence`,
  `P1RejectionProofArtifacts`, `P1AggregateRecomputationClosurePackage`, and
  `assess_p1_aggregate_recomputation_closure`, which bind the selected
  ML-DSA-65 coordinator-assisted Shamir nonce DKG P1 profile to
  a selected profile binding digest, ACVP/FIPS204-backed provider KAT evidence,
  aggregate recomputation evidence, a standard-verifier bridge evidence digest,
  bound/proof artifact digests, negative-corpus evidence, and external review
  digests. The P1 gate rejects smoke-only KATs, unreviewed proof artifacts,
  selected-profile drift, standard-verifier bridge drift, and digest drift
  between the P1 package and the underlying closure package.

The targeted conformance tests in `tests/production_rejection_equivalence.rs`
cover the red/green behavior:

- scaffold-only evidence is classified but does not satisfy the gate;
- provider-verified recomputation evidence satisfies the gate;
- failed standard verification is rejected;
- recomputed aggregate-signature mismatch is rejected;
- transcript mismatch is rejected;
- the checked-in standard-verifier bridge fixture package parses, rebuilds the
  bound transcript, derives the standard-verifier bridge evidence digest, and
  pins the negative-corpus cases.
- complete closure packages expose closure-ready status without claiming a
  production verifier;
- missing real recomputation evidence is rejected;
- missing standard provider/KAT evidence is rejected;
- scaffold-only recomputation or KAT evidence is rejected;
- missing bound evidence, zero external review digests, and scaffold-only
  conformance boundaries are rejected.
- P1 aggregate recomputation packages expose artifact-ready status only when the
  selected P1 profile, selected profile binding digest, ACVP/FIPS204-backed
  provider evidence, standard-verifier bridge evidence digest, reviewed proof
  artifacts, and closure-package digests agree;
- smoke-only provider evidence, unreviewed proof artifacts, mismatched selected
  profile binding digests, mismatched standard-verifier bridge evidence digests,
  and mismatched P1 KAT digests are rejected.

`tests/production_provider.rs` also includes a checked-in, bounded NIST
ACVP-Server FIPS204 `ML-DSA-sigVer` sample-vector fixture at
`tests/fixtures/acvp_mldsa65_sigver_fips204_sample.json`. The fixture is pinned
to upstream commit `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0` with SHA-256
digests for the upstream `prompt.json` and `expectedResults.json`. It exercises
one expected-accept and one expected-reject ML-DSA-65 external/pure sigVer case
through `HazmatMldsa65Provider::verify_with_context`. This is provider
sample-vector conformance evidence only; it is not CAVP/ACVTS production validation.

`tests/fixtures/p1_standard_verifier_bridge_fixture.json` is a checked-in
standard-verifier bridge fixture package. It is a fixture-backed bridge evidence
package that binds the selected profile binding digest, ACVP sample-vector
provider/KAT evidence digest, provider-checked candidate signature digest,
recomputed aggregate signature digest, aggregate-response digest, hint digest,
transcript-binding digest, and negative mismatch cases used by
`tests/production_rejection_equivalence.rs`. The fixture-backed bridge evidence package is a stricter blocker-2 release gate and is necessary but not sufficient for criterion-2 promotion. This is conformance evidence only: it is not selected-backend aggregate output evidence, not production threshold ML-DSA recomputation, not CAVP/ACVTS validation, not FIPS validation, and not a completed standard-verifier compatibility proof.
The P1 recomputation artifact path carries the raw fixture-package digest as
reviewed evidence, and the checked-in fixture test pins the expected digest so
fixture-package drift fails loudly during conformance review. This is
test-pinned drift detection and evidence carriage, not an independent freshness
proof for arbitrary externally supplied package digests.

`P1SelectedBackendAggregateArtifactPackage` and
`assess_p1_selected_backend_aggregate_artifact` add a selected-backend aggregate-output artifact gate. The gate binds `LocalAccept`/`AggregateAccept`
evidence to the production transcript, signer set, attempt ID, provider KAT
digest, real recomputation digest, and standard-verifier bridge evidence digest
before the artifact can be reported ready for proof review. The selected-backend
aggregate-output artifact gate is conformance/proof-review evidence only. It may
reject drift and bind checked-in artifact digests, but it is
not production threshold ML-DSA security, not selected-backend proof closure,
not CAVP/ACVTS or FIPS validation, and not a completed standard-verifier
compatibility proof.

`derive_p1_selected_backend_aggregate_artifact_package` and
`derive_p1_real_recomputation_evidence_digest` add a real standard-provider
aggregate-output package path for P1. The package is derived from a
provider-verified ML-DSA-65 candidate signature, `LocalAccept` and
`AggregateAccept` tokens, a public recomputation transcript, and a
standard-verifier bridge digest. The positive coverage in
`tests/production_rejection_equivalence.rs` uses a fixed-seed ML-DSA-65
signature through `HazmatMldsa65Provider`, and the stale recomputation test
rejects changed recomputation output before an artifact package can be minted.
This is stronger than fixture-only bridge confidence, but it remains
conformance/proof-review evidence only and does not claim a real threshold
aggregate signer.

`P1RealThresholdBackendEmissionArtifactPackage`,
`derive_p1_real_threshold_backend_emission_artifact_package`, and
`assess_p1_real_threshold_backend_emission_artifact` add the real threshold backend emission ingestion artifact for the 10,000-validator target. The
artifact binds `validators = 10000`, `threshold = 6667`,
`aggregate_signature.len() = 3309`, real threshold ML-DSA backend provenance,
backend source package, implementation, and transcript digests,
`MLDSA65.Verify(aggregate_public_key, message, aggregate_signature) == accept`,
matching threshold-output and standard-verifier compatibility artifact digests,
and mutation rejection for message, public key, and signature.

`P1RealThresholdBackendEmissionOutput` and
`derive_p1_verified_real_threshold_backend_emission_artifact_package` are the
checked backend-output adapter for future externally generated real-threshold
emissions. The adapter compares the submitted public key, message, and
aggregate signature against the predecessor certificates, calls the selected
standard ML-DSA provider boundary before minting the package, and derives the
backend source, implementation, transcript, and evidence digests from submitted
backend material. It is still an ingestion adapter only; it does not implement a
real threshold backend in this repository.

`P1RealThresholdBackendEmissionCapture`,
`P1OwnedRealThresholdBackendEmissionOutput`, and
`derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture`
are the canonical backend-emission capture schema/importer for actual external
backend-output ingestion. The capture schema
`lattice-aggregation:p1-real-threshold-backend-emission-capture:v1` requires the
backend provenance material, verifier tuple, request schema/name/SHA-256
binding, predecessor certificate digests, expected package digests, accepted
signature bytes, and mutation-rejection evidence to be present before the
importer feeds the provider-verified adapter.
`scripts/build_backend_emission_request.py` writes the repo-generated P1
backend-emission request manifest
`lattice-aggregation:p1-real-threshold-backend-emission-request:v1`. That
request binds the message, 10,000-validator target, threshold 6,667,
predecessor certificate digests, required capture schema, required
`RealThresholdMldsa` evidence class, mutation-rejection requirements, and
forbidden localnet/simulation/fixture capture sources before an external
backend attempts emission.
`derive_p1_verified_real_threshold_backend_emission_capture` and
`scripts/run_backend_emission_capture.py` are the actual backend capture runner
surfaces for producing this canonical JSON from externally generated
`RealThresholdMldsa` capture material. The Rust surface requires an
artifact-ready real-threshold backend package before it can emit an external
capture envelope, and the script rejects localnet and deterministic simulation
command sources, non-importable capture shapes, and stale or missing request
digest bindings before artifact write. It records `evidence_present_unclosed`
conformance/proof-review evidence only.
`scripts/run_hazmat_threshold_backend_capture.py` is the repo-owned adapter for
the current hazmat threshold backend run. It requires an explicit
`--backend-crate` path, or `LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE`, to a
`dytallix-pq-threshold` checkout; generates a temporary Rust emitter; runs the
10,000-validator, threshold-6,667 hazmat session; checks both the backend
external-pure verifier and the repo `HazmatMldsa65Provider`; checks mutated
message, public-key, and signature rejection; and prints the canonical
request-bound capture JSON consumed by `scripts/run_backend_emission_capture.py`.
This adapter is a reproducibility path for actual backend capture evidence, not
production threshold ML-DSA security, not rejection-distribution preservation,
and not theorem closure.
The capture transcript now carries per-attempt rejection-predicate evidence
when the backend exposes the hazmat predicate transcript API: it records the
accepted attempt id, attempt count, retry count, `per-attempt-bound-predicates`
capability, and an `attempts[]` array with each attempt id, mask-seed digest,
challenge digest, `z_bound_result`, `r0_bound_result`, `ct0_bound_result`,
`hint_bound_result`, and `accepted_or_rejected`. This means the current run can
prove accepted-output standard-verifier conformance, mutation rejection for the
emitted tuple, and backend predicate observability for the signing attempts.
It still does not prove rejection-distribution preservation until those
attempt-level predicates are compared against centralized ML-DSA rejection
behavior across reviewed batches.

`scripts/run_hazmat_rejection_equivalence_batch.py` now provides the first
centralized-vs-threshold comparison runner for that question. It generates a
temporary Rust emitter against an explicit backend checkout, derives
centralized ML-DSA per-attempt predicates and threshold per-attempt predicates,
and emits `threshold_attempts`, `centralized_attempts`, `predicate_mismatches`,
`challenge_digest_matches`, `accepted_or_rejected_matches`, and
`close_candidate`. A live 3-of-5, 8-attempt smoke batch produced artifact digest
`86115e5e8d50099b08f65ee1944ae996f4b5f80cd2407cd393f9648e0454021f` with 17
predicate mismatches, including 8 challenge-digest mismatches and 3
accepted/rejected outcome mismatches. That run confirms the comparator can
aggregate and compare actual backend predicate evidence, and it blocks theorem
closure for the current sampling path rather than proving rejection-distribution
preservation.
A 10,000-validator, threshold-6,667, 1-attempt comparator run produced artifact
digest `51b2e252360dfad0c06d863f41b8d0e5c6c63f39d24b55b77e3577d6a0f1a901`
with 4 predicate mismatches, including 1 challenge-digest mismatch and 1
accepted/rejected outcome mismatch. The threshold signature still passed both
backend and repo standard-verifier checks, so this result separates
standard-verifier compatibility from rejection-sampling equivalence: the large
fan-in path can aggregate and compare, but the current sampling path is not a
theorem-closure candidate.

The comparator also has an aligned-mask-domain mode that derives threshold
masking contributions in the centralized `rho_double_prime/kappa` mask domain.
This mode produced zero-mismatch close-candidate evidence:

- 3-of-5, 8 attempts:
  `3f007157d3a4540ba12ca6797e7efe5efe905920b8d444c983a83d06b1e41660`;
  zero predicate mismatches, accepted and rejected attempt coverage, backend
  and repo verifier acceptance, `close_candidate = true`.
- 10,000 validators, threshold 6,667, 8 attempts:
  `e74d8c56dc1f92b762bb42ac41157ac54eb6470062fdd30e8bcc1207b3f29e68`;
  zero predicate mismatches, accepted and rejected attempt coverage, backend
  and repo verifier acceptance, `close_candidate = true`.

This is the strongest Criterion 2 evidence so far: when the threshold mask
domain is aligned to centralized ML-DSA, aggregate rejection predicates match
centralized rejection predicates across accepted and rejected attempts, including
the 10,000-validator fan-in path. It is not theorem closure yet because the
aligned helper uses expanded secret-key material to place the aggregate mask in
the centralized domain; a reviewed distributed nonce-DKG/PRF replacement must
provide the same domain without central secret-key access.

The comparator now also has a distributed-nonce-prf-output-shares mode. In this
mode the threshold contribution path consumes active-set-bound nonce PRF output
shares rather than calling the centralized masking helper:

- 3-of-5, 8 attempts:
  `82f55f4f3ce5a76b8935d1b00a9ea2537993b590ca518120c714e5f2cdea20d8`;
  zero predicate mismatches, accepted and rejected attempt coverage, backend
  and repo verifier acceptance, `close_candidate = true`.
- 10,000 validators, threshold 6,667, 8 attempts:
  `5ca4d6d6a7a0f66a9eaca5b008832c96d84a11442c479856fbea378976f952b0`;
  zero predicate mismatches, accepted and rejected attempt coverage, backend
  and repo verifier acceptance, `close_candidate = true`.

This is a real step past the centralized masking helper on the threshold
contribution path. It is still not final theorem closure because the current
distributed nonce shares are fed by a hazmat PRF-output oracle; a reviewed
distributed PRF/MPC producer must replace that oracle before this can be treated
as cryptographic closure evidence rather than closure-candidate conformance
evidence.
Batch 7 now records that closure-candidate composition explicitly. The Rust
`P1ExternalBackendCryptographicClosureCandidatePackage` and
`scripts/build_p1_external_backend_cryptographic_closure_candidate.py` bundle the
strict actual external nonce gate, real-threshold backend emission capture,
standard-verifier acceptance evidence, complete mutation rejection evidence, and
this rejection-distribution comparison into
`artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json`.
The checked manifest is still `close_candidate = false` because those actual
external evidence slots are not all present. A future `close_candidate = true`
manifest would be closure-candidate evidence for review, not a completed theorem
proof or a claim of rejection-distribution preservation.
The selected replacement route is now tracked in
[`p1-nonce-producer-selection.md`](p1-nonce-producer-selection.md) as
`FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG P1`; Criterion 2 now
requires `distributed_nonce_producer_artifact_digest` from
`p1_criterion2_distributed_nonce_producer_artifact_gate` before the
distributed-nonce comparator can count as reviewed producer evidence.
The checked
`tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json`
fixture pins the future envelope, but it carries
`real_threshold_mldsa_capture_schema_fixture` evidence and is blocked until
actual backend-generated real-threshold ML-DSA emission artifacts exist.

The checked fixture harness at
`tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json`
pins the external backend-emission input shape, backend source package digest,
backend implementation digest, backend transcript digest, mutation rejection
flags, and raw fixture-package digest for review. The harness is now classified
as `FixtureHarness` and is blocked by
`assess_p1_real_threshold_backend_emission_artifact`; it cannot feed the
verifier closure package through `to_verifier_closure_package`.

The checked negative-control fixture at
`tests/fixtures/p1_standard_provider_single_key_emission_artifact_fixture.json`
carries actual `ml-dsa`/`HazmatMldsa65Provider` ML-DSA-65 output: fixed-seed
public key, accepted signature, backend source digest, implementation digest,
transcript digest, standard-verifier acceptance, and mutated message, public key,
and signature rejection evidence. It is deliberately classified as
`StandardProviderSingleKey` and rejected because ordinary single-key standard
provider output is not threshold backend provenance.

Both fixtures remain conformance/proof-review evidence only. They are not a
real threshold backend implementation, not actual real threshold backend
emission evidence, and not a completed cryptographic proof.

A reviewed `P1RealThresholdBackendEmissionArtifactCertificate` can feed
`P1RealThresholdVerifierClosurePackage` through `to_verifier_closure_package`,
which is then assessed by `assess_p1_real_threshold_verifier_closure_contract`. The
gate rejects `SimulatedDeterministic` evidence as `blocked_fail_closed` and
rejects `StandardProviderSingleKey` evidence because ordinary single-key standard-provider output is not threshold backend provenance. This is
framework/conformance evidence only and does not claim a real threshold backend
is implemented in this repository, production threshold ML-DSA security,
selected-backend proof closure, CAVP/ACVTS validation, FIPS validation,
rejection-distribution preservation, completed standard-verifier compatibility,
or a completed cryptographic proof.

`P1SelectedBackendThresholdOutputArtifactPackage`,
`derive_p1_selected_backend_threshold_output_artifact_package`, and
`assess_p1_selected_backend_threshold_output_artifact` add the Batch 3
selected-backend threshold-output artifact gate. The gate binds a reviewed
threshold-output source digest and reviewed source-package digest to the
selected-backend aggregate artifact certificate, signer set, attempt,
transcript, `LocalAccept`/`AggregateAccept` evidence, public recomputation
transcript, real recomputation digest, and standard-verifier bridge evidence
digest. This is stronger than real standard-provider aggregate-output package evidence because it requires a
successor source artifact to agree with the already accepted aggregate-output
certificate. It remains conformance/proof-review evidence only: it is not
selected-backend proof closure, not production threshold ML-DSA security, not
CAVP/ACVTS validation, not FIPS validation, not rejection-distribution preservation, and not a completed standard-verifier compatibility proof.

`P1SelectedBackendProofClosureArtifactPackage`,
`derive_p1_selected_backend_proof_closure_artifact_package`,
`derive_p1_selected_backend_threshold_output_certificate_digest`, and
`assess_p1_selected_backend_proof_closure_artifact` add the Batch 4
selected-backend proof-closure artifact package gate. The gate binds the
accepted threshold-output certificate to selected profile, provider KAT,
threshold-output source package, recomputation, standard-verifier bridge,
accepted aggregate output, reviewed proof-artifact, full KAT/validation artifact slots, rejection-distribution review, standard-verifier compatibility, and
theorem-linkage artifact digest evidence. This is stronger than the selected-backend threshold-output artifact gate because the proof-review package must agree with the accepted threshold-output certificate before it can be
reported. It remains conformance/proof-review evidence only: it is not
selected-backend proof closure, not production threshold ML-DSA security, not
CAVP/ACVTS validation, not FIPS validation, not rejection-distribution
preservation, and not a completed standard-verifier compatibility proof.

Typed Criterion 2 proof-slot artifact packages are the review boundary for the
new slot layer.

`P1Criterion2ProofSlotArtifact`, `P1Criterion2ProofSlotArtifacts`,
`derive_p1_criterion2_proof_slot_artifacts`, and
`derive_p1_criterion2_proof_slot_artifact` add Typed Criterion 2 proof-slot
artifact packages for the threshold-output certificate, real recomputation
evidence, full KAT/validation, rejection-distribution review, norm-bound,
hint-bound, challenge-bound, transcript-binding, theorem-linkage, and
external-review slots. The package gate domain-separates each slot, binds it to
the accepted threshold-output certificate and transcript binding, and rejects
wrong slot kind, predecessor source mismatches, proof-artifact source mismatches
for slots with predecessor proof-artifact sources, stale external-review
digests, production claim boundaries, and digest drift. This layer upgrades
loose digest carriage into typed
`p1_criterion2_proof_slot_artifact_package` evidence, but it remains
conformance/proof-review evidence only: it is not selected-backend proof
closure, not production threshold ML-DSA security, not CAVP/ACVTS validation,
not FIPS validation, not rejection-distribution preservation, and not a
completed standard-verifier compatibility proof.
All Criterion 2 proof slots now have typed `evidence_present_unclosed`
wrappers; the predecessor threshold-output certificate and recomputation slots
are also carried as durable certificate evidence on the accepted proof-closure
artifact certificate through
`P1SelectedBackendProofClosureArtifactCertificate::threshold_output_certificate_artifact_digest`
and
`P1SelectedBackendProofClosureArtifactCertificate::real_recomputation_evidence_artifact_digest`.
The real recomputation predecessor slot is also backed by the checked
`tests/fixtures/p1_real_recomputation_artifact_fixture.json` fixture, which
binds the real recomputation source digest, review evidence digest,
threshold-output certificate digest, transcript binding, and typed slot artifact
digest for proof review.
They are still not criterion closure by themselves.

## Claim Boundary

This is hazmat/conformance-only evidence. It does not claim production
threshold ML-DSA security, real threshold aggregate recomputation, CAVP/ACVTS
validation, FIPS 140 module status, or rejection-sampling distribution
preservation. `ClosureReady` and `ArtifactReady` mean the relevant framework has
all typed evidence digests needed for proof review; they do not mean those
artifacts have been independently validated in this repository.

The safe claim is narrower: the coordinator-assisted profile now has a typed
gate that prevents digest-only scaffold evidence from being mistaken for
standard-verifier/recomputation bridge evidence, a closure-package assessor that
prevents missing or scaffold-only recomputation/KAT evidence from being reported
as ready for blocker closure, an ACVP sample-vector provider conformance test,
and a selected-P1 artifact gate with a checked-in standard-verifier bridge
fixture package that prevents smoke-only KATs or unreviewed proof artifacts,
selected-profile drift, fixture-backed bridge evidence package drift, or
standard-verifier bridge drift from closing the P1 recomputation blocker.

## What Remains

To fully close blocker 2 cryptographically, the repo still needs:

- actual real threshold backend emissions for the selected P1 profile that
  satisfy the threshold verifier closure contract;
- reviewed selected-backend proof arguments tying threshold-output,
  recomputation, bounds, rejection behavior, and standard verification into one
  accepted argument beyond the current selected-backend proof-closure artifact
  package gate;
- reviewed selected profile binding evidence for the exact ML-DSA-65
  coordinator-assisted Shamir nonce DKG P1 profile under review;
- validation artifacts for the standard-verifier bridge and selected provider;
  the current checked-in bridge fixture, selected-backend aggregate-output
  artifact gate, real standard-provider aggregate-output package path,
  selected-backend threshold-output artifact gate, and selected-backend
  proof-closure artifact package gate are conformance/proof-review evidence
  only;
- full provider KAT coverage for the advertised API surface, plus any CAVP/ACVTS
  vector-set IDs, validation transcripts, certificate identifiers, lab sign-off,
  and prerequisite validation references if the claim moves beyond sample-vector
  conformance;
- reviewed norm, hint, and challenge bound artifacts whose digests match the
  closure package;
- a transcript-binding artifact showing the package is bound to the production
  signing transcript, original application message, signer set, and attempt;
- a negative test corpus showing scaffold/provider mismatch cases fail closed;
- external review evidence for the recomputation, KAT, bounds, transcript, and
  negative-corpus artifacts;
- broader coordinator/proof wiring after write-scope review, so closure-ready
  packages become an explicit release gate instead of a standalone assessor;
- crosswalk and proof-manifest updates once the artifact is promoted beyond
  this owned-file slice;
- proof work showing accepted aggregate rejection behavior matches centralized
  ML-DSA rejection checks, including distribution-preservation analysis.
