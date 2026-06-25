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
