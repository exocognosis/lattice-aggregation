# Protocol Code Crosswalk

Date: 2026-06-19

## Scope

This crosswalk maps the current threshold ML-DSA-65 scaffold protocol phases to
the Rust modules and tests that exercise them. It is a navigation aid for code
review, not a production threshold ML-DSA proof, not an audit result, and not a
release-readiness claim.

The implementation uses a deterministic simulation backend. The default
simulation path produces stable protocol-sized fixtures for tests, but it does
not produce or verify real ML-DSA signatures. Any future production claim must
continue to use the stricter claim boundaries in
[claims-matrix.md](claims-matrix.md),
[proof-implementation-crosswalk.md](proof-implementation-crosswalk.md), and
[side-channel-boundary.md](side-channel-boundary.md).

The repository also contains a non-default production coordinator candidate
behind `coordinator-assisted` and `hazmat-real-mldsa` gates. That surface is a
hazmat/conformance profile boundary only: the optional provider bridge can run
standard ML-DSA-65 verification smoke checks, but it is not a production
threshold ML-DSA security claim and does not establish aggregate threshold
verification.

The selected real-backend direction is ML-DSA-65 coordinator-assisted Shamir
nonce DKG P1 with a TEE/HSM coordinator assumption and
standard-verifier-compatible output. Later migration candidates remain P2/MPC
and TALUS. This is a selection artifact only; it is not proof closure or
production approval, and it does not promote any hypothesis criterion beyond
partial status without selected-backend implementation, proof, and audit
artifacts.

## Protocol Phase Crosswalk

| Protocol phase | Implementation surface | Test evidence | Current boundary |
| --- | --- | --- | --- |
| DKG scaffold | `src/dkg.rs`, `src/backend.rs`, `src/crypto/vss.rs`, `src/crypto/interpolation.rs` | `tests/simulated_flow.rs`, `tests/low_level.rs` | Deterministic research scaffold only; no malicious-secure DKG claim. |
| Signing state machine | `src/protocol.rs`, `src/types.rs`, `src/collections.rs` | `tests/simulated_flow.rs`, `tests/type_state.rs`, `tests/validation.rs` | Type-state and collection guards enforce call ordering and signer sets. |
| Transcript binding | `src/transcript.rs`, `src/backend.rs`, `src/protocol.rs` | `tests/transcript_determinism.rs`, `tests/simulated_flow.rs` | Deterministic challenge binding for scaffold tests; no distributional proof. |
| Aggregation boundary | `src/aggregation.rs`, `src/backend.rs`, `src/collections.rs` | `tests/simulated_flow.rs`, `tests/type_state.rs` | Boundary validation before backend aggregation; no standard-verifier claim. |
| Adapter wire and actor flow | `src/adapter/wire.rs`, `src/adapter/actor.rs`, `src/adapter/traits.rs` | `tests/simulation.rs` | Local async scaffold for P2P and consensus integration experiments. |
| Production coordinator candidate | `src/production/provider.rs`, `src/production/epsilon.rs`, `src/production/prefilter.rs`, `src/production/hints.rs`, `src/production/transcript.rs`, `src/production/preprocess.rs`, `src/production/coordinator.rs`, `src/production/acceptance.rs`, `src/adapter/production_wire.rs` | `tests/production_provider.rs`, `tests/production_epsilon.rs`, `tests/production_prefilter.rs`, `tests/production_hints.rs`, `tests/production_transcript.rs`, `tests/production_preprocess.rs`, `tests/production_coordinator.rs`, `tests/production_acceptance.rs`, `tests/production_wire.rs`, `tests/ui/production_simulated_backend_rejected.rs` | Gated hazmat/conformance boundary only; provider smoke plus a bounded NIST ACVP-Server FIPS204 ML-DSA-65 sigVer sample fixture verify ordinary provider behavior, but coordinator-assisted acceptance predicates are conformance-only and do not establish aggregate threshold verification, CAVP/ACVTS validation, or production threshold security. |
| Selected backend direction artifact | `docs/cryptography/proof-implementation-crosswalk.md`, `docs/cryptography/protocol-code-crosswalk.md`, `scripts/assess_lattice_hypothesis.py` | `script_tests/test_assess_lattice_hypothesis.py`, `tests/proof_documentation_manifest.rs` | ML-DSA-65 coordinator-assisted Shamir nonce DKG P1 direction selection only; not proof closure, backend implementation evidence, or production approval. |
| Hypothesis blocker evidence gates and closure frameworks | `src/production/mask_distribution.rs`, `src/production/rejection_equivalence.rs`, `src/production/abort_bias.rs`, `src/production/partial_soundness.rs`, `docs/cryptography/unauthorized-aggregate-reduction.md` | `tests/production_mask_distribution.rs`, `tests/production_rejection_equivalence.rs`, `tests/production_abort_bias.rs`, `tests/production_partial_soundness.rs`, `tests/unauthorized_aggregate_reduction_manifest.rs` | Typed assessment evidence, a P1 aggregate recomputation artifact gate, selected-backend aggregate-output artifact gate, selected-backend threshold-output artifact gate, selected-backend proof-closure artifact package gate, sample-vector provider conformance, fixture-backed bridge conformance evidence, and stricter release gate coverage only; each gate keeps the corresponding criterion partially met until the selected backend, proof, and audit artifacts exist. |
| Evidence and timeout diagnostics | `src/adapter/evidence.rs`, `src/adapter/actor.rs`, `src/low_level/poly.rs` | `tests/simulation.rs`, `tests/low_level.rs` | Diagnostic evidence packets only; not production slashing authority. |
| Benchmark and export harness | `src/main.rs`, `src/utils/exporter.rs` | library tests in `src/utils/exporter.rs`, harness review docs | Reproducible research output only; not security evidence. |

## DKG Scaffold

`src/dkg.rs` and `src/backend.rs` provide the simulated DKG path used by
integration tests. `src/crypto/vss.rs` and `src/crypto/interpolation.rs` expose
Shamir-style arithmetic scaffolding that helps exercise reconstruction-shaped
flows.

The corresponding tests in `tests/simulated_flow.rs` and `tests/low_level.rs`
show deterministic public-key binding, interpolation behavior, and arithmetic
guard rails. They do not show VSS hiding, binding, extractability, complaint
soundness, key-bias resistance, or active-adversary robustness.

## Signing State Machine

`src/protocol.rs` owns the type-state signing flow from initialized sessions to
commitment collection, transcript binding, partial signing, and aggregation
readiness. `src/types.rs` and `src/collections.rs` provide the opaque protocol
types and duplicate-free validator/share containers consumed by that flow.

`tests/simulated_flow.rs` checks the normal flow and mismatch rejection.
`tests/validation.rs` checks duplicate, unknown, malformed, and insufficient
collection behavior. `tests/type_state.rs` uses compile-fail examples to guard
invalid state transitions.

## Transcript Binding

`src/transcript.rs` constructs the canonical signing transcript and derives the
challenge from explicit protocol fields. The transcript binds the session,
threshold, validator universe, public key, message, and ordered commitments
before any simulated partial signature is produced.

`tests/transcript_determinism.rs` checks that network-order differences do not
change the challenge and that message, validator, or commitment mismatches are
rejected. This is an implemented engineering guard, not a proof of formal
injectivity, random-oracle programming soundness, or ML-DSA distributional
equivalence.

## Aggregation Boundary

`src/aggregation.rs` requires a bound transcript and threshold-valid partial
share set before delegating to the backend. `src/backend.rs` provides the
deterministic simulation aggregation behavior, and `src/collections.rs` rejects
inconsistent signer sets before aggregation can proceed.

`tests/simulated_flow.rs` covers deterministic ordering, public-key mismatch
rejection, and signer-universe mismatch rejection. The simulated aggregate
bytes are stable fixtures; they are not claimed to verify with a standard
ML-DSA verifier.

## Adapter Wire and Actor Flow

`src/adapter/wire.rs` owns versioned frame encoding and decoding for scaffold
messages. `src/adapter/actor.rs` drives bounded local session state and calls
the adapter traits in `src/adapter/traits.rs`.

`tests/simulation.rs` checks round trips, golden encodings, malformed-frame
rejection, actor capacity, finalization, and evidence emission. The adapter
layer does not include production authenticated transport, replay protection
outside the local frame fields, consensus finality, or operational key
management.

## Production Coordinator Candidate

`src/production/provider.rs` defines the provider boundary and KAT-gated
conformance contract. `src/production/transcript.rs` binds the
production-candidate transcript fields. `src/production/preprocess.rs` tracks
preprocessing attempts and retry context. `src/production/coordinator.rs`
enforces the coordinator profile and final verifier gate.
`src/production/acceptance.rs` defines the coordinator-assisted acceptance
predicates that carry typed `LocalAccept` and `AggregateAccept` conformance
tokens.
`src/adapter/production_wire.rs` defines the production coordinator frame
shapes.

`tests/production_provider.rs`, `tests/production_transcript.rs`,
`tests/production_preprocess.rs`, `tests/production_coordinator.rs`,
`tests/production_acceptance.rs`, and `tests/production_wire.rs` exercise the
coordinator boundary, acceptance predicates, and wire conformance.
`tests/ui/production_simulated_backend_rejected.rs` guards that the simulated
backend cannot satisfy the production coordinator backend contract.
`HazmatMldsa65Provider` runs optional ML-DSA-65 verifier smoke checks over
ordinary provider-generated signatures and a checked-in NIST ACVP-Server FIPS204
ML-DSA-65 sigVer sample fixture through its context-aware verifier path. The
standard-verifier trait receives the original application message, while
`MessageBinding`/`mu` remains transcript-internal. The current public API exposes
only the blocked hazmat policy; approved release policy is crate-internal until
real release evidence exists. These are gate and conformance tests only; they
are not threshold proof, real threshold aggregate recomputation, aggregate
threshold verification, distribution proof, side-channel audit, CAVP/ACVTS
validation, FIPS 140 module certification, or release approval.

## Selected Backend Direction

The selected real threshold backend direction is ML-DSA-65
coordinator-assisted Shamir nonce DKG P1. P1 assumes a TEE/HSM coordinator
assumption for nonce DKG coordination and targets standard-verifier-compatible
output. Later migration candidates remain P2/MPC and TALUS.

This crosswalk is the protocol-side anchor consumed by
`scripts/assess_lattice_hypothesis.py`; the proof-side anchor is
`docs/cryptography/proof-implementation-crosswalk.md`. The selected direction
narrows the next implementation path, but it is a selection artifact only. It
is not proof closure or production approval, not completed backend
implementation evidence, not complete standard-verifier KAT or validation
evidence, and not external cryptographic review. All five hypothesis criteria
remain partial until selected-backend proof, implementation, and audit artifacts
exist.

For blocker 2, the P1 aggregate recomputation artifact gate in
`src/production/rejection_equivalence.rs` binds the selected profile to
ACVP/FIPS204-backed provider evidence, aggregate recomputation evidence,
selected profile binding digest, standard-verifier bridge evidence digest,
bound/proof artifact digests, negative-corpus evidence, and external review
digests. The checked-in standard-verifier bridge fixture package at
`tests/fixtures/p1_standard_verifier_bridge_fixture.json` provides fixture-backed bridge conformance evidence for drift rejection only. The checked-in bridge fixture is a stricter release gate for drift rejection only; it is not selected-backend aggregate recomputation and not a completed standard-verifier compatibility proof. The selected-backend aggregate-output artifact gate binds `LocalAccept`/`AggregateAccept`, signer-set, attempt, transcript, provider KAT, recomputation, and bridge digests as conformance/proof-review evidence only. `derive_p1_selected_backend_aggregate_artifact_package` and `derive_p1_real_recomputation_evidence_digest` add a real standard-provider aggregate-output package path that derives the package from a provider-verified ML-DSA-65 candidate signature, public recomputation transcript, and standard-verifier bridge digest evidence. The selected-backend threshold-output artifact gate adds successor source-package binding, and the selected-backend proof-closure artifact package gate binds that threshold-output certificate to full KAT/validation artifact slots, rejection-distribution review, standard-verifier compatibility evidence, and a theorem-linkage artifact digest. These gates are not selected-backend proof closure, not production threshold ML-DSA security, not CAVP/ACVTS validation, not FIPS validation, not rejection-distribution preservation, and not a completed standard-verifier compatibility proof. They reject smoke-only provider evidence and digest mismatch, but remain framework evidence until real threshold recomputation and reviewed proofs are supplied.

## Evidence and Timeout Diagnostics

`src/adapter/evidence.rs` defines local evidence containers and payloads that
the simulation actor can emit for malformed or invalid contributions. The
evidence fields are useful review targets because they may influence a future
consensus-facing design.

Current evidence is diagnostic. It is not a production slashing transaction,
not an anti-framing proof, and not a public complaint system for malicious DKG
or partial-share validity.

## Benchmark and Export Harness

`src/main.rs` runs the deterministic harness used to produce simulation output.
`src/utils/exporter.rs` formats LaTeX table rows and PGFPlots-compatible CSV
for review artifacts. `scripts/run_simulation_benchmarks.py` runs the bounded
large profile and writes checked-in deterministic simulation artifacts under
`docs/benchmarks/generated/latest-simulation/`, with the review index in
`docs/benchmarks/simulation-results.md`.

The harness and exporter are useful for reproducibility and comparison of
research scenarios. They must not be used as side-channel evidence, liveness
evidence, cryptographic security evidence, or proof that the scaffold is ready
for production consensus signing.

## Open Production Gaps

The following remain outside the current implementation claim:

- implementation artifacts for the selected ML-DSA-65 coordinator-assisted
  Shamir nonce DKG P1 backend direction;
- a completed active-adversary security proof;
- malicious-secure VSS/DKG with complaint soundness and anti-framing;
- standard ML-DSA verifier compatibility for aggregate signatures beyond the
  gated production-candidate verifier boundary;
- audited randomness, erasure, side-channel, and constant-time behavior;
- authenticated transport, consensus integration, and operational slashing
  policy;
- FIPS validation or certification evidence.

## Manifest Anchors

The documentation manifest test treats these headings and phrases as stable
anchors:

- `# Protocol Code Crosswalk`
- `## Scope`
- `## Protocol Phase Crosswalk`
- `## DKG Scaffold`
- `## Signing State Machine`
- `## Transcript Binding`
- `## Aggregation Boundary`
- `## Adapter Wire and Actor Flow`
- `## Production Coordinator Candidate`
- `## Selected Backend Direction`
- `## Evidence and Timeout Diagnostics`
- `## Benchmark and Export Harness`
- `## Open Production Gaps`
- `## Manifest Anchors`
- `deterministic simulation backend`
- `not a production threshold ML-DSA proof`
- `does not produce or verify real ML-DSA signatures`
- `ML-DSA-65 coordinator-assisted Shamir nonce DKG P1`
- `TEE/HSM coordinator assumption`
- `standard-verifier-compatible output`
- `P2/MPC`
- `TALUS`
- `selection artifact`
- `not proof closure`
- `not production approval`
- `scripts/assess_lattice_hypothesis.py`
- `script_tests/test_assess_lattice_hypothesis.py`
- `coordinator-assisted acceptance predicates`
- `src/production/acceptance.rs`
- `tests/production_acceptance.rs`
- `LocalAccept`
- `AggregateAccept`
- `Hypothesis blocker evidence gates and closure frameworks`
- `P1 aggregate recomputation artifact gate`
- `src/production/mask_distribution.rs`
- `src/production/rejection_equivalence.rs`
- `src/production/abort_bias.rs`
- `src/production/partial_soundness.rs`
- `docs/cryptography/unauthorized-aggregate-reduction.md`
- `tests/production_mask_distribution.rs`
- `tests/production_rejection_equivalence.rs`
- `tests/production_abort_bias.rs`
- `tests/production_partial_soundness.rs`
- `tests/unauthorized_aggregate_reduction_manifest.rs`
