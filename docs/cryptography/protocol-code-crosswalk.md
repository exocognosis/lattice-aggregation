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
hazmat/conformance profile boundary only: it is not a production threshold
ML-DSA security claim and does not by itself establish real ML-DSA
verification.

## Protocol Phase Crosswalk

| Protocol phase | Implementation surface | Test evidence | Current boundary |
| --- | --- | --- | --- |
| DKG scaffold | `src/dkg.rs`, `src/backend.rs`, `src/crypto/vss.rs`, `src/crypto/interpolation.rs` | `tests/simulated_flow.rs`, `tests/low_level.rs` | Deterministic research scaffold only; no malicious-secure DKG claim. |
| Signing state machine | `src/protocol.rs`, `src/types.rs`, `src/collections.rs` | `tests/simulated_flow.rs`, `tests/type_state.rs`, `tests/validation.rs` | Type-state and collection guards enforce call ordering and signer sets. |
| Transcript binding | `src/transcript.rs`, `src/backend.rs`, `src/protocol.rs` | `tests/transcript_determinism.rs`, `tests/simulated_flow.rs` | Deterministic challenge binding for scaffold tests; no distributional proof. |
| Aggregation boundary | `src/aggregation.rs`, `src/backend.rs`, `src/collections.rs` | `tests/simulated_flow.rs`, `tests/type_state.rs` | Boundary validation before backend aggregation; no standard-verifier claim. |
| Adapter wire and actor flow | `src/adapter/wire.rs`, `src/adapter/actor.rs`, `src/adapter/traits.rs` | `tests/simulation.rs` | Local async scaffold for P2P and consensus integration experiments. |
| Production coordinator candidate | `src/production/provider.rs`, `src/production/epsilon.rs`, `src/production/prefilter.rs`, `src/production/hints.rs`, `src/production/transcript.rs`, `src/production/preprocess.rs`, `src/production/coordinator.rs`, `src/adapter/production_wire.rs` | `tests/production_provider.rs`, `tests/production_epsilon.rs`, `tests/production_prefilter.rs`, `tests/production_hints.rs`, `tests/production_transcript.rs`, `tests/production_preprocess.rs`, `tests/production_coordinator.rs`, `tests/production_wire.rs`, `tests/ui/production_simulated_backend_rejected.rs` | Gated hazmat/conformance boundary only; no real ML-DSA verification or production threshold security claim. |
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
`src/adapter/production_wire.rs` defines the production coordinator frame
shapes.

`tests/production_provider.rs`, `tests/production_transcript.rs`,
`tests/production_preprocess.rs`, `tests/production_coordinator.rs`, and
`tests/production_wire.rs` exercise the coordinator boundary and wire
conformance. `tests/ui/production_simulated_backend_rejected.rs` guards that
the simulated backend cannot satisfy the production coordinator backend
contract. The standard-verifier trait receives the original application
message, while `MessageBinding`/`mu` remains transcript-internal. The current
public API exposes only the blocked hazmat policy; approved release policy is
crate-internal until real release evidence exists. These are gate and
conformance tests only; they are not a real ML-DSA verifier, threshold proof,
side-channel audit, FIPS validation, or release approval.

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
for review artifacts.

The harness and exporter are useful for reproducibility and comparison of
research scenarios. They must not be used as side-channel evidence, liveness
evidence, cryptographic security evidence, or proof that the scaffold is ready
for production consensus signing.

## Open Production Gaps

The following remain outside the current implementation claim:

- a selected concrete threshold ML-DSA-65 construction and backend;
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
- `## Evidence and Timeout Diagnostics`
- `## Benchmark and Export Harness`
- `## Open Production Gaps`
- `## Manifest Anchors`
- `deterministic simulation backend`
- `not a production threshold ML-DSA proof`
- `does not produce or verify real ML-DSA signatures`
