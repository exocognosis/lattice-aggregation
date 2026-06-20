# Trusted Computing Base

Date: 2026-05-26

## Scope

This document identifies what a reviewer would need to trust for the current
research scaffold and the non-default production-candidate skeleton. The
production-candidate surfaces exist under `coordinator-assisted` and
`hazmat-real-mldsa`, but this document is a triage aid, not an audit result,
certification statement, proof package, or production-readiness claim.
There is no real ML-DSA verifier, audited production backend, completed proof,
FIPS validation, or release approval in this checkout.

The authoritative claim boundaries remain in
[claims-matrix.md](../cryptography/claims-matrix.md),
[proof-implementation-crosswalk.md](../cryptography/proof-implementation-crosswalk.md),
and the [release-readiness checklist](../benchmarks/release-readiness-checklist.md).

## Current TCB

The current TCB for research-review purposes includes:

- Rust compiler, Cargo feature resolution, and build profile selection.
- Runtime dependencies in `Cargo.toml`: `async-trait`, `serde`, `sha3`,
  `thiserror`, `tokio`, and `zeroize`.
- Test-only or development dependencies when evaluating conformance evidence:
  `serde_json` and `trybuild`.
- `src/types.rs`, `src/errors.rs`, and shared protocol types used by wire,
  actor, and crypto paths.
- `src/adapter/wire.rs` for canonical frame encoding and decoding.
- `src/adapter/actor.rs`, `src/adapter/traits.rs`, and
  `src/adapter/evidence.rs` for actor behavior, external adapter assumptions,
  and evidence payloads.
- `src/low_level/poly.rs`, `src/crypto/vss.rs`, and
  `src/crypto/interpolation.rs` for arithmetic and simulated VSS scaffolding.
- `src/backend.rs`, `src/dkg.rs`, `src/protocol.rs`, and
  `src/aggregation.rs` for simulation backend behavior and signing flow
  validation.
- `src/production/provider.rs`, `src/production/transcript.rs`,
  `src/production/preprocess.rs`, `src/production/coordinator.rs`, and
  `src/adapter/production_wire.rs` for non-default production-candidate
  skeleton gates, provider boundaries, transcript/preprocessing bindings,
  final verifier boundary, and production coordinator frames.
- `src/utils/exporter.rs` and `src/main.rs` for harness output behavior.
- The cryptography and audit docs that define current claims, non-claims, and
  review boundaries.

This TCB is intentionally broad because the project is a scaffold: claim
accuracy depends on code behavior, feature gates, tests, harnesses, and docs
remaining aligned.

## Dependency Assumptions

Reviewers should treat dependency behavior as assumed rather than proven by
this repository:

- `sha3` implements the hash and XOF primitives used for transcript and
  scaffold digest derivation.
- `serde` and `serde_json` correctly serialize and parse benchmark artifacts
  where used, but canonical cryptographic frame encodings are local code and
  must be reviewed directly.
- `tokio` scheduling in tests and harnesses is not a production network model.
- `zeroize` availability does not by itself prove reliable erasure or adaptive
  security.
- Cargo feature resolution is part of the trust boundary. Reviewers should test
  intended feature combinations explicitly.

No dependency assumption substitutes for formal proof, side-channel review, or
external cryptographic audit.

## Feature-Gate Risks

Feature gates are security-relevant because they decide which scaffold and
hazmat paths are compiled:

- `simulated` is enabled by default and supports scaffold behavior only.
- `coordinator-assisted` exposes a non-default coordinator profile boundary for
  hazmat conformance and review.
- `hazmat-real-mldsa` exposes the production-candidate provider boundary and
  KAT-gated skeleton.
- `hazmat-real-mldsa` implies `hazmat`; neither gate should be treated as
  production approval.
- No `experimental-vss` feature is declared in the current `Cargo.toml`.

Triage should look for accidental default exposure, docs that omit feature
conditions, tests that only cover one feature combination, and public APIs that
make scaffold backends appear production-approved.

## High-Priority Review Files

Start with these files for security triage:

| File | Why it is high priority |
| --- | --- |
| `Cargo.toml` | Feature-gate graph, dependency set, and default behavior. |
| `src/adapter/wire.rs` | Untrusted byte parsing, canonical frame encoding, replay/context fields, and bounded variable payloads. |
| `src/adapter/actor.rs` | State machine, quorum behavior, strict commitment enforcement, and evidence emission. |
| `src/low_level/poly.rs` | Polynomial arithmetic scaffold used by lower-level experiments. |
| `src/crypto/interpolation.rs` | Field inversion and Lagrange interpolation helpers. |
| `src/crypto/vss.rs` | Simulated VSS/interpolation scaffold. |
| `src/backend.rs` | Deterministic simulation backend and production-claim boundary. |
| `src/dkg.rs` | Simulated distributed key generation scaffold. |
| `src/protocol.rs` | Type-state signing flow and validation ordering. |
| `src/aggregation.rs` | Aggregation boundary and threshold-valid share checks. |
| `src/production/provider.rs` | Provider contract, provider KAT gate, ignored release-blocking KAT test target, and final verification boundary. |
| `src/production/transcript.rs` | Production-candidate transcript fields and binding assumptions. |
| `src/production/preprocess.rs` | Preprocessing attempts, retry context, and nonce/mask claim boundary. |
| `src/production/coordinator.rs` | Coordinator-assisted profile policy gates, final verifier gate, and non-default production-candidate flow. |
| `src/production/epsilon.rs` | `EpsilonLedger` conformance accounting with open Renyi divergence obligations. |
| `src/production/prefilter.rs` | Blinded pre-filter pass/abort guardrails before response-share release. |
| `src/production/hints.rs` | Hint-routing conformance state using public digests only. |
| `src/adapter/production_wire.rs` | Production coordinator frame parsing, encoding, and context binding. |
| `tests/ui/production_simulated_backend_rejected.rs` | Compile-fail guard that simulated backends do not satisfy production coordinator contracts. |
| `src/adapter/evidence.rs` | Evidence payload encoding and fields that could become consensus-facing. |
| `src/main.rs` | Feature-gated benchmark/export entrypoint and sample artifact generation behavior. |

The crosswalk in
[proof-implementation-crosswalk.md](../cryptography/proof-implementation-crosswalk.md)
maps proof obligations to implementation surfaces and tests.

## What Is Outside Production Trust Today

The following are explicitly outside the production TCB because production trust
has not been established:

- The deterministic VSS/DKG scaffold as malicious-secure DKG.
- The production-candidate coordinator skeleton as a real verifier, audited
  backend, completed threshold proof, or production approval.
- Any future transcript-hash contribution proofs as sound, hiding,
  zero-knowledge, or valid-share proofs.
- Any future VSS complaint artifacts as production slashing evidence.
- Any future raw hazmat contribution payloads as production MPC-compatible
  messages.
- Simulated P2P and consensus harnesses as authenticated transport or
  consensus integration.
- Deterministic benchmark seeds and schedules as production randomness.
- Benchmark tables, JSONL/CSV artifacts, and checksums as cryptographic
  security evidence.
- `zeroize` usage as sufficient adaptive-corruption or erasure support.
- Existing tests as side-channel, constant-time, FIPS, or certification
  evidence.

These exclusions should remain visible until the corresponding proof,
implementation, operational, and external audit work is complete.

## Review Questions For TCB Reduction

Use these questions to decide whether a future change narrows or expands the
TCB:

- Does the change move a scaffold path into a production-labeled API?
- Does any production-labeled constructor bypass the combined backend policy
  gate?
- Does a new wire field alter canonical frame binding or artifact replay
  verification?
- Does new evidence become consensus-facing before anti-framing and complaint
  soundness are proven?
- Does a benchmark or test artifact support a narrower engineering claim, or is
  it being used as security evidence?
- Does new cryptographic code add secret-dependent branches, memory lifetime
  assumptions, randomness assumptions, or dependency assumptions?
- Are docs and claims updated in the same change when behavior or evidence
  changes?

## Minimum Production-Gate Evidence Still Missing

A future production TCB would require at least:

- a completed formal threshold ML-DSA-65 security proof under an explicit
  adversary, network, and abort model;
- FIPS/ACVP-style provider KATs, coordinator-assisted threshold KATs, and
  fuzzing coverage for production coordinator frames with linked release
  evidence;
- malicious-secure production DKG/VSS with complaint soundness and anti-framing
  analysis;
- sound and hiding production contribution proof or audited MPC verification
  boundary;
- audited randomness, nonce derivation, transcript binding, key handling, and
  erasure behavior;
- side-channel and constant-time review for selected arithmetic and encoding
  paths;
- authenticated transport and consensus integration analysis;
- external cryptographic and implementation audit;
- any required certification or validation campaign before certification
  claims are made.
