# Trusted Computing Base

Date: 2026-05-26

## Scope

This document identifies what a reviewer would need to trust for the current
research scaffold. The requested feature-gated real ML-DSA-65 backend is not
present in this checkout. This document is a triage aid, not an audit result,
certification statement, or production-readiness claim.

The authoritative claim boundaries remain in
[claims-matrix.md](../cryptography/claims-matrix.md),
[proof-implementation-crosswalk.md](../cryptography/proof-implementation-crosswalk.md),
and a release-readiness checklist once one is added.

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
- `hazmat-real-mldsa` is declared for a future or restored real ML-DSA backend.
  No `src/low_level/mldsa65.rs` backend is present in this checkout.
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
| `src/adapter/evidence.rs` | Evidence payload encoding and fields that could become consensus-facing. |
| `src/main.rs` | Feature-gated benchmark/export entrypoint and sample artifact generation behavior. |

The crosswalk in
[proof-implementation-crosswalk.md](../cryptography/proof-implementation-crosswalk.md)
maps proof obligations to implementation surfaces and tests.

## What Is Outside Production Trust Today

The following are explicitly outside the production TCB because production trust
has not been established:

- The deterministic VSS/DKG scaffold as malicious-secure DKG.
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
