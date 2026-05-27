# Trusted Computing Base

Date: 2026-05-26

## Scope

This document identifies what a reviewer would need to trust for the current
research scaffold and feature-gated hazmat ML-DSA-65 backend. It is a triage
aid, not an audit result, certification statement, or production-readiness
claim.

The authoritative claim boundaries remain in
[claims-matrix.md](../cryptography/claims-matrix.md),
[protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md), and
[release-readiness-checklist.md](../benchmarks/release-readiness-checklist.md).

## Current TCB

The current TCB for research-review purposes includes:

- Rust compiler, Cargo feature resolution, and build profile selection.
- Runtime dependencies in `Cargo.toml`: `async-trait`, `serde`, `sha2`, `sha3`,
  `thiserror`, `tokio`, and `zeroize`.
- Test-only or development dependencies when evaluating conformance evidence:
  `ml-dsa`, `serde_json`, and `trybuild`.
- `src/types.rs`, `src/errors.rs`, and shared protocol types used by wire,
  actor, and crypto paths.
- `src/adapter/wire.rs` for canonical frame encoding and decoding.
- `src/adapter/actor.rs`, `src/adapter/traits.rs`, and
  `src/adapter/evidence.rs` for actor behavior, external adapter assumptions,
  and evidence payloads.
- `src/low_level/mldsa65.rs` and `src/low_level/poly.rs` when
  `hazmat-real-mldsa` is enabled.
- `src/crypto/contribution_proof.rs`, `src/crypto/vss.rs`,
  `src/crypto/interpolation.rs`, and `src/crypto/production_policy.rs` for
  scaffold proof/VSS relations, interpolation, and production policy gates.
- `src/utils/hazmat_artifacts.rs`, `src/utils/hazmat_simulation.rs`,
  `src/utils/hazmat_fuzz.rs`, `src/utils/exporter.rs`, and `src/main.rs` for
  reproducibility artifacts and benchmark harness behavior.
- The cryptography and benchmark docs that define current claims, non-claims,
  and review boundaries.

This TCB is intentionally broad because the project is a scaffold: claim
accuracy depends on code behavior, feature gates, tests, harnesses, and docs
remaining aligned.

## Dependency Assumptions

Reviewers should treat dependency behavior as assumed rather than proven by
this repository:

- `sha2` and `sha3` implement the hash and XOF primitives used for transcript,
  statement, and artifact digests.
- `serde` and `serde_json` correctly serialize and parse benchmark artifacts
  where used, but canonical cryptographic frame encodings are local code and
  must be reviewed directly.
- `tokio` scheduling in tests and harnesses is not a production network model.
- `zeroize` availability does not by itself prove reliable erasure or adaptive
  security.
- `ml-dsa` is a dev-dependency for differential or regression evidence; it is
  not a validation authority for this implementation.
- Cargo feature resolution is part of the trust boundary. Reviewers should test
  intended feature combinations explicitly.

No dependency assumption substitutes for formal proof, side-channel review, or
external cryptographic audit.

## Feature-Gate Risks

Feature gates are security-relevant because they decide which scaffold and
hazmat paths are compiled:

- `simulated` is enabled by default and supports scaffold behavior only.
- `hazmat-real-mldsa` enables local ML-DSA-65 internals and typed hazmat actor
  rounds. This is the main implementation review target, but it is still
  experimental.
- `hazmat-real-mldsa` implies `hazmat`; neither gate should be treated as
  production approval.
- `experimental-vss` enables structural VSS complaint artifacts and
  experimental statement/opening/proof encodings. It does not implement
  malicious-secure VSS.
- Production-labeled construction must fail closed through
  `require_production_threshold_backends` and related backend policy gates.
  Passing those gates is a configuration check, not proof of production
  security.

Triage should look for accidental default exposure, docs that omit feature
conditions, tests that only cover one feature combination, and public APIs that
make scaffold backends appear production-approved.

## High-Priority Review Files

Start with these files for security triage:

| File | Why it is high priority |
| --- | --- |
| `Cargo.toml` | Feature-gate graph, dependency set, and default behavior. |
| `src/adapter/wire.rs` | Untrusted byte parsing, canonical frame encoding, replay/context fields, and proof-bound hazmat variants. |
| `src/adapter/actor.rs` | State machine, quorum behavior, strict commitment enforcement, evidence emission, and production-checked configuration. |
| `src/low_level/mldsa65.rs` | Hazmat ML-DSA-65 arithmetic, encodings, contribution validation, aggregation, and verification compatibility. |
| `src/crypto/contribution_proof.rs` | Transcript-hash proof scaffold, production statement serialization, digest binding, and production proof gate. |
| `src/crypto/vss.rs` | VSS/interpolation scaffold, production VSS relation statement, experimental complaint artifacts, and VSS backend policy. |
| `src/crypto/production_policy.rs` | Combined production backend policy report and fail-closed enforcement. |
| `src/adapter/evidence.rs` | Evidence payload encoding and fields that could become consensus-facing. |
| `src/utils/hazmat_artifacts.rs` | Artifact replay checks, frame digest verification, and experimental complaint export verification. |
| `src/utils/hazmat_simulation.rs` | Deterministic network/adversary model used by Section V-style results. |
| `src/main.rs` | Feature-gated benchmark/export entrypoint and sample artifact generation behavior. |

The crosswalk in
[protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md)
maps these files to protocol rounds and tests.

## What Is Outside Production Trust Today

The following are explicitly outside the production TCB because production trust
has not been established:

- The deterministic VSS/DKG scaffold as malicious-secure DKG.
- Transcript-hash contribution proofs as sound, hiding, zero-knowledge, or
  valid-share proofs.
- Experimental VSS complaint artifacts as production slashing evidence.
- Raw hazmat contribution payloads as production MPC-compatible messages.
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
