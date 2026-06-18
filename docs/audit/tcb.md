# Trusted Computing Base

Date: 2026-05-27

## Status

This document describes the trusted computing base for the current research
artifact. The crate is not production-ready. The TCB below supports review of
the scaffold, hazmat backend, simulation harnesses, and publication artifacts;
it is not a deployment certification boundary.

## Trusted Computing Base

For current research claims, reviewers should treat these components as inside
the trusted computing base:

- ML-DSA-65 hazmat arithmetic, packing, unpacking, contribution, aggregation,
  and verifier compatibility code in `src/low_level/mldsa65.rs`.
- Polynomial and interpolation helpers in `src/low_level/poly.rs`,
  `src/crypto/vss.rs`, and `src/crypto/interpolation.rs`.
- Transcript, wire, actor, and evidence state transitions in `src/adapter/`.
- Production policy gates in `src/crypto/production_policy.rs`.
- Artifact exporters and verifiers in `src/utils/hazmat_artifacts.rs`,
  `src/utils/hazmat_simulation.rs`, and `src/utils/exporter.rs`.
- Manifest and claim-boundary tests in `tests/protocol_spec_manifest.rs`,
  `tests/reproducibility_manifest.rs`, `tests/section_v_sample_bundle.rs`,
  and `tests/audit_manifest.rs`.

## Dependency Assumptions

Current review assumes:

- Rust compiler and standard library behavior match the tested toolchain.
- Hash implementations used for transcript and artifact digests behave as
  specified by their crates.
- Tokio and async-trait behavior is trusted for the in-memory actor tests.
- Test fixtures and checked-in Section V sample artifacts are not maliciously
  replaced outside Git review.

These assumptions are sufficient for research reproducibility review. A
production deployment would require dependency pinning policy, supply-chain
review, build reproducibility requirements, and operational key-management
review.

## Feature-Gate Risks

Feature-gate risks are part of the TCB because `hazmat-real-mldsa` and
`experimental-vss` expose production-shaped data flows while remaining
research-only.

Review files:

- `Cargo.toml`
- `src/utils.rs`
- `src/crypto/production_policy.rs`
- `tests/production_policy.rs`

Required behavior: production-labeled configuration must reject scaffold VSS
and contribution-proof backends. Enabling a feature gate must not be described
as enabling production security.

## Review Files

High-priority review files:

- `src/low_level/mldsa65.rs`
- `src/adapter/actor.rs`
- `src/adapter/wire.rs`
- `src/crypto/contribution_proof.rs`
- `src/crypto/vss.rs`
- `src/crypto/production_policy.rs`
- `src/utils/hazmat_artifacts.rs`
- `docs/cryptography/claims-matrix.md`
- `docs/cryptography/proof-obligations.md`
- `docs/cryptography/protocol-code-crosswalk.md`
- `docs/benchmarks/release-readiness-checklist.md`

These files are the best starting points for checking implementation behavior,
claim boundaries, and whether production blockers are still open.

## Non-Production Boundaries

The following are explicit non-production boundaries:

- Deterministic VSS/DKG scaffolding is not malicious-secure DKG.
- Transcript-hash contribution proofs are not sound or hiding production
  contribution proofs.
- Experimental VSS complaint artifacts are not production slashing evidence.
- Hazmat ML-DSA internals are not FIPS validated or side-channel audited.
- In-memory actor simulations are not production network or consensus
  integration evidence.
- Benchmark outputs are performance and reproducibility artifacts, not
  security proofs.

## Closure Requirements

Before this project can be treated as production-ready, the TCB must be reduced
or justified by:

1. production VSS/DKG and contribution-proof backends,
2. completed formal proof obligations,
3. constant-time and leakage review,
4. authenticated transport and consensus integration review,
5. supply-chain and build reproducibility review, and
6. external cryptographic and implementation audit.
