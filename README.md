# Lattice Aggregation

Audit-oriented Rust scaffolding for threshold ML-DSA-65 protocol engineering: state machines, transcript binding, wire formats, DKG/signing simulation, and validator-system integration boundaries.

[![CI](https://github.com/exocognosis/lattice-aggregation/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/lattice-aggregation/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust 2021](https://img.shields.io/badge/Rust-2021-f74c00.svg)](Cargo.toml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](src/lib.rs)
[![status: research](https://img.shields.io/badge/status-research-orange.svg)](SECURITY.md)
[![backend: deterministic simulation](https://img.shields.io/badge/backend-deterministic%20simulation-lightgrey.svg)](docs/cryptography/claims-matrix.md)

Lattice Aggregation makes the hard parts of threshold post-quantum signing reviewable before production cryptography is wired in. It models the API boundaries, transcript commitments, validator attribution, aggregation checks, adapter contracts, and audit surface that a distributed validator system would need around threshold ML-DSA.

> Research status: the default backend is deterministic simulation machinery. It produces stable, standard-size byte outputs for testing protocol behavior, but it does not produce or verify real ML-DSA signatures. Treat this repository as protocol scaffolding, integration shape, benchmark shape, and review preparation.

## The Problem

As L1 blockchains prepare for the post-quantum era, migration to NIST-standardized lattice-based cryptography such as FIPS 204 ML-DSA introduces a severe scalability tax. Unlike legacy BLS signature schemes, ML-DSA signatures do not natively compose or aggregate algebraically because of structured lattice secrets, masking vectors, and interactive rejection sampling.

Naively storing one ML-DSA signature per validator produces linear `O(N)` state and bandwidth growth. For large validator sets, that creates an unacceptable trade-off: cap validator participation to preserve performance, or accept network congestion and storage bloat to gain post-quantum security.

## The Proposed Framework

`lattice-aggregation` is a research scaffold for exploring a zero-compromise target: interactive threshold ML-DSA-65 signature aggregation.

The target architecture asks whether a large validator quorum can collectively generate a single, standard-sized ML-DSA-65 signature. If the required theorem obligations close, the verification path remains backward-compatible: an unmodified NIST-style verifier checks one signature under one epoch threshold public key, without needing to know that the signature was produced by a multi-party protocol.

To make that claim reviewable, the framework models an "Epsilon Residual Ledger" of five security boundaries that must be isolated before production cryptography can be claimed:

- transcript and Fiat-Shamir challenge binding across validator sets, sessions, and messages
- masking-vector and rejection-sampling residuals needed to match the single-signer distribution
- private-key-share isolation across DKG, partial signing, aggregation, and evidence paths
- selective-abort and liveness bias introduced by interactive participants
- byte-level verifier compatibility, domain separation, and standard ML-DSA-65 encoding constraints

## Practical Implications Upon Theorem Closure

If the hypothesis is proven, implemented with a reviewed threshold backend, and validated against standard ML-DSA verification, the architecture would unlock several distributed-system benefits:

- **Validator scalability target (`O(1)` verification footprint).** Compresses the cryptographic proof of consensus for 10,000+ validators into a single approximately 3.3 KB ML-DSA-65 signature, decoupling verification and storage cost from validator count.
- **Zero-overhead quantum-resistance target.** Allows L1 blockchains to adopt post-quantum security without paying the normal lattice multi-signature penalty in network bandwidth and persistent state.
- **Backward-compatible verification path.** Lets light clients, cross-chain bridges, and hardware wallets verify post-quantum network consensus with off-the-shelf ML-DSA verification code rather than custom threshold-verifier modules.
- **Hyper-efficient interoperability target.** Replaces large multi-signature verification sets or expensive zero-knowledge wrappers with a single native ML-DSA verification check for bridge and cross-chain consensus proofs.

## Why This Repo Exists

Threshold post-quantum signatures are not just a primitive swap. A credible validator integration has to make several boundaries explicit:

- which transcript fields are committed before the Fiat-Shamir challenge
- which validators contributed commitments and partial shares
- which malformed, duplicate, stale, or cross-session messages are rejected
- which state transitions are impossible by construction
- which networking, consensus, and timeout effects are outside the cryptographic core
- which claims are implemented today, simulated today, or still proof obligations

This repository turns those boundaries into Rust APIs, tests, wire types, actor scaffolding, and audit documentation.

## What Is Unique Here

- **Protocol-first threshold ML-DSA shape.** The crate focuses on the reviewer-visible boundary around threshold ML-DSA-65 instead of burying protocol assumptions inside an opaque backend.
- **Type-state signing sessions.** Session phases are encoded in the API so callers cannot aggregate before commitments, generate partials for invalid sessions, or skip validation paths accidentally.
- **Deterministic transcript binding.** Tests can assert stable session identifiers, challenge derivation, validator sets, commitments, and partial-share relationships without depending on live cryptographic randomness.
- **Production-shaped simulation outputs.** The simulation backend preserves ML-DSA-65-sized public keys and signatures, which keeps serialization, storage, adapter, and benchmark paths realistic while avoiding false production-security claims.
- **Audit packet plus proof crosswalks.** The docs map protocol phases to code, tests, trusted computing base assumptions, attack surface, side-channel boundaries, and open proof obligations.
- **Distributed-validator adapter boundary.** Async actor, P2P, consensus, evidence, and timeout traits show how a threshold signer could sit inside a larger validator stack without moving network effects into the core protocol model.

## Implemented Today

- `lattice-aggregation` package with Rust library name `lattice_aggregation`
- threshold signing session state machine in [src/protocol.rs](src/protocol.rs)
- backend trait and deterministic simulation backend in [src/backend.rs](src/backend.rs)
- partial-share aggregation boundary in [src/aggregation.rs](src/aggregation.rs)
- simulated DKG scaffold in [src/dkg.rs](src/dkg.rs)
- async actor, wire messages, consensus/P2P traits, and evidence types in [src/adapter/](src/adapter/)
- interpolation, verifiable-secret-sharing support, and polynomial experiments in [src/crypto/](src/crypto/) and [src/low_level/](src/low_level/)
- regression coverage for simulation flow, validation, transcript determinism, serialization, type-state compile failures, and documentation link integrity in [tests/](tests/)
- reviewer packet in [docs/audit/](docs/audit/) and cryptographic notes in [docs/cryptography/](docs/cryptography/)

## Explicit Non-Claims

This is not production cryptography.

The repository does not currently claim:

- real ML-DSA signing or verification
- a production threshold ML-DSA construction
- side-channel resistance or constant-time production behavior
- audited distributed key generation
- FIPS validation
- consensus safety for production validator keys

The current security boundary is documented in [SECURITY.md](SECURITY.md), the [Cryptographic Claims Matrix](docs/cryptography/claims-matrix.md), and the [Release Readiness Checklist](docs/benchmarks/release-readiness-checklist.md).

## Quick Start

```sh
cargo test
```

Run the included experiment harness:

```sh
cargo run
```

The harness prints LaTeX tables and PGFPlots-compatible CSV for simulated threshold signing sessions across small, mid-scale, and adversarial cluster profiles.

## Verification

The CI workflow runs the same core checks reviewers should start with:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The documentation manifest test also validates reviewer-facing documentation anchors and local markdown links:

```sh
cargo test --test proof_documentation_manifest
```

## Reviewer Entry Points

- [Audit Packet](docs/audit/README.md): attack surface, trusted computing base, dependency assumptions, and high-priority review paths
- [Cryptographic Claims Matrix](docs/cryptography/claims-matrix.md): what is implemented, simulated, planned, or explicitly not claimed
- [Protocol Code Crosswalk](docs/cryptography/protocol-code-crosswalk.md): where each protocol phase lives in code and tests
- [Proof Implementation Crosswalk](docs/cryptography/proof-implementation-crosswalk.md): mapping from proof obligations to current implementation and test coverage
- [Formal Threshold ML-DSA Transcript](docs/cryptography/formal-threshold-mldsa-transcript.md): transcript fields, binding invariants, and stable anchors
- [Side-Channel and Constant-Time Boundary](docs/cryptography/side-channel-boundary.md): current leakage claims and production gate
- [Release Readiness Checklist](docs/benchmarks/release-readiness-checklist.md): gates before any production-readiness language

## Repository Map

- [src/backend.rs](src/backend.rs): backend trait boundary and deterministic simulation backend
- [src/protocol.rs](src/protocol.rs): type-state signing session flow
- [src/aggregation.rs](src/aggregation.rs): partial-share aggregation interface
- [src/dkg.rs](src/dkg.rs): simulated distributed key generation scaffold
- [src/adapter/](src/adapter/): async actor, wire messages, consensus and P2P adapter traits, and evidence types
- [src/crypto/](src/crypto/): interpolation and verifiable-secret-sharing support code
- [src/low_level/](src/low_level/): polynomial primitives used by lower-level experiments
- [tests/](tests/): simulation, validation, transcript determinism, type-state, and low-level coverage
- [docs/audit/](docs/audit/): reviewer packet for attack surface and trusted computing base analysis
- [docs/cryptography/](docs/cryptography/): cryptographic notes, formal models, and proof-obligation crosswalks

## Design Boundaries

The repository separates protocol shape from cryptographic backend implementation:

- public APIs make transcript, validator set, threshold, commitment, and partial-share relationships explicit
- deterministic simulation lets tests assert stable behavior without relying on live cryptographic randomness
- type-state transitions prevent generating partials or aggregates from invalid session states
- adapter traits keep networking and consensus effects outside the core protocol model
- audit docs state what reviewers should trust, what is simulated, and what still needs production hardening

## Feature Gates

- `simulated` is enabled by default and provides deterministic protocol-test behavior.
- `hazmat` marks low-level experimental surfaces that should not be treated as stable production APIs.
- `hazmat-real-mldsa` is reserved for future production-backend integration work and currently remains behind explicit opt-in.

## Roadmap Shape

Near-term production-threshold work should move through the documented gates:

- define the production backend boundary and domain-separated transcript contract
- replace deterministic signing output with externally reviewed threshold ML-DSA machinery
- add proof-carrying share validation, complaint/evidence handling, and DKG hardening
- add side-channel review, constant-time gates, and production benchmark artifacts
- require the [Release Readiness Checklist](docs/benchmarks/release-readiness-checklist.md) before production-readiness claims

## Suggested GitHub Topics

`rust`, `post-quantum`, `cryptography`, `threshold-signatures`, `ml-dsa`, `mldsa`, `dilithium`, `lattice-cryptography`, `distributed-systems`, `validator`, `consensus`, `protocol-engineering`, `security-audit`, `research`

## Contributing

Contributions should keep claims precise. If a change touches cryptographic behavior, transcript construction, validation logic, or wire formats, include tests and update the relevant audit notes.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before opening larger changes.
