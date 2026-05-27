# Lattice Aggregation

Research-grade Rust scaffolding for threshold post-quantum signature aggregation over lattice-based ML-DSA-65 style primitives.

This repository explores the API boundaries, state machines, wire formats, actor integration points, and audit surface needed for threshold signing in distributed validator systems. The current implementation uses a deterministic simulation backend so protocol flow, validation, transcript binding, and aggregation behavior can be tested without claiming production cryptographic security.

[![CI](https://github.com/exocognosis/lattice-aggregation/actions/workflows/ci.yml/badge.svg)](https://github.com/exocognosis/lattice-aggregation/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What This Is

Lattice Aggregation is a research and engineering scaffold for:

- threshold ML-DSA-65 signing protocol experiments
- deterministic transcript and challenge binding
- canonical commitment and partial-share collection
- simulated distributed key generation and signing flows
- async validator actor integration with P2P and consensus adapters
- audit-oriented documentation for trusted computing base and attack surface review

The crate is published locally as `lattice-aggregation` and exposes the Rust library name `lattice_aggregation`.

## Current Status

This is not production cryptography.

The default backend is deterministic simulation machinery. It produces stable, standard-size byte outputs for testing protocol behavior, but it does not produce or verify real ML-DSA signatures. Treat this repository as a research scaffold for protocol design, integration testing, benchmarking shape, and review preparation.

## Quick Start

```sh
cargo test
```

Run the included experiment harness:

```sh
cargo run
```

The harness prints LaTeX tables and PGFPlots-compatible CSV for simulated threshold signing sessions across small, mid-scale, and adversarial cluster profiles.

## Repository Map

- `src/backend.rs`: backend trait boundary and deterministic simulation backend
- `src/protocol.rs`: type-state signing session flow
- `src/aggregation.rs`: partial-share aggregation interface
- `src/dkg.rs`: simulated distributed key generation scaffold
- `src/adapter/`: async actor, wire messages, consensus and P2P adapter traits, and evidence types
- `src/crypto/`: interpolation and verifiable-secret-sharing support code
- `src/low_level/`: polynomial primitives used by lower-level experiments
- `tests/`: simulation, validation, transcript determinism, type-state, and low-level coverage
- `docs/audit/`: reviewer packet for attack surface and trusted computing base analysis
- `docs/cryptography/`: cryptographic notes and proof-model work in progress

## Design Boundaries

The repository separates protocol shape from cryptographic backend implementation:

- public APIs make transcript, validator set, threshold, commitment, and partial-share relationships explicit
- deterministic simulation lets tests assert stable behavior without relying on live cryptographic randomness
- type-state transitions prevent generating partials or aggregates from invalid session states
- adapter traits keep networking and consensus effects outside the core protocol model
- audit docs state what reviewers should trust, what is simulated, and what still needs production hardening

## Suggested GitHub Topics

`rust`, `post-quantum`, `cryptography`, `threshold-signatures`, `mldsa`, `dilithium`, `lattice-cryptography`, `distributed-systems`, `validator`, `research`

## Contributing

Contributions should keep claims precise. If a change touches cryptographic behavior, transcript construction, validation logic, or wire formats, include tests and update the relevant audit notes.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before opening larger changes.
