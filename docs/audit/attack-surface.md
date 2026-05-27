# Attack Surface Map

Date: 2026-05-26

## Scope

This audit packet supports reviewer and security triage for the current
research scaffold. It does not certify production readiness, FIPS validation,
malicious-secure threshold signing, production slashing soundness, or
side-channel resistance.

The implementation currently exposes a default simulated scaffold plus
feature-gated hazmat ML-DSA-65 internals for experiments. Reviewers should read
this map together with the claim boundaries in
[claims-matrix.md](../cryptography/claims-matrix.md),
[protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md), and
[release-readiness-checklist.md](../benchmarks/release-readiness-checklist.md).

## First-Pass Review Order

1. `Cargo.toml` feature gates: confirm which code exists under `simulated`,
   `hazmat`, `hazmat-real-mldsa`, and `experimental-vss`.
2. `src/adapter/wire.rs`: inspect canonical wire encoding, version handling,
   length checks, and feature-gated message variants.
3. `src/adapter/actor.rs`: inspect actor state transitions, quorum handling,
   strict precommitment checks, proof-bound secret contribution verification,
   and evidence emission.
4. `src/low_level/mldsa65.rs`: inspect hazmat ML-DSA-65 arithmetic,
   encodings, contribution decoding, challenge derivation, aggregation, and
   verifier compatibility.
5. `src/crypto/contribution_proof.rs`,
   `src/crypto/vss.rs`, and `src/crypto/production_policy.rs`: inspect
   scaffold proof/VSS relations and fail-closed production policy gates.
6. `src/adapter/evidence.rs` and `src/utils/hazmat_artifacts.rs`: inspect
   evidence payloads, artifact frame binding, and experimental complaint
   artifact verification.
7. `src/utils/hazmat_simulation.rs`, `src/utils/exporter.rs`, and `src/main.rs`:
   inspect benchmark harness assumptions and exported artifact generation.
8. `docs/cryptography/*` and `docs/benchmarks/*`: check for implementation
   claim drift against the code and tests.

## Feature-Gate Boundary

| Gate | Exposed surface | Review focus | Production boundary |
| --- | --- | --- | --- |
| default `simulated` | Type-state API, simulated backend, adapter scaffold, policy tests | Make sure scaffold behavior cannot be described as production cryptography. | Research and simulation only. |
| `hazmat` | Marker gate used by real hazmat backend | Ensure no production API silently depends on hazmat behavior. | Not a production assurance boundary. |
| `hazmat-real-mldsa` | Local ML-DSA-65 internals, typed hazmat wire rounds, actor execution, standard-verifying artifacts | Arithmetic, encoding, decoding, challenge derivation, contribution validation, transcript binding, retry/evidence behavior. | Feature-gated experimental backend; raw contribution material remains unsuitable for production MPC. |
| `experimental-vss` | Experimental VSS-shaped statement/opening/proof and complaint artifacts | Canonical serialization, digest binding, complaint artifact shape, interaction with evidence records. | Structural evidence shaping only; not malicious-secure VSS or production slashing proof. |

Feature-gate risk is mainly claim confusion and accidental promotion. A reviewer
should confirm that production-labeled constructors call the combined backend
policy gate and that passing a declaration gate is not treated as a proof.

## Actor And Network Boundaries

The adapter models actors, consensus, and P2P networking through local traits
and deterministic harnesses rather than a production network. The key surfaces
are:

- `src/adapter/traits.rs`: network and consensus adapter contracts.
- `src/adapter/actor.rs`: session configuration, actor events, quorum handling,
  inbound frame processing, finalization, and malformed contribution evidence.
- `src/utils/hazmat_simulation.rs`: in-memory benchmark network profiles,
  retry schedules, byzantine profiles, and transcript capture.
- `src/main.rs`: Section V-style harness orchestration.

Security triage should treat authenticated transport, validator identity
binding, replay protection outside the local frame envelope, timeout policy,
retry limits, consensus penalties, and operational key management as external
production obligations. The current harness can model some ordering and
malformed-frame behavior, but it does not establish production network liveness
or consensus safety.

## Wire Decoding And Transcript Inputs

Wire decoding is a primary attack surface because it accepts untrusted bytes.
Review `src/adapter/wire.rs` for:

- wire version and message tag rejection;
- fixed-width and length-prefixed field parsing;
- trailing-byte rejection;
- session, block height, validator index, attempt, and digest binding;
- hazmat masking commitment, masking opening, challenge, secret commitment,
  secret opening, and proof-bound secret contribution variants;
- malformed decode error behavior and test coverage.

The hazmat contribution payload decoders in `src/low_level/mldsa65.rs` are also
part of the untrusted-byte boundary. Reviewers should inspect
`decode_mldsa65_masking_contribution`,
`decode_mldsa65_secret_contribution`, receiver-index validation, contribution
shape checks, and `w = A*y` validation for masking openings.

## Hazmat ML-DSA-65 Internals

`src/low_level/mldsa65.rs` is the highest-density cryptographic review target.
It contains parameter constants, packing/unpacking, sampling, NTT arithmetic,
share splitting/reconstruction, masking and secret contribution derivation,
challenge derivation, threshold response finalization, and standard verifier
paths.

Priority review questions:

- Are ML-DSA-65 byte layouts, bounds, hints, and verifier compatibility
  faithfully implemented in tested paths?
- Do threshold aggregation and reconstruction paths reject malformed or
  inconsistent partials before finalization?
- Are context, `mu`, `w1`, challenge, attempt, and session identifiers bound in
  the intended places?
- Are deterministic seeds and benchmark-only derivations impossible to mistake
  for production randomness?
- Are secret-dependent arithmetic and encoding paths unaudited for timing and
  leakage, as documented?

Current evidence is compatibility and regression evidence only. It is not a
complete correctness proof, distributional equivalence proof, constant-time
audit, or FIPS validation.

## Evidence And Slashing Artifacts

Evidence generation is security-sensitive because a production system must not
be able to frame honest validators. Current evidence is an engineering scaffold
for malformed or proof-invalid frames, not production slashing authority.

Review:

- `src/adapter/evidence.rs`: `EvidenceKind`, `SlashingEvidence`,
  `SlashingEvidencePayload`, and payload encoding/decoding.
- `src/adapter/actor.rs`: points where invalid contribution evidence is
  emitted and where production VSS or contribution statement digests are
  attached.
- `src/utils/hazmat_artifacts.rs`: transcript event generation, frame digest
  binding, JSONL/CSV verification, and experimental VSS complaint artifact
  checks under `experimental-vss`.
- `src/crypto/vss.rs`: `ProductionVssRelationStatement` and experimental VSS
  complaint structures.
- `src/crypto/contribution_proof.rs`: `ProductionContributionStatement` digest
  binding and transcript-hash proof scaffold.

Audit focus should include anti-framing assumptions, canonical serialization,
digest domain separation, missing-authentication behavior, duplicate frames,
retry versus slashable violation boundaries, and whether evidence artifacts
state enough public input for a future verifier.

## Benchmark And Export Pipeline

Benchmark artifacts are useful for reproducibility, not security proof. The
attack surface is mostly claim drift and artifact verifier fragility.

Review:

- `src/utils/hazmat_simulation.rs`: deterministic experiment profiles,
  adversarial modes, trace event capture, baseline comparison, and checksum
  assumptions.
- `src/utils/hazmat_artifacts.rs`: JSONL/CSV generation and verification,
  allowed directions/rounds, frame digest checks, production statement digest
  population.
- `src/utils/exporter.rs`: LaTeX and PGFPlots table rendering.
- `src/main.rs`: feature-gated harness entrypoints and generated output
  sections.
- `docs/benchmarks/reproducibility-manifest.md`,
  `docs/benchmarks/section-v-reproducibility.md`,
  `docs/benchmarks/section-v-results.md`, and checked-in artifacts under
  `docs/benchmarks/artifacts/`.

Reviewers should verify that benchmark output is described as deterministic
research telemetry and not as a side-channel, liveness, or cryptographic
security result.

## Docs And Claim Drift

Documentation is part of the review surface because unsafe wording can promote
research scaffolding into unsupported production claims. Keep these files in
sync when behavior changes:

- [claims-matrix.md](../cryptography/claims-matrix.md): publication-facing
  claim status and safe wording.
- [protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md):
  protocol-to-source navigation.
- [release-readiness-checklist.md](../benchmarks/release-readiness-checklist.md):
  release gates and production blockers.
- [security-model.md](../cryptography/security-model.md),
  [formal-proof-scaffold.md](../cryptography/formal-proof-scaffold.md),
  [production-vss-backend.md](../cryptography/production-vss-backend.md), and
  [proof-bearing-contribution-boundary.md](../cryptography/proof-bearing-contribution-boundary.md):
  open proof and backend replacement boundaries.

Any new claim should identify the supporting source files, tests or artifacts,
remaining blockers, and precise non-claims.

## Explicit Non-Claims

The current repository does not claim:

- production-ready threshold ML-DSA-65 security;
- malicious-secure DKG or production VSS complaint soundness;
- sound or hiding production contribution proofs;
- side-channel resistance or constant-time behavior;
- adaptive security or reliable erasure semantics;
- FIPS validation or certified module status;
- production network liveness, transport authentication, or consensus slashing
  integration;
- benchmark results as security evidence.
