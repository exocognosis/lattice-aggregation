# Attack Surface Map

Date: 2026-05-26

## Scope

This audit packet supports reviewer and security triage for the current
implementation track. Production readiness, FIPS validation, malicious-secure
threshold signing, production slashing soundness, and side-channel resistance
each require linked evidence artifacts.

The current checkout exposes a default simulated scaffold plus non-default
production-candidate skeleton surfaces under `coordinator-assisted` and
`hazmat-real-mldsa`. Those skeleton surfaces are hazmat/conformance tracks
whose promotion requires production threshold ML-DSA security, FIPS validation,
audited backend evidence, and proof evidence artifacts. Reviewers should read
this map together with the evidence requirements in
[side-channel-boundary.md](../cryptography/side-channel-boundary.md),
[claims-matrix.md](../cryptography/claims-matrix.md),
[proof-implementation-crosswalk.md](../cryptography/proof-implementation-crosswalk.md),
and the [release-readiness checklist](../benchmarks/release-readiness-checklist.md).

## First-Pass Review Order

1. `Cargo.toml` feature gates: confirm which code exists under `simulated`,
   `coordinator-assisted`, `hazmat`, and `hazmat-real-mldsa`.
2. `src/adapter/wire.rs`: inspect canonical wire encoding, version handling,
   length checks, and message variants.
3. `src/production/provider.rs`, `src/production/transcript.rs`,
   `src/production/preprocess.rs`, `src/production/coordinator.rs`, and
   `src/adapter/production_wire.rs`: inspect production-candidate policy
   gates, provider KAT gate, transcript and attempt binding, final verifier
   gate, production wire frames, `src/production/epsilon.rs`,
   `src/production/prefilter.rs`, `src/production/hints.rs`, and simulator
   compile-fail rejection.
4. `src/adapter/actor.rs`: inspect actor state transitions, quorum handling,
   strict precommitment checks, and evidence emission.
5. `src/low_level/poly.rs`, `src/crypto/interpolation.rs`, and
   `src/crypto/vss.rs`: inspect arithmetic and simulated VSS/DKG scaffolding.
6. `src/dkg.rs`, `src/backend.rs`, `src/protocol.rs`, and
   `src/aggregation.rs`: inspect simulation backend boundaries and signing
   flow validation.
7. `src/adapter/evidence.rs`, `src/utils/exporter.rs`, and `src/main.rs`:
   inspect evidence payload shape, harness assumptions, and exported output.
8. `docs/cryptography/*`: check for implementation claim drift against the
   code and tests.

## Feature-Gate Boundary

| Gate | Exposed surface | Review focus | Production boundary |
| --- | --- | --- | --- |
| default `simulated` | Type-state API, simulated backend, adapter scaffold, policy tests | Make sure simulation behavior stays separated from production cryptography. | Research and simulation track. |
| `coordinator-assisted` | Non-default coordinator profile types, transcript binding, preprocessing attempts, final verifier gate, and production coordinator frames | Confirm the coordinator skeleton remains gated and evidence-bounded. | Hazmat conformance track feeding production threshold ML-DSA evidence. |
| `hazmat` | Marker gate reserved for hazmat experiments | Ensure production APIs declare hazmat dependencies explicitly. | Hazmat assurance boundary. |
| `hazmat-real-mldsa` | Production-candidate provider boundary and KAT-gated skeleton | Review the provider KAT gate, bounded ACVP sample fixture, context-aware hazmat verifier, and final verifier boundary before compatibility promotion. | Production assurance requires full KAT, audit, proof, side-channel, validation, and release gates. |

Feature-gate risk is mainly claim confusion and accidental promotion. A reviewer
should confirm that production-labeled constructors fail closed and that
declaration or conformance gates link to the required proof artifacts.

## Actor And Network Boundaries

The adapter models actors, consensus, and P2P networking through local traits
and deterministic harnesses rather than a production network. The key surfaces
are:

- `src/adapter/traits.rs`: network and consensus adapter contracts.
- `src/adapter/actor.rs`: session configuration, actor events, quorum handling,
  inbound frame processing, finalization, and malformed contribution evidence.
- `src/main.rs`: Section V-style harness orchestration.

Security triage should treat authenticated transport, validator identity
binding, replay protection outside the local frame envelope, timeout policy,
retry limits, consensus penalties, and operational key management as external
production obligations. The current harness models ordering and malformed-frame
behavior while production network liveness and consensus safety require linked
evidence.

## Wire Decoding And Transcript Inputs

Wire decoding is a primary attack surface because it accepts untrusted bytes.
Review `src/adapter/wire.rs` for:

- wire version and message tag rejection;
- fixed-width and length-prefixed field parsing;
- trailing-byte rejection;
- session, block height, validator index, attempt, and digest binding;
- DKG commitment, DKG share exchange, signing commitment, and partial-signature
  variants;
- malformed decode error behavior and test coverage.

Production-candidate coordinator frames are now present in
`src/adapter/production_wire.rs`. Reviewers should treat them as untrusted-byte
inputs for hazmat conformance and verify that decode success links to the
standard-verifier compatibility and production security evidence requirements.

## Production-Candidate Coordinator And Hazmat Internals

The current production-candidate skeleton is concentrated in:

- `src/production/provider.rs`: provider contract, KAT status, and verifier
  boundary.
- `src/production/transcript.rs`: production-candidate transcript binding.
- `src/production/preprocess.rs`: preprocessing attempt and retry binding.
- `src/production/coordinator.rs`: coordinator policy gates and final verifier
  gate.
- `src/adapter/production_wire.rs`: production coordinator wire frames.
- `tests/production_provider.rs`: provider KAT gate coverage, including bounded
  NIST ACVP-Server FIPS204 sample-vector conformance for ordinary ML-DSA-65
  verification. Aggregate threshold verification and validation evidence are
  tracked as separate artifacts.
- `tests/ui/production_simulated_backend_rejected.rs`: compile-fail guard that
  the simulated backend cannot satisfy the production coordinator contract.

A concrete ML-DSA-65 backend remains a highest-density cryptographic review
target because it would contain parameter constants, packing/unpacking,
sampling, NTT arithmetic, share splitting/reconstruction, masking and secret
contribution derivation, challenge derivation, threshold response finalization,
and standard verifier paths.

Priority review questions:

- Are ML-DSA-65 byte layouts, bounds, hints, and verifier compatibility
  faithfully implemented in tested paths?
- Does the final verifier receive the original application message, with `mu`
  kept only as transcript-internal binding material?
- Is production approval evidence-backed and non-forgeable rather than a public
  caller-selected switch?
- Do threshold aggregation and reconstruction paths reject malformed or
  inconsistent partials before finalization?
- Are context, `mu`, `w1`, challenge, attempt, and session identifiers bound in
  the intended places?
- Are deterministic seeds and benchmark-only derivations impossible to mistake
  for production randomness?
- Are secret-dependent arithmetic and encoding paths unaudited for timing and
  leakage, as documented?

Current evidence includes simulation, arithmetic-scaffold, and regression
evidence. Correctness proof, distributional equivalence proof, constant-time
audit, and FIPS validation require linked artifacts.

## Evidence And Slashing Artifacts

Evidence generation is security-sensitive because a production system requires
anti-framing evidence for honest validators. Current evidence records malformed
or proof-invalid frames and feeds production slashing-authority review.

Review:

- `src/adapter/evidence.rs`: `EvidenceKind`, `SlashingEvidence`,
  `SlashingEvidencePayload`, and payload encoding/decoding.
- `src/adapter/actor.rs`: points where invalid contribution evidence is
  emitted.
- `src/crypto/vss.rs`: simulated Shamir-style polynomial sharing scaffold.

Audit focus should include anti-framing assumptions, canonical serialization,
digest domain separation, missing-authentication behavior, duplicate frames,
retry versus slashable violation boundaries, and whether evidence payloads state
enough public input for a future verifier.

## Benchmark And Export Pipeline

Benchmark artifacts are useful for reproducibility. Security proof use requires
linked proof artifacts, and the attack surface is mostly claim drift and artifact
verifier fragility.

Review:

- `src/utils/exporter.rs`: LaTeX and PGFPlots table rendering.
- `src/main.rs`: feature-gated harness entrypoints and generated output
  sections.
- Future benchmark manifests and checked-in artifacts under `docs/benchmarks`.

Reviewers should verify that benchmark output links to side-channel, liveness,
or cryptographic security artifacts before promotion.

## Side-Channel And Constant-Time Risks

The side-channel boundary is documented in
[side-channel-boundary.md](../cryptography/side-channel-boundary.md). This
attack-surface map treats timing and leakage resistance as production evidence
obligations for the selected backend.

Reviewers should track at least these risks:

- Secret-dependent branches, memory access, table indexing, or early exits in
  future ML-DSA-65 arithmetic, interpolation, NTT, packing, unpacking, norm
  checks, and aggregation paths.
- Public-input parser behavior that becomes secret-dependent after decoded
  values are mixed with shares, masks, or responses.
- Abort, retry, evidence, logging, panic, and error behavior that leaks more
  than the formal model permits.
- Compiler, target CPU, allocator, and build-profile effects that can change
  source-level constant-time intent.
- Treating comments, deterministic tests, benchmark artifacts, or branch-free
  source snippets as side-channel evidence.

Required evidence remains separate from the mathematical proof package:
dudect-style timing tests, ctgrind or equivalent dynamic checks, compiler-output
review for selected targets, code review of secret-dependent paths, and external
side-channel audit before production claims.

## Docs And Claim Drift

Documentation is part of the review surface because unsafe wording can promote
research scaffolding into unsupported production claims. Keep these files in
sync when behavior changes:

- [side-channel-boundary.md](../cryptography/side-channel-boundary.md):
  separates mathematical proof claims from implementation leakage claims.
- [claims-matrix.md](../cryptography/claims-matrix.md): publication-facing
  claim status and safe wording.
- [proof-implementation-crosswalk.md](../cryptography/proof-implementation-crosswalk.md):
  proof-obligation-to-source navigation.
- [Release-readiness checklist](../benchmarks/release-readiness-checklist.md):
  release gates and production blockers require linked evidence for the
  selected backend and release scope.
- [active-adversary-model.md](../cryptography/active-adversary-model.md),
  [formal-security-theorem.md](../cryptography/formal-security-theorem.md),
  [proof-obligations.md](../cryptography/proof-obligations.md),
  [vss-dkg-security-plan.md](../cryptography/vss-dkg-security-plan.md), and
  [random-oracle-game.md](../cryptography/random-oracle-game.md): open proof,
  adversary-model, VSS/DKG, contribution-proof, and backend replacement
  boundaries.

Any new claim should identify the supporting source files, tests or artifacts,
remaining blockers, and precise evidence requirements.

## Production Evidence Requirements

Production promotion requires linked evidence for:

- production-ready threshold ML-DSA-65 security;
- malicious-secure DKG or production VSS complaint soundness;
- sound or hiding production contribution proofs;
- side-channel resistance or constant-time behavior;
- adaptive security or reliable erasure semantics;
- FIPS validation or certified module status;
- production network liveness, transport authentication, or consensus slashing
  integration;
- benchmark results as security evidence.
