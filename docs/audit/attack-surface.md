# Attack Surface Map

Date: 2026-05-26

## Scope

This audit packet supports reviewer and security triage for the current
research scaffold. It does not certify production readiness, FIPS validation,
malicious-secure threshold signing, production slashing soundness, or
side-channel resistance.

The current checkout exposes a default simulated scaffold and feature names for
hazmat experiments. The requested real ML-DSA-65 backend path and hazmat
artifact utilities are not present in this branch, so references to those
surfaces are future or restored-backend review targets rather than current
evidence. Reviewers should read this map together with the claim boundaries in
[side-channel-boundary.md](../cryptography/side-channel-boundary.md),
[claims-matrix.md](../cryptography/claims-matrix.md),
[proof-implementation-crosswalk.md](../cryptography/proof-implementation-crosswalk.md),
and a release-readiness checklist once one is added.

## First-Pass Review Order

1. `Cargo.toml` feature gates: confirm which code exists under `simulated`,
   `hazmat`, and `hazmat-real-mldsa`.
2. `src/adapter/wire.rs`: inspect canonical wire encoding, version handling,
   length checks, and message variants.
3. `src/adapter/actor.rs`: inspect actor state transitions, quorum handling,
   strict precommitment checks, and evidence emission.
4. `src/low_level/poly.rs`, `src/crypto/interpolation.rs`, and
   `src/crypto/vss.rs`: inspect arithmetic and simulated VSS/DKG scaffolding.
5. `src/dkg.rs`, `src/backend.rs`, `src/protocol.rs`, and
   `src/aggregation.rs`: inspect simulation backend boundaries and signing
   flow validation.
6. `src/adapter/evidence.rs`, `src/utils/exporter.rs`, and `src/main.rs`:
   inspect evidence payload shape, harness assumptions, and exported output.
7. `docs/cryptography/*`: check for implementation claim drift against the
   code and tests.

## Feature-Gate Boundary

| Gate | Exposed surface | Review focus | Production boundary |
| --- | --- | --- | --- |
| default `simulated` | Type-state API, simulated backend, adapter scaffold, policy tests | Make sure scaffold behavior cannot be described as production cryptography. | Research and simulation only. |
| `hazmat` | Marker gate reserved for hazmat experiments | Ensure no production API silently depends on hazmat behavior. | Not a production assurance boundary. |
| `hazmat-real-mldsa` | Feature declaration for a future or restored real ML-DSA backend | Confirm whether any real backend code exists in the checkout before making implementation claims. | No production assurance boundary in the current branch. |

Feature-gate risk is mainly claim confusion and accidental promotion. A reviewer
should confirm that any future production-labeled constructors fail closed and
that passing a declaration gate is not treated as a proof.

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
- DKG commitment, DKG share exchange, signing commitment, and partial-signature
  variants;
- malformed decode error behavior and test coverage.

The requested hazmat contribution payload decoders are not present in this
branch. If `src/low_level/mldsa65.rs` or equivalent backend code is restored,
its decoders should become a primary untrusted-byte review target.

## Future Hazmat ML-DSA-65 Internals

`src/low_level/mldsa65.rs` is not present in this checkout. A future or
restored real backend would likely become the highest-density cryptographic
review target because it would contain parameter constants, packing/unpacking,
sampling, NTT arithmetic, share splitting/reconstruction, masking and secret
contribution derivation, challenge derivation, threshold response finalization,
and standard verifier paths.

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

Current evidence is simulation, arithmetic-scaffold, and regression evidence
only. It is not a complete correctness proof, distributional equivalence proof,
constant-time audit, or FIPS validation.

## Evidence And Slashing Artifacts

Evidence generation is security-sensitive because a production system must not
be able to frame honest validators. Current evidence is an engineering scaffold
for malformed or proof-invalid frames, not production slashing authority.

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

Benchmark artifacts are useful for reproducibility, not security proof. The
attack surface is mostly claim drift and artifact verifier fragility.

Review:

- `src/utils/exporter.rs`: LaTeX and PGFPlots table rendering.
- `src/main.rs`: feature-gated harness entrypoints and generated output
  sections.
- Future benchmark manifests and checked-in artifacts if a `docs/benchmarks`
  packet is added.

Reviewers should verify that benchmark output is described as deterministic
research telemetry and not as a side-channel, liveness, or cryptographic
security result.

## Side-Channel And Constant-Time Risks

The side-channel boundary is documented in
[side-channel-boundary.md](../cryptography/side-channel-boundary.md). This
attack-surface map treats timing and leakage resistance as open production
obligations, not solved properties of the current branch.

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
- Release-readiness checklist: no checklist exists under `docs/benchmarks`;
  do not treat release gates or production blockers as complete until one is
  added.
- [active-adversary-model.md](../cryptography/active-adversary-model.md),
  [formal-security-theorem.md](../cryptography/formal-security-theorem.md),
  [proof-obligations.md](../cryptography/proof-obligations.md),
  [vss-dkg-security-plan.md](../cryptography/vss-dkg-security-plan.md), and
  [random-oracle-game.md](../cryptography/random-oracle-game.md): open proof,
  adversary-model, VSS/DKG, contribution-proof, and backend replacement
  boundaries.

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
