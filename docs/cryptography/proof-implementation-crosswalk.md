# Proof Implementation Crosswalk

Date: 2026-05-27

## Scope

This crosswalk ties the current proof and proof-model areas for the threshold
ML-DSA-65 scaffold to Rust modules and tests that exercise the corresponding
engineering invariants. It is a documentation manifest, not a formal proof, an
audit result, or a production-readiness claim.

The implementation currently uses a deterministic simulation backend. The
entries below therefore distinguish proof obligations that are represented by
code-level guards from obligations that remain open until a concrete threshold
ML-DSA-65 construction and backend are selected.

This document complements `protocol-code-crosswalk.md`,
`proof-obligations.md`, and `formal-threshold-mldsa-transcript.md`. Those files
remain the source of truth for protocol-specific traceability, while this
crosswalk focuses on the proof surface introduced by the full-cryptographic
proof phase.

## Crosswalk

| Theorem or lemma area | Proof-side obligation | Implementation surface | Test evidence | Current status |
| --- | --- | --- | --- | --- |
| Transcript binding and Fiat-Shamir challenge derivation | The challenge must be derived from a canonical transcript that binds the protocol label, version, session ID, threshold, validator set, public key, message, and ordered commitments before any partial signature is produced. | `src/transcript.rs`, `src/protocol.rs`, `src/backend.rs` | `tests/transcript_determinism.rs`, `tests/simulated_flow.rs` | Implemented as deterministic transcript construction and simulation challenge binding; not a proof of ML-DSA distributional equivalence. |
| Canonical validator, commitment, and partial-share sets | Set construction must reject duplicate, unknown, insufficient, or mismatched validators so aggregation cannot mix signers or commitments across universes. | `src/collections.rs`, `src/types.rs`, `src/errors.rs` | `tests/validation.rs`, `tests/transcript_determinism.rs`, `tests/simulated_flow.rs` | Implemented as Rust API validation and error checks. |
| Wire encoding and untrusted-frame rejection | Network-facing frames must use crate-owned versioned encodings, reject malformed or oversized inputs, and preserve replay-relevant context fields. | `src/adapter/wire.rs`, `src/serialization.rs`, `src/adapter/evidence.rs` | `tests/simulation.rs`, `tests/validation.rs`, `tests/low_level.rs` | Implemented for scaffold adapter frames and commitment payloads. |
| Aggregation boundary and transcript consistency | Aggregation must receive a bound transcript and a threshold-valid partial-share set, then reject shares that do not match transcript validators or public key context. | `src/aggregation.rs`, `src/backend.rs`, `src/protocol.rs` | `tests/simulated_flow.rs`, `tests/type_state.rs`, `tests/ui/type_state_invalid_aggregate.rs`, `tests/ui/type_state_invalid_partial.rs` | Implemented for deterministic simulation backend and compile-fail state transitions. |
| Simulation-only backend and production proof gates | The repository must not present deterministic simulation behavior as production threshold ML-DSA security. Production use requires a selected protocol, completed proof, verifier compatibility, timing review, and external cryptographic review. | `src/backend.rs`, `src/dkg.rs`, `src/crypto/vss.rs`, `docs/cryptography/phase-1-noise-bound-model.md`, `docs/audit/tcb.md` | `tests/simulated_flow.rs`, `tests/simulation.rs`, `tests/low_level.rs`, `tests/proof_documentation_manifest.rs` | Open proof obligation; current code and docs are scoped to research scaffold claims. |

## Transcript Binding and Fiat-Shamir Challenge Derivation

The transcript lemma maps most directly to `SigningTranscript::new` in
`src/transcript.rs`. The constructor canonicalizes the validator set, checks
that commitment threshold and validator universe match the transcript inputs,
and derives the challenge internally with SHAKE256 over explicit fields.

The primary regression tests are:

- `tests/transcript_determinism.rs`: checks that network-order differences do
  not affect the challenge and that message or validator mismatches are caught.
- `tests/simulated_flow.rs`: checks that simulated commitment, partial signing,
  and aggregation paths use the same transcript-derived challenge.

## Set Membership and Threshold Validation

The collection invariants are the code counterpart of set-membership lemmas:
duplicate validators, unknown validators, insufficient shares, and inconsistent
validator universes must fail before they can affect transcript or aggregation
state.

The primary implementation surfaces are `src/collections.rs`, `src/types.rs`,
and `src/errors.rs`. The primary tests are `tests/validation.rs`,
`tests/transcript_determinism.rs`, and `tests/simulated_flow.rs`.

## Wire and Serialization Boundaries

The wire-format obligations are engineering preconditions for any later proof
that assumes authenticated, context-bound protocol messages. The current
adapter codec in `src/adapter/wire.rs` binds a wire version, message tag,
session ID, validator fields, block height where relevant, and bounded payload
lengths. `src/serialization.rs` provides crate-owned commitment payload
encoding used by validation tests.

The primary tests are:

- `tests/simulation.rs`: golden and round-trip checks for adapter wire messages,
  malformed-frame rejection, and payload-size rejection.
- `tests/validation.rs`: commitment payload golden encoding and decode
  rejection checks.

## Aggregation Boundary and Backend Claims

The aggregation obligation is implemented as a boundary rather than a
cryptographic proof. `src/aggregation.rs` requires a
`ThresholdSigningTranscript` and checks threshold and validator-set consistency
before calling the backend. `src/backend.rs` is deterministic simulation code
that exercises API behavior and produces stable outputs for tests.

The corresponding tests in `tests/simulated_flow.rs` cover deterministic
aggregation, public-key mismatch rejection, and validator-set mismatch
rejection. Type-state tests in `tests/type_state.rs` and `tests/ui/` preserve
the intended ordering of protocol operations at compile time.

## Open Proof Obligations

The following obligations remain outside the implemented security claim:

- A formal threshold ML-DSA-65 security proof under an explicit adversary,
  network, abort, and corruption model.
- A distributional equivalence argument that the threshold transcript and
  response generation preserve ML-DSA-65 masking and rejection behavior.
- A malicious-secure DKG or VSS construction with complaint soundness and
  anti-framing guarantees.
- A production contribution-proof or MPC verification boundary that is sound,
  hiding where required, and externally reviewed.
- Constant-time, side-channel, randomness, erasure, and authenticated-transport
  review for a selected production backend.

## Manifest Anchors

The documentation manifest test treats these headings and text anchors as the
stable contract for this file:

- `# Proof Implementation Crosswalk`
- `## Scope`
- `## Crosswalk`
- `## Manifest Anchors`
- `Transcript binding and Fiat-Shamir challenge derivation`
- `Canonical validator, commitment, and partial-share sets`
- `Wire encoding and untrusted-frame rejection`
- `Aggregation boundary and transcript consistency`
- `Simulation-only backend and production proof gates`

Keep these anchors stable when reorganizing this document, or update
`tests/proof_documentation_manifest.rs` in the same change.
