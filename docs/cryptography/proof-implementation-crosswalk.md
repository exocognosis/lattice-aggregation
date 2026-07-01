# Proof Implementation Crosswalk

Date: 2026-05-27

## Scope

This crosswalk ties the current proof and proof-model areas for the threshold
ML-DSA-65 scaffold to Rust modules and tests that exercise the corresponding
engineering invariants. It is a documentation manifest, not a formal proof, an
audit result, or a production-readiness claim.

The implementation currently uses a deterministic simulation backend. A real
backend direction is now selected for traceability: ML-DSA-65
coordinator-assisted Shamir nonce DKG P1 with a TEE/HSM coordinator assumption
and standard-verifier-compatible output. Later migration candidates remain
P2/MPC and TALUS. This is a selection artifact only; it is not proof closure or
production approval. The entries below therefore distinguish proof obligations
that are represented by code-level guards from obligations that remain open
until selected-backend implementation, proof, and audit artifacts exist.

The prompt for this work referenced `protocol-code-crosswalk.md`,
`proof-obligations.md`, and `formal-threshold-mldsa-transcript.md`. The current
checkout includes `proof-obligations.md` and
`formal-threshold-mldsa-transcript.md`; `protocol-code-crosswalk.md` now maps
the implemented scaffold protocol phases to source files and tests.

This document uses the present proof-surface docs, available cryptography
notes, audit notes, Rust modules, and test files as the source of truth for
current repository state.

## Crosswalk

| Theorem or lemma area | Proof-side obligation | Implementation surface | Test evidence | Current status |
| --- | --- | --- | --- | --- |
| Transcript binding and Fiat-Shamir challenge derivation | The challenge must be derived from a canonical transcript that binds the protocol label, version, session ID, threshold, validator set, public key, message, and ordered commitments before any partial signature is produced. | `src/transcript.rs`, `src/protocol.rs`, `src/backend.rs` | `tests/transcript_determinism.rs`, `tests/simulated_flow.rs` | Implemented as deterministic transcript construction and simulation challenge binding; not a proof of ML-DSA distributional equivalence. |
| Canonical validator, commitment, and partial-share sets | Set construction must reject duplicate, unknown, insufficient, or mismatched validators so aggregation cannot mix signers or commitments across universes. | `src/collections.rs`, `src/types.rs`, `src/errors.rs` | `tests/validation.rs`, `tests/transcript_determinism.rs`, `tests/simulated_flow.rs` | Implemented as Rust API validation and error checks. |
| Wire encoding and untrusted-frame rejection | Network-facing frames must use crate-owned versioned encodings, reject malformed or oversized inputs, and preserve replay-relevant context fields. | `src/adapter/wire.rs`, `src/serialization.rs`, `src/adapter/evidence.rs` | `tests/simulation.rs`, `tests/validation.rs`, `tests/low_level.rs` | Implemented for scaffold adapter frames and commitment payloads. |
| Aggregation boundary and transcript consistency | Aggregation must receive a bound transcript and a threshold-valid partial-share set, then reject shares that do not match transcript validators or public key context. | `src/aggregation.rs`, `src/backend.rs`, `src/protocol.rs` | `tests/simulated_flow.rs`, `tests/type_state.rs`, `tests/ui/type_state_invalid_aggregate.rs`, `tests/ui/type_state_invalid_partial.rs` | Implemented for deterministic simulation backend and compile-fail state transitions. |
| Production coordinator candidate boundary | The non-default production-candidate coordinator must fail closed behind profile and policy gates, bind transcript and preprocessing attempts, keep provider KAT status outside proof claims, pass final verifier gates before compatibility language, and reject simulated backends at compile time. `EpsilonLedger`, blinded pre-filter tokens, hint-routing conformance frames, and the DKG setup-only boundary are guardrails for review. | `src/production/provider.rs`, `src/production/epsilon.rs`, `src/production/prefilter.rs`, `src/production/hints.rs`, `src/production/transcript.rs`, `src/production/preprocess.rs`, `src/production/coordinator.rs`, `src/adapter/production_wire.rs` | `tests/production_provider.rs`, `tests/production_epsilon.rs`, `tests/production_prefilter.rs`, `tests/production_hints.rs`, `tests/production_transcript.rs`, `tests/production_preprocess.rs`, `tests/production_coordinator.rs`, `tests/production_wire.rs`, `tests/ui/production_simulated_backend_rejected.rs` | Boundary and gate implementation only; hazmat provider smoke plus a bounded NIST ACVP-Server FIPS204 ML-DSA-65 sigVer sample fixture cover ordinary provider verification, not aggregate threshold verification, not CAVP/ACVTS validation, not a proof of threshold security, and not production release evidence. |
| Selected backend direction artifact | The assessment and proof docs must name the selected real-backend direction while preserving the five open proof criteria. | `docs/cryptography/proof-implementation-crosswalk.md`, `docs/cryptography/protocol-code-crosswalk.md`, `scripts/assess_lattice_hypothesis.py` | `script_tests/test_assess_lattice_hypothesis.py`, `tests/proof_documentation_manifest.rs` | Selection artifact only; not proof closure, not completed backend implementation evidence, and not production approval. |
| Coordinator-assisted acceptance predicates | Local and aggregate acceptance decisions must remain typed conformance predicates until a selected backend supplies verifier-bridge, recomputation, proof, and audit evidence. | `src/production/acceptance.rs`, `src/production/provider.rs`, `src/production/coordinator.rs` | `tests/production_acceptance.rs`, `tests/production_coordinator.rs` | coordinator-assisted acceptance predicates are conformance-only tokens: `LocalAccept` and `AggregateAccept` do not prove production partial validity, real aggregate recomputation, or distribution preservation. |
| Five-criterion blocker evidence gates and closure frameworks | The five hypothesis blockers now have typed conformance evidence gates, closure-package frameworks, a P1 aggregate recomputation artifact gate, fixture-backed bridge conformance evidence, selected-backend aggregate-output artifact gate coverage, selected-backend threshold-output artifact gate coverage, selected-backend proof-closure artifact package gate coverage, stricter release gate coverage, and a reduction-case manifest, but each remains proof-blocked until selected-backend artifacts, reviewed proofs, and external audit evidence exist. | `src/production/mask_distribution.rs`, `src/production/rejection_equivalence.rs`, `src/production/abort_bias.rs`, `src/production/partial_soundness.rs`, `docs/cryptography/unauthorized-aggregate-reduction.md` | `tests/production_mask_distribution.rs`, `tests/production_rejection_equivalence.rs`, `tests/production_abort_bias.rs`, `tests/production_partial_soundness.rs`, `tests/unauthorized_aggregate_reduction_manifest.rs` | Evidence gates, sample-vector provider conformance, fixture-backed bridge conformance evidence, selected-backend aggregate-output artifact gate coverage, selected-backend threshold-output artifact gate coverage, selected-backend proof-closure artifact package gate coverage, and closure frameworks only; not completed Renyi evidence, not selected-backend proof closure, not selected-backend aggregate recomputation, not real threshold aggregate recomputation, not an abort-bias theorem, not production partial verification, and not threshold EUF-CMA proof. |
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

## Production Coordinator Candidate Boundary

The production coordinator candidate is a gated implementation boundary, not a
completed cryptographic implementation. `src/production/provider.rs` defines
the provider contract and KAT gate; `src/production/epsilon.rs` records
deterministic epsilon residual accounting; `src/production/prefilter.rs`
models blinded pre-filter pass/abort ordering; `src/production/hints.rs`
binds digest-only hint-routing conformance state; `src/production/transcript.rs`
binds the coordinator transcript fields; `src/production/preprocess.rs` tracks
preprocessing attempts; `src/production/coordinator.rs` coordinates the
non-default profile flow; and `src/adapter/production_wire.rs` carries the
production-candidate wire frames.

The matching tests are `tests/production_provider.rs`,
`tests/production_epsilon.rs`, `tests/production_prefilter.rs`,
`tests/production_hints.rs`, `tests/production_transcript.rs`,
`tests/production_preprocess.rs`, `tests/production_coordinator.rs`,
`tests/production_wire.rs`, and
`tests/ui/production_simulated_backend_rejected.rs`. These tests are conformance
and guard evidence. `HazmatMldsa65Provider` provides an optional ML-DSA-65
standard-verifier smoke bridge for ordinary provider-generated signatures and a
context-aware verifier path for the checked-in NIST ACVP-Server FIPS204
ML-DSA-65 sigVer sample fixture. This is provider conformance evidence, not
aggregate threshold verification, CAVP/ACVTS validation, FIPS 140 module status,
or threshold recomputation evidence. The final verifier boundary is defined over
the original application message; the `MessageBinding`/`mu` value is
transcript-internal and is not a substitute verifier message. Production
approval is not publicly mintable in the current API. These tests do not show
threshold unforgeability, distributional equivalence, side-channel safety, or
audit approval.

The coordinator-assisted acceptance predicates in
`src/production/acceptance.rs` add typed `LocalAccept` and `AggregateAccept`
conformance tokens. `tests/production_acceptance.rs` is the conformance anchor
for these tokens. The tokens are useful for wiring future evidence through the
coordinator path, but they do not establish production partial-share
verification, real aggregate recomputation, rejection-distribution
preservation, or release approval.

## Selected Backend Direction

The selected real threshold backend direction is ML-DSA-65
coordinator-assisted Shamir nonce DKG P1. The P1 selection assumes a TEE/HSM
coordinator assumption for nonce DKG coordination and targets
standard-verifier-compatible output. Later migration candidates remain P2/MPC
and TALUS.

`scripts/assess_lattice_hypothesis.py` scans this document and
`docs/cryptography/protocol-code-crosswalk.md` so the generated assessment can
report the selected direction. The matching unit coverage is
`script_tests/test_assess_lattice_hypothesis.py`, and
`tests/proof_documentation_manifest.rs` protects the documentation anchors.
`docs/cryptography/thesis-operating-parameters.md` and
`docs/cryptography/thesis-operating-parameters.json` now pin the
`native-threshold-mldsa65-aggregation-p1` thesis id, P1 operating parameters,
promotion criteria, failure criteria, and fallback trigger as a research
boundary only.

This is a selection artifact only. It is not proof closure or production
approval, not completed backend implementation evidence, not complete
standard-verifier KAT or validation evidence, and not external cryptographic
review. The five hypothesis criteria remain partial
until the corresponding selected-backend proof, implementation, and audit
artifacts exist.

For blocker 2, `src/production/rejection_equivalence.rs` now adds a P1 aggregate
recomputation artifact gate that binds the selected profile to
ACVP/FIPS204-backed provider evidence, recomputation evidence, selected profile
binding digest, standard-verifier bridge evidence digest, proof-artifact
digests, negative-corpus evidence, and external review digests. The checked-in
standard-verifier bridge fixture package at
`tests/fixtures/p1_standard_verifier_bridge_fixture.json` is fixture-backed bridge conformance evidence for drift rejection only. The checked-in bridge fixture is a stricter release gate for drift rejection only; it is not selected-backend aggregate recomputation and not a completed standard-verifier compatibility proof. The selected-backend aggregate-output artifact gate binds `LocalAccept`/`AggregateAccept`, signer-set, attempt, transcript, provider KAT, recomputation, and bridge digests as conformance/proof-review evidence only. `derive_p1_selected_backend_aggregate_artifact_package` and `derive_p1_real_recomputation_evidence_digest` add a real standard-provider aggregate-output package path that derives the package from a provider-verified ML-DSA-65 candidate signature, public recomputation transcript, and standard-verifier bridge digest evidence. The selected-backend threshold-output artifact gate adds successor source-package binding, and the selected-backend proof-closure artifact package gate binds that threshold-output certificate to full KAT/validation artifact slots, rejection-distribution review, standard-verifier compatibility evidence, and a theorem-linkage artifact digest. The real-threshold backend emission gate adds a threshold verifier closure contract for 10,000 validators and threshold 6,667; it rejects deterministic simulation and ordinary single-key standard-provider output as closure evidence. These gates are not selected-backend proof closure, not production threshold ML-DSA security, not CAVP/ACVTS validation, not FIPS validation, not rejection-distribution preservation, and not a completed standard-verifier compatibility proof. They reject smoke-only KAT evidence and digest drift, but remain framework gates until real threshold aggregate recomputation artifacts, actual real threshold backend emissions, and reviewed proof artifacts are checked in.

The open proof payload for blocker 2 is now stated in
`docs/cryptography/criterion-2-proof-substance.md` and
`docs/cryptography/criterion-2-proof-substance.json`. Those files name the
required digest slots and theorem links for `aggregate_rejection_equivalence`;
they are proof-review input only and do not promote Criterion 2 beyond
`partially_met`.

## Open Proof Obligations

The following obligations remain outside the implemented security claim:

- A formal threshold ML-DSA-65 security proof under an explicit adversary,
  network, abort, and corruption model.
- Implementation and conformance artifacts for the selected ML-DSA-65
  coordinator-assisted Shamir nonce DKG P1 backend direction.
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
- `formal-security-theorem.md`
- `formal-threshold-mldsa-transcript.md`
- `proof-obligations.md`
- `claims-matrix.md`
- `side-channel-boundary.md`
- `Transcript binding and Fiat-Shamir challenge derivation`
- `Canonical validator, commitment, and partial-share sets`
- `Wire encoding and untrusted-frame rejection`
- `Aggregation boundary and transcript consistency`
- `Production coordinator candidate boundary`
- `Selected backend direction artifact`
- `Selected Backend Direction`
- `ML-DSA-65 coordinator-assisted Shamir nonce DKG P1`
- `TEE/HSM coordinator assumption`
- `standard-verifier-compatible output`
- `P2/MPC`
- `TALUS`
- `selection artifact`
- `not proof closure`
- `not production approval`
- `scripts/assess_lattice_hypothesis.py`
- `script_tests/test_assess_lattice_hypothesis.py`
- `Coordinator-assisted acceptance predicates`
- `src/production/acceptance.rs`
- `tests/production_acceptance.rs`
- `LocalAccept`
- `AggregateAccept`
- `Five-criterion blocker evidence gates and closure frameworks`
- `P1 aggregate recomputation artifact gate`
- `src/production/mask_distribution.rs`
- `src/production/rejection_equivalence.rs`
- `src/production/abort_bias.rs`
- `src/production/partial_soundness.rs`
- `docs/cryptography/unauthorized-aggregate-reduction.md`
- `tests/production_mask_distribution.rs`
- `tests/production_rejection_equivalence.rs`
- `tests/production_abort_bias.rs`
- `tests/production_partial_soundness.rs`
- `tests/unauthorized_aggregate_reduction_manifest.rs`
- `Simulation-only backend and production proof gates`

Keep these anchors stable when reorganizing this document, or update
`tests/proof_documentation_manifest.rs` in the same change.
