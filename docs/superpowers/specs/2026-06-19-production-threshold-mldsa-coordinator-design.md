# Production Threshold ML-DSA Coordinator Profile Design

Date: 2026-06-19

## Status

Approved design direction for the first real threshold ML-DSA-65 backend
profile in `lattice-aggregation`.

The selected direction optimizes for the fastest credible implementation while
keeping the coordinator replaceable. The first production candidate should be a
coordinator-assisted, TEE/HSM-assisted Shamir nonce DKG profile that produces
FIPS 204-compatible ML-DSA-65 signatures verified by an unmodified standard
ML-DSA verifier.

The selected construction is **Profile P1: ML-DSA-65 coordinator-assisted
Shamir nonce DKG with a TEE/HSM-backed coordinator assumption**. This is the
current production-candidate backend direction, not a production claim. Later
migration candidates are **Profile P2**, a fully distributed MPC profile, and
TALUS-style optimized threshold ML-DSA, each requiring separate proof, audit,
KAT, and implementation evidence before promotion.

This document is a design spec, not an implementation plan, cryptographic
proof, audit result, FIPS validation claim, or production-readiness statement.

## Source Basis

The design is grounded in:

- NIST FIPS 204 as the standard ML-DSA signing and verification compatibility
  target.
- IETF ML-DSA security-considerations guidance for randomness, contexts,
  rejection sampling, and side-channel discipline.
- The current FIPS 204-compatible threshold ML-DSA research direction based on
  masked Lagrange reconstruction and Shamir nonce DKG.
- Profile P2 fully distributed MPC and TALUS-style optimized threshold ML-DSA
  as later migration candidates, not the first implementation target.
- The current repository architecture and claim boundaries in
  `docs/cryptography/*`, `docs/audit/*`, and the scaffold Rust modules.

Any implementation must cite exact paper versions, theorem statements, and
reviewed protocol assumptions before moving beyond a hazmat profile.

## Scope

This spec covers:

- The first production-candidate profile choice.
- Trust boundaries for a coordinator-assisted threshold signing service.
- Required high-level protocol phases.
- New Rust module and trait boundaries.
- Feature-gate and policy-gate structure.
- Test, KAT, fuzzing, side-channel, and review gates.
- Migration from the current deterministic simulation scaffold.

This spec does not cover:

- A full line-by-line implementation plan.
- A completed formal proof of threshold ML-DSA security.
- A production VSS/DKG construction.
- A full TEE/HSM product selection or attestation integration.
- FIPS validation or certification.
- A fully distributed no-trusted-coordinator MPC profile.
- Production consensus deployment.

## Design Goals

The first real backend profile must:

- Produce standard-size ML-DSA-65 signatures that verify with an unmodified
  standard verifier.
- Keep the current simulation backend as the default and preserve all
  simulation-only claim boundaries.
- Make the coordinator an explicit profile component, not a hidden permanent
  assumption.
- Require signers to verify coordinator attestation and transcript context
  before sending masked signing material.
- Enforce one-time use of preprocessed nonce attempts.
- Require final standard verification before returning `ThresholdSignature`.
- Leave room for a later fully distributed MPC profile behind compatible
  high-level signer/session boundaries.

## Evidence Requirements

The first profile requires separate evidence for:

- FIPS validation or certification.
- Production threshold ML-DSA security before external review.
- Production DKG/VSS security.
- Adaptive-corruption security.
- Production slashing soundness or anti-framing evidence.
- Constant-time or side-channel resistance from source shape alone.
- That a TEE/HSM removes the need for cryptographic and implementation audits.

## Recommended Profile

Target **Profile P1: ML-DSA-65, coordinator-assisted Shamir nonce DKG** first,
under a TEE/HSM-backed coordinator assumption.

The profile has three practical advantages for this repository:

1. It preserves the most important compatibility target: standard ML-DSA
   verification.
2. It fits the current actor, adapter, transcript, partial-share, and evidence
   scaffold.
3. It isolates the hardest trusted step in a coordinator component that can be
   replaced later by Profile P2 fully distributed MPC or TALUS-style optimized
   threshold ML-DSA.

The first narrow implementation claim, after evidence exists, should be:

> This profile produces standard-verifier-compatible ML-DSA-65 signatures under
> the documented coordinator, share-provisioning, attestation, and review
> assumptions.

General production threshold ML-DSA security requires proof, side-channel,
deployment, and audit gates.

## Protocol Overview

### Setup And Key Material

The profile fixes:

- ML-DSA-65 parameter set.
- Threshold `t/n`.
- Validator set and validator-set digest.
- Epoch or key identifier.
- Protocol profile identifier.
- Context string.
- Threshold public key.
- DKG transcript digest or explicitly documented external share ceremony.

The fastest credible path may begin with externally provisioned audited key
shares, for example an attested HSM dealer ceremony. That shortcut must remain
outside any production DKG/VSS claim. A proof-grade DKG/VSS implementation is a
later gate.

### Nonce Preprocessing

For each future signing attempt, signers prepare a single-use nonce attempt:

- Each signer contributes nonce material under a Shamir nonce DKG-style
  relation.
- Attempt state is identified by `AttemptId` and bound to the epoch, key ID,
  validator set digest, and protocol profile.
- Preprocessing is message-independent and may be batched.
- Consumed or failed attempts are never reused.
- Secret nonce state is erased after use or abort.

### Signing Attempt

A signing attempt proceeds in profile-specific rounds:

1. Signers commit to nonce-derived public material before any challenge is
   derived.
2. Signers send masked commitment material only to the attested coordinator.
3. The coordinator aggregates masked material, derives the FIPS-compatible
   challenge, and broadcasts only public challenge material.
4. Signers verify the challenge context and return response shares plus the
   required masked check material.
5. The coordinator applies Lagrange coefficients, performs aggregate bound,
   `r0`, hint, and final verifier checks, and emits either a signature or an
   abort.

### Rejection And Retry

Rejection sampling is normal ML-DSA behavior. The profile retries with a fresh
attempt on:

- challenge or transcript mismatch;
- malformed or missing signer material;
- reused nonce attempt;
- aggregate `z` bound failure;
- `r0` or hint failure;
- final standard-verifier failure;
- coordinator attestation or policy mismatch.

Retry limits are operational controls. Low fixed retry caps require correctness
and liveness impact analysis before introduction.

## Trust Model

### Coordinator Trust Boundary

The coordinator, ideally backed by a TEE or HSM, is trusted for:

- confidentiality and integrity of masked individual inputs;
- reconstructed `r0` and hint-sensitive intermediates;
- aggregate rejection decisions;
- final signature encoding and final verifier enforcement;
- zeroization of coordinator-local sensitive state.

The coordinator is not trusted for liveness. It may delay, censor, or force
retries. The actor and consensus layers must treat this as operational
availability risk, not a signature-forgery risk by itself.

### Signer Obligations

Each signer must:

- verify coordinator attestation before sending masked material;
- bind the request to epoch, key ID, validator set, public key, context,
  attempt ID, and message binding;
- enforce one-time nonce attempt use locally;
- erase attempt-local secrets after use;
- reject mismatched challenge material;
- verify any returned final signature locally.

### Logging And Attestation

Coordinator logs must include only non-secret review material:

- session ID;
- epoch and key ID;
- protocol profile;
- ML-DSA parameter set;
- validator set digest;
- threshold;
- public key or public key digest;
- DKG transcript digest or share-ceremony identifier;
- message digest or `mu`;
- active signer set;
- nonce attempt ID;
- commitment digests;
- challenge digest;
- response receipt set;
- abort reason class;
- final signature digest;
- standard verifier result;
- attestation quote and TCB version.

Logs must not include secret shares, nonce shares, raw `r0`, unmasked
intermediate values, or signer-private masked values unless an externally
reviewed public evidence predicate explicitly requires and permits disclosure.

## Architecture

The production profile should be added beside the existing simulation scaffold.
The default feature remains `simulated`.

### Feature Gates

Use non-default gates with conservative names:

- `coordinator-assisted`: enables coordinator profile types and adapter frames.
- `raw-real-mldsa`: enables experimental real ML-DSA-65 primitives.
- `production-mldsa65-coordinator`: reserved for a later evidence-backed
  promotion gate and must remain disabled until release gates pass.

The presence of `raw-real-mldsa` or `coordinator-assisted` must not imply
production approval.

### Module Layout

Add modules in small, reviewable units:

```text
src/
  coordinator.rs
  preprocess.rs
  production.rs
  production/
    provider.rs
    transcript.rs
    signing.rs
    policy.rs
    evidence.rs
```

If the files grow beyond a focused responsibility, split by function rather
than by cryptographic phase name alone.

### Provider And Backend Split

Separate standard ML-DSA primitives from threshold protocol logic:

```rust
pub trait StandardMldsa65Provider {
    type Error;

    fn verify(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, Self::Error>;
}

pub trait ThresholdMldsa65CoordinatorProfile {
    type Error;
    type KeyShare;
    type PreprocessedAttempt;
    type PartialResponse;
    type CoordinatorState;

    fn prepare_attempt(
        request: PreprocessRequest,
    ) -> Result<Self::PreprocessedAttempt, Self::Error>;

    fn bind_transcript(
        request: ProductionSigningRequest,
    ) -> Result<ProductionSigningTranscript, Self::Error>;

    fn partial_sign(
        request: PartialSigningRequest<Self::KeyShare, Self::PreprocessedAttempt>,
    ) -> Result<Self::PartialResponse, Self::Error>;

    fn verify_partial(request: PartialVerificationRequest<Self::PartialResponse>)
        -> Result<(), Self::Error>;

    fn aggregate_attempt(
        request: AggregateAttemptRequest<Self::CoordinatorState, Self::PartialResponse>,
    ) -> Result<ThresholdSignature, Self::Error>;
}
```

The request wrapper fields should be finalized during implementation planning,
but the separation is mandatory. The current `Mldsa65Backend` may remain for
the simulation API; production should not be forced through its single-round
shape.

### Production Context Types

Add typed context wrappers:

- `ProtocolProfile`
- `EpochId`
- `KeyId`
- `AttemptId`
- `ValidatorSetDigest`
- `DkgTranscriptDigest`
- `ActiveSignerSet`
- `MessageBinding`
- `CoordinatorAttestationDigest`
- `PreprocessingBatchId`

These types prevent accidental mixing of session, epoch, key, attempt, and
message domains.

## Transcript Design

The current `SigningTranscript` pattern is reusable but incomplete for
production. A `ProductionSigningTranscript` must bind:

- protocol profile and version;
- ML-DSA parameter set;
- epoch and key ID;
- session ID;
- block height or consensus object identifier;
- validator set digest;
- active signer set;
- threshold;
- public key;
- DKG transcript digest or share ceremony digest;
- context string;
- message binding or `mu`;
- nonce attempt ID;
- ordered commitment digests;
- coordinator attestation digest;
- retry counter or attempt sequence.

Domain separators must be explicit for message binding, commitment binding,
challenge derivation, partial-response proof material, and evidence payloads.

## Wire And Adapter Changes

The existing `PqcThresholdWireMsg` is a v1 simulation scaffold. Production
requires v2 coordinator frames or a separate production enum:

- `PreprocessCommit`
- `PreprocessShare`
- `CoordinatorCommitmentRequest`
- `SignerCommitmentResponse`
- `CoordinatorChallenge`
- `SignerPartialResponse`
- `CoordinatorAbort`
- `CoordinatorFinalSignature`
- `CoordinatorAttestation`
- `ComplaintOrEvidence`

Production frames must bind:

- wire version;
- protocol profile;
- epoch and key ID;
- session ID;
- attempt ID;
- validator ID;
- active signer set digest;
- block height or object identifier;
- payload length;
- payload digest;
- authentication envelope or external authenticated-transport binding.

The actor must stop using poison-byte invalid-share checks for production. It
must call backend partial verification and only then store a response.

## DKG And Share Provisioning

The first implementation may use externally provisioned audited shares to avoid
blocking the first real signing path on production DKG. If so:

- the share ceremony must be explicitly documented;
- public key, validator set, threshold, and share identifiers must be bound into
  a ceremony digest;
- docs must state that production DKG/VSS is not implemented;
- promotion beyond hazmat remains blocked.

Production DKG/VSS later requires binding, hiding, extractability, complaint
soundness, anti-framing, robustness, and key-bias analysis.

## Error Handling And Evidence

Production errors must separate:

- local validation failures;
- coordinator attestation failures;
- malformed wire frames;
- stale or reused attempts;
- rejection-sampling aborts;
- invalid partial responses;
- final verifier failures;
- timeout and liveness failures.

Evidence emitted outside the coordinator must remain non-secret unless a public
evidence predicate has been externally reviewed. Diagnostic evidence is not
production slashing authority.

## Testing Strategy

Required implementation tests:

- FIPS/ACVP-style ML-DSA-65 provider KATs.
- Standard verifier bridge tests for every successful aggregate.
- Fixed threshold KATs, at minimum 2-of-3 and 3-of-5.
- Negative vectors for wrong message binding, wrong `mu`, wrong attempt ID,
  wrong active signer set, wrong signer ID, malformed proof, malformed
  response, stale attestation, and reused attempt.
- Transcript determinism tests for epoch, key ID, DKG digest, active set,
  attempt ID, coordinator attestation digest, and commitment ordering.
- Wire v2 golden tests and malformed/trailing/oversized rejection tests.
- Actor integration tests for reorder, drop, duplicate, retry, timeout, and
  malicious coordinator transcript behavior.
- Compile-fail tests for invalid state transitions and reused preprocessed
  attempts if typestate is used for attempt consumption.
- Fuzz targets for wire frames, production transcripts, evidence payloads,
  partial-response parsing, aggregate signature parsing, replay/session fields,
  and public evidence predicates.

## Side-Channel And Operational Gates

Before any production label is allowed:

- run dudect or equivalent timing tests for selected secret-dependent paths;
- run ctgrind or equivalent leakage checks where supported;
- review generated code or compiler output for selected targets;
- review zeroization and erasure behavior;
- document randomness source, entropy health checks, and nonce lifecycle;
- document authenticated transport and validator identity binding;
- document retry, timeout, DoS, observability, incident-response, and rollback
  policies;
- complete independent cryptographic, implementation, side-channel, and
  operational review.

## Migration Path

1. Keep `simulated` as the default backend and keep current documentation
   non-claims intact.
2. Add production context, preprocessing, coordinator, and provider traits under
   non-default gates.
3. Add a standard ML-DSA-65 provider with KATs and standard verification.
4. Add the coordinator-assisted threshold signing profile with externally
   provisioned shares.
5. Require standard verification before any aggregate is returned.
6. Add wire v2 and actor integration tests for coordinator-assisted signing.
7. Add negative vectors, fuzzing, side-channel gates, and audit evidence.
8. Only after external review, consider promoting a `production-*` feature.
9. Later, replace externally provisioned shares with proof-grade VSS/DKG.
10. Later, evaluate Profile P2 fully distributed MPC and TALUS-style optimized
    threshold ML-DSA as separate migration candidates.

## Documentation Updates Required During Implementation

Implementation work must update:

- `docs/cryptography/claims-matrix.md`
- `docs/cryptography/proof-obligations.md`
- `docs/cryptography/proof-implementation-crosswalk.md`
- `docs/cryptography/protocol-code-crosswalk.md`
- `docs/cryptography/side-channel-boundary.md`
- `docs/cryptography/vss-dkg-security-plan.md`
- `docs/audit/attack-surface.md`
- `docs/audit/tcb.md`
- `docs/benchmarks/release-readiness-checklist.md`
- `tests/proof_documentation_manifest.rs`

Every new claim must name the supporting source files, tests, artifacts,
reviewers, and remaining blockers.

## Acceptance Criteria For The First Implementation Plan

The implementation plan derived from this spec must:

- start with provider/KAT work before threshold aggregation;
- keep feature gates non-default;
- avoid routing production through `SimulatedBackend`;
- make attempt reuse unrepresentable or explicitly rejected;
- include a standard-verifier bridge test before any aggregate API returns
  success;
- include negative tests before implementation for replay, context mismatch,
  active-set mismatch, and malformed partial responses;
- update documentation claim boundaries in the same changes that add behavior.

## Open Questions For Implementation Planning

- Which exact ML-DSA-65 provider crate or local implementation will be used as
  the first standard verifier target?
- Will the first share-provisioning path be external audited shares, an HSM
  dealer ceremony, or an in-repo experimental DKG?
- Which TEE/HSM attestation format is realistic for the first integration?
- What consensus object is signed: raw block hash, canonical block header, or
  an application-specific message binding?
- What replay window, retry policy, and timeout policy does the validator
  network require?
- Which fuzzing and side-channel harnesses are available in this environment?
