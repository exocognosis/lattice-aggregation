# Epsilon Prefilter Guardrails Design

Date: 2026-06-20

## Status

Approved direction for a conformance-layer implementation that closes the
repository's documented threshold ML-DSA sequencing gaps without claiming
production cryptography.

This design implements reviewable guardrails for the coordinator-assisted
profile. It does not implement a real ML-DSA-65 threshold signer, a production
Gaussian sampler, a production hint equation, or a malicious-secure DKG.

## Scope

This work adds typed Rust boundaries, tests, and proof-surface documentation
for:

- `EpsilonLedger` accounting over `epsilon_mask`, `epsilon_rej`, and
  `epsilon_withhold`;
- blinded pre-filtering before any response-share release;
- zeroization of attempt-local secret material on pre-filter abort;
- conformance-only asymmetric noise-flooding parameters;
- conformance-only interactive hint-routing states and wire frames;
- explicit DKG setup isolation through `DkgTranscriptDigest`.

The implementation must keep the current `coordinator-assisted` feature
non-default and preserve the existing claim boundary: hazmat/conformance only.

## Architecture

Add focused production modules beside the existing coordinator skeleton:

- `src/production/epsilon.rs` owns epsilon residual accounting and Renyi
  divergence annotations.
- `src/production/prefilter.rs` owns blinded pre-filter inputs, outcomes, and
  the `PreFilterPassed` capability token required before share release.
- `src/production/hints.rs` owns hint-routing request/response state wrappers
  without implementing final ML-DSA hint equations.
- `src/adapter/production_wire.rs` gains v2 conformance frames for pre-filter
  abort/pass and hint routing.

`PreprocessedAttempt` remains the one-time secret-material owner. It gains an
explicit `abort_and_zeroize` path so tests can prove rejected attempts are
consumed and wiped before any share-release API can borrow their bytes.

## Protocol Ordering

The production-candidate signing sequence becomes:

1. Signers publish or deliver blinded commitment summaries.
2. The coordinator constructs a blinded pre-filter request from public digests
   and bound parameters.
3. The pre-filter returns either `PreFilterPassed` or `PreFilterAborted`.
4. On abort, the ledger increments `epsilon_rej`, attempt-local material is
   zeroized, and only an abort frame can be emitted.
5. Only a `PreFilterPassed` token enables share-release or finalization APIs.
6. Hint-routing may run after pre-filter pass to resolve public near-boundary
   carry cases.
7. Final aggregate output remains gated by standard verifier and release
   policy.

This ordering directly addresses the state-leakage paradox: raw scalar
response shares are not generated, exposed, or transmitted if the pre-filter
gate fails.

## Epsilon Ledger

The ledger tracks three counters:

- `epsilon_mask`: Renyi-divergence budget consumed by conformance noise
  flooding.
- `epsilon_rej`: public rejection/abort budget consumed by pre-filter aborts.
- `epsilon_withhold`: budget consumed by attributable withholding events.

Counters are represented as deterministic fixed-point units, not floats, so
test expectations are stable. Documentation must use Renyi divergence wording
for `epsilon_mask`; statistical-distance wording is allowed only as a legacy
open proof item that has not been satisfied.

## Blinded Pre-Filtering

The pre-filter does not inspect raw `z_i` or secret shares. It accepts bounded
commitment summaries representing `w_i = A * y_i` style public material and a
clearance boundary representing `gamma_1 - beta`.

The conformance predicate is deliberately simple:

- reject malformed active-set or threshold data through existing transcript
  types;
- pass if the declared aggregate infinity norm is at or below the clearance
  boundary;
- abort if the declared aggregate infinity norm exceeds the boundary.

This is a guardrail interface for future reviewed backend math. It is not a
proof that the placeholder norm summary is a real ML-DSA norm computation.

## Asymmetric Noise Flooding

Add a typed `NoiseFloodingParameters` object with:

- a `beta` bound;
- a `gaussian_sigma_bound`;
- validation that `gaussian_sigma_bound <= beta / 4`;
- an `epsilon_mask` Renyi increment supplied by the reviewed backend or proof
  harness.

This design records and enforces the parameter relationship. It does not
sample production Gaussian noise.

## Interactive Hint-Routing

Hint routing is modeled as public conformance state:

- `HintRoutingRequest` binds the session, attempt, active-set digest, challenge
  digest, and near-boundary commitment digest.
- `HintRoutingResponse` binds the responding validator and a response digest.
- `HintRoutingDecision` records whether hint routing completed or aborts.

The implementation must not expose raw low bits, raw `r0`, secret masks, or
response scalars in the public types.

## DKG Isolation

The signing path treats DKG as setup input only:

- `ProductionSigningTranscript` already binds `DkgTranscriptDigest`.
- No signing API should call `SimulatedDkg` or start DKG/VSS rounds during
  block production.
- Docs must say any real DKG remains an offline or epoch-transition phase and
  is not part of the per-block hot path.

## Testing

Tests must be written before implementation and must prove:

- `EpsilonLedger` starts at zero and increments the intended component only.
- Noise parameters reject `sigma > beta / 4`.
- A pre-filter abort increments `epsilon_rej` and consumes/zeroizes the
  attempt.
- A pre-filter pass yields a `PreFilterPassed` token.
- Share-release helper APIs require `PreFilterPassed`.
- Production wire frames reject truncated and trailing bytes.
- Hint-routing types and frames bind session, attempt, challenge, and active
  set digests.
- Documentation anchors keep the conformance-only and Renyi-divergence claim
  boundaries intact.

## Evidence Requirements

This work requires separate evidence for:

- standard-verifier-compatible threshold signatures;
- real ML-DSA-65 hint correctness;
- production Gaussian sampling;
- resolved threshold unforgeability;
- DKG/VSS malicious security;
- production release approval;
- FIPS validation or certification.
