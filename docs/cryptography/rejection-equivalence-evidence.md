# Aggregate Rejection-Equivalence Evidence

This note records a bounded conformance artifact for blocker 2:
aggregate rejection checks should match centralized ML-DSA rejection checks.
The current artifact does not close the blocker. It separates scaffold-only
digest evidence from evidence that is tied to both a standard-verifier bridge
and a public aggregate recomputation transcript.

## Implemented Gate

`src/production/rejection_equivalence.rs` defines:

- `AggregateRejectionEvidenceStrength::ScaffoldOnly`, for digest-only evidence
  that can support conformance plumbing but cannot satisfy the equivalence gate.
- `AggregateRejectionEvidenceStrength::ProviderRecomputedBridge`, for evidence
  minted only after `StandardVerifierEvidence::verify::<P>` accepts the
  candidate signature and the recomputed aggregate signature digest matches the
  verifier-checked candidate signature digest.
- `AggregateRecomputationTranscript`, a public-output transcript that binds the
  production challenge digest, aggregate-response digest, hint digest, and
  recomputed aggregate-signature digest.
- `AggregateRejectionEquivalenceGate`, which rejects scaffold-only evidence and
  returns bridge evidence only when the standard provider and recomputation
  transcript agree on the candidate signature.

The targeted conformance tests in `tests/production_rejection_equivalence.rs`
cover the red/green behavior:

- scaffold-only evidence is classified but does not satisfy the gate;
- provider-verified recomputation evidence satisfies the gate;
- failed standard verification is rejected;
- recomputed aggregate-signature mismatch is rejected.

## Claim Boundary

This is hazmat/conformance-only evidence. It does not claim production
threshold ML-DSA security, real aggregate recomputation, or rejection-sampling
distribution preservation.

The safe claim is narrower: the coordinator-assisted profile now has a typed
gate that prevents digest-only scaffold evidence from being mistaken for
standard-verifier/recomputation bridge evidence.

## What Remains

To fully close blocker 2, the repo still needs:

- a real ML-DSA-65 provider with KAT-backed verification;
- a real threshold aggregate recomputation transcript produced by the selected
  backend, not test-only public bytes;
- integration of `src/production/rejection_equivalence.rs` into the
  `production` module declaration after write-scope review;
- crosswalk and proof-manifest updates once the artifact is promoted beyond
  this owned-file slice;
- proof work showing accepted aggregate rejection behavior matches centralized
  ML-DSA rejection checks, including distribution-preservation analysis.
