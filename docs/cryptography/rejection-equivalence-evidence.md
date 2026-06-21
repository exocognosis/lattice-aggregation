# Aggregate Rejection-Equivalence Evidence

This note records a bounded conformance artifact for blocker 2:
aggregate rejection checks should match centralized ML-DSA rejection checks.
The current artifact does not close the blocker. It separates scaffold-only
digest evidence from evidence that is tied to both a standard-verifier bridge
and a public aggregate recomputation transcript. It also defines a stronger
closure-package framework for the evidence that must exist before blocker 2 can
move from conformance plumbing to proof closure.

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
- `AggregateRejectionEvidenceDigest`, which tags each digest by artifact class
  so scaffold-only placeholders cannot be supplied where real recomputation or
  KAT evidence is required.
- `AggregateRejectionClosurePackage`, which represents the complete blocker-2
  closure package: real aggregate recomputation evidence, standard verifier
  provider/KAT evidence, norm-bound evidence, hint-bound evidence,
  challenge-bound evidence, transcript-binding evidence, negative test corpus
  evidence, external review evidence, and an explicit conformance boundary.
- `assess_rejection_equivalence_closure`, which returns
  `AggregateRejectionClosureAssessment::ClosureReady` only when the package uses
  the `ClosureCandidate` boundary and every required digest is present,
  non-zero, and classified as the expected non-scaffold artifact.

The targeted conformance tests in `tests/production_rejection_equivalence.rs`
cover the red/green behavior:

- scaffold-only evidence is classified but does not satisfy the gate;
- provider-verified recomputation evidence satisfies the gate;
- failed standard verification is rejected;
- recomputed aggregate-signature mismatch is rejected.
- complete closure packages expose closure-ready status without claiming a
  production verifier;
- missing real recomputation evidence is rejected;
- missing standard provider/KAT evidence is rejected;
- scaffold-only recomputation or KAT evidence is rejected;
- missing bound evidence, zero external review digests, and scaffold-only
  conformance boundaries are rejected.

## Claim Boundary

This is hazmat/conformance-only evidence. It does not claim production
threshold ML-DSA security, real aggregate recomputation, or rejection-sampling
distribution preservation. `ClosureReady` means the closure framework has all
typed evidence digests needed for proof review; it does not mean those artifacts
have been independently validated in this repository.

The safe claim is narrower: the coordinator-assisted profile now has a typed
gate that prevents digest-only scaffold evidence from being mistaken for
standard-verifier/recomputation bridge evidence, and a closure-package assessor
that prevents missing or scaffold-only recomputation/KAT evidence from being
reported as ready for blocker closure.

## What Remains

To fully close blocker 2, the repo still needs:

- a selected real ML-DSA-65 provider with provider identity and KAT evidence
  digests backed by FIPS/ACVP-style vectors;
- a real threshold aggregate recomputation artifact produced by the selected
  backend, with digest evidence tied to the package;
- reviewed norm, hint, and challenge bound artifacts whose digests match the
  closure package;
- a transcript-binding artifact showing the package is bound to the production
  signing transcript, original application message, signer set, and attempt;
- a negative test corpus showing scaffold/provider mismatch cases fail closed;
- external review evidence for the recomputation, KAT, bounds, transcript, and
  negative-corpus artifacts;
- broader coordinator/proof wiring after write-scope review, so closure-ready
  packages become an explicit release gate instead of a standalone assessor;
- crosswalk and proof-manifest updates once the artifact is promoted beyond
  this owned-file slice;
- proof work showing accepted aggregate rejection behavior matches centralized
  ML-DSA rejection checks, including distribution-preservation analysis.
