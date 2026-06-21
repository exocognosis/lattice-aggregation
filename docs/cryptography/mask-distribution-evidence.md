# Mask Distribution Evidence

This note tracks concrete evidence for blocker 1: aggregate masks must match,
or be bounded close to, centralized ML-DSA masks. The current artifact is a
typed coordinator-assisted evidence gate, not a production ML-DSA proof.

## Evidence Gate

`src/production/mask_distribution.rs` is feature-gated behind
`coordinator-assisted`. It accepts digest-only evidence containing:

- a statement that aggregate masks either match centralized ML-DSA masks or are
  approximated by an explicit Renyi-style bound;
- a digest of the centralized reference distribution artifact;
- a digest of the aggregate threshold-mask distribution artifact;
- a digest of the reviewed Renyi/divergence evidence package;
- the claimed Renyi divergence in `EpsilonUnit` ledger units;
- the claimed aggregate-mask min-entropy.

The gate returns `Missing`, `Invalid`, or `Accepted`. `Accepted` records the
bound and entropy requirements that were satisfied, but still exposes that it
does not claim a complete ML-DSA security proof.

## Accepted Evidence Requirements

Evidence is accepted only when all of the following are true:

- evidence is present;
- all distribution and proof digests are nonzero;
- exact centralized-match claims report zero Renyi divergence;
- claimed Renyi divergence is no greater than the configured mask residual
  allowance;
- claimed aggregate-mask min-entropy is no lower than the configured
  requirement.

Missing evidence, zero proof digests, divergence above the configured bound,
and insufficient entropy are rejected by tests in
`tests/production_mask_distribution.rs`.

## Claim Boundary

This gate is evidence plumbing for the aggregate-mask distribution obligation.
It does not prove that the threshold implementation is production-ready, does
not prove full ML-DSA accepted-signature distribution equivalence, and does not
replace external cryptographic review.

To fully close blocker 1, the repository still needs a reviewed proof or
measurement-backed evidence package whose digests are fed into this gate, plus
agreement on the concrete Renyi residual and min-entropy thresholds accepted by
the security proof.
