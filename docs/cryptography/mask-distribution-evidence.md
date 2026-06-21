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

## Closure Package Framework

`MaskDistributionClosurePackage` is the stronger blocker-1 closure framework.
It represents the complete set of artifacts that must be present before the
mask-distribution obligation can be treated as closure-ready at the framework
level:

- selected aggregate-mask construction id;
- centralized distribution artifact digest;
- aggregate distribution artifact digest;
- Renyi proof artifact digest;
- accepted `epsilon_mask` bound;
- aggregate-mask min-entropy threshold;
- external review artifact digest and accepted signoff;
- explicit `NonProductionProofFramework` boundary.

`closure_report()` returns missing and invalid closure fields plus convenience
accessors for the selected construction id, accepted `epsilon_mask` bound,
min-entropy threshold, and proof boundary. `is_closure_ready()` is true only
when every required field is present, all supplied digests and thresholds are
well-formed, external review has signed off, and the package explicitly
disclaims production proof closure.

Incomplete packages remain rejected. For example, a package without an
aggregate distribution digest or external review signoff reports those missing
fields and is not closure-ready. A package that attempts to claim production
proof closure reports an invalid `NonProductionProofBoundary` field.

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
`tests/production_mask_distribution.rs`. The same test file also covers closure
packages that are incomplete, complete as non-production framework packages,
and invalid because they claim production proof closure.

## Claim Boundary

This gate is evidence plumbing for the aggregate-mask distribution obligation.
It does not prove that the threshold implementation is production-ready, does
not prove full ML-DSA accepted-signature distribution equivalence, and does not
replace external cryptographic review.

To fully close blocker 1, the repository still needs a reviewed proof or
measurement-backed evidence package whose digests are fed into this gate, plus
agreement on the concrete Renyi residual and min-entropy thresholds accepted by
the security proof. Turning this framework into actual proof closure still
requires selecting the construction, producing the centralized and aggregate
distribution artifacts, proving or measuring the Renyi bound, justifying the
accepted `epsilon_mask` and min-entropy thresholds, and obtaining external
review signoff over the exact digests and assumptions.
