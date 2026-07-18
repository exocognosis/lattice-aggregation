# Distributed Mask MPC Feasibility

Status: feasibility charter and executable cost model. This is not a protocol
implementation, not a proof, not an audit result, and not theorem closure.
Date: 2026-07-17.

## Scope and Claim Boundary

The ratified epsilon-mask fork chooses a small-committee heavy-MPC route as the
only current path that can keep both target properties:

- standard ML-DSA-65 verifier compatibility;
- no single party learning the signing key or one-time mask.

This document turns that direction into a reviewable engineering scope. It does
not change any hypothesis criterion from `partially_met`. It does not close `epsilon_mask`, does not claim rejection-distribution preservation, and does not claim production threshold ML-DSA security.

Required claim flags remain false:

- `claims_theorem_closure = false`
- `claims_criterion_met = false`
- `claims_selected_backend_proof_closure = false`
- `claims_epsilon_mask_closed = false`
- `claims_rejection_distribution_preservation = false`
- `claims_standard_verifier_compatibility_complete = false`
- `claims_production_threshold_mldsa_security = false`
- `claims_cavp_acvts_validation = false`
- `claims_fips_validation = false`

## Target Construction

The scoped target is an exact distributed implementation of the ML-DSA-65
signing attempt, where the committee jointly samples one `ExpandMask`-uniform
mask `y` that no committee member learns.

Inside the MPC envelope:

- jointly sample `y` with the exact ML-DSA-65 `ExpandMask` distribution;
- maintain secret shares of `s1`, `s2`, and `y`;
- compute `z = y + c*s1` on shares;
- compute `Decompose(w)` / `HighBits(w)` and `LowBits(w)` predicates;
- evaluate `||z||_inf < gamma1 - beta`;
- evaluate `||r0||_inf < gamma2 - beta`;
- compute `MakeHint` and enforce the `omega` bound;
- loop internally until an accepted attempt is produced.

Outside the MPC envelope:

- `A*y` and `A*z` remain linear share operations;
- `w1` is commit-revealed before challenge derivation;
- `c = H(mu, w1)` is computed over public committed transcript material;
- the accepted `(c_tilde, z, h)` tuple is packed as the ordinary 3309-byte
  ML-DSA-65 signature;
- an unmodified ML-DSA-65 verifier checks the result.

## Prototype Scope

The first prototype should be committee-sized, not validator-sized:

- committee size: `k = 64` target, with test vectors at `k = 8, 16, 32, 128`;
- cadence: epoch certificate, not per-block signing;
- schedule: sequential attempts first; speculative attempts only as a benchmark;
- multiplication protocol model: king-based Damgard-Nielsen style, not naive
  all-to-all resharing;
- active validator set: still `n = 10000`, threshold `t = 6667`, but the MPC
  committee produces the epoch certificate for the validator set rather than a
  per-block aggregate signature.

The prototype deliverable is not a production backend. It is a measurement and
correctness harness that can later be reviewed against FST-A10, FST-A11, and
FST-A12.

## Executable Model

The reproducible model is:

```bash
python3 scripts/model_distributed_mask_mpc_feasibility.py --json
```

The model emits schema
`lattice-aggregation:distributed-mask-mpc-feasibility-model:v1` with all claim
flags false, `evidence_status = evidence_present_unclosed`,
`overall_verdict_preserved = partially_proven`, and every criterion status
preserved as `partially_met`. It records:

- ML-DSA-65 parameter constants;
- the nonlinear MPC scope;
- comparison-equivalent operation counts;
- per-party bandwidth estimates for king-DN and all-to-all protocols;
- sequential and speculative latency estimates;
- go/no-go verdicts for fast blocks, 6-second blocks, 12-second slots, epoch
  certificates, and hourly checkpoints.

The current model result is:

- Solana-class 0.4-second per-block signing: `no_go`;
- Cosmos/Tendermint 6-second cadence: `go_requires_speculative_regional`;
- Ethereum 12-second slot: `go_requires_speculative_regional`;
- 6.4-minute epoch certificate: `go_even_worst_case`;
- hourly checkpoint: `go_even_worst_case`.

## Required Next Artifacts

To advance this from feasibility to cryptographic evidence, the repo needs:

- exact circuit inventory for `ExpandMask`, `Decompose`, norm predicates, and
  `MakeHint`;
- a concrete MPC protocol selection with corruption model, output delivery, and
  abort policy;
- a transcript format for committee commitments, reveals, attempt ids, and retry
  counters;
- a proof that public `w1` commit-reveal before challenge derivation does not
  permit challenge grinding;
- a leakage proof for attempt counts and any abort/retry metadata;
- an executable small-committee prototype with accepted and rejected attempts;
- external review binding the implementation, circuit, assumptions, and
  transcript digest.

## Non-Closure Summary

This artifact is meaningful progress because it converts the hard theorem
bottleneck into a costed and testable implementation target. It is still
pre-implementation evidence. The remaining theorem gap is a real MPC protocol,
its proof, and reviewed execution evidence showing the accepted outputs are
byte-exact ML-DSA-65 signatures with the centralized signing distribution.

## Cross-References

- [Epsilon Mask Fork Decision](epsilon-mask-fork-decision.md)
- [Design-Space Boundary Theorems](design-space-boundary-theorems.md)
- [FST-L12 Committee Cost Model](fst-l12-committee-cost-model.md)
- [Threshold Stack Architecture](threshold-stack-architecture.md)
- [Noise-Bound and Rejection-Sampling Proof Plan](noise-rejection-proof-plan.md)
