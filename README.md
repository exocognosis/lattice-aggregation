# ML-DSA Lattice Aggregator

Rust research scaffold for threshold-style ML-DSA-65 aggregation on validator
networks. The project studies whether an L1 can replace a growing set of
individual post-quantum validator signatures with one standard-size ML-DSA-65
signature while preserving the verification path expected by unmodified
ML-DSA verifiers.

## The Problem

BLS signatures made validator aggregation operationally attractive because
public keys and signatures compose algebraically. ML-DSA, standardized in
FIPS 204 from the Dilithium family, does not have that property. Its signing
algorithm uses structured lattice secrets, masking vectors, Fiat-Shamir
challenges, hints, and rejection sampling. If validator outputs are naively
added together, the aggregate can leave the distribution and norm bounds that
standard ML-DSA verification and security arguments rely on.

That creates a practical L1 design problem:

- storing one ML-DSA signature per validator creates state and bandwidth
  growth with validator count;
- replacing signatures with a Merkle or bitfield proof compresses some data,
  but still leaves consensus and state-transition complexity;
- emitting one flat ML-DSA-65 signature would be operationally ideal, but only
  if the multi-party signing process preserves the same accepted-signature
  distribution and verification semantics as ordinary ML-DSA-65.

The thesis explored here is that a threshold or interactive ML-DSA-65 protocol
can compress a validator quorum into one standard ML-DSA-65 signature, but only
if the protocol proves five hard properties:

1. aggregate masks match or closely approximate centralized ML-DSA masks;
2. aggregate rejection checks match centralized ML-DSA rejection checks;
3. selective aborts and retries do not bias accepted signatures;
4. every accepted partial contribution is sound, context-bound, and hiding
   enough for the chosen leakage model;
5. every unauthorized accepting aggregate output reduces to a base ML-DSA
   forgery or a named threshold-side assumption violation.

## The Solution Direction

This repository builds the artifact boundary for that thesis. It does not claim
the full thesis is proven. It provides the Rust crate structure, hazmat
ML-DSA-65 experimentation path, async protocol scaffold, reproducible telemetry,
and proof-route documentation needed to evaluate the construction rigorously.

At a high level, the proposed system is:

```text
Validator set for epoch E
  -> DKG/VSS or ideal setup for one epoch public key
  -> per-block threshold signing session
  -> prechallenge masking commitments
  -> challenge bound to canonical transcript
  -> proof-bound partial contribution exchange
  -> aggregate rejection and standard ML-DSA-65 verification checks
  -> one standard-size ML-DSA-65 signature in the block header
```

The operational target is backward-compatible verification: a verifier should
check the final block signature against the epoch threshold public key with the
standard ML-DSA-65 verification path. The verifier should not need to know that
the signature came from a threshold execution.

## What Is Implemented

The crate currently includes:

- typed signing-session and aggregation boundaries for threshold-style flows;
- simulated backend paths for deterministic protocol testing;
- feature-gated `hazmat-real-mldsa` ML-DSA-65 internals, KAT-style fixtures,
  differential checks, threshold bridge tests, and standard-verifying hazmat
  signing paths for controlled experiments;
- VSS and interpolation scaffolding, plus production-policy gates that reject
  scaffold backend families for production-labeled configuration;
- async actor and wire-format adapters for in-memory P2P simulations,
  malformed-frame handling, retry telemetry, and evidence-shaped artifacts;
- deterministic Section V-style exporters for reproducible benchmark tables,
  transcript artifacts, and sample bundles;
- proof-route worksheets and manifest tests that keep the claim boundary
  explicit as the project evolves.

## Theoretical Underpinnings

The proof package is organized around a real/ideal and hybrid proof surface:

- [Formal security theorem](docs/cryptography/formal-security-theorem.md)
  defines the target threshold ML-DSA security statements and explicitly marks
  them as not yet proved.
- [Proof closure ledger](docs/cryptography/proof-closure-ledger.md)
  indexes the current status, evidence route, and closure requirement for each
  visible advantage term.
- [FST-T1-IdealVSS theorem consolidation](docs/cryptography/fst-t1-idealvss-theorem.md)
  gathers the immediate IdealVSS signing-side theorem target into one
  conservative statement, with ideal `F_VSS_DKG` and `F_CONTRIB` boundaries
  kept explicit.
- [Epsilon residual ledger final form](docs/cryptography/epsilon-residual-ledger-final-form.md)
  normalizes the publication-facing advantage terms, rejection expansion, and
  classifier expansion without claiming those terms are closed.
- [Proof gap priority map](docs/cryptography/proof-gap-priority-map.md)
  orders the remaining proof, production-realization, and audit blockers.
- [Ideal functionality](docs/cryptography/ideal-functionality.md) and
  [real/ideal simulator skeleton](docs/cryptography/real-ideal-simulator.md)
  define how DKG, signing, aborts, evidence, and releases should map into an
  ideal threshold signing functionality.
- [Rejection-sampling bounds worksheet](docs/cryptography/rejection-sampling-bounds.md)
  decomposes accepted-distribution loss into visible terms.
- [Mask distribution equivalence](docs/cryptography/mask-distribution-equivalence.md)
  tracks `eps_mask`, the distance between aggregate threshold masks and
  centralized ML-DSA-65 masks.
- [Rejection predicate equivalence](docs/cryptography/rejection-predicate-equivalence.md)
  tracks `eps_rej`, the gap between aggregate and centralized rejection
  predicates over the same candidate values.
- [Withholding and abort bound](docs/cryptography/withholding-abort-bound.md)
  tracks `eps_withhold`, the selective-abort, retry, timeout, and observable
  abort-label route.
- [Contribution soundness relation](docs/cryptography/contribution-soundness-relation.md)
  and [contribution backend instantiation](docs/cryptography/contribution-backend-instantiation.md)
  track `eps_contrib`, the future production proof or MPC relation for partial
  contribution validity and hiding.
- [Unauthorized output classifier closure](docs/cryptography/unauthorized-output-classifier-closure.md)
  tracks `eps_classify`, the remaining route for mapping every unauthorized
  accepting output to a base ML-DSA forgery or a threshold-side assumption
  violation.

The current top-level advantage shape is intentionally conservative:

```text
Adv_threshold
  <= Adv_MLDSA
   + eps_vss
   + eps_mask
   + eps_commit
   + eps_ro
   + eps_rej
   + eps_withhold
   + eps_contrib
   + eps_classify
   + implementation/audit residuals
```

The repository is valuable precisely because it keeps those terms visible. It
does not collapse them into a security claim before the required proofs exist.

## Operational Underpinnings

The intended L1 integration model is epoch based:

- at epoch transition, validators run DKG/VSS or a future production setup
  protocol to derive one epoch threshold public key;
- during block production, the proposer or aggregator coordinates a threshold
  signing session over authenticated P2P channels;
- validators commit to masking material before the challenge is derived;
- validators return proof-bound partial contribution frames after the challenge;
- the aggregator accepts a threshold-valid set, performs aggregate rejection
  checks, and emits one standard-size ML-DSA-65 signature;
- the state transition verifies only the flat signature against the epoch key,
  avoiding validator-count signature state growth.

The repository models this operational path with actor simulations, wire
messages, telemetry, malformed-frame evidence, retry behavior, and deterministic
benchmark artifacts. These are engineering and reproducibility evidence, not
cryptographic proof of production network liveness or production slashing
soundness.

## Current Status

In practical terms, this is a publishable research scaffold with strong
reproducibility and review boundaries. It is not yet a cryptographically proven
threshold ML-DSA-65 construction.

Completed artifact layers:

- Rust crate API boundaries, simulated flows, actor/wire adapters, and
  Section V artifact generation;
- feature-gated hazmat ML-DSA-65 internals for controlled conformance and
  threshold-bridge experiments;
- formal theorem targets, ideal functionality, simulator skeletons,
  random-oracle domains, adversary models, correctness lemmas, and a
  proof-to-code crosswalk;
- dedicated closure routes for `eps_mask`, `eps_rej`, `eps_withhold`,
  `eps_contrib`, and `eps_classify`;
- a proof closure ledger that keeps every visible theorem-loss term mapped to
  its current status, evidence route, and remaining closure requirement;
- central IdealVSS theorem consolidation, final-form epsilon ledger, and
  proof-gap priority map for reviewer-facing proof closure work;
- fail-closed production policy gates for scaffold VSS and contribution proof
  backend declarations.

Open proof layers:

- malicious-secure DKG/VSS or a reviewed production realization of the ideal
  `F_VSS_DKG` setup route;
- production contribution proof soundness and witness hiding;
- accepted-distribution proof for aggregate masks, rejection sampling, retries,
  and selective aborts;
- final unauthorized-output classifier proof with `eps_cls_unmapped = 0`;
- side-channel review, constant-time audit, randomness review, external
  cryptographic review, and production operational review.

## Warning

This repository is a publishable research artifact scaffold. It is not
production-ready, not an audited implementation, and not a security proof for
threshold ML-DSA-65. The current code and tests provide engineering evidence for
the documented artifact boundary only. Production security still depends on the
open proof, backend replacement, audit, side-channel, and external review work
tracked in the linked proof obligations.

Those obligations include malicious-secure DKG, contribution proof soundness,
rejection-sampling distribution preservation, selective-abort bounds,
side-channel review, and external cryptographic review.

## Quickstart

Run from the repository root:

```bash
export CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target
export CARGO_INCREMENTAL=0

scripts/reproduce-section-v.sh
```

The reproduction script regenerates Section V output into a temporary file,
checks the checked-in sample bundle checksum, runs artifact verifier tests, and
prints a digest for the regenerated output.

Useful local checks:

```bash
cargo fmt --check
cargo clippy -j1 --all-targets --all-features -- -D warnings
cargo test -j1 --all-features
```

## Review Map

- [Reviewer quickstart](docs/paper/reviewer-quickstart.md)
- [Proof closure ledger](docs/cryptography/proof-closure-ledger.md)
- [FST-T1-IdealVSS theorem consolidation](docs/cryptography/fst-t1-idealvss-theorem.md)
- [Epsilon residual ledger final form](docs/cryptography/epsilon-residual-ledger-final-form.md)
- [Proof gap priority map](docs/cryptography/proof-gap-priority-map.md)
- [Claims matrix](docs/cryptography/claims-matrix.md)
- [Audit packet](docs/audit/README.md)
- [Proof obligations](docs/cryptography/proof-obligations.md)
- [Formal security theorem](docs/cryptography/formal-security-theorem.md)
- [Ideal functionality](docs/cryptography/ideal-functionality.md)
- [Real/ideal simulator skeleton](docs/cryptography/real-ideal-simulator.md)
- [Rejection-sampling bounds worksheet](docs/cryptography/rejection-sampling-bounds.md)
- [Mask distribution equivalence](docs/cryptography/mask-distribution-equivalence.md)
- [Rejection predicate equivalence](docs/cryptography/rejection-predicate-equivalence.md)
- [Withholding and abort bound](docs/cryptography/withholding-abort-bound.md)
- [Contribution soundness relation](docs/cryptography/contribution-soundness-relation.md)
- [Contribution backend instantiation](docs/cryptography/contribution-backend-instantiation.md)
- [Unauthorized output classifier closure](docs/cryptography/unauthorized-output-classifier-closure.md)
- [Reproducibility manifest](docs/benchmarks/reproducibility-manifest.md)
- [Section V sample bundle](docs/benchmarks/artifacts/section-v-sample-output.txt)
- [Section V sample checksum](docs/benchmarks/artifacts/SHA256SUMS)

## Feature Gates

- `hazmat-real-mldsa`: enables the local hazmat ML-DSA-65 backend used for
  experiments, verifier-compatibility checks, actor simulations, and Section V
  artifact generation. This is implementation evidence only and is not a
  production cryptographic module or FIPS validation claim.
- `experimental-vss`: enables experimental VSS complaint-evidence artifacts and
  structural checks. These artifacts are research scaffolding only and are not a
  production VSS relation proof, malicious-secure DKG, or production slashing
  mechanism.

## Artifact Boundary

The supported claim is narrow: this repository demonstrates a reproducible Rust
research scaffold with feature-gated hazmat ML-DSA-65 conformance paths,
deterministic simulations, transcript artifacts, evidence-shaping paths, and
fail-closed production policy boundaries. The formal documents now also define
the theorem targets, idealized setup boundary, rejection-sampling closure
routes, contribution-proof replacement relation, and remaining reduction gaps.

Do not describe the current artifact as a secure, production-ready,
malicious-secure threshold ML-DSA-65 signature scheme.

## Remaining Cryptographic Gaps

The next work is theorem closure, not more scaffold construction:

- lock the production transcript grammar in
  [production-transcript-grammar.md](docs/cryptography/production-transcript-grammar.md)
  so random-oracle, contribution, evidence, and classifier proofs share one
  canonical byte-level input language;
- turn the IdealVSS route into lemma-by-lemma proof text using
  [idealvss-lemma-skeleton.md](docs/cryptography/idealvss-lemma-skeleton.md);
- close the early IdealVSS lemma worksheets for
  [FST-L1 transcript injectivity](docs/cryptography/fst-l1-transcript-injectivity.md),
  [FST-L2 challenge binding](docs/cryptography/fst-l2-challenge-binding.md),
  and [FST-L3 collection soundness](docs/cryptography/fst-l3-collection-soundness.md);
- close the middle IdealVSS lemma worksheets for
  [FST-L4 partial-share validity](docs/cryptography/fst-l4-partial-share-validity.md),
  [FST-L5 aggregation correctness](docs/cryptography/fst-l5-aggregation-correctness.md),
  and [FST-L6 no subthreshold signing](docs/cryptography/fst-l6-no-subthreshold-signing.md);
- close abort and classifier worksheets for
  [FST-L7 abort compatibility](docs/cryptography/fst-l7-abort-compatibility.md)
  and [FST-L10 classifier closure](docs/cryptography/fst-l10-classifier-closure.md);
- use the immediate
  [contribution backend decision record](docs/cryptography/contribution-backend-decision-record.md)
  to keep `F_CONTRIB` idealized until a concrete backend theorem is selected;
- prove or explicitly bound `eps_mask` for the aggregate threshold mask
  distribution using the route in
  [rejection-sampling-closure-plan.md](docs/cryptography/rejection-sampling-closure-plan.md)
  and
  [mask-distribution-equivalence.md](docs/cryptography/mask-distribution-equivalence.md);
- prove or explicitly bound `eps_rej` by showing threshold aggregate rejection
  matches standard ML-DSA-65 rejection on the same candidate values using the
  [rejection-sampling closure plan](docs/cryptography/rejection-sampling-closure-plan.md);
- prove or explicitly bound `eps_withhold` for selective aborts, timeout
  behavior, retries, and observable abort labels using the route in
  [rejection-sampling-closure-plan.md](docs/cryptography/rejection-sampling-closure-plan.md)
  and [withholding-abort-bound.md](docs/cryptography/withholding-abort-bound.md);
- instantiate the production contribution proof or MPC relation described in
  [contribution-backend-selection.md](docs/cryptography/contribution-backend-selection.md),
  [contribution-soundness-relation.md](docs/cryptography/contribution-soundness-relation.md),
  and
  [contribution-backend-instantiation.md](docs/cryptography/contribution-backend-instantiation.md);
- eliminate `eps_classify` by mapping every unauthorized accepting output to
  either a base ML-DSA forgery or a named threshold-side assumption violation
  using
  [unauthorized-output-classifier-elimination.md](docs/cryptography/unauthorized-output-classifier-elimination.md)
  and
  [unauthorized-output-classifier-closure.md](docs/cryptography/unauthorized-output-classifier-closure.md).
