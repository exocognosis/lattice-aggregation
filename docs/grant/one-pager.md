# lattice-aggregation — Executive Summary

**Tagline:** A rigorously bounded, audit-first research effort toward turning a
post-quantum validator quorum into **one standard-size ML-DSA-65 signature** that
an unmodified verifier accepts.

> Status: research preview (`v0.2.0-research-preview`). This is a pre-proof
> research scaffold, not a security claim or production system. The latest
> hypothesis assessment reports `partially_proven`, with all five criteria
> `partially_met`.

---

## Problem

Post-quantum validator sets cannot reuse BLS-style algebraic signature
aggregation: ML-DSA (FIPS 204) signatures do not compose, so naively combining
them leaves the distribution and norm bounds that standard verification relies
on. That forces L1s to either store one large ML-DSA signature per validator
(`O(N)` state and bandwidth growth) or add a separate proof system to the
consensus-critical verification path. Neither preserves the operational
ergonomics that made BLS aggregation attractive.

## Solution & Unique Value

We study an **interactive / threshold ML-DSA-65 protocol** whose *design target*
is a single standard ML-DSA-65 signature (approximately 3.3 KB) against an epoch
threshold public key — so that, if the theorem obligations close, a verifier
would run the unmodified, standardized verification path once, independent of
validator count (`O(1)` in the quorum size). None of this is achieved today; it
is the target the five criteria gate.

What makes this effort distinctive for reviewers:

- **Native-signature aggregation, no verifier fork.** The aggregate is a normal
  ML-DSA-65 signature; no SNARK/STARK verifier enters the signature check.
- **Epsilon Residual Ledger.** The framework models five security boundaries
  (transcript/challenge binding, mask/rejection residuals, key-share isolation,
  selective-abort bias, and byte-level verifier compatibility) that must be
  isolated before any production claim — enumerated in the README and tracked,
  per criterion, in the [Cryptographic Claims Matrix](../cryptography/claims-matrix.md)
  and the [thesis operating parameters](../cryptography/thesis-operating-parameters.md).
  Reviewers see exactly what is assumed, what is open, and what closing it would
  require — no hidden gaps.
- **Fail-closed honesty.** Production-labeled configurations reject scaffold
  backends in code, so research machinery cannot masquerade as production
  security.
- **Reproducible evidence.** A single assessment command
  (`scripts/assess_lattice_hypothesis.py`) regenerates the closure verdict, and
  the documentation manifest test validates reviewer-facing links and anchors.

## Current Status & Evidence

A publishable Rust research scaffold with a strong review boundary:

- Type-state signing-session / aggregation API, deterministic simulation
  backend with ML-DSA-65-sized outputs, async actor/wire adapters, and an
  opt-in `hazmat-real-mldsa` provider with a bounded NIST ACVP/FIPS204 sample
  fixture.
- Five-criterion evidence gates with closure-package frameworks, a Criterion 2
  proof-substance payload, and fixture-backed conformance gates.
- Verification passes on the tagged commit: `cargo fmt --all -- --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --all-features`, the documentation manifest tests, and
  `scripts/assess_lattice_hypothesis.py` (reports `partially_proven`).

Honest boundary: **no criterion is fully proven**, no production threshold
backend is selected, and there is no side-channel audit, FIPS/CAVP validation,
or external cryptographic review yet. The artifact is engineering and
proof-route evidence, not a proven construction. See the
[Cryptographic Claims Matrix](../cryptography/claims-matrix.md) and the
[Hypothesis Closure Requirements](../../README.md#hypothesis-closure-requirements).

## Ethereum / Post-Quantum Alignment

The Ethereum post-quantum roadmap ([pq.ethereum.org](https://pq.ethereum.org))
and the lean-consensus effort make quantum-resistant attestation aggregation a
first-order priority. This work is **complementary** to the hash-based +
SNARK aggregation path (e.g. `leanMultisig`-style succinct proofs over
hash-based signatures): instead of proving a batch of signatures inside a proof
system, it would produce one native ML-DSA-65 signature with an `O(1)`, standard
verification footprint if the theorem and backend obligations close. A robust PQ
roadmap benefits from evaluating both, and
this effort delivers a rigorously bounded read on the native-signature option.
See [Alignment with Ethereum Post-Quantum Priorities](../../README.md#alignment-with-ethereum-post-quantum-priorities).

## Proposed Grant Scope

Milestones are independently reviewable; each ends with a written, externally
checkable deliverable. (Estimates are planning-grade for an experienced
cryptographer.)

| # | Milestone | Key deliverables | Est. |
| --- | --- | --- | --- |
| M1 | **Mask & rejection distribution closure** | `epsilon_mask` Renyi-divergence evidence and a real (not fixture) aggregate-rejection recomputation closing the Criterion 2 payload | 4–6 mo |
| M2 | **Abort-bias & partial-soundness closure** | Concrete retry/timeout policy with an accepted-sample bound; production local-acceptance / partial-verification predicates with soundness and hiding evidence (partial soundness is the long pole) | 6–12 mo |
| M3 | **Unforgeability reduction & theorem assembly** | Completed per-case reductions and a threshold EUF-CMA reduction to base ML-DSA forgery or a named threshold assumption; assessment verdict moves beyond `partially_proven` | 3–5 mo |
| M4 | **Comparative evaluation & reference spec** | Apples-to-apples comparison vs. hash-based + SNARK aggregation (verification cost, liveness, trust, audit surface); reference Rust protocol spec + conformance suite | 2–3 mo |
| M5 | **External review & audit prep** | Independent cryptographic review of M1–M3; side-channel/randomness review scope; malicious-secure DKG realization plan | 3–4 mo |

M1–M3 are the criterion-closing milestones (mapping to the five
[Hypothesis Closure Requirements](../../README.md#hypothesis-closure-requirements));
M4 and M5 are complementary deliverables that run alongside and after M1–M3, not
additional closure criteria.

## Team / Contact

- **Maintainer:** Rick Glenn (GitHub: [`exocognosis`](https://github.com/exocognosis))
- **Repository:** <https://github.com/exocognosis/lattice-aggregation>
- **Contact:** rick@dytallixcom

We welcome co-maintainers and reviewers from cryptography and post-quantum
research groups. See [AUTHORS.md](../../AUTHORS.md).

## Impact & Why Now

- **Now:** ML-DSA-65 is standardized (FIPS 204) and Ethereum's PQ migration is
  actively choosing its attestation-aggregation strategy. The native-signature
  option deserves a rigorous, bounded evaluation before that choice hardens.
- **Impact even if the answer is "prefer SNARKs":** the effort surfaces exactly
  which assumptions (mask-distribution preservation, selective-abort bounds,
  malicious-secure DKG) gate *any* native PQ signature aggregator — directly
  useful to the roadmap.
- **Leverage:** the proof-route scaffolding, reproducible assessment, five-criterion
  evidence gates, and fail-closed release boundaries already exist, so grant
  funding goes to closing the criteria and external review rather than to
  rebuilding infrastructure.
