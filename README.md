# lattice-aggregation

**Implementation-track repository for interactive threshold ML-DSA-65 signature aggregation**

**Goal**: Enable a large post-quantum validator quorum to jointly produce **one standard-size ML-DSA-65 signature** (3,309 bytes) that verifies using unmodified FIPS 204 code against a single epoch threshold public key.

Unlike BLS, native ML-DSA signatures do not aggregate. A naive migration creates severe signature bloat (tens of MB per block for large validator sets). This project explores a zero-compromise path: an interactive threshold protocol that preserves standard verification.

**Current status (v0.2.0)**: Closure-run implementation track

`partially_proven` — All five tracked hypothesis criteria are `partially_met`. Three foundation results have already been proved. The remaining cryptographic backend, proof, validation, and audit artifacts are tracked explicitly as run inputs.

## Protocol Overview

![Protocol Flow](docs/assets/lattice-aggregation-protocol-flow.png)

The diagram above shows the intended end-to-end flow, including epoch setup, threshold signing session, and the security boundaries tracked by the Epsilon Residual Ledger.

## Why This Matters

Post-quantum migration for proof-of-stake chains creates a difficult tradeoff: either limit validator participation or accept massive increases in signature state and bandwidth. A working native threshold solution would allow light clients, bridges, and hardware wallets to verify post-quantum consensus with standard ML-DSA code.

## What Exists Today

- Type-state Rust protocol with deterministic transcripts and commitment-before-challenge enforcement
- Reproducible evidence and hypothesis assessment tooling
- Explicit Epsilon Residual Ledger tracking the five open security boundaries
- Three proved foundation lemmas (transcript injectivity, subthreshold share privacy, conditional aggregation correctness)
- Grant-ready documentation and reviewer materials

## Quick Start – Reproduce Current Evidence

```bash
git clone https://github.com/exocognosis/lattice-aggregation.git
cd lattice-aggregation

cargo fmt --all -- --check
python3 scripts/assess_lattice_hypothesis.py --out artifacts/hypothesis/latest --offline
```

See the full reproduction commands and interpretation in the repository.

## Key Documents

- **Technical Whitepaper v0.2.0** (Problem formalization, proved lemmas, and Epsilon Residual Ledger)
  - [Direct Download](https://github.com/exocognosis/lattice-aggregation/releases/download/v0.2.0/ML-DSA_Lattice_Aggregator_v0.2.0.pdf)
- [One-page executive summary](docs/grant/one-pager.md)
- [Cryptographic Claims Matrix](docs/cryptography/claims-matrix.md)
- [Protocol flow diagram](docs/assets/lattice-aggregation-protocol-flow.png)
- [Hypothesis assessment script](scripts/assess_lattice_hypothesis.py)
- [Simulation Benchmark Results](docs/benchmarks/simulation-results.md)
- [Real-World Benchmark Protocol](docs/benchmarks/real-world-benchmark-protocol.md)

## Current Hypothesis Status

| Criterion | Status | What it guards |
| --- | --- | --- |
| εmask | `partially_met` | Aggregate masking distribution |
| εrej | `partially_met` | Rejection sampling equivalence |
| εwithhold | `partially_met` | No selective abort / retry bias |
| εcontrib | `partially_met` | Sound and hiding partial contributions |
| εclassify | `partially_met` | Unauthorized outputs reduce to base forgery |

Full details and open obligations: [docs/cryptography/](docs/cryptography/)

## For Reviewers and Collaborators

Fastest path to review:

1. Read the one-pager: [docs/grant/one-pager.md](docs/grant/one-pager.md)
2. Run the assessment script above.
3. Review the Claims Matrix: [docs/cryptography/claims-matrix.md](docs/cryptography/claims-matrix.md)

We welcome cryptographic review, especially on the remaining open epsilon terms. Contact information is in [AUTHORS.md](AUTHORS.md).

## Implementation Targets

The next backend and proof batches target:

- Full threshold ML-DSA construction evidence for the selected P1 direction
- Selected-backend implementation artifacts
- Standard-verifier compatibility evidence for aggregate signatures
- Security evidence that extends beyond the three proved foundation lemmas

## License

MIT

Repository maintained by Rick Glenn.

Seeking high-signal cryptographic collaboration and research funding to close the remaining hypothesis criteria.
