# Authors & Maintainers

## Maintainer

**Rick Glenn** — project lead and maintainer.

- GitHub: [`exocognosis`](https://github.com/exocognosis)
- Contact: rick@dytallix.com

Rick maintains `lattice-aggregation`, an audit-first research effort studying
whether a post-quantum validator quorum can be compressed into one
standard-size ML-DSA-65 (FIPS 204) signature without changing the verifier. The
project is run with an explicit research-stage boundary: every security-loss
boundary is enumerated as an "Epsilon Residual Ledger" and tracked, per
criterion, in the [Cryptographic Claims Matrix](docs/cryptography/claims-matrix.md)
and the [Hypothesis Closure Requirements](README.md#hypothesis-closure-requirements)
rather than collapsed into a premature claim.

## Collaboration

We welcome contributors and reviewers, especially from cryptography and
post-quantum research groups (Ethereum Foundation / ESP, PQCA / Open Quantum
Safe, and academic teams).

- Start with the [Reviewer Entry Points](README.md#reviewer-entry-points) and the
  [Audit Packet](docs/audit/README.md).
- For funding or partnership, see the
  [one-page executive summary](docs/grant/one-pager.md) and
  [FUNDING.yml](.github/FUNDING.yml).
- For contribution guidelines and security reporting, see
  [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Acknowledgements

This work builds on the FIPS 204 ML-DSA-65 standard and the broader
post-quantum signature and threshold-cryptography literature referenced in the
[cryptography notes](docs/cryptography/README.md).
