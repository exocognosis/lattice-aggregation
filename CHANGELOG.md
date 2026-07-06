# Changelog

All notable research-artifact packaging changes are tracked here. This project
is a research scaffold; entries describe documentation, packaging, and evidence
changes, not production cryptographic guarantees.

## v0.2.0-research-preview - Grant Readiness + Ethereum/PQ Alignment

Research-preview milestone. This release marks the point where the grant-readiness
materials, Ethereum/post-quantum alignment, and reproducible evidence boundaries
are in place. It is a documentation and packaging milestone only; no hypothesis
criterion is closed and the artifact is not production-ready.

### Added

- Grant-readiness materials: one-page executive summary (`docs/grant/one-pager.md`),
  `.github/FUNDING.yml`, `AUTHORS.md`, a top-level "Grant & Collaboration" section,
  and status badges in the README.
- "Alignment with Ethereum Post-Quantum Priorities" README section positioning the
  work as complementary to the hash-based + SNARK aggregation path, with a
  conservative, research-stage framing.
- "Path to Full Hypothesis Closure" README subsection mapping each of the five
  hypothesis criteria to concrete next steps, effort estimate, open obligations,
  and controlling evidence docs.
- Mermaid protocol-flow diagram with marked security boundaries in the README and
  a standalone `docs/assets/protocol-flow.md` mapping each Epsilon Residual Ledger
  boundary to its closure criterion and evidence docs.
- Release Tag readiness confirmation for `v0.2.0-research-preview` with the
  canonical tagging commands.

### Pre-Tag Verification (on the release commit)

The `v0.2.0-research-preview` tag is created only after this work merges to
`main`; the checks below pass on the release commit and are the gate for tagging:

- `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  and `cargo test --all-features` (including the documentation manifest tests) pass.
- `python3 -m unittest script_tests.test_assess_lattice_hypothesis` passes, and
  `scripts/assess_lattice_hypothesis.py` reports `partially_proven` with all five
  criteria `partially_met`.

### Still Open (unchanged by this release)

- No hypothesis criterion is fully proven; no production threshold backend is
  selected; no side-channel audit, FIPS/CAVP validation, or external cryptographic
  review is complete.

## v0.1.0

Historical protocol-conformance tag.
