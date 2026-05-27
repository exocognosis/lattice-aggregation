# Final Archive Manifest

Date: 2026-05-27

## Purpose

This manifest defines the expected contents and final checks for the paper
artifact archive. It is an archive-packaging checklist for a research scaffold,
not a production release procedure.

The artifact remains a research scaffold. It is not production-ready, and it is
not a security proof boundary for threshold ML-DSA-65. Production security
claims remain blocked by the open obligations in
[../cryptography/proof-obligations.md](../cryptography/proof-obligations.md)
and the claim boundaries in
[../cryptography/claims-matrix.md](../cryptography/claims-matrix.md).

## Expected Archive Contents

The final archive should preserve the repository layout and include these files
and directories at minimum:

Paper-facing docs:

- [artifact-overview.md](artifact-overview.md)
- [evaluation-appendix.md](evaluation-appendix.md)
- [limitations.md](limitations.md)
- [reviewer-quickstart.md](reviewer-quickstart.md)
- [release-checklist.md](release-checklist.md)
- [archive-manifest.md](archive-manifest.md)

Evidence and boundary docs:

- [../cryptography/claims-matrix.md](../cryptography/claims-matrix.md)
- [../cryptography/proof-obligations.md](../cryptography/proof-obligations.md)
- [../audit/README.md](../audit/README.md)
- [../benchmarks/reproducibility-manifest.md](../benchmarks/reproducibility-manifest.md)

Section V sample bundle:

- [../benchmarks/artifacts/section-v-sample-output.txt](../benchmarks/artifacts/section-v-sample-output.txt)
- [../benchmarks/artifacts/SHA256SUMS](../benchmarks/artifacts/SHA256SUMS)

Reproduction entry point:

- [../../scripts/reproduce-section-v.sh](../../scripts/reproduce-section-v.sh)

Repository source directories required by the reproduction script and Cargo
checks should be included with their current paths, including:

- `src/`
- `tests/`
- `benches/` if present
- `examples/` if present
- `scripts/`
- `docs/`
- `Cargo.toml`
- `Cargo.lock`

## Final Commit Hash

Do not hardcode the final commit hash in this manifest. At archive creation
time, run:

```bash
git rev-parse HEAD
```

Record that output in the submitted archive notes, camera-ready artifact notes,
or external release metadata that accompanies the packaged source archive.

## Required Verification Commands

Run from the repository root:

```bash
export CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target
export CARGO_INCREMENTAL=0

scripts/reproduce-section-v.sh
cargo fmt --check
cargo clippy -j1 --all-targets --all-features -- -D warnings
cargo test -j1 --all-features
git status --short
git rev-parse HEAD
```

`git status --short` should be empty immediately before packaging, except for
intentional archive-note files that are excluded from the source archive by
policy. The `git rev-parse HEAD` output is the final commit identifier to
record with the archive.

## Section V Checksum Instructions

The checked-in Section V sample bundle is:

```text
docs/benchmarks/artifacts/section-v-sample-output.txt
docs/benchmarks/artifacts/SHA256SUMS
```

Validate the checked-in sample bundle with:

```bash
cd docs/benchmarks/artifacts
shasum -a 256 -c SHA256SUMS
cd ../../..
```

The reproduction script also validates this checksum as part of:

```bash
scripts/reproduce-section-v.sh
```

To refresh the checked-in Section V sample bundle intentionally, use:

```bash
REFRESH_SECTION_V_SAMPLE=1 scripts/reproduce-section-v.sh
```

Only refresh the sample bundle when the benchmark artifact format or expected
fixture content changes intentionally. After refresh, rerun the required
verification commands and record the resulting commit hash with
`git rev-parse HEAD`.

## Generated Output Locations

By default, `scripts/reproduce-section-v.sh` writes regenerated Section V output
to:

```text
/tmp/dytallix-section-v-sample-output.txt
```

The required verification command block sets Cargo build output to:

```text
/tmp/dytallix-pq-threshold-target
```

Use `SECTION_V_OUTPUT` to choose a different temporary output location without
changing checked-in artifacts:

```bash
SECTION_V_OUTPUT=/tmp/section-v-output.txt scripts/reproduce-section-v.sh
```

The script prints the SHA-256 digest of the regenerated output file. That digest
is useful for reviewer notes, but benchmark timing values are machine-dependent
and are not expected to match the checked-in sample byte-for-byte unless the
sample is refreshed explicitly.

When `REFRESH_SECTION_V_SAMPLE=1` is set, the script updates:

```text
docs/benchmarks/artifacts/section-v-sample-output.txt
docs/benchmarks/artifacts/SHA256SUMS
```

## Archive Boundary Statement

Include this boundary statement in the archive notes:

```text
This artifact is a reproducible Rust research scaffold for threshold-style
ML-DSA-65 protocol integration. It is not production-ready, not externally
audited, and not a security proof boundary for threshold ML-DSA-65.
```

Do not describe the archive as production-ready, malicious-secure, audited,
side-channel safe, FIPS validated, or a complete cryptographic proof.
