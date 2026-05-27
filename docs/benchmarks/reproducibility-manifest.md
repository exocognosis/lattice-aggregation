# Reproducibility Manifest

Date: 2026-05-26

## Purpose

This manifest is the paper-facing index for reproducing the current
`dytallix-pq-threshold` research artifact. It enumerates the supported command
paths, feature combinations, generated artifact sections, and claim boundaries
for Section V evaluation.

The manifest separates engineering evidence from security proof obligations.
Engineering evidence means deterministic tests, benchmark runs, transcript
artifacts, and policy-gate checks that can be reproduced from this repository.
Security proof obligations are the mathematical reductions, production DKG,
production contribution proof relation, side-channel review, and external
cryptographic review still required before making production-security claims.

## Workspace Assumptions

Run all commands from the crate root containing `Cargo.toml`. In the current
local workspace this is:

```text
/Users/rickglenn/Library/Mobile Documents/com~apple~CloudDocs/Desktop/ML-DSA Lattice Aggregator
```

Use the isolated target directory in all manuscript-reproduction commands:

```bash
export CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target
export CARGO_INCREMENTAL=0
```

The workspace is currently not a Git repository in this local folder. If a
release artifact is archived later, include a source tarball digest or commit
hash from the canonical repository in the camera-ready appendix.

## Feature Matrix

| Feature set | Purpose | Main commands |
| --- | --- | --- |
| default (`simulated`) | Type-state, adapter scaffold, simulated backend, production policy guards | `cargo test -j1 --test simulation --test simulated_flow --test production_policy` |
| `--no-default-features` | Proves core library and policy gates do not depend on default simulation feature leakage | `cargo clippy -j1 --no-default-features --lib --test production_policy --test contribution_proof -- -D warnings` |
| `--features experimental-vss` | Experimental VSS statement/opening/proof and complaint-evidence structural checks | `cargo test -j1 --features experimental-vss --test dkg_vss_soundness --test production_policy` |
| `--features hazmat-real-mldsa` | Local ML-DSA-65 hazmat backend, actor simulation grid, transcript artifacts | `cargo run -j1 --features hazmat-real-mldsa` |
| `--features hazmat-real-mldsa,experimental-vss` | Hazmat benchmark path plus experimental VSS complaint-evidence artifacts | `cargo run -j1 --features hazmat-real-mldsa,experimental-vss` |

## Canonical Evaluation Commands

One-command Section V reproduction path:

```bash
scripts/reproduce-section-v.sh
```

This command regenerates the Section V artifact stream into a temporary file,
checks the checked-in sample bundle SHA-256 sidecar, runs the artifact verifier
tests, and prints the digest of the regenerated output. To intentionally refresh
the checked-in sample bundle and sidecar, run:

```bash
REFRESH_SECTION_V_SAMPLE=1 scripts/reproduce-section-v.sh
```

Default scaffold and production-policy smoke path:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 \
  --test simulation \
  --test simulated_flow \
  --test contribution_proof \
  --test production_policy
```

Experimental VSS and combined production policy path:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features experimental-vss \
  --test dkg_vss_soundness \
  --test production_policy
```

Hazmat ML-DSA-65 Section V benchmark runner:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo run -j1 --features hazmat-real-mldsa
```

Hazmat benchmark runner with experimental complaint artifacts:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo run -j1 --features hazmat-real-mldsa,experimental-vss
```

Refresh the frozen sample Section V bundle:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo run -j1 --features hazmat-real-mldsa,experimental-vss \
  > docs/benchmarks/artifacts/section-v-sample-output.txt
```

Current sample bundle checksum:

```text
c12c09b7c526b71e82d9a7b1a38b97c7232be4e39467f98d448ef338bbaac972  docs/benchmarks/artifacts/section-v-sample-output.txt
```

The checksum sidecar is stored at
`docs/benchmarks/artifacts/SHA256SUMS`.
Validate the checked-in fixture from `docs/benchmarks/artifacts` with:

```bash
shasum -a 256 -c SHA256SUMS
```

The checked-in sample bundle is a structural publication fixture. Its exact
latency values are machine-dependent; tests assert artifact sections, headers,
profile labels, complaint-evidence presence, and the fixture checksum rather
than treating freshly regenerated benchmark timings as bit-stable constants.

Focused hazmat benchmark regression:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa \
  --test hazmat_mldsa65_simulation_grid
```

Focused hazmat benchmark regression with complaint artifacts:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa,experimental-vss \
  --test hazmat_mldsa65_simulation_grid
```

Hazmat wire, proof-bound contribution, and evidence path:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa,experimental-vss \
  --test hazmat_mldsa65_wire
```

Deterministic fuzz/property regression:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa \
  --test hazmat_mldsa65_fuzzing \
  --test hazmat_mldsa65_hardening
```

KAT and differential verification path:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa \
  --test hazmat_mldsa65_kat \
  --test hazmat_mldsa65_differential
```

Focused clippy path for the current production-policy and proof boundaries:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo clippy -j1 --features experimental-vss \
  --lib \
  --test production_policy \
  --test contribution_proof \
  --test dkg_vss_soundness \
  -- -D warnings
```

No-default-feature clippy path:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo clippy -j1 --no-default-features \
  --lib \
  --test production_policy \
  --test contribution_proof \
  -- -D warnings
```

Type-state compile-fail check:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --test type_state -- --skip invalid_signing_state_calls_do_not_compile

TYPE_STATE_BIN=$(find /tmp/dytallix-pq-threshold-target/debug/deps \
  -maxdepth 1 -type f -perm +111 -name 'type_state-*' -print \
  | xargs ls -t | head -1)

"$TYPE_STATE_BIN" --exact invalid_signing_state_calls_do_not_compile --nocapture
```

## Generated Artifact Sections

`cargo run -j1 --features hazmat-real-mldsa` prints these sections for each
benchmark profile:

```text
===== <profile label>: LaTeX =====
===== <profile label>: PGFPlots CSV =====
===== <profile label>: Transcript JSONL =====
===== <profile label>: Transcript CSV =====
```

`cargo run -j1 --features hazmat-real-mldsa,experimental-vss` may also print
these sections when a profile emits complaint evidence:

```text
===== <profile label>: Experimental VSS Complaint JSONL =====
===== <profile label>: Experimental VSS Complaint CSV =====
```

PGFPlots CSV header:

```text
session_id,duration_ms,aborts,bandwidth_bytes
```

Transcript CSV header:

```text
experiment,trial,attempt,direction,round,validator_index,block_height,session_id,encoded_len,frame_digest,production_statement_digest
```

Experimental VSS complaint CSV header:

```text
experiment,trial,validator_index,evidence_kind,session_id,evidence_len,evidence_digest,production_vss_relation_statement_digest,evidence_hex
```

The transcript and complaint exporters verify their generated artifacts before
printing them. Complaint evidence remains structural evidence only; it does not
prove the VSS relation and is not a production slashing transaction.

## Experiment Profiles

The Section V runner emits three deterministic profiles:

```text
Small-Scale Consensus
N = 3
t = 2
network = ideal local mesh
byzantine mode = none

Mid-Scale Distributed Fabric
N = 7
t = 5
network = bounded distributed-fabric latency
byzantine mode = malformed secret contribution

Adversarial WAN Cluster
N = 15
t = 10
network = bounded WAN latency and deterministic retry pressure
byzantine mode = none
```

Latency values are wall-clock measurements and vary by local machine load.
Validator counts, thresholds, event ordering constraints, artifact schemas, and
retry models are deterministic.

The `hazmat-real-mldsa` runner also emits one baseline comparison CSV before
the per-profile artifacts. Each row joins a threshold trial to an ordinary
single-signer ML-DSA-65 internal-`mu` signing and verification run:

```text
profile,validators,threshold,trial,baseline_sign_ns,baseline_verify_ns,
threshold_duration_ns,threshold_bytes,signature_bytes,latency_overhead_x
```

The baseline is an engineering comparison artifact. It supports overhead
measurement against ordinary ML-DSA-65 signing but is not security evidence.

## Engineering Evidence

The current repository supports these implementation claims:

- standard-size ML-DSA-65 public key and signature byte handling in the hazmat
  path
- standard verifier acceptance for tested hazmat signing paths
- deterministic actor simulations that finalize when an honest quorum remains
- transcript precommitment/opening ordering checks
- attributable malformed contribution evidence in simulation
- experimental VSS complaint artifact generation and structural verification
- fail-closed VSS, contribution-proof, and combined production policy gates
- public production-labeled actor configuration construction that rejects
  scaffold backend families
- deterministic replay artifacts for Section V tables and appendices

## Security Proof Obligations

The current repository does not establish:

- malicious-secure production DKG
- hiding/binding production VSS commitments
- zero-knowledge or MPC-sound contribution proof relations
- selective-abort resistance under a formal adversary
- adaptive security
- side-channel resistance
- production transport liveness
- production slashing validity
- FIPS validation or external certification

Those obligations are tracked in:

```text
docs/cryptography/security-model.md
docs/cryptography/formal-proof-scaffold.md
docs/cryptography/production-vss-backend.md
docs/cryptography/proof-bearing-contribution-boundary.md
docs/cryptography/claims-matrix.md
docs/cryptography/protocol-code-crosswalk.md
docs/benchmarks/release-readiness-checklist.md
```

## Manifest Maintenance Checklist

Before submitting or archiving a paper artifact:

- run the canonical evaluation commands listed above
- confirm the generated artifact sections match this manifest
- update `docs/benchmarks/section-v-results.md` if profile behavior changes
- update `docs/cryptography/claims-matrix.md` if and only if claim status
  changes
- include this manifest with any generated Section V output bundle
- preserve the distinction between engineering evidence and security proof
  obligations in manuscript wording
