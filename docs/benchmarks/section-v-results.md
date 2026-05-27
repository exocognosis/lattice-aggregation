# Section V Results Summary

Date: 2026-05-25

## Scope

This note summarizes the current evaluation layer for the
`hazmat-real-mldsa` backend. It is intended as manuscript support text, not a
claim of production cryptographic security.

The evaluation covers deterministic in-memory actor runs over the local
ML-DSA-65 arithmetic boundary. It measures protocol completion, attributable
malformed contribution handling, flat standard signature output, and replayable
wire-transcript artifacts.

## Reproduction Command

Run from the crate root:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo run -j1 --features hazmat-real-mldsa
```

The runner emits, for each profile:

- a single-signer ML-DSA-65 baseline comparison CSV row per trial
- a LaTeX table for manuscript inclusion
- a PGFPlots CSV matrix for latency/abort/bandwidth plots
- newline-delimited JSON transcript records
- CSV transcript records
- when `experimental-vss` is enabled and Byzantine evidence is emitted,
  newline-delimited JSON and CSV complaint-evidence records

The runner verifies transcript artifacts before printing them.
With `experimental-vss`, it also verifies complaint-evidence artifacts before
printing them.

## Profiles

```text
Small-Scale Consensus
N = 3
t = 2
network = ideal local mesh
Byzantine behavior = none

Mid-Scale Distributed Fabric
N = 7
t = 5
network = bounded distributed-fabric latency
Byzantine behavior = malformed secret contribution

Adversarial WAN Cluster
N = 15
t = 10
network = bounded WAN latency and deterministic retry pressure
Byzantine behavior = none
```

## Artifact Guarantees

The transcript verifier checks:

- every artifact is non-empty
- every record uses a known direction and round label
- `session_id`, `frame_digest`, and populated production statement digest
  fields are canonical 32-byte hex strings
- fixed-size commitment frames have expected encoded lengths
- each experiment/trial/attempt binds to one session ID and block height
- each masking opening is immediately preceded by a matching masking
  precommitment
- each secret opening is immediately preceded by a matching challenge-bound
  secret precommitment

The snapshot test for the deterministic `N=3, t=2` profile additionally checks
that masking commitments, masking openings, secret commitments, and secret
openings have stable equal counts across completed attempts.

## Claims Supported By The Current Results

The current results support these implementation claims:

- the hazmat actor path can finalize standard-sized ML-DSA-65 signatures
- finalized signatures pass the standard internal-`mu` verification path
- each threshold trial can be joined to a deterministic ordinary ML-DSA-65
  single-signer baseline over the same internal `mu`
- malformed contribution payloads produce attributable evidence
- a round can still finalize when one malformed contribution appears but honest
  quorum remains
- transcript precommitment/opening order is mechanically auditable
- experimental VSS complaint-evidence frames are exported as canonical bytes
  and checked structurally in the benchmark artifact path
- Section V tables and plot inputs are regenerable from documented commands,
  with a checked-in sample fixture pinned by SHA-256

## Publication Claims Table

The current conformance boundary is publication-ready only for narrow
implementation claims. It is not a proof of secure threshold ML-DSA
aggregation.

| Claim area | What the current implementation shows | What it does not show |
| --- | --- | --- |
| Standard ML-DSA output shape | The `hazmat-real-mldsa` path emits standard-sized ML-DSA-65 public keys and signatures in tested paths, and finalized signatures pass the ordinary internal-`mu` verifier. | It does not prove that the threshold transcript has the same distribution as centralized ML-DSA-65 signing. |
| Actor protocol execution | Deterministic in-memory profiles exercise round progression, retry pressure, bandwidth accounting, and finalization when an honest quorum remains. | It does not establish production network liveness, authenticated transport safety, timeout adequacy, or consensus integration safety. |
| Transcript conformance | Wire frames are replayable; frame digests and production statement digests are exported; precommitment/opening order is mechanically checked. | Digest binding is not a cryptographic proof that each secret-dependent contribution is valid, hidden, or simulation-sound. |
| Malformed contribution attribution | Malformed contribution payloads can produce attributable evidence without forcing abort when honest quorum remains. | The evidence is not a production slashing proof and does not replace a sound contribution proof relation. |
| Experimental VSS evidence | With `experimental-vss`, complaint artifacts carry canonical bytes and production VSS relation statement digests for structural review. | The deterministic VSS scaffold is not malicious-secure DKG, does not verify a production VSS relation, and does not prove anti-framing or complaint soundness. |
| Production policy boundary | Production-labeled configuration paths are expected to fail closed for scaffold backend families and require production-declared VSS and contribution-proof backends. | Passing a declaration gate is not a security proof, audit, constant-time review, or deployment readiness result. |
| Side-channel and implementation hardening | Benchmarks report empirical telemetry for deterministic simulations. | They do not establish constant-time behavior, leakage resistance, audited randomness, memory erasure, FIPS validation, or external certification. |

## Claims Not Supported Yet

The current results do not establish:

- adaptive MPC security
- production-grade DKG security
- zero-knowledge contribution soundness
- production VSS complaint verification or production slashing validity
- selective-abort resistance under a formal adversary
- side-channel resistance
- network-level liveness under real transport faults

Those are separate proof and audit obligations. They should be stated as future
work or explicitly scoped out of the present prototype.

## Frozen Sample Fixture

The paper-facing reproducibility manifest is
`docs/benchmarks/reproducibility-manifest.md`. A checked-in sample output bundle
is stored at `docs/benchmarks/artifacts/section-v-sample-output.txt`, with
checksum sidecar `docs/benchmarks/artifacts/SHA256SUMS`.

The fixture is for structural review of LaTeX, PGFPlots CSV, transcript, and
complaint-evidence sections. Fresh benchmark runs may produce different
wall-clock latency values and therefore require an updated checksum if the
sample bundle is refreshed.

## Verification Commands

Focused evaluation path:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa --test hazmat_mldsa65_simulation_grid
```

Full hazmat regression path:

```bash
CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo test -j1 --features hazmat-real-mldsa -- --skip invalid_signing_state_calls_do_not_compile

CARGO_TARGET_DIR=/tmp/dytallix-pq-threshold-target \
CARGO_INCREMENTAL=0 \
cargo clippy -j1 --all-targets --all-features -- -D warnings
```
