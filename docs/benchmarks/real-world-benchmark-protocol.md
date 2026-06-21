# Real-World Benchmark Protocol

This protocol defines the minimum evidence needed before this repository can
claim real-world benchmark results. Until every required input is present,
reviewed, and linked, the repository must not claim real-world benchmark results, production validator performance, production liveness, side-channel resistance, FIPS validation, or production consensus signing readiness.

## Required Inputs

A real-world benchmark packet must include:

- exact commit, branch, feature set, and dependency lockfile;
- production threshold backend under review, with the simulated backend
  explicitly excluded from production-labeled measurements;
- hardware model, CPU, memory, accelerator, TEE/HSM, and operating-system
  details for every benchmark node;
- external validator deployment topology, validator count, threshold,
  geographic or network placement, authenticated transport, timeout policy,
  retry policy, and session cleanup policy;
- compiler, Rust toolchain, build profile, flags, and feature gates;
- raw command logs, structured metrics, artifact SHA-256 checksums, and
  regeneration commands;
- reviewer sign-off and residual-risk notes.

## Collection Procedure

1. Verify the release-readiness checklist names the backend, feature set,
   target platforms, proof package, and claim-boundary documents under review.
2. Run provider KATs, standard-verifier bridge tests, production acceptance
   tests, side-channel checks, and documentation manifest tests before
   collecting performance results.
3. Record wall-clock latency, logical protocol latency, abort/retry counts,
   bandwidth, CPU, memory, queue depth, timeout events, failed sessions, and
   evidence emissions for every run.
4. Store raw logs and normalized CSV or JSON artifacts with SHA-256 checksums.
5. Compare the real-world run against the deterministic simulation harness only
   as engineering telemetry. Do not treat agreement with simulation as
   cryptographic security evidence.

## Claim Boundary

The deterministic simulation backend is not a real-world benchmark target. A
production threshold backend, standard verifier compatibility evidence,
external validator deployment, reviewed proof artifacts, and operational
sign-off are required before any real-world performance statement can appear in
top-level docs.

Benchmark packets must also preserve all explicit non-claims in the release
readiness checklist, including no FIPS validation or production-readiness
language unless the corresponding external validation and review evidence is
linked.
