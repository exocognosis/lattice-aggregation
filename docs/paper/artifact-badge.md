# Artifact Badge Readiness

Date: 2026-05-27

## Scope

This page summarizes readiness for artifact-availability and
artifact-evaluation review. It is documentation for reviewers and authors, not
a legal statement, license selection, or production-security claim.

The artifact is a research scaffold for threshold-style ML-DSA-65. It includes
a feature-gated hazmat backend, deterministic simulations, transcript and
evaluation artifacts, and claim-boundary documentation. It is not
production-ready and not a security proof.

Short badge boundary: research scaffold; not production-ready; not a security
proof.

## Artifact Available Readiness

The repository is structured for artifact review when the submitted archive or
venue package includes:

- the source tree needed to run the documented reproduction commands,
- the checked-in Section V sample artifact bundle and SHA-256 sidecar,
- the paper-facing documentation under `docs/paper`,
- the benchmark reproducibility manifest, and
- the cryptographic claim-boundary and proof-obligation documents.

This readiness statement does not choose or imply a software license. The
author must separately confirm any archive access terms, venue requirements,
and license decisions before submission.

## Evaluation Readiness

This section is the artifact evaluated readiness note for reviewers who are
checking whether the package can be exercised with the documented commands.

The expected reproduction path begins with
[reviewer-quickstart.md](reviewer-quickstart.md). The one-command Section V
path and broader command matrix are maintained in
[../benchmarks/reproducibility-manifest.md](../benchmarks/reproducibility-manifest.md).

Reviewers should expect the reproduction path to:

- regenerate Section V-style output into a temporary file,
- verify the checked-in sample bundle checksum,
- run artifact verifier checks,
- print a digest for the regenerated output, and
- leave wall-clock benchmark timings as machine-dependent observations.

Stable review targets are schemas, headings, profile labels, digest fields,
fixture hashes, transcript artifact shapes, and fail-closed policy boundaries.
Benchmark timings are useful evaluation telemetry, not security evidence.

## Claim Boundary

Badge materials should point to the claim matrix:
[../cryptography/claims-matrix.md](../cryptography/claims-matrix.md).

Open proof, implementation, audit, and review blockers are tracked in
[../cryptography/proof-obligations.md](../cryptography/proof-obligations.md).

Conservative artifact claims include:

- research scaffold for threshold-style ML-DSA-65 protocol integration,
- feature-gated hazmat backend for experiments and conformance regression,
- deterministic Section V-style reproduction path,
- transcript, evidence-shaping, and benchmark artifacts for review, and
- explicit non-claim boundaries for production security.

## Non-Claims

Do not describe the current artifact as:

- production-ready,
- a security proof,
- malicious-secure threshold ML-DSA-65,
- side-channel safe,
- externally audited,
- FIPS validated, or
- covered by a chosen software license unless that license has been explicitly
  approved and added through the project release process.

The badge package can support availability and evaluation review for the
documented research artifact. It does not by itself establish production
deployment readiness or close the cryptographic proof obligations.
