# Limitations

Date: 2026-05-27

## Boundary

The current artifact is a research scaffold with a feature-gated hazmat
ML-DSA-65 backend. It is not production-ready and not a security proof for a
malicious-secure threshold ML-DSA-65 signature scheme.

The proof closure ledger is
[../cryptography/proof-closure-ledger.md](../cryptography/proof-closure-ledger.md).
The authoritative claim matrix is
[../cryptography/claims-matrix.md](../cryptography/claims-matrix.md). The
numbered proof blockers are tracked in
[../cryptography/proof-obligations.md](../cryptography/proof-obligations.md).

## Cryptographic Limitations

- The VSS/DKG implementation is a scaffold, not malicious-secure DKG.
- The current contribution proof is a transcript-hash boundary, not a sound or
  hiding production relation.
- The selective-abort/retry bound is not proven.
- The aggregation/noise correctness argument is not complete for all accepted
  transcripts.
- Transcript/challenge unbiasability remains a proof obligation.
- Side-channel resistance and leakage freedom are not claimed.
- Production slashing/evidence soundness is not established.

## Implementation Limitations

- `hazmat-real-mldsa` code is useful for experiments and conformance
  regression, but it is not externally audited or FIPS validated.
- In-memory actor simulations do not replace authenticated network,
  consensus, or timeout analysis.
- Benchmark outputs are performance and reproducibility artifacts, not security
  evidence.
- Experimental VSS complaint artifacts are evidence-shaping scaffolds, not
  production penalty transactions.

## Review Links

- Audit packet: [../audit/README.md](../audit/README.md)
- Proof closure ledger: [../cryptography/proof-closure-ledger.md](../cryptography/proof-closure-ledger.md)
- Protocol crosswalk: [../cryptography/protocol-code-crosswalk.md](../cryptography/protocol-code-crosswalk.md)
- Release readiness: [../benchmarks/release-readiness-checklist.md](../benchmarks/release-readiness-checklist.md)
- Reproducibility manifest: [../benchmarks/reproducibility-manifest.md](../benchmarks/reproducibility-manifest.md)

## Safe Manuscript Language

Use “research scaffold,” “hazmat backend,” “implementation evidence,”
“reproducible artifact,” and “proof obligation” when describing the current
state.

Do not use “production secure,” “audited,” “malicious-secure threshold
ML-DSA,” “side-channel safe,” or “FIPS validated” unless the corresponding
proof, implementation, audit, and certification work is completed.
