# Cryptography Notes

This directory collects implementation, proof, and evidence notes for the
threshold ML-DSA-65 closure-run track.

The current implementation uses deterministic simulation labels under the
`lattice-aggregation/threshold-mldsa65` domain. Those labels provide stable test
vectors and transcript separation while the selected backend artifacts are
filled in.

Available notes:

- [Active Adversary Model](active-adversary-model.md)
- [Cryptographic Claims Matrix](claims-matrix.md)
- [Algebraic Correctness Lemmas](correctness-lemmas.md)
- [Formal Security Theorem](formal-security-theorem.md)
- [Formal Threshold ML-DSA Transcript](formal-threshold-mldsa-transcript.md)
- [Ideal Functionality](ideal-functionality.md)
- [Mask Distribution Evidence](mask-distribution-evidence.md)
- [Noise-Bound and Rejection-Sampling Proof Plan](noise-rejection-proof-plan.md)
- [Phase 1 Noise Bound Model](phase-1-noise-bound-model.md)
- [Partial Contribution Soundness Evidence](partial-soundness-evidence.md)
- [Proof Implementation Crosswalk](proof-implementation-crosswalk.md)
- [Protocol Code Crosswalk](protocol-code-crosswalk.md)
- [Proof Obligations Matrix](proof-obligations.md)
- [Random-Oracle Game](random-oracle-game.md)
- [Aggregate Rejection-Equivalence Evidence](rejection-equivalence-evidence.md)
- [Side-Channel and Constant-Time Boundary](side-channel-boundary.md)
- [Unauthorized Aggregate Reduction Manifest](unauthorized-aggregate-reduction.md)
- [Proof-Grade VSS/DKG Security Plan](vss-dkg-security-plan.md)
- [Abort/Retry Bias Evidence Checks](abort-retry-bias-evidence.md)

When adding cryptographic documentation, identify the exact implemented
behavior, required proof artifact, or backend evidence artifact it supports.
