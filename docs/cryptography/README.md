# Cryptography Notes

This directory collects research notes for the threshold ML-DSA-65 scaffold.

The current implementation uses deterministic simulation labels under the `lattice-aggregation/threshold-mldsa65` domain. Those labels are for stable test vectors and transcript separation only; they are not evidence of a production threshold ML-DSA construction.

Available notes:

- [Active Adversary Model](active-adversary-model.md)
- [Cryptographic Claims Matrix](claims-matrix.md)
- [Algebraic Correctness Lemmas](correctness-lemmas.md)
- [Formal Security Theorem](formal-security-theorem.md)
- [Formal Threshold ML-DSA Transcript](formal-threshold-mldsa-transcript.md)
- [Ideal Functionality](ideal-functionality.md)
- [Noise-Bound and Rejection-Sampling Proof Plan](noise-rejection-proof-plan.md)
- [Phase 1 Noise Bound Model](phase-1-noise-bound-model.md)
- [Proof Implementation Crosswalk](proof-implementation-crosswalk.md)
- [Protocol Code Crosswalk](protocol-code-crosswalk.md)
- [Proof Obligations Matrix](proof-obligations.md)
- [Random-Oracle Game](random-oracle-game.md)
- [Side-Channel and Constant-Time Boundary](side-channel-boundary.md)
- [Proof-Grade VSS/DKG Security Plan](vss-dkg-security-plan.md)

When adding cryptographic documentation, keep claims explicit about whether they describe implemented behavior, planned behavior, or open research work.
