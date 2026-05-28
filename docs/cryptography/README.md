# Cryptography Notes

This directory collects research notes for the threshold ML-DSA-65 scaffold.

The current implementation uses deterministic simulation labels under the `lattice-aggregation/threshold-mldsa65` domain. Those labels are for stable test vectors and transcript separation only; they are not evidence of a production threshold ML-DSA construction.

Available notes:

- [Phase 1 Noise Bound Model](phase-1-noise-bound-model.md)
- [Proof Closure Ledger](proof-closure-ledger.md)
- [Production Transcript Grammar](production-transcript-grammar.md)
- [IdealVSS Signing Theorem Closure](idealvss-signing-theorem-closure.md)
- [IdealVSS Lemma Skeleton](idealvss-lemma-skeleton.md)
- [Contribution Backend Selection Framework](contribution-backend-selection.md)
- [Rejection-Sampling Closure Plan](rejection-sampling-closure-plan.md)
- [Random-Oracle and Commitment Closure Plan](random-oracle-commitment-closure.md)
- [Unauthorized Output Classifier Elimination Plan](unauthorized-output-classifier-elimination.md)

When adding cryptographic documentation, keep claims explicit about whether they describe implemented behavior, planned behavior, or open research work.
