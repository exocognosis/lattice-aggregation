# Cryptography Notes

This directory collects research notes for the threshold ML-DSA-65 scaffold.

The current implementation uses deterministic simulation labels under the `lattice-aggregation/threshold-mldsa65` domain. Those labels are for stable test vectors and transcript separation only; they are not evidence of a production threshold ML-DSA construction.

Available notes:

- [Phase 1 Noise Bound Model](phase-1-noise-bound-model.md)
- [Proof Closure Ledger](proof-closure-ledger.md)
- [Production Transcript Grammar](production-transcript-grammar.md)
- [FST-T1-IdealVSS Theorem Consolidation](fst-t1-idealvss-theorem.md)
- [Epsilon Residual Ledger Final Form](epsilon-residual-ledger-final-form.md)
- [Proof Gap Priority Map](proof-gap-priority-map.md)
- [IdealVSS Signing Theorem Closure](idealvss-signing-theorem-closure.md)
- [IdealVSS Lemma Skeleton](idealvss-lemma-skeleton.md)
- [FST-T1-IdealVSS Final Proof Assembly](fst-t1-idealvss-final-proof.md)
- [FST-L1..FST-L3 Theorem Closure Batch](fst-l1-l3-theorem-closure.md)
- [FST-L1 Transcript Injectivity Worksheet](fst-l1-transcript-injectivity.md)
- [FST-L2 Challenge Binding Worksheet](fst-l2-challenge-binding.md)
- [FST-L3 Collection Soundness Worksheet](fst-l3-collection-soundness.md)
- [FST-L4..FST-L7 Theorem Closure Batch](fst-l4-l7-theorem-closure.md)
- [FST-L4 Partial-Share Validity Worksheet](fst-l4-partial-share-validity.md)
- [FST-L5 Aggregation Correctness Worksheet](fst-l5-aggregation-correctness.md)
- [FST-L6 No Subthreshold Signing Worksheet](fst-l6-no-subthreshold-signing.md)
- [FST-L7 Abort Compatibility Worksheet](fst-l7-abort-compatibility.md)
- [FST-L10 Classifier Theorem Closure Batch](fst-l10-classifier-theorem-closure.md)
- [FST-L10 Classifier Closure Worksheet](fst-l10-classifier-closure.md)
- [Contribution Backend Selection Framework](contribution-backend-selection.md)
- [Contribution Backend Decision Record](contribution-backend-decision-record.md)
- [Rejection-Sampling Closure Plan](rejection-sampling-closure-plan.md)
- [Rejection-Sampling Theorem Closure Batch](rejection-sampling-theorem-closure.md)
- [eps_mask Theorem Closure Batch](eps-mask-theorem-closure.md)
- [eps_mask Formalization Route](eps-mask-formalization.md)
- [eps_rej Theorem Closure Batch](eps-rej-theorem-closure.md)
- [eps_rej Predicate Sublemma Route](eps-rej-predicate-sublemmas.md)
- [eps_withhold Theorem Closure Batch](eps-withhold-theorem-closure.md)
- [eps_withhold Simulator Obligation Route](eps-withhold-simulator-obligations.md)
- [Random-Oracle and Commitment Closure Plan](random-oracle-commitment-closure.md)
- [Unauthorized Output Classifier Elimination Plan](unauthorized-output-classifier-elimination.md)

When adding cryptographic documentation, keep claims explicit about whether they describe implemented behavior, planned behavior, or open research work.
