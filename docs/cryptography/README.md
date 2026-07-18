# Cryptography Notes

This directory collects implementation, proof, and evidence notes for the
threshold ML-DSA-65 closure-run track.

The current implementation has two deliberately separate tracks. The
coordinator-assisted Stack B path emits standard-verifier-compatible ML-DSA-65
signatures under an explicit TEE/HSM no-export assumption. The distributed Stack
A path contains real VSS/DKG, BDLOP, distributed nonce, and partial-validity
research components, but it keeps the aggregate-mask `epsilon_mask` problem open
and does not emit a FIPS-verifier-valid signature.

Available notes:

- [Active Adversary Model](active-adversary-model.md)
- [Strong Threshold Security Model](security-model.md)
- [Strong Threshold Protocol Specification](threshold-mldsa-protocol-spec.md)
- [Internal Theorem-Closure Candidate Semantics](internal-theorem-closure-candidate.md)
- [Cryptographic Claims Matrix](claims-matrix.md)
- [Algebraic Correctness Lemmas](correctness-lemmas.md)
- [Criterion 1 Proof Substance](criterion-1-proof-substance.md)
- [Criterion 2 Proof Substance](criterion-2-proof-substance.md)
- [P1 Nonce Producer Selection](p1-nonce-producer-selection.md)
- [P1 Nonce Producer Backend CLI Contract](p1-nonce-producer-backend-cli-contract.md)
- [Criterion 3 Proof Substance](criterion-3-proof-substance.md)
- [10,000 Validator Standard-Verifier Gate](validator-10000-standard-verifier-gate.md)
- [BDLOP Parameter Security Estimate](bdlop-parameter-security-estimate.md)
- [Design-Space Boundary Theorems](design-space-boundary-theorems.md)
- [Distributed Mask MPC Feasibility](distributed-mask-mpc-feasibility.md)
- [Epsilon Mask Fork Decision](epsilon-mask-fork-decision.md)
- [Epsilon Mask Fork Reconciliation](epsilon-mask-fork-reconciliation.md)
- [Formal Security Theorem](formal-security-theorem.md)
- [Formal Threshold ML-DSA Transcript](formal-threshold-mldsa-transcript.md)
- [FST-L12 Committee Cost Model](fst-l12-committee-cost-model.md)
- [Hypothesis Outcome Taxonomy](hypothesis-outcome-taxonomy.md)
- [Ideal Functionality](ideal-functionality.md)
- [Mask Distribution Evidence](mask-distribution-evidence.md)
- [Noise-Bound and Rejection-Sampling Proof Plan](noise-rejection-proof-plan.md)
- [Phase 1 Noise Bound Model](phase-1-noise-bound-model.md)
- [Partial Soundness Advancement](partial-soundness-advancement-2026-07-12.md)
- [Partial Contribution Soundness Evidence](partial-soundness-evidence.md)
- [Proof Implementation Crosswalk](proof-implementation-crosswalk.md)
- [Protocol Code Crosswalk](protocol-code-crosswalk.md)
- [Proof Obligations Matrix](proof-obligations.md)
- [Random-Oracle Game](random-oracle-game.md)
- [Aggregate Rejection-Equivalence Evidence](rejection-equivalence-evidence.md)
- [Side-Channel and Constant-Time Boundary](side-channel-boundary.md)
- [Thesis and Operating Parameters](thesis-operating-parameters.md)
- [Theorem Closure Assessment Readiness](theorem-closure-assessment-readiness.md)
- [Threshold Stack Architecture](threshold-stack-architecture.md)
- [Unauthorized Aggregate Reduction Manifest](unauthorized-aggregate-reduction.md)
- [Proof-Grade VSS/DKG Security Plan](vss-dkg-security-plan.md)
- [Abort/Retry Bias Evidence Checks](abort-retry-bias-evidence.md)

When adding cryptographic documentation, identify the exact implemented
behavior, required proof artifact, or backend evidence artifact it supports.
