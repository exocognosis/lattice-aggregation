# Protocol-To-Code Crosswalk

Date: 2026-05-26

## Status

This document is an audit navigation index for protocol reviewers. It maps the
threshold ML-DSA-65 protocol rounds, claim boundaries, source modules, and test
coverage currently present in the repository.

This crosswalk is not a security proof and does not create new implementation
claims. The claim boundaries in
[formal-threshold-mldsa-transcript.md](formal-threshold-mldsa-transcript.md),
[threshold-mldsa-protocol-spec.md](threshold-mldsa-protocol-spec.md),
[hazmat-real-mldsa-protocol.md](hazmat-real-mldsa-protocol.md),
[production-vss-backend.md](production-vss-backend.md), and
[proof-bearing-contribution-boundary.md](proof-bearing-contribution-boundary.md)
remain authoritative.

## Reviewer Usage

Use this file as a first-pass index when moving from the formal transcript to
implementation evidence:

1. Start with the protocol object or round in the first column.
2. Read the cited specification documents for the intended relation and
   non-claims.
3. Inspect the cited source modules for the current scaffold or hazmat
   enforcement point.
4. Run or read the cited tests to see which invariant is actually checked.
5. Treat every "Scaffold/research" entry as navigation to evidence, not as a
   production-security claim.

## Crosswalk Table

| Protocol area | Protocol document anchors | Source modules | Test coverage | Current status |
| --- | --- | --- | --- | --- |
| DKG/VSS setup and share reconstruction | `threshold-mldsa-protocol-spec.md` "DKG and VSS Scaffold"; `formal-threshold-mldsa-transcript.md` "DKG Placeholder"; `production-vss-backend.md` | `src/crypto/vss.rs` (`ShareContribution`, `split_secret_poly`, `VssCommitmentBackend`, `ProductionVssRelationStatement`); `src/crypto/interpolation.rs` (`compute_lagrange_coefficient`, `reconstruct_secret_poly`); `src/low_level/mldsa65.rs` (`split_mldsa65_expanded_secret_key`, `dkg_public_commitment_digest`) | `tests/dkg_vss_soundness.rs`; `tests/hazmat_mldsa65_threshold_bridge.rs`; `tests/production_policy.rs` | Scaffold/research. Deterministic VSS commitment and interpolation boundaries are tested; malicious-secure DKG, production complaint soundness, and anti-framing proofs are not implemented. |
| Masking commitment | `hazmat-real-mldsa-protocol.md` "Round 1a: Masking Precommitment"; `formal-threshold-mldsa-transcript.md` "Round 1a: Masking Precommitment" | `src/adapter/wire.rs` (`PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment`); `src/low_level/mldsa65.rs` (`masking_commitment_digest`); `src/adapter/actor.rs` (`submit_masking_commitment_wire_message`, `verify_masking_precommitment`) | `tests/hazmat_mldsa65_wire.rs` (`hazmat_actor_session_requires_masking_precommitment_in_strict_mode`, `hazmat_commitment_digests_bind_replay_context_and_payload`); `tests/hazmat_mldsa65_simulation_grid.rs` | Implemented hazmat binding check. The digest binds context and later payload, but it is not a production hiding commitment. |
| Masking opening | `hazmat-real-mldsa-protocol.md` "Round 1b: Masking Opening"; `formal-threshold-mldsa-transcript.md` "Round 1b: Masking Opening" | `src/adapter/wire.rs` (`PqcThresholdWireMsg::HazmatMldsa65MaskingContribution`); `src/low_level/mldsa65.rs` (`encode_mldsa65_masking_contribution`, `decode_mldsa65_masking_contribution`, `submit_mldsa65_masking_contribution`, `aggregate_mldsa65_masking_contributions`); `src/adapter/actor.rs` (`submit_masking_wire_message`) | `tests/hazmat_mldsa65_wire.rs`; `tests/hazmat_mldsa65_hardening.rs`; `tests/hazmat_mldsa65_fuzzing.rs` | Implemented hazmat validation. Receivers check envelope context, validator index, duplicate status, payload decoding, commitment opening, and `w = A*y`; raw masking material is still exposed in this research backend. |
| Challenge derivation | `hazmat-real-mldsa-protocol.md` "Round 2: Challenge Fixing"; `formal-threshold-mldsa-transcript.md` "Round 2: Challenge Derivation" | `src/low_level/mldsa65.rs` (`derive_mldsa65_session_challenge_once_quorum_met`, `derive_mldsa65_challenge_from_aggregated_masking`); `src/adapter/wire.rs` (`PqcThresholdWireMsg::HazmatMldsa65Challenge`); `src/adapter/actor.rs` (`process_hazmat_message`, challenge broadcast path) | `tests/hazmat_mldsa65_wire.rs`; `tests/hazmat_mldsa65_threshold_bridge.rs`; `tests/hazmat_mldsa65_simulation_grid.rs`; `tests/transcript_determinism.rs` | Implemented for hazmat execution. Standard ML-DSA challenge compatibility is preserved through `mu` and `w1`; formal context-binding and selective-abort bounds remain proof obligations. |
| Secret commitment | `hazmat-real-mldsa-protocol.md` "Round 3a: Secret Precommitment"; `formal-threshold-mldsa-transcript.md` "Round 3a: Secret Precommitment" | `src/adapter/wire.rs` (`PqcThresholdWireMsg::HazmatMldsa65SecretCommitment`); `src/low_level/mldsa65.rs` (`secret_commitment_digest`); `src/adapter/actor.rs` (`submit_secret_commitment_wire_message`, `verify_secret_precommitment`) | `tests/hazmat_mldsa65_wire.rs` (`hazmat_actor_session_requires_secret_precommitment_in_strict_mode`, `hazmat_commitment_digests_bind_replay_context_and_payload`); `tests/hazmat_mldsa65_simulation_grid.rs` | Implemented hazmat binding check. Secret openings must match a challenge-bound digest; this is not a production proof of a valid secret contribution. |
| Secret opening | `hazmat-real-mldsa-protocol.md` "Round 3b: Secret Opening"; `formal-threshold-mldsa-transcript.md` "Round 3b: Secret Opening With Proof-Bound Frame" | `src/adapter/wire.rs` (`PqcThresholdWireMsg::HazmatMldsa65SecretContribution`, `PqcThresholdWireMsg::HazmatMldsa65ProofBoundSecretContribution`); `src/low_level/mldsa65.rs` (`encode_mldsa65_secret_contribution`, `decode_mldsa65_secret_contribution`, `submit_mldsa65_secret_contribution`); `src/adapter/actor.rs` (`submit_secret_wire_message`, `verify_proof_bound_secret_contribution`) | `tests/hazmat_mldsa65_wire.rs` (`hazmat_actor_session_accepts_proof_bound_secret_opening`, `hazmat_actor_session_rejects_proof_bound_secret_tampering`, `hazmat_actor_session_accepts_real_wire_contributions_and_finalizes`) | Implemented hazmat/proof-bound frame checks. The accepted scaffold proof binds statement and payload digest; it does not prove knowledge, zero-knowledge privacy, or algebraic contribution soundness. |
| Contribution proof boundary | `proof-bearing-contribution-boundary.md`; `formal-threshold-mldsa-transcript.md` "proof-bound secret contribution"; `formal-threshold-mldsa-transcript.md` "G4 contribution proof soundness" | `src/crypto/contribution_proof.rs` (`ContributionStatement`, `ContributionProof`, `ProductionContributionStatement`, `verify_contribution_proof`); `src/adapter/actor.rs` (`production_contribution_statement`, `production_contribution_statement_digest`, `production_contribution_statement_from_scaffold`); `src/crypto/production_policy.rs` | `tests/contribution_proof.rs`; `tests/hazmat_mldsa65_wire.rs`; `tests/production_policy.rs` | Scaffold/research. Canonical statement and digest binding are implemented for future replacement; production proof relation and cryptographic review are open. |
| Aggregation and finalization | `threshold-mldsa-protocol-spec.md` "Aggregation"; `hazmat-real-mldsa-protocol.md` "Finalization"; `formal-threshold-mldsa-transcript.md` "Finalization And Verification" | `src/aggregation.rs` (`SimulatedAggregator`); `src/crypto/interpolation.rs` (`reconstruct_secret_poly`); `src/low_level/mldsa65.rs` (`reconstruct_mldsa65_secret_contribution_from_shares`, response/hint/signature assembly helpers, `verify_mldsa65_internal_mu`); `src/adapter/actor.rs` (`finalize_signature`) | `tests/simulated_flow.rs`; `tests/hazmat_mldsa65_threshold_bridge.rs`; `tests/hazmat_mldsa65_wire.rs`; `tests/hazmat_mldsa65_differential.rs`; `tests/hazmat_mldsa65_kat.rs` | Implemented in deterministic simulation and hazmat paths. Hazmat signatures verify through the unmodified verifier in tested paths; distributional compatibility and complete security reduction remain open. |
| Evidence export and fault attribution | `threshold-mldsa-protocol-spec.md` "Evidence and Fault Attribution"; `hazmat-real-mldsa-protocol.md` "Evidence Behavior"; `formal-threshold-mldsa-transcript.md` "Rejection, Retry, And Evidence Boundaries" | `src/adapter/evidence.rs` (`EvidenceKind`, `SlashingEvidence`, `SlashingEvidencePayload`); `src/adapter/actor.rs` (invalid contribution evidence emission, production VSS relation statement digest attachment); `src/utils/hazmat_artifacts.rs` (`experimental_vss_complaint_artifacts_from_evidence`) | `tests/low_level.rs`; `tests/hazmat_mldsa65_wire.rs`; `tests/dkg_vss_soundness.rs`; `tests/hazmat_mldsa65_simulation_grid.rs` | Implemented engineering evidence for malformed frames and experimental VSS-shaped complaints. Production slashing soundness and anti-framing analysis remain proof obligations. |
| Artifact verification | `hazmat-real-mldsa-protocol.md` "Current Security Boundary"; benchmark reproducibility docs for artifact formats | `src/utils/hazmat_artifacts.rs` (`event_from_hazmat_wire_frame`, `verify_hazmat_transcript_events`, `verify_hazmat_transcript_jsonl`, `verify_hazmat_transcript_csv`, `verify_hazmat_transcript_frame_bindings`); `src/utils/hazmat_simulation.rs`; `src/main.rs` | `tests/hazmat_mldsa65_simulation_grid.rs`; `tests/section_v_sample_bundle.rs`; `tests/reproducibility_manifest.rs` | Implemented reproducibility and replay checks. These verify artifact structure, frame digests, ordering constraints, and production statement digest presence; they are not cryptographic security evidence. |

## Limitations

- The crosswalk is descriptive and may lag implementation unless manifest
  coverage and reviewer discipline keep it current.
- Source references identify modules and symbols, not exhaustive line-by-line
  proof obligations.
- The current hazmat backend intentionally exposes raw contribution material.
  This is suitable for research instrumentation only.
- DKG/VSS, contribution proofs, selective-abort analysis, adaptive security,
  side-channel resistance, production slashing soundness, and full
  ML-DSA-65 security reduction remain outside current implementation claims.
- The production policy gates are fail-closed configuration guards. Passing a
  backend declaration gate is not a cryptographic proof or audit result.
