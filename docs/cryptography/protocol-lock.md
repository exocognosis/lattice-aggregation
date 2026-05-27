# Protocol Lock: Hazmat Threshold ML-DSA-65 Scaffold

Date: 2026-05-26

## Scope

This file records the protocol properties that are currently locked by code,
tests, and documentation. It is a boundary document for implementation and
paper wording. It does not claim that the crate implements a production-secure
threshold ML-DSA-65 construction.

The locked implementation target is:

- feature-gated local ML-DSA-65 internals under `hazmat-real-mldsa`;
- standard-size ML-DSA-65 public key and signature byte layouts;
- deterministic, in-memory threshold transcript experiments;
- fail-closed production policy boundaries for scaffold proof and VSS backends;
- explicit separation between retryable rejection sampling and slashable
  malformed or transcript-inconsistent shares.

## Locked Transcript Invariants

The hazmat signing attempt must preserve these invariants:

1. A challenge is derived only after masking quorum is met.
2. Secret contributions are accepted only after the session challenge exists.
3. Finalization is attempted only after secret-share quorum is met.
4. Duplicate masking or secret contributions from the same validator are
   rejected.
5. Transcript challenges bind the session identifier, validator universe,
   threshold, public key, message, and canonical commitment set.
6. Proof-bound secret contribution frames bind the DKG digest, masking
   commitment digest, secret commitment digest, challenge, session identifier,
   block height, attempt, validator index, and payload witness digest.
7. ML-DSA rejection sampling failures are non-slashable retry events.
8. Malformed, cross-session, stale-challenge, inconsistent, or proof-invalid
   contribution frames remain attributable invalid-share evidence candidates.

## Locked Non-Claims

The repository must not be described as any of the following until the listed
gaps are closed:

- a production threshold ML-DSA-65 implementation;
- a malicious-secure DKG;
- a zero-knowledge or knowledge-sound contribution proof system;
- a side-channel-hardened implementation;
- a FIPS-validated cryptographic module;
- an adaptive-security construction;
- an L1-integrated consensus implementation.

## Required Gates Before Stronger Claims

Before moving from research scaffold to publishable cryptographic claim, the
project needs:

- a formal transcript definition with simulators and extraction conditions;
- a production VSS/DKG backend with complaint resolution and anti-framing
  analysis;
- hidden and sound contribution proofs replacing transcript-hash scaffolds;
- a complete rejection-sampling distribution argument;
- side-channel review of polynomial arithmetic and secret-dependent branches;
- authenticated network identity binding and replay analysis;
- independent cryptographic review of the reduction and implementation.

## Test Anchors

The current implementation anchors this lock through:

- `tests/hazmat_mldsa65_threshold_bridge.rs`
- `tests/hazmat_mldsa65_wire.rs`
- `tests/transcript_determinism.rs`
- `tests/contribution_proof.rs`
- `tests/production_policy.rs`
- `tests/hazmat_mldsa65_simulation_grid.rs`

These tests justify narrow implementation claims only. They are regression
guards for the research scaffold, not proof substitutes.
