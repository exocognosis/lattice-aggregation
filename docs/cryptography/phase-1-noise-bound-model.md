# Phase 1 Threshold ML-DSA-65 Noise-Bound Model

Date: 2026-05-22

## Scope

This document records the mathematical constraints the crate API is designed to preserve. It does not prove production security for the simulation backend.

## ML-DSA-65 Constraint

ML-DSA-65 relies on Fiat-Shamir with aborts. Any threshold construction must preserve the distribution and norm bounds of the effective masking vector `y` and response vector `z`.

## Threshold Signing Requirement

Participants must commit to local masking contributions before challenge derivation. The transcript binds the protocol version, session ID, validator set, public key, message, and ordered commitments.

## Rejection Requirement

A real backend must reject local or aggregate partial shares when backend-specific bounds for `z`, hint vectors, or challenge consistency fail. The simulation backend exercises API behavior only and has no ML-DSA security claim.

## Production Gates

No production consensus signing is permitted until a concrete threshold ML-DSA protocol is selected, the noise-bound proof is completed for ML-DSA-65, a standard verifier accepts aggregate signatures, timing tests are run on the concrete backend, and external cryptographic review is complete.
