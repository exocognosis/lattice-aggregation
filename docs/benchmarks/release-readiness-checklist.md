# Release Readiness Checklist

Date: 2026-05-26

## Purpose

This checklist separates the current Section V conformance evidence from the
work required before any production-security or secure threshold ML-DSA
aggregation claim. It is intended for manuscript and release review, not as a
replacement for the cryptographic claims matrix.

Current status: the repository supports a research scaffold plus a
feature-gated `hazmat-real-mldsa` evaluation backend. It does not yet prove a
secure threshold ML-DSA-65 aggregation protocol.

## Research Scaffold

These items support publication of a scoped research artifact:

- [x] Document deterministic Section V benchmark commands and feature gates.
- [x] Export replayable transcript JSONL and CSV artifacts.
- [x] Verify transcript artifact shape before printing.
- [x] Bind transcript artifacts to canonical frame digests.
- [x] Export populated production contribution statement digests where a
  production-shaped statement exists.
- [x] Export experimental VSS complaint evidence under `experimental-vss`.
- [x] Bind complaint artifacts to canonical production VSS relation statement
  digests.
- [x] Maintain a checksum-pinned sample output bundle for structural review.
- [x] Keep manuscript wording scoped to implementation behavior and
  reproducibility, not production security.
- [ ] Update `docs/cryptography/claims-matrix.md` whenever a claim changes
  status.

## Hazmat Implementation

These items describe the `hazmat-real-mldsa` backend boundary:

- [x] Keep ML-DSA-65 internals feature-gated behind `hazmat-real-mldsa`.
- [x] Produce standard-sized ML-DSA-65 public keys and signatures in tested
  paths.
- [x] Verify finalized signatures with the ordinary internal-`mu` verifier in
  the benchmark path.
- [x] Compare each threshold trial with a deterministic single-signer baseline
  over the same internal `mu`.
- [x] Reject malformed contribution encodings in the actor path.
- [x] Emit attributable malformed-contribution evidence when a bad payload is
  observed.
- [x] Allow finalization to continue after one malformed contribution when an
  honest quorum remains.
- [ ] Complete constant-time review and timing-leakage tests for secret
  dependent arithmetic and encoding paths.
- [ ] Complete memory erasure and adaptive-corruption handling if adaptive
  security is claimed.
- [ ] Obtain external cryptographic and implementation audit before removing
  hazmat status or making production-readiness claims.

## Production Blockers

No secure threshold ML-DSA aggregation claim should be made until these blockers
are closed:

- [ ] Complete a formal threshold ML-DSA-65 protocol specification with exact
  adversary model, corruption timing, network assumptions, and abort model.
- [ ] Prove that aggregate outputs preserve ML-DSA-65 challenge, rejection
  sampling, norm-bound, and distributional requirements.
- [ ] Replace transcript-hash contribution proofs with a sound production
  relation, verifier, or audited MPC verification boundary.
- [ ] Provide hiding and binding guarantees for secret-dependent contribution
  material.
- [ ] Replace deterministic VSS/DKG scaffold code with malicious-secure
  production DKG, private share delivery, complaint resolution, and
  anti-framing analysis.
- [ ] Prove production VSS complaint soundness before using complaint evidence
  for slashing or consensus penalties.
- [ ] Audit randomness generation, nonce derivation, domain separation,
  transcript binding, and key-management assumptions.
- [ ] Validate authenticated transport, replay protection, retry limits, and
  consensus integration behavior under real faults.
- [ ] Complete constant-time, side-channel, and leakage review for the selected
  backend.
- [ ] Complete external cryptographic review and implementation audit.
- [ ] Decide whether FIPS validation or other certification is required before
  deployment claims.

## Release Gate

A release may describe the current artifact as a reproducible research scaffold
with a hazmat ML-DSA-65 conformance backend. It must not describe the artifact
as a secure, production-ready, malicious-secure, or audited threshold ML-DSA-65
aggregation implementation until the production blockers above are complete.
