# Security Model Draft for Threshold ML-DSA-65

Date: 2026-05-23

## Status

This document defines the security model that a publishable
`dytallix-pq-threshold` construction must satisfy. It is a proof target, not a
completed proof.

The current Rust implementation is a research scaffold with deterministic
simulation backends. It must not be described as cryptographically secure until
the games and reductions below are completed for a concrete threshold ML-DSA-65
backend.

## Participants

The system has:

- A validator set `V = {1, ..., N}`.
- A signing threshold `t`.
- A blockchain consensus environment that selects block proposers.
- A network adversary controlling message scheduling.
- A cryptographic adversary corrupting up to `f` validators.

For BFT-style consensus deployments, the intended parameter regime is:

```text
N >= 3f + 1
t >= 2f + 1
```

The cryptographic proof should be parameterized by `N`, `t`, and corruption
bound `f`, rather than hard-coding consensus assumptions into the primitive.

## Assets

The primitive must protect:

- Unforgeability of epoch signatures.
- Secrecy of honest validators' key shares.
- Unbiasability of the Fiat-Shamir challenge.
- Soundness of DKG share verification.
- Soundness of partial-signature verification.
- Integrity of slashing/fault evidence.
- Availability under fewer than `N - t + 1` offline or faulty validators.

## Adversary Classes

### Passive Adversary

A passive adversary observes all public transcripts:

- commitments
- wire messages
- public keys
- finalized signatures
- timing and telemetry

Security target:

- The view leaks no information about honest validators' secret shares beyond
  what follows from public outputs.

### Static Active Adversary

A static active adversary chooses corrupted validators before DKG. It can:

- send malformed DKG commitments
- send inconsistent encrypted shares
- equivocate between peers
- withhold commitments
- withhold partial signatures
- submit invalid partial signatures
- attempt challenge bias by selective aborts
- attempt rogue-key or duplicate-validator attacks

Security target:

- It cannot forge a valid signature for a message not authorized by at least
  `t` valid shares.
- It cannot make honest parties accept an invalid aggregate.
- Invalid behavior is either harmlessly rejected or attributable by evidence.

### Adaptive Active Adversary

An adaptive adversary corrupts validators during or after protocol execution.

Security target for publication:

- Define whether adaptive security is in scope.
- If in scope, model erasures of local masking material `y_i` and commitment
  secrets.
- Prove that post-round corruption does not reveal enough information to
  reconstruct prior honest shares.

Current recommendation:

- Target static active security first.
- State adaptive security as future work unless the implementation supports
  reliable erasures and the proof models them.

### Network Adversary

The network adversary can:

- delay messages
- reorder messages
- duplicate messages
- drop messages
- partition validators temporarily

It cannot break authenticated transport or forge validator identity if the
production P2P layer enforces identity binding.

Security target:

- Safety is independent of network scheduling.
- Liveness requires at least `t` responsive validators within timeout.
- Timeout evidence is not automatically slashable without consensus-layer
  policy distinguishing network loss from malicious withholding.

## Security Games

### Game 1: Threshold EUF-CMA

Goal:

An adversary wins if it outputs `(M*, sigma*)` such that:

```text
Verify_MLDSA65(pk_epoch, M*, sigma*) = accept
```

and fewer than `t` honest-valid signing shares were produced for `M*`.

Oracle access:

- DKG initialization
- signing sessions for chosen messages
- corruption of up to `f` validators under the chosen corruption model
- transcript observation

Required proof:

- Reduce a winning adversary to either a break of ML-DSA unforgeability, a
  binding failure in commitments, a random-oracle programming event, or a DKG
  soundness failure.

### Game 2: DKG Share Soundness

Goal:

An adversary wins if an honest validator accepts a private share inconsistent
with the public DKG commitments, or if accepted shares reconstruct to different
epoch secrets for different honest subsets.

Required proof:

- VSS commitments bind all accepted shares to one polynomial per dealer.
- Complaint resolution removes or exposes invalid dealers.
- Public key derivation is deterministic from accepted commitments.

### Game 3: Challenge Unbiasability

Goal:

An adversary wins if it can significantly bias challenge `c` away from the
random-oracle distribution expected by ML-DSA.

Attack surfaces:

- choosing `y_i` after seeing honest commitments
- equivocation on commitments
- selective abort after seeing `c`
- proposer-controlled ordering

Required proof:

- Commitment phase is binding before challenge derivation.
- Transcript canonicalization removes ordering influence.
- Abort/retry policy does not let corrupted validators amplify challenge bias
  beyond a stated bound.

### Game 4: Partial-Share Soundness

Goal:

An adversary wins if an invalid partial share is accepted into the final
aggregate.

Required proof:

- Each accepted partial share verifies against the corresponding Round 1
  commitment, public DKG data, and transcript challenge.
- Duplicate and unknown validator IDs are rejected.
- Accepted partial shares bind to exactly one session ID and message.

### Game 5: Evidence Soundness

Goal:

An adversary wins if it creates valid-looking evidence against an honest
validator for behavior the validator did not perform.

Required proof:

- Evidence includes canonical session ID, block height, validator index,
  commitment, malicious share bytes, and verification failure proof.
- Evidence verifier is deterministic.
- Evidence cannot be replayed across sessions or epochs.
- Liveness penalties are separated from cryptographic slashing proofs.

## Assumptions

The proof may rely on:

- ML-DSA-65 unforgeability under its stated hardness assumptions.
- Random oracle model for Fiat-Shamir challenge derivation.
- Binding and hiding properties of the chosen commitment scheme.
- Authenticated P2P identity binding in production.
- Honest validators securely erasing ephemeral masking secrets if adaptive
  security is claimed.
- Side-channel resistance of real backend arithmetic if timing claims are made.

The proof must not rely on:

- Honest aggregators.
- Honest block proposers.
- Network message ordering.
- Secret validator identities.
- Simulation-only deterministic masks.

## Current Implementation Coverage

Implemented scaffold coverage:

- Type-state ordering prevents accidental local API misuse.
- Canonical `CommitmentSet` and `PartialShareSet` reject duplicates and
  unknown validators.
- `SigningTranscript` canonicalizes validator ordering.
- Adapter actor rejects unknown validators.
- Adapter actor emits local evidence for poisoned partials and missing partials.
- Wire codec is versioned and length-bounded.
- VSS and interpolation tests demonstrate algebraic reconstruction over the
  scaffold polynomial type.

Not yet covered:

- Real DKG commitments.
- Real ML-DSA signing equations.
- Real partial-share verification.
- Real aggregate signature verification.
- Formal rejection-sampling proof.
- Side-channel testing.
- Cryptographic randomness.
- Adaptive corruption model.

## Publication Claim Boundaries

Acceptable claim today:

> We implement and test a Rust research scaffold for threshold ML-DSA-65
> protocol integration, including typed transcripts, async adapter simulation,
> low-level polynomial arithmetic scaffolding, VSS/interpolation algebra, and
> reproducible telemetry export.

Unacceptable claim today:

> We implement a secure or production-ready threshold ML-DSA-65 signature
> scheme.

Target publishable claim after completing the proof and backend:

> We specify, prove, implement, and evaluate an actively secure threshold
> ML-DSA-65 signing protocol whose aggregate output verifies under the standard
> ML-DSA-65 verification algorithm.
