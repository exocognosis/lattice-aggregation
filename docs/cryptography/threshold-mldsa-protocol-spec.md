# Threshold ML-DSA-65 Protocol Specification Draft

Date: 2026-05-23

## Status

This is a publication-oriented protocol specification draft for the
`dytallix-pq-threshold` research crate. It describes the intended mathematical
construction and maps every protocol component to the current Rust scaffold.

This document is not a security proof and does not claim that the crate
currently implements a production threshold ML-DSA-65 signature scheme. The
current backend remains deterministic simulation infrastructure. A publishable
cryptographic result requires the proof obligations listed in
`noise-bound-proof-outline.md` and the adversary model in `security-model.md`.

## Goals

The target construction is an interactive threshold signing protocol for
ML-DSA-65 in which a threshold quorum of validators produces one standard-sized
ML-DSA-65 verification artifact for a block message.

The intended public-verification goal is:

```text
Verify_MLDSA65(pk_epoch, M, sigma) = accept
```

where:

- `pk_epoch` is the joint epoch public key.
- `M` is the block payload or block-header signing message.
- `sigma` is a standard-sized ML-DSA-65 signature.
- The verifier does not need to know that threshold signing occurred.

The current crate has the API and systems scaffold for this goal, but the
`SimulatedBackend` does not produce real ML-DSA signatures.

## Parameters and Algebra

The low-level scaffold models the ML-DSA polynomial ring:

```text
R_q = Z_q[X] / (X^256 + 1)
q   = 8380417
n   = 256
```

Rust mapping:

```text
R_q coefficient vector     -> src/low_level/poly.rs::Poly
n                            -> src/low_level/poly.rs::N
q                            -> src/low_level/poly.rs::Q
crypto namespace re-export   -> src/crypto.rs::poly
```

ML-DSA-65 byte-size constants:

```text
public key bytes  = 1952
signature bytes   = 3309
commitment bytes  = 32
session id bytes  = 32
```

Rust mapping:

```text
MLDSA65_PUBLICKEY_BYTES   -> src/types.rs
MLDSA65_SIGNATURE_BYTES   -> src/types.rs
COMMITMENT_BYTES          -> src/types.rs
SESSION_ID_BYTES          -> src/types.rs
```

## Entities

An epoch has validator set:

```text
V = {1, 2, ..., N}
```

with threshold:

```text
t <= N
```

Each validator `i` owns an epoch-local private key share:

```text
sk_i = (s1_i, s2_i, metadata_i)
```

The idealized joint public key is:

```text
pk_epoch = KeyGenFromShares({sk_i}_{i in V})
```

Rust mapping:

```text
Validator index           -> ValidatorId
private key share          -> PrivateKeyShare
joint public key           -> ThresholdPublicKey
signing session            -> SigningSession<State>
```

## DKG and VSS Scaffold

The scaffold uses Shamir-style polynomial sharing over coefficient lanes as a
testable algebraic boundary.

Let `f(X)` be a polynomial over `R_q` with:

```text
f(0) = secret
deg(f) < t
share_i = f(i)
```

Rust mapping:

```text
ShareContribution                 -> src/crypto/vss.rs
evaluate_polynomial_at             -> src/crypto/vss.rs
split_secret_poly                  -> src/crypto/vss.rs
compute_lagrange_coefficient       -> src/crypto/interpolation.rs
reconstruct_secret_poly            -> src/crypto/interpolation.rs
```

Current limitation:

- `split_secret_poly` uses deterministic mask polynomials for reproducible
  tests.
- A publishable DKG must replace these masks with cryptographically sampled
  polynomial coefficients, commitments to those coefficients, and share
  verification equations.

Required DKG algorithm for the real construction:

1. Each dealer samples secret polynomial coefficients in the correct ML-DSA
   share domain.
2. Each dealer broadcasts coefficient commitments.
3. Each dealer privately sends `share_i` to validator `i`.
4. Each receiver verifies the share against the public commitments.
5. Complaints are resolved with deterministic transcript evidence.
6. The accepted shares define `sk_i`.
7. The accepted public commitments define `pk_epoch`.

## Signing Protocol

The signing protocol is modeled as a two-round interactive protocol above the
type-state signing session.

### Round 0: Session Initialization

Inputs:

```text
sid       session identifier
V         canonical validator set
t         threshold
pk_epoch  joint public key
M         message
sk_i      local share for validator i
```

Rust mapping:

```text
SigningSession<state::Initialized>::new(...)
ActorEvent::TriggerSigningRound { session_id, block_height, message_hash }
```

Validation:

- `t > 0`
- `t <= |V|`
- no duplicate validators
- local share belongs to `V`
- `sid` is unique for the block/epoch context

### Round 1: Masking Commitment

Each validator samples or derives local masking material:

```text
y_i in R_q^k
```

and computes a public commitment contribution:

```text
w_i = HighBits(A * y_i)
C_i = H("commit" || sid || i || w_i || aux_i)
```

The current scaffold represents this as:

```text
Commitment([u8; 32])
PqcThresholdWireMsg::SignCommit
state::AwaitingCommitments {
    local_y,
    local_commitment,
    received_commitments,
}
```

Publication requirement:

- Define whether `C_i` commits to `w_i`, a binding commitment to `y_i`, or both.
- Prove validators cannot adapt `y_i` after seeing peers' commitments.
- Specify the opening/verification relation used by the aggregator.

### Round 2: Challenge and Partial Signature

After at least `t` commitments are canonically ordered, all parties derive:

```text
c = H("challenge" || sid || V || t || pk_epoch || M || C_1 || ... || C_t)
```

Validator `i` computes a partial response:

```text
z_i = y_i + c * s1_i
```

with corresponding hint material:

```text
h_i = Hint_i(...)
```

and performs local rejection checks:

```text
||z_i||_infty < B_z
hint_count(h_i) <= B_h
```

The scaffold represents partial shares as:

```text
PartialSignatureShare { signer, bytes }
PqcThresholdWireMsg::PartialSignature
state::AwaitingPartialSignatures {
    global_challenge,
    partial_shares,
}
```

Publication requirement:

- Define the exact partial-share byte encoding.
- Define per-share verification against Round 1 commitments.
- Define the exact local rejection rule and distribution-preservation argument.

### Aggregation

Given a valid set `S` of size at least `t`, the aggregator combines partial
responses using Lagrange coefficients:

```text
lambda_i = product_{j in S, j != i} x_j / (x_j - x_i) mod q
z        = sum_{i in S} lambda_i * z_i
```

Rust mapping:

```text
compute_lagrange_coefficient
reconstruct_secret_poly
SimulatedAggregator::aggregate_shares
```

Current limitation:

- `SimulatedAggregator` produces deterministic test bytes, not a valid
  ML-DSA-65 signature.

Publication requirement:

- Prove the aggregated `z` and hint values are distributed as required by
  ML-DSA-65.
- Prove the final `sigma = (c_tilde, z, h)` verifies under the unmodified
  ML-DSA-65 verifier.

## Transcript and Canonical Ordering

All hashes must bind:

- protocol label
- protocol version
- domain separator
- `sid`
- `t`
- ordered validator set
- public key
- message
- ordered commitments
- ordered partial-share metadata

Rust mapping:

```text
src/transcript.rs::SigningTranscript
src/collections.rs::CommitmentSet
src/collections.rs::PartialShareSet
```

Required invariant:

```text
H(transcript(network_order_1)) = H(transcript(network_order_2))
```

for any permutation of the same valid validator-indexed inputs.

## Wire Protocol

Adapter messages:

```text
DkgCommit
DkgShareExchange
SignCommit
PartialSignature
```

Rust mapping:

```text
src/adapter/wire.rs::PqcThresholdWireMsg
```

The wire codec is canonical and versioned. It is not the production L1 wire
protocol. A production integration must bind transport peer identity to
`validator_index` and reject index spoofing at the P2P boundary.

## Evidence and Fault Attribution

Current evidence classes:

```text
MalformedWireMessage
DuplicateMessage
CommitmentWithoutPartial
InvalidPartialSignature
SessionTimeout
```

Rust mapping:

```text
src/adapter/evidence.rs::EvidenceKind
src/adapter/evidence.rs::SlashingEvidence
src/adapter/evidence.rs::SlashingEvidencePayload
```

Publication requirement:

- Define algebraic evidence for invalid partial shares.
- Define transcript evidence for equivocation.
- Define liveness evidence separately from slashable safety faults.
- Prove evidence verification is deterministic and does not require secret
  material.

## Implementation Boundary

The current crate has three layers:

```text
crypto/math scaffold:
  src/low_level/poly.rs
  src/crypto/vss.rs
  src/crypto/interpolation.rs

protocol and backend boundary:
  src/protocol.rs
  src/transcript.rs
  src/backend.rs
  src/aggregation.rs
  src/dkg.rs

adapter and empirical harness:
  src/adapter/*
  src/utils/exporter.rs
  src/main.rs
```

## Publication Readiness Checklist

The project becomes publishable only after:

- A concrete threshold ML-DSA-65 protocol is fully specified.
- Real ML-DSA polynomial internals replace simulation bytes.
- DKG randomness and commitments are cryptographically sound.
- The aggregate signature verifies with an unmodified ML-DSA-65 verifier.
- Rejection sampling is proven not to leak or bias secrets.
- Malicious-party behavior is proven safe under the stated adversary model.
- Constant-time claims are backed by implementation review and timing tests.
- Benchmarks are reproducible from committed scripts and artifacts.
