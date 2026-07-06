# Formal Threshold ML-DSA Transcript

Status: transcript-binding proof target with required completion artifacts.

Date: 2026-05-27

<a id="ftmt-0-scope"></a>
## FTMT-0. Scope

This document records the stable transcript-binding references for threshold
ML-DSA-65. It is intentionally aligned with `src/transcript.rs` and the
random-oracle model in `random-oracle-game.md`.

The current implementation binds the signing challenge to the protocol label
`lattice-aggregation/threshold-mldsa65`, protocol version `1`, session ID,
threshold, canonical validator set, threshold public key, raw message bytes,
and ordered commitment set. This is implementation traceability for the
deterministic scaffold, not a production threshold ML-DSA proof.

<a id="ftmt-1-transcript-tuple"></a>
## FTMT-1. Transcript Tuple

The signing transcript tuple is:

```text
T = (label, version, sid, t, V, pk, m, Com)
```

where:

- `label = lattice-aggregation/threshold-mldsa65`
- `version = 1`
- `sid` is the 32-byte signing session identifier
- `t` is the threshold
- `V` is the canonical ordered validator set
- `pk` is the threshold public key
- `m` is the message bytes currently bound by `SigningTranscript::new`
- `Com` is the ordered validator-to-commitment map

Production proof work may replace or supplement `m` with the message-binding
representative `mu`, but it must do so under the `H_mu` rules in
`random-oracle-game.md#rog-d1-h-mu` and must preserve a
single unambiguous challenge input.

<a id="ftmt-2-challenge-derivation"></a>
## FTMT-2. Challenge Derivation

The implemented challenge derivation is the `H_c` surface described in
`random-oracle-game.md#rog-d3-h-c`:

```text
c = H_c(sid, t, V, pk, m, Com)
```

`src/transcript.rs` derives `c` by hashing the label, version, fixed-width
session and threshold fields, validator count and IDs, public key, message
length and bytes, commitment count, and ordered `(validator, commitment)` pairs
with SHAKE256, then reading 32 output bytes.

The challenge must be derived only after the commitment set is fixed. The
commitment precondition is modeled by the `H_w` domain in
`random-oracle-game.md#rog-d2-h-w`.

<a id="ftmt-3-binding-invariants"></a>
## FTMT-3. Binding Invariants

The transcript-binding proof must establish:

- Canonical encoding injectivity for all transcript fields.
- Validator-set uniqueness and canonical ordering.
- Commitment-set uniqueness and canonical ordering.
- Message binding through either raw `m` or the production `mu` value.
- Non-portability of commitments, partial shares, and contribution proofs
  across `sid`, `t`, `V`, `pk`, message binding value, `Com`, and `c`.
- Replay rejection according to `random-oracle-game.md#rog-4-replay-concurrency`.

These invariants correspond to FST-L1, FST-L2, FST-L3, and FST-L4 in
`formal-security-theorem.md`.

<a id="ftmt-4-implementation-traceability"></a>
## FTMT-4. Implementation Traceability

Current implementation references:

- `src/transcript.rs`: constructs `SigningTranscript` and derives `Challenge`.
- `src/collections.rs`: validates canonical commitment and partial-share sets.
- `src/protocol.rs`: enforces commitment collection before partial-signature
  generation in the public type-state flow.
- `src/adapter/wire.rs`: carries session, validator, and commitment fields in
  versioned adapter frames.

The deterministic backend labels in `src/backend.rs` and `src/dkg.rs` are test
machinery labels. They are not production random-oracle domains unless a later
proof explicitly promotes and analyzes them.

<a id="ftmt-5-stable-anchors"></a>
## FTMT-5. Stable Anchors

Keep these anchors stable when reorganizing this document:

- `ftmt-0-scope`
- `ftmt-1-transcript-tuple`
- `ftmt-2-challenge-derivation`
- `ftmt-3-binding-invariants`
- `ftmt-4-implementation-traceability`
- `ftmt-5-stable-anchors`
