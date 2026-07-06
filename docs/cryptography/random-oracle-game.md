# Random-Oracle Game for Threshold ML-DSA-65

Status: proof target with required completion artifacts.

Date: 2026-05-27

## ROG-0. Scope

This document defines the random-oracle game and domain-separation obligations
for the threshold ML-DSA-65 proof package. It complements
`formal-security-theorem.md`, `ideal-functionality.md`, and
`formal-threshold-mldsa-transcript.md`.

The current Rust implementation is a deterministic scaffold. In particular,
`src/transcript.rs` implements the signing-challenge derivation with SHAKE256
over the label `lattice-aggregation/threshold-mldsa65`, protocol version `1`,
and canonical transcript fields. The production proof may model that derivation
as the challenge random oracle `H_c`, but this document does not claim the
current backend implements production ML-DSA signing, VSS, or proof-carrying
contributions.

## ROG-1. Encoding Discipline

All random-oracle inputs are typed encodings. The proof must use one canonical
encoding function:

```text
Enc(domain, version, fields...)
```

with the following rules:

- Every oracle input starts with a protocol domain label and version.
- Fixed-width integers are big-endian.
- Variable-length byte strings are length-prefixed.
- Ordered sets include their element count and then elements in canonical
  validator order.
- Validator identifiers are serialized as their canonical integer encoding.
- Public keys, commitments, partial shares, proofs, and evidence artifacts are
  encoded as typed fields, never as untagged byte concatenations.

The implementation challenge encoding in `src/transcript.rs` follows this
shape for the signing transcript: label, version, session ID, threshold,
validator count and validator IDs, public key, message length and bytes,
commitment count, and ordered `(validator, commitment)` pairs.

## ROG-2. Oracle Domains

The proof treats each domain label below as an independent random oracle. If a
concrete implementation realizes several domains with SHAKE256, the proof must
show that labels and encodings are prefix-free enough to justify independent
oracle modeling.

<a id="rog-d1-h-mu"></a>
### ROG-D1. Message-Binding Oracle `H_mu`

Purpose: bind the user message and key context before ML-DSA challenge
derivation.

Recommended domain:

```text
lattice-aggregation/threshold-mldsa65/ro/mu/v1
```

Input:

```text
(key_id or epoch, t, V, pk, message_context, m)
```

Output: `mu`, the message representative used by the production ML-DSA signing
relation.

Obligation: the proof must state whether the signing transcript binds raw
message bytes `m`, a prehash `mu`, or both. The current scaffold binds raw
`m` directly in `SigningTranscript::new`; a production backend that signs `mu`
must prove that the same message-binding value is used consistently by honest
partial signing, aggregation, standard verification, evidence, and simulation.

<a id="rog-d2-h-w"></a>
### ROG-D2. Commitment and `w`-Binding Oracle `H_w`

Purpose: bind each validator to its public masking contribution before the
Fiat-Shamir challenge is derived.

Recommended domain:

```text
lattice-aggregation/threshold-mldsa65/ro/commitment/v1
```

Input:

```text
(sid, t, V, pk, mu or m, id_i, attempt, public_w_i, commitment_statement_i)
```

Output: the public commitment digest `com_i` for validator `id_i`, or the
challenge material used by a concrete statistically or computationally binding
commitment scheme.

Obligation: an honest participant must publish `com_i` before learning `H_c`
for the same signing session. A partial share for `id_i` is admissible only if
its verified opening or proof binds to the exact `com_i` included in the
ordered commitment set `Com`.

<a id="rog-d3-h-c"></a>
### ROG-D3. Signing-Challenge Oracle `H_c`

Purpose: derive the threshold ML-DSA Fiat-Shamir challenge after commitments
are fixed.

Implemented scaffold domain:

```text
lattice-aggregation/threshold-mldsa65
```

Implemented scaffold version: `1`.

Input:

```text
(sid, t, V, pk, m, Com)
```

where `V` is canonical and `Com` is an ordered map of validator identifiers to
commitments.

Output: 32-byte `Challenge c`.

Obligation: `H_c` must be queried only after the commitment set for the session
is fixed. Any change to `sid`, `t`, `V`, `pk`, `m` or `mu`, or ordered `Com`
must produce a distinct oracle input. In the current code this obligation maps
to `SigningTranscript::new` and `derive_challenge`.

<a id="rog-d4-h-vss"></a>
### ROG-D4. VSS and DKG Proof Oracle `H_vss`

Purpose: domain-separate non-interactive proof challenges used by production
VSS, DKG, complaint, and dealer-contribution relations.

Recommended domain:

```text
lattice-aggregation/threshold-mldsa65/ro/vss-proof/v1
```

Input:

```text
(dkg_session, epoch, t, V, dealer_id, receiver_id optional,
 coefficient_commitments, encrypted_shares, dealer_key_contribution,
 complaint_or_response_context, proof_statement)
```

Output: proof-system challenge bytes.

Obligation: every VSS proof, complaint response, and dealer contribution proof
must bind the same epoch, threshold, validator set, dealer, receiver when
applicable, commitment transcript, and message type. The deterministic
`src/crypto/vss.rs` and `src/dkg.rs` scaffolds do not instantiate this oracle.

<a id="rog-d5-h-contrib"></a>
### ROG-D5. Signing Contribution-Proof Oracle `H_contrib`

Purpose: domain-separate proof challenges that show a partial signing
contribution is consistent with the participant's commitment, key-share
metadata, and the bound transcript.

Recommended domain:

```text
lattice-aggregation/threshold-mldsa65/ro/contribution-proof/v1
```

Input:

```text
(sid, t, V, pk, mu or m, Com, c, id_i, com_i,
 public_share_metadata_i, partial_share_statement_i, proof_statement)
```

Output: proof-system challenge bytes.

Obligation: a valid contribution proof must not be portable across validator
identities, sessions, messages, public keys, commitment sets, or challenges.
The production proof must state whether this proof is zero-knowledge,
witness-hiding, extractable, publicly verifiable, or replaced by an audited MPC
verification relation.

## ROG-3. Random-Oracle Game

Game `ROG-G1` is parameterized by the security parameter `lambda`, threshold
parameters `(t, V)`, public key `pk`, and the oracle domains in ROG-2.

Setup:

1. The challenger initializes lazy-sampled random-oracle tables for `H_mu`,
   `H_w`, `H_c`, `H_vss`, and `H_contrib`.
2. The challenger registers one key epoch `(key_id, t, V, pk)` and gives all
   public epoch data to the adversary.
3. The adversary receives oracle access, scheduling control, and corruption
   capabilities allowed by `formal-security-theorem.md` and
   `ideal-functionality.md`.

Signing query:

1. The adversary requests a signing session `(sid, m, requested_signers)`.
2. Honest parties compute or receive the message-binding value `mu` according
   to ROG-D1.
3. Each honest signer commits to its local `w_i` contribution under ROG-D2
   before `H_c` is queried for the session.
4. The ordered commitment set `Com` is formed only from commitments that pass
   collection validation.
5. The signing challenge is `c = H_c(sid, t, V, pk, m or mu, Com)`.
6. Honest partial shares and their contribution proofs bind to `c`, `Com`, and
   the validator identity under ROG-D5.
7. Aggregation or rejection proceeds according to the protocol and the ideal
   functionality mapping.

Adversarial queries: the adversary may query any oracle on any input, including
inputs for sessions that are never authorized. The challenger answers
consistently from the corresponding lazy table.

Winning events:

- Transcript collision: two distinct typed transcript tuples produce the same
  `H_c` input accepted by the protocol.
- Replay: a commitment, partial share, proof, or aggregate signature from one
  typed session is credited in a different typed session.
- Challenge malleability: the adversary obtains an accepted partial or
  aggregate signature under a challenge not equal to the `H_c` value for the
  accepted transcript.
- Proof portability: a VSS or contribution proof verifies under a context
  different from the one used when it was generated.
- Unauthorized signing: the adversary outputs a valid ML-DSA signature for a
  message not authorized by `F_TMLDSA`, except by breaking an explicitly listed
  assumption.

<a id="rog-4-replay-concurrency"></a>
## ROG-4. Replay and Concurrency Rules

Rule ROG-R1, session uniqueness. A `sid` is unique within a key epoch. Reusing
`sid` with a different message or signer universe is rejected or recorded as
evidence when attributable.

Rule ROG-R2, exact-context reuse only. A commitment, partial share, VSS proof,
contribution proof, complaint, or evidence record is valid only for the exact
typed context encoded into its oracle input.

Rule ROG-R3, concurrent sessions. Concurrent sessions are allowed only because
their oracle inputs include distinct `sid` values, message-binding values, or
commitment sets.

Rule ROG-R4, aggregate idempotence. Re-releasing an already accepted aggregate
for the same transcript must not create a fresh oracle-programming opportunity
unless the production protocol explicitly models rerandomized signatures.

<a id="rog-5-simulator-programming"></a>
## ROG-5. Simulator Programming Obligations

A real/ideal simulator that programs random oracles must maintain one global
table per domain and satisfy these obligations:

- It may program `H_mu` only consistently with the authorized message relation
  exposed by `F_TMLDSA`.
- It may program honest `H_w` or commitment-proof outputs only before the
  adversary has received values that would make later reprogramming detectable.
- It may program `H_c` only on the exact accepted transcript tuple
  `(sid, t, V, pk, m or mu, Com)`.
- It must answer adversarial prior queries consistently; if the adversary
  queried an input before programming, the simulator must either use the
  existing value or account for the collision/probability loss.
- It must not program one domain to satisfy a query in another domain.
- It must preserve consistency across concurrent sessions and retries.
- It must translate malformed, duplicate, invalid, and missing contributions to
  the evidence events allowed by `ideal-functionality.md` without exposing
  honest secret shares or honest one-time masks.

Any proof that relies on programmability must state the bad events, probability
loss, and extraction points explicitly.

## ROG-6. Required Proof Artifacts

The complete proof package must supply:

- ML-DSA-65 unforgeability.
- Threshold signing correctness.
- VSS/DKG soundness, hiding, or extractability.
- Soundness of production contribution proofs.
- That the deterministic simulation backend realizes these oracle domains.

Those remain separate proof obligations in the formal theorem package.
