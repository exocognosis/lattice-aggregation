# Production VSS Backend Design Spec

Date: 2026-05-25

## Status

This document specifies the production VSS/DKG backend that should eventually
replace the deterministic transcript-hash scaffold in `src/crypto/vss.rs`.

It is a design target and proof checklist. It is not an implementation claim.
The current backend remains `TranscriptHashVssCommitmentBackend`, whose
commitments and proofs are deterministic SHAKE transcript digests used for
integration tests. The tests in `tests/dkg_vss_soundness.rs` exercise algebraic
reconstruction, trait boundaries, structural checks, and the policy gate that
rejects the scaffold for production-security claims; they do not establish
malicious-secure VSS or DKG.

Current publication boundaries are tracked in
`docs/cryptography/claims-matrix.md`, `docs/cryptography/security-model.md`,
and `docs/cryptography/formal-proof-scaffold.md`.

## Purpose and Non-Goals

Purpose:

- Define the mathematical VSS relation that a production backend must enforce.
- Specify public parameters, commitment objects, opening objects, proof objects,
  verification, transcript binding, complaint evidence, and feature-gating.
- Give implementers a precise replacement target for
  `VssCommitmentSecurityProfile::ProductionBindingHiding`.
- State assumptions and open proof obligations without claiming that they are
  complete.

Non-goals:

- This document does not select a final concrete commitment scheme.
- This document does not prove a complete DKG theorem.
- This document does not claim that production VSS is implemented.
- This document does not claim adaptive security, side-channel security, or
  production network liveness.
- This document does not replace the threshold ML-DSA proof obligations in
  `docs/cryptography/formal-proof-scaffold.md`.

The intended first security target is static active security for at most `f`
corrupted validators, as described in `docs/cryptography/security-model.md`.

## Public Parameters

Let:

```text
V = {1, ..., N}
t = threshold
f = static active corruption bound
q = 8380417
n = 256
R_q = Z_q[X] / (X^n + 1)
```

Validator identifiers are one-based epoch indices. A production DKG instance
MUST bind all public objects to:

```text
protocol_id
backend_id
backend_version
epoch_id
session_id
validator_set_digest
dealer_index
receiver_index, when receiver-specific
N
t
q
n
scheme_parameters
```

The Rust boundary now exposes `ProductionVssRelationStatement` as a fixed-width
canonical statement for the receiver-specific VSS relation. It is not a proof
object and does not implement the production VSS relation. It exists so backend
implementers, evidence formats, and formal documentation bind the same public
inputs before any backend may claim
`VssCommitmentSecurityProfile::ProductionBindingHiding`.

The canonical field order is:

```text
protocol_version
epoch_id
session_id
validator_set_digest
backend_id
dealer_index
receiver_index
threshold
total_nodes
dealer_commitment_digest
encrypted_share_digest
opening_digest
public_key_contribution_digest
```

`statement_digest()` hashes those fixed-width canonical bytes under the
`dytallix.threshold.vss.production-relation-statement.v1` domain. The statement
rejects zero schema versions, invalid threshold parameters, dealer index zero,
receiver index zero, and participant indices outside the epoch set.

Adapter evidence for invalid hazmat ML-DSA shares now records the digest of a
session-derived `ProductionVssRelationStatement` alongside the existing
experimental complaint-evidence bytes. That digest binds the observed evidence
to the public VSS inputs a future production backend must verify. It is not a
cryptographic VSS proof and must not be treated as production slashing evidence
without the relation implementation and proof obligations below.

The backend MUST reject `t = 0`, `N = 0`, and `t > N`. A threshold-signing
deployment that composes with BFT consensus is expected to instantiate
parameters satisfying:

```text
N >= 3f + 1
t >= 2f + 1
f < t
```

The VSS primitive itself should be specified for generic `N`, `t`, and `f`
rather than relying on consensus scheduling assumptions.

The coefficient domain for the DKG secret polynomial is `R_q`. Each dealer `d`
samples a polynomial:

```text
F_d(X) = A_{d,0} + A_{d,1} X + ... + A_{d,t-1} X^(t-1)
```

where each `A_{d,j} in R_q`. The constant coefficient `A_{d,0}` contributes to
the epoch secret. All non-constant coefficients MUST be sampled with
cryptographic randomness from the distribution required by the final DKG
construction and security proof. They MUST NOT use the deterministic masks
currently used by `split_secret_poly` in `src/crypto/vss.rs`.

## Share Relation

For dealer `d` and receiver `i`, the private share is:

```text
s_{d,i} = F_d(i) in R_q
```

with evaluation performed coefficient-wise modulo `q`:

```text
F_d(i) = sum_{j=0}^{t-1} A_{d,j} i^j mod q
```

A receiver accepts a dealer share only if it verifies against the dealer's
public commitment object and the bound DKG context. The core relation is:

```text
R_vss(ctx, C_d, i, s_{d,i}, open_{d,i}, pi_{d,i}) = 1
```

where:

- `ctx` is the canonical public DKG context.
- `C_d` is the dealer's public commitment to `F_d`.
- `i` is the receiver index.
- `s_{d,i}` is the receiver's private share.
- `open_{d,i}` is any receiver-specific opening material.
- `pi_{d,i}` is any proof needed to verify the opening without exposing
  unrelated coefficients or other receivers' shares.

The relation must imply:

1. Binding: for a fixed `ctx`, `d`, and `C_d`, no efficient adversary can make
   honest receivers accept shares that are not evaluations of a single
   degree-`t - 1` polynomial, except with negligible probability.
2. Receiver privacy: public transcript data and complaint evidence do not reveal
   honest receivers' unopened shares beyond what follows from corrupted
   receivers' shares and public outputs.
3. Subset consistency: any accepted set of at least `t` shares for the same
   dealer reconstructs the same `A_{d,0}`.
4. Public-key consistency: the epoch public key contribution derived from
   accepted dealer commitments is deterministic and matches the committed
   constant term under the selected commitment scheme.

The final epoch share held by receiver `i` is:

```text
s_i = sum_{d in AcceptedDealers} s_{d,i} mod q
```

The final epoch public key is derived deterministically from the accepted
dealers' public constant commitments. The derivation rule is an open
scheme-specific item and must be fixed before implementation.

## Commitment, Opening, and Proof Objects

The production backend should replace `VssShareCommitment` and `VssShareProof`
semantics with objects that carry a concrete VSS relation. The names below are
conceptual; the Rust API may preserve the existing trait boundary while changing
serialized internals under a new backend ID.

### Dealer Commitment

`DealerCommitment` is public and contains:

```text
context_digest
dealer_index
commitment_scheme_id
commitment_scheme_version
coefficient_commitments or polynomial_commitment
public_key_contribution
commitment_randomness_commitment, if required by the scheme
serialization_version
```

Requirements:

- It MUST be binding to one degree-`t - 1` polynomial over `R_q`.
- It MUST support verification of receiver openings.
- It MUST bind the dealer identity and validator set.
- It MUST be canonical-encoded before hashing or signing.
- It MUST expose only public data required by the DKG and later threshold
  signing proof.

### Share Opening

`ShareOpening` is sent privately from dealer `d` to receiver `i` over an
authenticated confidential channel and contains:

```text
context_digest
dealer_index
receiver_index
encrypted_or_plain_private_share_payload
opening_material
opening_nonce_or_label, if required
```

If the production transport encrypts shares outside the VSS object, the opening
still must bind to the ciphertext or transport transcript so equivocation is
evidentiary. The plaintext share must never appear in the public DKG transcript
except as part of a valid complaint.

### Share Proof

`ShareProof` proves that the receiver-specific share opens the public dealer
commitment:

```text
pi_{d,i}: proves R_vss(ctx, C_d, i, s_{d,i}, open_{d,i}) = 1
```

Requirements:

- It MUST be sound for the selected relation.
- It MUST be zero-knowledge or share-hiding for any statement that would
  otherwise reveal honest private-share material.
- It MUST bind `ctx`, `dealer_index`, `receiver_index`, `C_d`, and the exact
  opened share representation.
- It MUST be non-malleable enough for complaint evidence to identify the dealer
  and session being disputed.

The current `VssShareProof` in `src/crypto/vss.rs` is only a transcript digest
over context and commitment bytes. It is not a production proof object.

## Verification Algorithm

The production verifier is deterministic. For each dealer `d` and receiver `i`,
it takes:

```text
VerifyVssShare(ctx, d, i, C_d, opening_{d,i}, pi_{d,i}) -> accept | reject
```

Algorithm:

1. Parse all objects using canonical, length-bounded encodings.
2. Reject if `ctx` has invalid parameters, including `t = 0`, `N = 0`, or
   `t > N`.
3. Reject if `d` or `i` is outside `1..=N`.
4. Reject if `C_d`, `opening_{d,i}`, or `pi_{d,i}` binds a different
   `context_digest`, dealer index, receiver index, backend ID, or version.
5. Reject duplicate dealer commitments for the same `ctx` and dealer index.
6. Reject duplicate receiver openings for the same `(ctx, d, i)` unless the
   duplicate is byte-identical and accepted by the replay policy.
7. Check that `C_d` encodes a valid commitment under the selected scheme and
   the declared public parameters.
8. Decrypt or receive the private share through the authenticated confidential
   share-delivery layer.
9. Verify `pi_{d,i}` for the relation:

   ```text
   R_vss(ctx, C_d, i, s_{d,i}, open_{d,i}, pi_{d,i}) = 1
   ```

10. Reject on any proof failure, malformed coefficient, invalid norm/range
    predicate, or inconsistent public-key contribution.
11. Accept only after every bound context field and scheme predicate has been
    checked.

For batch verification, the verifier also checks:

```text
exactly one commitment per accepted dealer
at most one opening per (dealer, receiver)
accepted dealer set is canonical
accepted dealer set is bound into epoch public key derivation
```

The verifier MUST NOT depend on aggregator honesty or network message order.

## Complaint and Slashing Evidence

Complaint evidence is public data that lets third parties deterministically
verify a cryptographic DKG fault. It is separate from liveness evidence, which
requires consensus-layer timeout policy and should not be treated as a pure
cryptographic slashing proof.

The feature-gated `experimental-vss` path may expose an
`ExperimentalVssComplaintEvidence` frame as canonical serialization and
verifier scaffolding only. Its purpose is to shape the eventual evidence
boundary, not to establish a production slashing condition. The frame should
carry a statement, opening, and proof container with explicit dealer,
receiver/complainant, and DKG context attribution. All sub-objects should use
fixed-width canonical encodings; the structural verifier should reject context
mismatches between the statement and opening, identity mismatches between the
evidence frame and its sub-objects, malformed lengths, and a proof whose
statement digest does not match the canonical statement bytes. Passing those
checks only means the evidence is internally well formed. It does not validate
the VSS relation, does not prove dealer misbehavior, and is not yet a
production slashing proof.

Valid cryptographic complaint evidence should include:

```text
evidence_version
context_digest
epoch_id
session_id
validator_set_digest
dealer_index
complainant_receiver_index
dealer_commitment_bytes
opening_or_ciphertext_bytes
decryption transcript or receiver-local opening, if needed
share_proof_bytes
verification_failure_code
complainant signature over the evidence frame
```

Evidence verifier:

```text
VerifyVssComplaint(evidence) -> valid_fault | invalid_evidence
```

The evidence verifier must:

1. Recompute `context_digest`.
2. Check canonical encodings and identity bounds.
3. Verify the complainant signature under the epoch validator identity.
4. Re-run `VerifyVssShare`.
5. Return `valid_fault` only for deterministic failures attributable to the
   dealer, such as malformed commitment bytes, invalid opening bytes,
   inconsistent proof, invalid ciphertext binding, or a public-key contribution
   that does not match the committed polynomial.
6. Refuse to slash for missing messages or timeout-only behavior unless a
   separate consensus policy explicitly defines that fault class.

The complaint system must prevent framing honest validators. In particular,
evidence must not allow a corrupted receiver to alter a valid private opening
into invalid-looking public evidence without detection. The exact anti-framing
argument is scheme-specific and remains an open proof obligation.

## Transcript Binding and Domain Separation

Every hash, commitment challenge, proof challenge, encryption label, evidence
frame, and public-key derivation must use an explicit domain separator. Domain
strings should be stable ASCII byte strings with version suffixes, for example:

```text
dytallix.vss.production.context.v1
dytallix.vss.production.dealer-commitment.v1
dytallix.vss.production.share-opening.v1
dytallix.vss.production.share-proof.v1
dytallix.vss.production.complaint-evidence.v1
dytallix.vss.production.epoch-public-key.v1
```

The current scaffold domains:

```text
dytallix.vss.share.commitment.scaffold.v1
dytallix.vss.share.proof.scaffold.v1
```

MUST NOT be reused for production objects.

The canonical DKG context digest is:

```text
ctx_digest = H_vss_context(
    protocol_id,
    backend_id,
    backend_version,
    epoch_id,
    session_id,
    validator_set_digest,
    N,
    t,
    q,
    n,
    scheme_parameters
)
```

All object encodings must be unambiguous, length-bounded, and ordered by
canonical validator index. Transcript binding must remove any dependence on
network delivery order, proposer ordering, or aggregator-local maps.

## Feature-Gating and Status

The current VSS code exposes:

```text
VssCommitmentSecurityProfile::DeterministicTranscriptScaffold
VssCommitmentSecurityProfile::ProductionCandidateScaffold
VssCommitmentSecurityProfile::ProductionBindingHiding
ExperimentalVssCommitmentBackend, under the experimental-vss feature
ExperimentalVssStatement, under the experimental-vss feature
ExperimentalVssOpening, under the experimental-vss feature
ExperimentalVssProof, under the experimental-vss feature
try_reconstruct_secret_poly(...)
try_reconstruct_secret_poly_with_threshold(...)
require_production_vss_backend(...)
```

Production code must preserve an explicit status gate:

- The deterministic transcript-hash backend remains available only for tests,
  simulations, and research-scaffold artifacts.
- The feature-gated `ExperimentalVssCommitmentBackend` is a production-shaped
  candidate scaffold only. It must fail closed and must not pass
  `require_production_vss_backend(...)`.
- The feature-gated experimental statement, opening, and proof objects provide
  fixed-width canonical serialization for the future relation. They are not
  prover/verifier implementations and do not make the candidate backend
  production-secure.
- Any feature-gated experimental complaint evidence object is a structural
  evidence frame only. It may check canonical lengths, dealer/receiver/context
  attribution, context equality, and proof statement-digest binding, but it
  must not be described as validating the VSS relation or as sufficient for
  production slashing.
- A production backend must declare a distinct backend ID and version.
- Calling production DKG setup with a scaffold backend must fail closed.
- Production-security claims must require
  `VssCommitmentSecurityProfile::ProductionBindingHiding` or a stricter future
  profile.
- Declaring the production profile is only a policy marker. It is not an audit
  and is not sufficient for publication without the proof obligations below.

Documentation, CLI output, benchmark reports, and manuscript text must continue
to distinguish scaffold evidence from production VSS security. The wording
constraints in `docs/cryptography/claims-matrix.md` remain authoritative until
the production backend, proof, and review gates are complete.

## Proof Obligations

A complete production VSS/DKG claim requires at least the following obligations:

1. Commitment binding: a dealer cannot make honest receivers accept shares that
   are inconsistent with one degree-`t - 1` polynomial.
2. Share hiding: public commitments, proofs, and complaint-resistant transcript
   data do not reveal unopened honest receiver shares.
3. Complaint soundness: invalid dealer behavior is attributable by deterministic
   public evidence, and honest dealers cannot be framed by malformed receiver
   evidence except with negligible probability.
4. Subset consistency: any honest accepted subset of size at least `t`
   reconstructs the same dealer secret contribution.
5. Epoch-key consistency: all honest validators derive the same epoch public key
   from the same accepted dealer set and commitment transcript.
6. Rogue-key resistance: corrupted dealers cannot bias or replace the epoch
   public key outside the committed DKG relation.
7. Transcript binding: an adversary cannot change DKG acceptance or epoch-key
   derivation through message reordering, duplicate delivery, or equivocation
   across validators.
8. Composition with threshold ML-DSA: accepted VSS shares satisfy the assumptions
   used by the signing proof in `docs/cryptography/formal-proof-scaffold.md`.
9. Selective-abort accounting: DKG exclusion, retry, and complaint policy do not
   introduce an unbounded key-bias or challenge-bias channel.
10. Implementation fidelity: serialized Rust objects implement exactly the
    mathematical relation used in the proof.
11. Side-channel scope: either exclude side-channel resistance from the claim or
    complete a constant-time/leakage review for secret-dependent share handling.
12. Adaptive security scope: either exclude adaptive corruption from the theorem
    or define erasure semantics and prove the adaptive game.

These obligations are assumptions and open work items until a concrete scheme,
implementation, tests, and proof are completed.

## Implementation Checklist

Before replacing the scaffold backend, implementation work should complete:

- Select the concrete VSS commitment/proof scheme and document its assumptions.
- Define canonical encodings for context, dealer commitments, share openings,
  proofs, accepted-dealer sets, and complaint evidence.
- Add a production backend ID, version, and domain separators distinct from
  scaffold domains.
- Implement cryptographic coefficient sampling; remove deterministic masks from
  production DKG paths.
- Implement authenticated confidential share delivery or bind VSS openings to
  the production transport ciphertext transcript.
- Implement dealer commitment generation and verification.
- Implement receiver-specific share opening verification.
- Implement share proof generation and verification.
- Implement accepted-dealer set canonicalization and epoch public key
  derivation.
- Implement complaint evidence construction and deterministic verification.
- Ensure production setup fails closed unless the selected backend declares a
  production security profile.
- Ensure threshold production setup also passes the combined policy gate in
  `src/crypto/production_policy.rs`, which requires both the VSS backend and
  the contribution proof backend to declare production relations.
- Add negative tests for malformed encodings, duplicate dealers, duplicate
  receiver openings, wrong context, wrong dealer, wrong receiver, invalid proof,
  invalid public-key contribution, and complaint anti-replay.
- Add interoperability tests for canonical encodings and transcript hashes.
- Add proof-to-code mapping notes linking each verifier predicate to the formal
  relation.
- Update `docs/cryptography/claims-matrix.md` only after implementation and
  proof status changes are actually true.
- Obtain external cryptographic review before using production-ready wording.

Until this checklist and the proof obligations are closed, the project should
describe VSS/DKG as a scaffold with a specified production replacement target,
not as an implemented malicious-secure DKG.
