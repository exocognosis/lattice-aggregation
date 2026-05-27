# Contribution Soundness Relation Worksheet

Date: 2026-05-27

Anchor: `contribution-soundness-relation`

## Status

This worksheet defines the target production contribution
soundness/extractability relation for threshold ML-DSA-65. It is a relation
specification and proof-planning artifact, not a completed proof and not a
claim that the current proof-bearing contribution scaffold is sound.

The existing scaffold gives the protocol an explicit proof-bearing boundary,
canonical public-input digest discipline, and a fail-closed production policy
gate for non-production backends. Those are useful integration constraints.
They do not prove algebraic correctness, knowledge soundness, zero knowledge,
MPC privacy, ML-DSA bound satisfaction, or extractability for accepted
contributions.

The production relation below is the intended replacement target for the open
Game 4 obligation in `formal-proof-scaffold.md` and PO-2 in
`proof-obligations.md`.

## Public Statement

Anchor: `csr-production-statement`

The production verifier receives a public statement `S_contrib` and proof or
verification artifact `pi_contrib`. The statement must be canonical,
domain-separated, injectively encoded, and sufficient for verification without
reading secret-dependent payload bytes.

The initial production statement is the canonical
`ProductionContributionStatement` digest target:

```text
protocol_version
epoch_id
session_id
block_height
attempt
validator_index
threshold
total_nodes
validator_set_digest
public_key_digest
parameter_set_digest
mu
challenge
dkg_commitment_digest
masking_commitment_digest
secret_commitment_digest
contribution_commitment_digest
```

The statement domain is:

```text
dytallix.threshold.contribution.production-statement.v1
```

A production successor may extend the public statement, but only by assigning a
new protocol/schema version and a new domain or explicitly versioned field map.
New proof-relevant context must not be hidden inside opaque payload bytes.

The statement fields have the following intended meaning:

- `protocol_version`: the threshold signing protocol version and statement
  schema version.
- `epoch_id`: the DKG epoch whose public commitments and epoch key are used.
- `session_id`: the signing session identifier.
- `block_height` and `attempt`: consensus and retry context for the signing
  attempt.
- `validator_index`: the contributor identity within the epoch validator set.
- `threshold` and `total_nodes`: the Shamir reconstruction parameters.
- `validator_set_digest`: a digest of the canonical validator set and ordering.
- `public_key_digest`: a digest of the epoch ML-DSA public key.
- `parameter_set_digest`: a digest or fixed identifier for ML-DSA-65
  parameters and any threshold-specific parameter choices.
- `mu`: the message representative used by the ML-DSA signing equations.
- `challenge`: the ML-DSA-compatible challenge fixed after the required
  prechallenge commitments.
- `dkg_commitment_digest`: a digest of public DKG/VSS commitment material
  needed to bind the contributor share.
- `masking_commitment_digest`: a digest of prechallenge masking commitment
  material for this contributor and attempt.
- `secret_commitment_digest`: a digest of any postchallenge secret
  contribution commitment material.
- `contribution_commitment_digest`: a digest of the claimed public
  contribution encoding or commitment to that encoding.

The verifier must reject statements with invalid schema versions, invalid
threshold parameters, zero validator indices, validator indices outside the
epoch set, malformed fixed-width fields, unsupported parameter sets, or
non-canonical encodings.

## Witness Relation

The production witness `W_contrib` is the private material proving that the
claimed contribution is consistent with the public statement. Its exact shape
depends on the selected backend, but the relation must cover at least:

```text
validator secret share material derived from the accepted DKG relation
opening or witness material for masking commitments
opening or witness material for secret contribution commitments, if present
ephemeral masking values used for this session and attempt
intermediate ML-DSA partial terms needed for the contribution equation
claimed contribution encoding before public commitment/digest
randomness used by the production proof or MPC verification relation
```

The relation `R_contrib(S_contrib, W_contrib) = 1` must establish:

- The contributor identity in `S_contrib` owns a share consistent with the
  accepted DKG/VSS public commitment material for `epoch_id`.
- The share, challenge, masking material, and contribution encoding satisfy the
  selected threshold ML-DSA-65 partial-contribution equations.
- The masking and secret commitment witnesses open to the public commitment
  material bound by `S_contrib`.
- The claimed contribution encoding is exactly the value committed by
  `contribution_commitment_digest`.
- All parameter-specific ML-DSA-65 bound predicates required before aggregation
  hold for the partial contribution or are deferred to a separately named
  aggregation predicate with an explicit dependency.
- Attempt-local masking is fresh and bound to `(epoch_id, session_id,
  block_height, attempt, validator_index, challenge)`.
- Verification does not require disclosing `c*s1`, `c*s2`, `c*t0`, masking
  secrets, DKG private shares, or other secret-dependent witness material.

If the first production backend is not a zero-knowledge proof system, this same
relation still has to be made explicit for the reviewed MPC verification,
interactive proof, or other production mechanism. The proof obligation may use
that backend's native theorem, but the public statement and extracted target
must remain auditable against the same relation.

## Soundness Game

Anchor: `csr-soundness-game`

The target soundness game is parameterized by the ML-DSA-65 parameter set,
validator set `V = {1, ..., N}`, threshold `t`, static corruption bound
`f < t`, production DKG/VSS public commitment relation, and production
contribution proof backend.

1. The challenger samples or receives an accepted DKG epoch according to the
   selected DKG/VSS relation and publishes the epoch public material.
2. The adversary statically corrupts up to `f` validators and learns their
   private shares and local signing state.
3. The adversary adaptively chooses messages, sessions, scheduling, malformed
   frames, contribution statements, and proof artifacts, subject to authenticated
   validator identities and the public protocol syntax.
4. For each candidate contribution from validator `i`, the challenger computes
   or checks the canonical production statement `S_contrib` from the public
   transcript context and runs the production verifier on
   `(S_contrib, pi_contrib)`.
5. The adversary wins if an accepted contribution for any validator identity is
   not in the production relation, cannot be extracted to the target witness, or
   is bound to a different context than the one used for aggregation.

The soundness theorem must show that a polynomial-time adversary wins with at
most negligible probability, except by causing one of the explicitly named
failure events already tracked by the full proof:

```text
DkgSoundnessBreak
MaskingCommitmentBindingBreak
ChallengeBias
PartialProofSoundnessBreak
SelectiveAbortBias
AggregationEquationFailure
StandardVerificationMismatch
```

The game must treat a valid transcript-hash scaffold proof as irrelevant for
production soundness. Acceptance by the current scaffold is not an accepting
event in this game unless a separate production verifier also accepts the
production relation.

## Extraction Target

Anchor: `csr-extraction-target`

For every accepted adversarial contribution, the production proof theorem must
provide an extractor or equivalent verified output that yields:

```text
validator_index
epoch_id
session_id
block_height
attempt
challenge
claimed contribution encoding
share-consistency witness or proof-system-native witness handle
masking commitment openings or proof-system-native verified openings
secret contribution commitment openings, if applicable
ML-DSA partial-equation witness terms needed by the reduction
bound predicates or deferred aggregation predicates with explicit labels
```

The extracted object does not need to expose raw secrets to the implementation.
It must be sufficient for the formal reduction to replace accepted adversarial
contribution frames with relation witnesses in Game 4 of the proof scaffold.

The extraction target must be context-bound. An extracted witness for one
`epoch_id`, `session_id`, `block_height`, `attempt`, `validator_index`,
`challenge`, DKG commitment digest, masking commitment digest, secret
commitment digest, contribution commitment digest, `mu`, or parameter-set
digest must not verify for any different value of those fields.

If the selected backend gives only verification soundness rather than explicit
knowledge extraction, the proof must state the substitute target precisely:
for example, an accepted contribution can be replaced by an ideal valid partial
contribution with the same public encoding except with the backend soundness
error. The substitute must be strong enough for the threshold EUF-CMA reduction
and must be identified as a deviation from knowledge extraction.

## Witness-Hiding And Simulation Target

Anchor: `csr-witness-hiding-target`

The production relation must also provide a witness-hiding target appropriate
to the selected backend:

- For a zero-knowledge proof backend, there must be a simulator that produces
  proofs indistinguishable from real proofs given only `S_contrib`, the claimed
  public contribution encoding or commitment, and the public transcript.
- For an MPC verification backend, the transcript must reveal no more than the
  reviewed leakage function for the selected MPC protocol.
- For an interactive proof, the simulator and rewinding or programmability
  assumptions must be stated explicitly, including how they compose with the
  random-oracle challenge game.

The hiding target must cover at least:

```text
DKG private share material
masking secrets
secret contribution openings
c*s1-dependent terms
c*s2-dependent terms
c*t0-dependent terms
proof randomness
unused rejected-attempt secrets after required erasure points
```

The simulator for the full threshold signing proof must be able to produce
accepted contribution evidence for honest validators without knowing or leaking
extra secret-dependent state beyond the ideal functionality outputs, public
transcript, corrupted parties' shares, and any explicitly stated leakage
function.

Witness hiding is separate from soundness. A backend that is sound but leaks
secret-dependent witness material does not satisfy this production relation.

## Context-Binding Requirements

The production verifier must bind the proof to the exact transcript context
used by the aggregator. At minimum, verification must fail when any of these
fields is substituted:

```text
protocol_version
epoch_id
session_id
block_height
attempt
validator_index
threshold
total_nodes
validator_set_digest
public_key_digest
parameter_set_digest
mu
challenge
dkg_commitment_digest
masking_commitment_digest
secret_commitment_digest
contribution_commitment_digest
```

Context binding also requires:

- Domain separation between production statements, scaffold transcript hashes,
  DKG/VSS commitments, random-oracle challenges, contribution commitments, and
  final ML-DSA verification inputs.
- Canonical byte encoding with no alternate encodings for the same field value.
- Explicit parameter-set binding for ML-DSA-65 and any threshold-specific
  bounds.
- Authenticated mapping from transport identity to `validator_index`.
- Attempt-local freshness for masking material and rejection/retry state.
- A clear rule for whether `mu` directly includes consensus context or whether
  consensus context is audit metadata outside standard ML-DSA verification.
- No verifier dependence on raw hazmat payload bytes, debug output, artifact
  logs, or untyped side channels.

The current production statement digest check is a public-input binding guard.
It helps ensure future proof bytes are checked against the intended statement,
but it does not itself establish this context-binding theorem.

## Integration With The Existing Scaffold

The existing proof-bearing contribution scaffold remains useful as an API and
transcript boundary:

- It identifies where production proof bytes should live.
- It prevents production-labeled configuration from silently accepting known
  scaffold backends.
- It fixes current public-input digest discipline for the future statement.
- It gives tests a stable place to assert statement mutation and wire-binding
  behavior.

The bridge to production is therefore:

```text
current scaffold boundary
  -> canonical production statement digest
  -> selected production relation R_contrib
  -> backend theorem for soundness/extraction and hiding/simulation
  -> Game 4 replacement in the threshold ML-DSA proof
```

This bridge is directional. The existence of the scaffold and its tests does
not imply the production relation is satisfied.

## Non-Claims

Anchor: `csr-non-claims`

This worksheet does not claim:

- The current transcript-hash contribution scaffold is sound.
- The current scaffold is zero knowledge, witness hiding, or MPC private.
- The current scaffold proves knowledge of a valid ML-DSA secret share.
- The current scaffold proves algebraic correctness of `c*s1`, `c*s2`,
  `c*t0`, masking terms, hints, low bits, or aggregate `z`.
- A production backend declaration by itself proves a cryptographic theorem.
- A statement digest check by itself proves contribution validity.
- Local tests, deterministic simulations, benchmark artifacts, or strict wire
  parsers prove contribution soundness or hiding.
- The DKG/VSS relation, commitment scheme, rejection-sampling bound, or
  aggregate ML-DSA verification theorem is already closed.
- Adaptive security, erasure safety, side-channel resistance, or production
  slashing readiness follows from this relation worksheet.

Any future production claim must cite the selected backend theorem, instantiate
the public statement and witness relation above or an explicitly versioned
successor, close the Game 4 replacement argument, and preserve the non-claim
boundary for all remaining open proof obligations.
