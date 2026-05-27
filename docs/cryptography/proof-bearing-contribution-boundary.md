# Proof-Bearing Contribution Boundary

Date: 2026-05-25

## Status

This document defines the current proof-bearing contribution boundary and the
next implementation backlog for replacing raw hazmat contribution payloads.

The current code in `src/crypto/contribution_proof.rs` is a deterministic
transcript-hash proof scaffold. It is not a production zero-knowledge proof, MPC
proof, or sound partial-contribution proof system. Its purpose is to freeze the
API shape where a production relation can later be installed without continuing
to expose raw secret-dependent hazmat payloads at the protocol boundary.

The code now also exposes a production policy gate for contribution proof
backends, analogous to the VSS production gate. The gate must fail closed for
the transcript-hash scaffold backend. Passing the gate requires a backend that
declares a production proof relation; that declaration is a policy marker, not
by itself a proof, audit, or publication claim.

## Current Scaffold API

The scaffold exposes three types and two operations:

```text
ContributionStatement
ContributionWitness
ContributionProof

prove_contribution(statement, witness) -> ContributionProof
verify_contribution_proof(statement, proof) -> ()
```

`ContributionStatement` is the public statement. It identifies the signing
context, contributor, challenge, and public commitment digests that the proof is
supposed to bind.

`ContributionWitness` is the private scaffold witness. Today it is constructed
from the currently exposed raw hazmat contribution payload:

```text
ContributionWitness::from_payload(payload)
```

The witness intentionally redacts payload contents in `Debug`, but it still
contains the raw payload in memory. This is only a boundary scaffold.

`ContributionProof` is the public proof object. Today it contains:

```text
payload_len
payload_digest
proof_digest
```

`payload_digest` is `SHA3-256(payload)`. `proof_digest` is a deterministic
SHA3-256 transcript digest over the proof domain, all statement fields,
`payload_len`, and `payload_digest`.

## Exact Statement Binding

The current `ContributionStatement` binds exactly these fields:

```text
session_id
block_height
attempt
validator_index
challenge
masking_commitment_digest
secret_commitment_digest
dkg_commitment_digest
```

The transcript-hash scaffold additionally binds:

```text
payload_len
payload_digest
```

The current digest input order is:

```text
CONTRIBUTION_PROOF_DOMAIN
session_id
block_height.to_be_bytes()
attempt.to_be_bytes()
validator_index.to_be_bytes()
challenge
masking_commitment_digest
secret_commitment_digest
dkg_commitment_digest
payload_len.to_be_bytes()
payload_digest
```

The current statement validation only rejects `validator_index == 0`. The proof
validation also rejects `payload_len == 0` and checks that the supplied
`proof_digest` recomputes under the supplied statement and payload digest.

## Security Provided Today

The scaffold provides statement-to-payload-digest binding:

- A verifier can detect if a `ContributionProof` was generated for a different
  statement field, payload length, or payload digest.
- The proof domain separates this scaffold from unrelated SHA3-256 transcript
  uses.
- The public statement includes the session, block height, attempt, validator
  index, challenge, masking commitment digest, secret commitment digest, and DKG
  commitment digest placeholders that a production proof relation must continue
  to bind.
- The API gives the protocol a single proof-bearing boundary instead of letting
  future work accrete around raw contribution bytes.

This is useful engineering evidence for transcript discipline and for testing
the shape of proof-carrying messages. It is not a cryptographic replacement for
the missing production relation.

## Security Not Provided Today

The scaffold does not provide:

- zero-knowledge privacy for witness material
- MPC privacy for `c*s1`, `c*s2`, `c*t0`, masking secrets, or other
  secret-dependent contribution terms
- proof of knowledge of a valid share or valid ML-DSA partial contribution
- soundness against malicious contributors who choose malformed but
  transcript-consistent payloads
- extraction for the formal proof Game 4 partial-contribution soundness hybrid
- hiding or binding commitments beyond the existing digest discipline
- a theorem that accepted contributions satisfy ML-DSA-65 bound predicates
- protection against side-channel leakage from the hazmat payload path
- adaptive-corruption security or erasure semantics

In particular, a valid scaffold `ContributionProof` only says:

```text
this proof digest is consistent with this statement, this payload length,
and this payload digest
```

It does not say:

```text
the contributor knows a valid secret share
the contribution is algebraically correct
the payload is safe to reveal
the aggregate signature distribution matches ML-DSA-65
```

## Production Gate Status

The contribution proof boundary separates scaffold evidence from
production-security claims:

- The transcript-hash contribution proof backend is a scaffold for tests,
  simulations, and API stabilization.
- Contribution proof backends declaring either `TranscriptHashScaffold` or
  `ProductionCandidateScaffold` must fail production gates. Candidate
  scaffolds are useful for integration shape checks only; they are not
  production proof relations.
- Production-targeted code must call the contribution proof production gate and
  must reject scaffold backends closed.
- A backend may pass the gate only by declaring a production proof relation that
  replaces payload-digest binding with a sound proof, MPC verification relation,
  or other reviewed relation for valid partial contributions.
- Declaring the production relation is necessary but not sufficient for a
  security claim. Production use still requires the external proof and
  cryptographic review obligations tracked in
  `docs/cryptography/formal-proof-scaffold.md`.
- The gate is distinct from the feature-gated experimental VSS complaint
  evidence path. Experimental VSS complaint evidence is structural evidence for
  VSS-shaped artifacts; it is not contribution proof verification and does not
  validate the contribution relation.

Documentation, CLI output, benchmark reports, and manuscript text should treat
any transcript-hash contribution proof as scaffold-only even when it is accepted
by local tests.

The contribution proof gate also composes with the VSS/DKG gate through
`src/crypto/production_policy.rs`. A threshold-level production policy check
must reject any backend selection unless the VSS backend declares a production
hiding/binding relation and the contribution proof backend declares a
production proof relation. This combined gate is a configuration guard only; it
does not make either declaration cryptographically sufficient without the proof
and review work tracked below.

## Production Boundary Target

The production replacement should preserve the public statement shape where it
is still correct, but replace the payload digest scaffold with a proof or
verification relation that establishes the partial contribution predicates
without exposing secret-dependent witness material.

At minimum, the production relation should bind:

```text
protocol version and proof domain
session_id
block_height
attempt
validator_index
challenge
DKG public commitment material
Round 1 masking commitment material
Round 2 secret commitment material where applicable
message or message digest used in challenge derivation
epoch public key
claimed contribution encoding
ML-DSA-65 parameter set
```

The exact public inputs may expand beyond the current scaffold. If they do, the
statement type should change explicitly rather than smuggling new context
through opaque payload bytes.

The Rust boundary now includes `ProductionContributionStatement` as the
canonical public-input object for that future relation. It is intentionally a
statement and digest target only; it does not verify a contribution proof and
does not allow the transcript-hash scaffold to pass production gates. The
canonical field order is:

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

`statement_digest()` hashes those fixed-width canonical bytes under the
`dytallix.threshold.contribution.production-statement.v1` domain. The object
rejects zero schema versions, invalid threshold parameters, validator index
zero, and validator indices outside the epoch set. Future production proof
bytes must prove the contribution relation against this digest or an explicitly
versioned successor statement.

The hazmat proof-bound secret-contribution wire frame now carries this
production statement digest alongside the current transcript-hash scaffold
proof. Actor verification derives the expected `ProductionContributionStatement`
from the session context, challenge, commitment digests, `mu`, and contribution
payload, then rejects the frame if the supplied digest differs. This is a
public-input binding check only; the accepted proof is still the transcript-hash
scaffold until a production proof backend replaces it.

## Larger-Batch Implementation Tickets

### Batch 1: Wire Boundary And Statement Completeness

- Define the production contribution message envelope that carries
  `ContributionStatement`, proof bytes, and contribution metadata without raw
  hazmat witness exposure.
- Add protocol-version and parameter-set fields if they are not otherwise
  unambiguously bound by the enclosing transcript.
- Replace the placeholder `dkg_commitment_digest` with a digest over canonical
  DKG public commitment material.
- Decide whether message digest, epoch public key digest, and validator-set
  digest belong directly in `ContributionStatement` or in an enclosing signed
  transcript object.
- Add negative tests for statement-field substitution across session, attempt,
  validator, challenge, and commitment digests.

Exit criterion: all proof-bearing contribution messages have a canonical public
statement with no implicit context required for verification.

### Batch 2: Commitment Scheme Upgrade

- Replace digest-only precommitment placeholders with a specified commitment
  scheme and encoding.
- Define opening rules for masking and secret contribution commitments.
- Specify binding and hiding assumptions for each commitment type.
- Add artifact verifier checks that commitment digests are derived from
  canonical commitment objects, not ad hoc byte concatenations.
- Update the formal proof scaffold's Game 2 commitment binding obligation with
  the selected scheme.

Exit criterion: commitment objects have canonical encodings and stated
cryptographic assumptions suitable for the proof.

### Batch 3: Contribution Relation Specification

- Write the exact relation for masking and secret partial contributions.
- Enumerate public inputs, private witnesses, and all ML-DSA-65 bound
  predicates.
- Define how validator shares, Lagrange coefficients, DKG commitments, and
  challenge bytes enter the relation.
- Specify rejection-sampling behavior and how aborts are represented.
- Decide whether the first production target is a ZK proof, MPC-in-the-head
  proof, interactive verifier, or audited MPC verification relation.

Exit criterion: the project has a relation document precise enough to implement
and review independently of Rust code.

### Batch 4: Proof System Integration

- Implement a trait or backend boundary that separates the current
  transcript-hash scaffold from the production proof backend.
- Preserve deterministic test vectors for the scaffold backend.
- Add production-proof serialization with length limits and domain separation.
- Reject scaffold proof backends in production configuration by using the
  contribution proof production gate.
- Require production backends to declare a production proof relation and keep
  that declaration separate from proof completion, audit, and publication
  readiness.
- Add differential tests showing that statement mutation invalidates both
  scaffold and production proofs.

Exit criterion: development builds can still use the scaffold for tests, while
production-targeted builds require a non-scaffold proof backend.

### Batch 5: Formal Soundness Hook

- Replace the Game 4 open obligation with the selected proof-system theorem.
- State extractor, simulator, or verifier assumptions explicitly.
- Prove that accepted adversarial contributions can be replaced with relation
  witnesses except with the proof-system soundness error.
- Connect the relation to aggregate ML-DSA-65 bound obligations for `z`, hints,
  and low bits.
- Document any looseness introduced by rejection sampling, validator exclusion,
  and retry policy.

Exit criterion: the formal proof scaffold can cite a concrete
partial-contribution soundness theorem rather than the current transcript-hash
API scaffold.

### Batch 6: Privacy And Leakage Review

- Remove raw hazmat payload exposure from normal protocol paths.
- Audit logs, artifact files, debug output, and error paths for witness leakage.
- Define erasure points for ephemeral masking secrets.
- Add tests proving proof verification does not require witness payload access.
- Run side-channel review for secret-dependent arithmetic and serialization.

Exit criterion: the contribution path no longer depends on exposing raw
secret-dependent payloads outside the intended witness holder.

## Cross-References

- `docs/cryptography/formal-proof-scaffold.md` defines the target theorem and
  Game 4 partial-contribution soundness obligation.
- `docs/cryptography/security-model.md` lists current implementation coverage
  and non-coverage.
- `docs/cryptography/hazmat-real-mldsa-protocol.md` documents the current raw
  hazmat contribution flow that this boundary is intended to replace.
- `docs/benchmarks/section-v-results.md` should not be treated as proof of
  contribution soundness; benchmark evidence is only engineering evidence.
- `docs/cryptography/production-vss-backend.md` documents the analogous VSS
  production gate and the separate experimental VSS complaint-evidence
  boundary.
