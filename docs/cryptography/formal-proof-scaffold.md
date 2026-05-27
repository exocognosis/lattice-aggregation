# Formal Proof Scaffold for Threshold ML-DSA-65

Date: 2026-05-25

## Status

This document is a theorem scaffold for a publishable threshold ML-DSA-65
construction. It is not a completed proof. It defines the intended theorem,
adversary model, game sequence, hybrid structure, and proof obligations needed
to move the current research crate from engineered evidence to a defensible
cryptographic result.

The current `hazmat-real-mldsa` backend demonstrates a standard-verifying local
artifact and an auditable transcript discipline. It does not yet implement the
zero-knowledge or MPC machinery required for the theorem below.

## Target Theorem

Let `Pi_TMLDSA65` be an interactive threshold signing protocol for ML-DSA-65
with validator set `V = {1, ..., N}`, threshold `t`, and static active
corruption bound `f < t`.

Assume:

- ML-DSA-65 is existentially unforgeable under chosen-message attack.
- The DKG/VSS protocol is binding, hiding where required, and complaint-sound.
- Round commitments are computationally binding before challenge derivation.
- Partial-contribution proofs are sound and zero-knowledge.
- The Fiat-Shamir challenge is modeled as a random oracle.
- Honest parties erase ephemeral masking secrets before any adaptive corruption
  claim is made.

Then any probabilistic polynomial-time adversary that produces a valid
standard ML-DSA-65 signature for an unauthorized message with non-negligible
probability implies one of:

```text
1. a break of ML-DSA-65 EUF-CMA security,
2. a DKG/VSS soundness failure,
3. a commitment binding failure,
4. a partial-contribution proof soundness failure,
5. a random-oracle programming or challenge-binding failure,
6. a selective-abort bias above the stated abort bound.
```

The final signature must verify under the unmodified ML-DSA-65 verification
algorithm:

```text
Verify_MLDSA65(pk_epoch, M, sigma) = accept
```

## Explicit Non-Claims For The Current Backend

The current repository does not yet prove or implement:

- malicious-secure production DKG
- hidden partial contribution proofs
- an externally reviewed production contribution proof relation
- leakage-free MPC for `c*s1`, `c*s2`, or `c*t0`
- adaptive security with erasures
- side-channel resistance
- a tight selective-abort reduction

These are future proof and implementation gates. The current backend supports
testing, transcript reproducibility, and standard-verification compatibility.
The contribution proof production gate must therefore reject the
transcript-hash scaffold closed. A backend that declares a production proof
relation may pass the code-level gate, but the theorem still requires a concrete
relation, proof-system assumptions, and external cryptographic review.

A numbered tracker for production-blocking proof obligations is maintained in
[proof-obligations.md](proof-obligations.md).

## Adversary Model

The initial theorem should target static active security.

The adversary may:

- corrupt up to `f` validators before DKG
- choose signing messages adaptively
- schedule, delay, duplicate, and reorder messages
- send malformed commitments and openings
- equivocate where the protocol does not bind identities
- withhold partial contributions after observing the challenge
- submit malformed partial contribution proofs
- act as proposer or aggregator

The adversary may not:

- forge authenticated validator transport identities
- break ML-DSA-65 assumptions directly
- invert or predict random oracle outputs
- corrupt more than the stated bound

Adaptive security should be treated as a separate theorem because it requires
precise erasure semantics and post-corruption simulator state.

## Ideal Functionality

A proof should define an ideal threshold signing functionality `F_TSign`:

```text
Setup(V, t) -> pk_epoch and private shares to validators
SignRequest(M, sid) -> records requested message/session
SubmitShare(i, sid, M) -> records valid authorization from validator i
Finalize(sid, M) -> sigma if at least t valid authorizations exist
```

Security target:

- no finalized signature exists unless at least `t` authorized shares exist in
  the ideal world
- corrupted parties learn no honest secret-share information beyond public
  outputs and their own shares
- abort behavior is observable but bounded and attributable

## Game-Hopping Skeleton

Every game below is OPEN. The current repository supplies engineering evidence
and transcript anchors only; none of these obligations is solved by the current
backend.

### Game 0: Real Transcript

The adversary interacts with the documented transcript: DKG setup, masking
precommitments and openings, challenge derivation, proof-bound contribution
frames, aggregation, rejection/retry handling, and evidence generation.

Status: OPEN.

Required assumptions: authenticated validator identities, canonical encodings,
static active corruptions `f < t`, and a fixed ML-DSA-65 parameter set.

Repository evidence: `docs/cryptography/formal-threshold-mldsa-transcript.md`,
`src/adapter/wire.rs`, `src/adapter/actor.rs`, and
`src/utils/hazmat_artifacts.rs` define the present transcript shape.

### Game 1: Setup/DKG Idealization

Replace accepted DKG outputs with an ideal setup that emits one `pk_epoch` and
shares consistent with a single epoch secret.

Status: OPEN.

Failure event: `DkgSoundnessBreak`.

Required assumptions: malicious-secure VSS commitments, verified complaint
resolution, deterministic exclusion rules, private share delivery, and public
key derivation binding `epoch_id`, `V`, `t`, and `dkg_digest`.

Repository evidence: threshold-aware interpolation checks cover duplicate,
zero, and too-few-share rejection. They are algebraic sanity checks only, not a
DKG/VSS soundness proof.

### Game 2: Masking Commitment Binding

Abort if a masking precommitment opens to two different valid masking openings
for the same `(epoch_id, sid, height, attempt, i)`.

Status: OPEN.

Failure event: `MaskingCommitmentBindingBreak`.

Required assumptions: a production commitment relation that is binding before
challenge derivation and hiding wherever the final protocol needs hidden
masking material.

Repository evidence: `masking_commitment_digest` and artifact verifier checks
bind current hazmat payloads by digest. This is engineering evidence, not a
complete commitment proof.

### Game 3: Challenge Unbiasability

Program the random oracle challenge at the canonical ML-DSA-compatible
challenge input after the accepted masking quorum and `w1` are fixed.

Status: OPEN.

Failure event: `ChallengeBias`.

Required assumptions: canonical participant ordering, domain separation,
prechallenge commitment binding, and a retry/exclusion policy that bounds an
adversary's ability to choose among challenges.

Repository evidence: transcript determinism tests and wire canonicalization
support order-independent artifacts. They do not bound challenge bias.

### Game 4: Contribution Proof Soundness

Replace accepted adversarial contribution frames with extractor outputs from a
sound proof or MPC verification relation.

Status: OPEN.

Failure event: `PartialProofSoundnessBreak`.

Required assumptions: a reviewed proof relation binding validator index,
session, challenge, DKG public material, masking commitment, ML-DSA-65 bound
predicates, and the claimed contribution encoding without exposing
secret-dependent witness material.

Repository evidence: `src/crypto/contribution_proof.rs` defines
`ContributionStatement`, `ContributionWitness`, and `ContributionProof`.
The current `ContributionProof` is a transcript-hash scaffold only; a backend
production declaration is a policy gate, not this proof.

### Game 5: Rejection-Sampling And Selective-Abort

Replace real retry behavior with an ideal abort process whose probability and
conditioning are bounded independently of honest secret material.

Status: OPEN.

Failure event: `SelectiveAbortBias`.

Required assumptions: fresh attempt-bound masking, no commitment reuse across
attempts, explicit maximum retry semantics, attributable exclusion rules, and a
statistical bound for conditioning on ML-DSA rejection predicates.

Repository evidence: retry telemetry and rejection-sampling failure paths
identify where aborts occur. They do not prove a selective-abort bound.

### Game 6: Aggregation Correctness

Replace accepted valid contribution frames with ideal shares and show the
aggregator reconstructs `z`, hints, and public values satisfying the ML-DSA-65
verification equations.

Status: OPEN.

Failure event: `AggregationEquationFailure`.

Required assumptions: correct Lagrange/recombination algebra, bounded noise
growth, contribution proof soundness, and ML-DSA-65 parameter-specific bounds
for `z`, low bits, hints, and challenge sparsity.

Repository evidence: standard-verification tests and hazmat bridge tests show
current artifacts can verify. They are not a proof that all accepted transcripts
aggregate correctly.

### Game 7: Standard Verification Compatibility

Map the accepted threshold transcript to a final byte string `sigma` accepted
by unmodified ML-DSA-65 verification.

Status: OPEN.

Failure event: `StandardVerificationMismatch`.

Required assumptions: exact FIPS 204-compatible encoding, challenge path,
public key, message digest, bounds, and hint semantics; all consensus context
that affects verification must be inside `M`/`mu` or otherwise remain audit
metadata outside standard verification.

Repository evidence: `src/low_level/mldsa65.rs` and hazmat differential and
bridge tests provide compatibility evidence for current artifacts. They do not
establish distributional equivalence or EUF-CMA reduction.

## Lemma Checklist

| Lemma | Statement | Current Evidence | Status |
| --- | --- | --- | --- |
| L1 | VSS subsets reconstruct the same secret | deterministic VSS/interpolation tests, including threshold-aware checked reconstruction for zero, duplicate, and too-few-share cases | scaffold only |
| L2 | transcript challenge is order-independent | transcript determinism tests | partial |
| L3 | masking precommitments bind openings | strict actor tests and artifact verifier | engineering evidence |
| L4 | secret precommitments bind challenge/opening pairs | strict actor tests and artifact verifier | engineering evidence |
| L5 | invalid encodings are rejected deterministically | hardening and fuzz/property tests | implementation |
| L6 | partial contribution proofs are sound | transcript-hash proof API scaffold | open |
| L7 | aggregate response satisfies ML-DSA bounds | standard verification tests | partial |
| L8 | selective abort has bounded bias | retry telemetry only | open |
| L9 | final signature distribution matches ML-DSA | not proved | open |
| L10 | evidence cannot frame honest validators | canonical frame evidence tests | partial |

## Mathematical Bound Obligations

A complete proof must instantiate ML-DSA-65-specific bounds:

```text
q = 8380417
n = 256
k = 6
l = 5
eta = 4
tau = 49
gamma_1 = 2^19
gamma_2 = (q - 1) / 32
beta = tau * eta
omega = 55
```

The proof must state how threshold recombination preserves:

```text
||z||_infty < gamma_1 - beta
hint_count(h) <= omega
LowBits(w - c*s2) bounds
challenge sparsity and sign distribution
```

If Lagrange coefficients are used directly on masking vectors, the proof must
either bound coefficient growth or redesign masking so the reconstructed `y`
has the target ML-DSA distribution.

## Implementation-to-Proof Mapping

Current files that provide engineering evidence:

```text
src/low_level/mldsa65.rs
src/crypto/contribution_proof.rs
src/adapter/actor.rs
src/adapter/wire.rs
src/utils/hazmat_artifacts.rs
tests/hazmat_mldsa65_threshold_bridge.rs
tests/hazmat_mldsa65_wire.rs
tests/hazmat_mldsa65_simulation_grid.rs
tests/hazmat_mldsa65_differential.rs
```

Documents that define adjacent proof material:

```text
docs/cryptography/security-model.md
docs/cryptography/noise-bound-proof-outline.md
docs/cryptography/hazmat-real-mldsa-protocol.md
docs/cryptography/proof-bearing-contribution-boundary.md
docs/benchmarks/section-v-results.md
```

## Publication Readiness Gate

Before the project can claim a threshold ML-DSA-65 construction, the following
must be complete:

1. Formalize DKG and VSS commitments with complaint resolution.
2. Replace raw hazmat partial payloads with proof-bearing contributions whose
   backend passes the contribution proof production gate and instantiates a
   reviewed sound proof, MPC verification relation, or equivalent production
   relation. Passing the code-level gate alone is not a Game 4 proof.
3. Prove Round 1 challenge unbiasability under selective abort.
4. Prove partial contribution soundness.
5. Prove aggregate response distribution compatibility with ML-DSA-65.
6. Define and test erasure semantics if adaptive security is claimed.
7. Run side-channel review for secret-dependent arithmetic.
8. Obtain external cryptographic review.
