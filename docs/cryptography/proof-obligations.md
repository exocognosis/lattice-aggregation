# Proof Obligation Tracker for Threshold ML-DSA-65

Date: 2026-05-26

## Status

This tracker collects the proof, implementation, and audit obligations that
must be closed before the repository can make production security claims for a
threshold ML-DSA-65 construction.

The current repository is a publishable research scaffold with a feature-gated
hazmat ML-DSA-65 backend for experiments. It is not a production-secure
threshold ML-DSA implementation. The obligations below are blockers for any
claim that the protocol is malicious-secure, side-channel resistant,
production-ready, or suitable for production slashing.

Implementation tests, deterministic simulations, transcript digests, and
feature gates are useful engineering evidence. They do not replace the formal
proofs, backend replacements, audits, and external cryptographic review called
out here.

## Claim Status Key

- **Open**: proof work is not complete and no production claim may rely on it.
- **Scaffold Evidence Only**: repository artifacts fix an interface,
  transcript shape, or test boundary, but do not prove the cryptographic claim.
- **Implementation Gate Only**: code rejects unsafe backend declarations or
  malformed artifacts, but the gate is not a proof of backend security.
- **Production Blocker**: this obligation must be closed before production
  security, deployment-readiness, or production slashing claims are made.

## PO-1: Malicious-Secure DKG/VSS

### Statement

The DKG/VSS layer must ensure that accepted dealer shares are bound to a single
degree-`t - 1` secret polynomial per dealer, preserve receiver privacy where
required, support sound complaint resolution, and derive one epoch public key
and one consistent set of validator shares for the accepted epoch.

### Current Evidence

- [production-vss-backend.md](production-vss-backend.md) specifies the target
  production VSS relation, public parameters, statement digest, complaint
  evidence boundary, and production backend profile.
- [security-model.md](security-model.md) states DKG share soundness as a
  required game.
- [formal-proof-scaffold.md](formal-proof-scaffold.md) tracks setup/DKG
  idealization as an open hybrid.
- The current scaffold includes deterministic VSS/interpolation tests and a
  production policy gate that rejects scaffold VSS backends for
  production-labeled configuration.

### Missing Proof Work

- Define the concrete commitment, opening, and proof relation for dealer shares.
- Prove binding to one polynomial per accepted dealer and subset consistency for
  all accepted honest receivers.
- Prove receiver privacy for unopened honest shares under the selected
  transcript and complaint model.
- Prove complaint resolution is deterministic, sound, anti-framing, and bound
  to `epoch_id`, validator set, threshold, dealer identity, and receiver
  identity.
- Prove public-key derivation is deterministic from accepted commitments and is
  compatible with the threshold signing proof.

### Implementation/Audit Closure Criteria

- Replace deterministic scaffold VSS with a reviewed production backend
  declaring `ProductionBindingHiding` only for the final relation.
- Exercise valid, invalid, equivocated, duplicate, unknown-validator, and
  complaint-resolution paths with deterministic and randomized tests.
- Audit canonical encoding, backend identifiers, versioning, randomness,
  confidential share delivery assumptions, and fail-closed production policy.
- Obtain external cryptographic review of the VSS/DKG construction and its
  integration with the signing proof.

### Claim Status

Production Blocker. Current evidence is scaffold evidence and implementation
gating only; it does not establish malicious-secure DKG or VSS.

## PO-2: Contribution Proof Soundness and Hiding

### Statement

Each accepted partial contribution must be accompanied by a sound relation that
binds the contributor, session, challenge, DKG public material, masking
commitments, claimed contribution encoding, and ML-DSA-65 parameter set while
hiding secret-dependent witness material.

### Current Evidence

- [proof-bearing-contribution-boundary.md](proof-bearing-contribution-boundary.md)
  defines the current proof-bearing boundary and the production replacement
  target.
- [formal-proof-scaffold.md](formal-proof-scaffold.md) tracks contribution
  proof soundness as an open hybrid.
- [security-model.md](security-model.md) explicitly states that the current
  `ContributionProof` is a transcript-hash scaffold, not a sound partial
  contribution relation.
- The current wire and actor paths bind production contribution statement
  digests and reject digest mismatches in tested scaffold paths.

### Missing Proof Work

- Specify the production contribution relation, including public inputs,
  witness material, accepted encodings, and ML-DSA partial-share predicates.
- Prove knowledge soundness or equivalent verification soundness for accepted
  contributions.
- Prove zero-knowledge, MPC privacy, or an equivalent hiding property for
  secret-share terms, masking material, and `c*s1`, `c*s2`, or `c*t0`-dependent
  values.
- Prove session, attempt, challenge, validator, DKG, and commitment binding
  without relying on opaque payload bytes.
- Show how extractor or verifier outputs plug into the threshold EUF-CMA
  reduction.

### Implementation/Audit Closure Criteria

- Replace transcript-hash payload-digest proofs with a production relation or
  reviewed MPC verification mechanism.
- Keep the production policy gate fail-closed for transcript-hash and candidate
  scaffold backends.
- Add tests for valid contributions, malformed witnesses, wrong challenge,
  wrong DKG statement, wrong validator index, replayed session data, and
  serialization edge cases.
- Audit witness lifetime, memory exposure, logging, debug formatting, and
  rejection paths.
- Obtain external cryptographic review of the proof system or MPC verification
  relation.

### Claim Status

Production Blocker. Current contribution proofs provide transcript
digest-binding only and must not be described as sound, hidden, zero-knowledge,
or production-ready.

## PO-3: Selective-Abort/Retry Bound

### Statement

The signing protocol must bound the advantage an active adversary gains by
withholding commitments, openings, or partial contributions after learning
protocol state, including any bias introduced by retrying ML-DSA rejection
sampling attempts.

### Current Evidence

- [formal-proof-scaffold.md](formal-proof-scaffold.md) identifies
  rejection-sampling and selective-abort as an open hybrid.
- [security-model.md](security-model.md) names challenge bias through selective
  aborts as an attack surface.
- [claims-matrix.md](claims-matrix.md) classifies the rejection sampling,
  retry, and selective-abort boundary as research scaffold only.
- Actor simulations and telemetry distinguish rejection/retry paths from
  malformed-evidence paths under modeled profiles.

### Missing Proof Work

- Define the maximum retry policy, exclusion policy, and attempt transcript
  binding used by production deployments.
- Prove no commitment or masking material is reused across attempts in a way
  that leaks honest shares or increases challenge bias.
- Bound adversarial conditioning on accepted challenges, rejection predicates,
  and quorum composition.
- Separate slashable malformed behavior from non-slashable network loss,
  timeout, or honest ML-DSA rejection events.
- State the final statistical or computational distance bound used in the
  security theorem.

### Implementation/Audit Closure Criteria

- Implement explicit production retry limits, attempt identifiers, fresh
  randomness requirements, and deterministic exclusion rules.
- Add tests for retry exhaustion, contribution withholding, reordered attempts,
  stale commitments, reused attempt data, and quorum replacement.
- Audit telemetry and evidence labels so retry failures are not treated as
  cryptographic slashing proof without the production policy.
- Review liveness and timeout assumptions with the consensus integration.

### Claim Status

Production Blocker. Current telemetry and simulations identify retry behavior
but do not prove a selective-abort or challenge-bias bound.

## PO-4: Aggregation/Noise Correctness

### Statement

Every accepted threshold transcript must aggregate to ML-DSA-65 values whose
response vector, low bits, hint data, challenge, and final encoding satisfy the
unmodified ML-DSA-65 verification equations and parameter bounds.

### Current Evidence

- [noise-bound-proof-outline.md](noise-bound-proof-outline.md) records the
  required lemmas and parameter-specific bound obligations.
- [formal-proof-scaffold.md](formal-proof-scaffold.md) tracks aggregation
  correctness and standard verification compatibility as open hybrids.
- [claims-matrix.md](claims-matrix.md) classifies the noise-bound and
  aggregation correctness proof as production blocked.
- Hazmat bridge and standard-verification tests show selected current
  artifacts can verify, but only as implementation evidence.

### Missing Proof Work

- Instantiate the ML-DSA-65 parameters and prove the final `z`, low-bit, hint,
  and challenge constraints for all accepted transcripts.
- Define how threshold masking is sampled so the reconstructed masking value
  has the required ML-DSA distribution or a quantified close distribution.
- Bound or avoid Lagrange-coefficient growth in reconstructed masking and
  response vectors.
- Prove rejection sampling restores the target distribution without violating
  the selective-abort bound.
- Prove final byte encoding and public verification semantics match FIPS 204
  ML-DSA-65 where claimed.

### Implementation/Audit Closure Criteria

- Implement production aggregation checks tied to the proven predicates rather
  than simulation-only noise checks.
- Add boundary tests for ML-DSA-65 coefficient limits, hint cardinality, sparse
  challenge handling, low-bit equations, and invalid encodings.
- Add differential or KAT-style regression coverage for the final production
  aggregation path where applicable.
- Audit serialization and canonical encoding used by the final verifier.

### Claim Status

Production Blocker. Current tests are compatibility and regression evidence;
they do not prove that every accepted threshold transcript satisfies ML-DSA-65
noise and aggregation requirements.

## PO-5: Transcript/Challenge Unbiasability

### Statement

The Fiat-Shamir challenge must be derived from a canonical, domain-separated,
pre-committed transcript that prevents participant ordering, proposer control,
commitment equivocation, retry selection, or missing context from biasing the
challenge beyond the stated bound.

### Current Evidence

- [formal-threshold-mldsa-transcript.md](formal-threshold-mldsa-transcript.md)
  defines the current transcript shape and binding fields.
- [formal-proof-scaffold.md](formal-proof-scaffold.md) tracks challenge
  unbiasability as an open hybrid.
- [security-model.md](security-model.md) identifies challenge unbiasability as
  a protected asset and security game.
- Transcript determinism and wire canonicalization tests support current
  ordering discipline in scaffold paths.

### Missing Proof Work

- Prove challenge derivation occurs only after a binding commitment quorum is
  fixed.
- Prove all challenge inputs are canonical, domain-separated, versioned, and
  bound to epoch, validator set, threshold, session, attempt, message, public
  key, and relevant DKG state.
- Prove proposer or aggregator ordering choices cannot influence the challenge.
- Compose the challenge proof with the selective-abort/retry bound.
- Specify which consensus context is inside the ML-DSA message or digest and
  which context is audit metadata outside standard verification.

### Implementation/Audit Closure Criteria

- Freeze canonical transcript encodings and domain labels for production.
- Add regression tests for field omission, field reordering, duplicate
  validators, unknown validators, stale attempts, cross-epoch replay, and
  alternate proposer ordering.
- Audit transcript versioning, digest inputs, public-key binding, and
  compatibility with unmodified ML-DSA verification.
- Obtain external review of the random-oracle programming and transcript
  binding argument.

### Claim Status

Production Blocker. Current canonicalization tests support the scaffold, but
they do not establish challenge unbiasability.

## PO-6: Side-Channel and Leakage Boundary

### Statement

Production code must not leak honest secret shares, masking material,
contribution witnesses, or rejection-sensitive information through timing,
memory access patterns, logging, serialization, telemetry, debug output,
benchmark artifacts, or exposed hazmat payloads.

### Current Evidence

- [security-model.md](security-model.md) lists side-channel resistance as an
  assumption only if timing claims are made.
- [formal-proof-scaffold.md](formal-proof-scaffold.md) names side-channel
  resistance as an explicit non-claim for the current backend.
- [proof-bearing-contribution-boundary.md](proof-bearing-contribution-boundary.md)
  documents that the current witness still contains raw payload material in
  memory and that current proofs are not hiding.
- [claims-matrix.md](claims-matrix.md) marks side-channel and timing resistance
  as not claimed.

### Missing Proof Work

- Define the leakage model for production arithmetic, proof generation,
  contribution verification, rejection sampling, and evidence generation.
- Prove or justify that public transcript data and accepted proof objects do not
  reveal honest witness material beyond intended public outputs.
- Define erasure requirements if adaptive-security claims are later added.
- Show benchmark, tracing, and telemetry artifacts do not expose
  secret-dependent values or rejection-sensitive correlations.

### Implementation/Audit Closure Criteria

- Replace raw hazmat payload exposure at protocol boundaries with hiding
  production proofs or MPC verification artifacts.
- Complete constant-time and leakage audits for arithmetic, proof generation,
  verification, rejection paths, serialization, logging, and debug formatting.
- Add leakage-oriented test or measurement coverage where meaningful, such as
  timing tests for selected critical paths.
- Document operational controls for randomness, memory handling, telemetry, and
  artifact retention.

### Claim Status

Production Blocker. Side-channel resistance and leakage freedom are not claimed
by the current repository.

## PO-7: Production Slashing/Evidence Soundness

### Statement

Production evidence must be sound, canonical, replay-resistant, and
anti-framing: an adversary must not be able to produce valid-looking slashing
evidence against an honest validator for behavior the validator did not perform.

### Current Evidence

- [security-model.md](security-model.md) defines evidence soundness as a
  required game and separates liveness penalties from cryptographic slashing
  proof.
- [production-vss-backend.md](production-vss-backend.md) explains that current
  `ProductionVssRelationStatement` digests bind observed evidence to future
  public VSS inputs, but are not production slashing evidence.
- [claims-matrix.md](claims-matrix.md) classifies artifact-to-frame binding and
  invalid-share evidence shape as research scaffold only.
- Current adapter evidence binds observed frames to canonical digests in tested
  scaffold paths.

### Missing Proof Work

- Specify the production evidence relation for malformed DKG shares, invalid
  contribution proofs, equivocated commitments, replayed frames, and other
  slashable cryptographic faults.
- Prove evidence cannot be replayed across epochs, sessions, attempts,
  validator sets, dealer identities, receiver identities, or backend versions.
- Prove evidence verification is deterministic and does not depend on honest
  aggregators, proposers, or network ordering.
- Prove anti-framing for honest validators under authenticated transport and
  canonical serialization assumptions.
- Define which failures are slashable cryptographic faults and which are
  non-slashable liveness, timeout, or network conditions.

### Implementation/Audit Closure Criteria

- Implement production evidence verifiers for the final VSS and contribution
  proof relations.
- Add tests for replay, equivocation, forged identity, malformed canonical
  encodings, stale backend versions, missing context, and honest-validator
  anti-framing cases.
- Audit integration with authenticated transport, consensus identity binding,
  evidence retention, and slashing policy.
- Obtain external review of evidence soundness before enabling production
  slashing or penalty claims.

### Claim Status

Production Blocker. Current evidence artifacts are structured candidates for
future verifiers; they are not production slashing evidence.

## Production Claim Gate

Before any production security claim, deployment-readiness claim, or production
slashing claim is made, all seven obligations above must be closed by the
combination of:

1. a concrete production backend or relation,
2. a completed proof under the stated security model,
3. implementation tests that exercise the proven boundary,
4. side-channel and leakage review where secret-dependent code exists,
5. operational and consensus assumptions documented in deployment terms, and
6. external cryptographic review.

Until then, safe wording is limited to research-scaffold, transcript-shape,
implementation-boundary, simulation, and regression-test claims of the kind
tracked in [claims-matrix.md](claims-matrix.md).
