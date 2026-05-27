# Hazmat Real ML-DSA-65 Threshold Transcript

Date: 2026-05-25

## Status

This document specifies the concrete transcript currently implemented behind
the `hazmat-real-mldsa` feature. It is a research backend for validating the
threshold architecture against local FIPS 204 ML-DSA-65 internals. It produces
standard ML-DSA-65 signature bytes that verify through the unmodified verifier,
but it is not yet a production MPC transcript.

The current wire format intentionally exposes raw experimental contribution
terms (`y`, `w`, `c*s1`, `c*s2`, and `c*t0`) so the crate can test algebraic
aggregation, rejection behavior, actor scheduling, evidence generation, and
benchmark reproducibility. A production construction must replace these raw
terms with a proof-carrying commitment protocol.

## Implemented Round Structure

### Inputs

Each signing attempt is parameterized by:

```text
sid          32-byte session identifier
height       consensus block height
attempt      rejection-sampling attempt number
V            canonical validator set {1, ..., N}
t            threshold
mu           64-byte ML-DSA internal message digest
share_i      local expanded ML-DSA component share
mask_seed    deterministic experimental masking seed
```

Rust mapping:

```text
ActorEvent::TriggerHazmatMldsa65SigningRound
ActorConfig::with_hazmat_mldsa65_share
HazmatMldsa65ActorSession
```

### Round 1a: Masking Precommitment

Validator `i` derives:

```text
y_i = ExpandMask(mask_seed, i, attempt)
w_i = A * y_i
```

and first sends a binding digest over the later opening:

```text
digest_i = SHA3-256(
    "dytallix.hazmat.mldsa65.masking.commit.v1" ||
    sid ||
    height ||
    attempt ||
    i ||
    len(payload_i) ||
    payload_i
)

HazmatMldsa65MaskingCommitment {
    sid,
    height,
    attempt,
    validator_index = i,
    commitment = digest_i
}
```

This is not yet a hiding commitment. It is a staged binding layer that prevents
the actor from accepting a masking opening that was not precommitted in the
same session and attempt.

### Round 1b: Masking Opening

After precommitment, validator `i` sends:

```text
HazmatMldsa65MaskingContribution {
    sid,
    height,
    attempt,
    validator_index = i,
    payload = Encode(i, t, N, rho, y_i, w_i)
}
```

The receiver enforces:

```text
1 <= i <= N
payload.receiver_index == validator_index
payload.threshold == t
payload.total_nodes == N
w_i == A * y_i
digest_i == Commit(payload_i)
no duplicate i in the attempt
```

Implementation:

```text
src/adapter/wire.rs::PqcThresholdWireMsg::HazmatMldsa65MaskingCommitment
src/adapter/wire.rs::PqcThresholdWireMsg::HazmatMldsa65MaskingContribution
src/low_level/mldsa65.rs::masking_commitment_digest
src/low_level/mldsa65.rs::encode_mldsa65_masking_contribution
src/low_level/mldsa65.rs::decode_mldsa65_masking_contribution
src/low_level/mldsa65.rs::submit_mldsa65_masking_contribution
```

### Round 2: Challenge Fixing

Once at least `t` valid masking contributions are available, the actor computes:

```text
y = sum(y_i)
w = sum(w_i)
w1 = HighBits(w)
c = H(mu || w1)
```

Implementation:

```text
aggregate_mldsa65_masking_contributions
derive_mldsa65_session_challenge_once_quorum_met
```

The actor then derives and broadcasts its local secret precommitment followed by
its local secret opening.

### Round 3a: Secret Precommitment

Validator `i` computes:

```text
cs1_i = c * s1_i
cs2_i = c * s2_i
ct0_i = c * t0_i
```

and first sends a binding digest over the later challenge-bound opening:

```text
digest_i = SHA3-256(
    "dytallix.hazmat.mldsa65.secret.commit.v1" ||
    sid ||
    height ||
    attempt ||
    i ||
    c ||
    len(payload_i) ||
    payload_i
)

HazmatMldsa65SecretCommitment {
    sid,
    height,
    attempt,
    validator_index = i,
    challenge = c,
    commitment = digest_i
}
```

### Round 3b: Secret Opening

After precommitment, validator `i` sends:

```text
HazmatMldsa65SecretContribution {
    sid,
    height,
    attempt,
    validator_index = i,
    challenge = c,
    payload = Encode(i, t, N, c, cs1_i, cs2_i, ct0_i)
}
```

The receiver enforces:

```text
1 <= i <= N
payload.receiver_index == validator_index
payload.challenge == challenge
payload.threshold == t
payload.total_nodes == N
digest_i == Commit(c, payload_i)
no duplicate i in the attempt
```

Implementation:

```text
src/adapter/wire.rs::PqcThresholdWireMsg::HazmatMldsa65SecretCommitment
src/adapter/wire.rs::PqcThresholdWireMsg::HazmatMldsa65SecretContribution
src/low_level/mldsa65.rs::secret_commitment_digest
encode_mldsa65_secret_contribution
decode_mldsa65_secret_contribution
submit_mldsa65_secret_contribution
```

### Finalization

Once at least `t` valid secret contributions are available, the actor
interpolates the shared secret terms, assembles:

```text
z = y + c * s1
```

checks ML-DSA-65 response bounds, computes hint material, packs a standard
ML-DSA-65 signature, and submits it through:

```text
ConsensusStateAdapter::on_signature_finalized(height, signature)
```

Verification target:

```text
verify_mldsa65_internal_mu(pk, mu, signature) == true
```

## Wire Encoding

Contribution payloads use canonical big-endian `i32` coefficients. Decoders
reject:

- wrong payload length
- trailing bytes
- truncated bytes
- coefficients outside `[0, q)`
- unknown validator indexes
- duplicate validator indexes
- masking payloads where `w != A*y`

Current raw payload sizes:

```text
masking contribution = 11302 bytes
secret contribution  = 17462 bytes
```

Adapter limits:

```text
MAX_HAZMAT_MLDSA65_MASKING_CONTRIBUTION_BYTES = 16 KiB
MAX_HAZMAT_MLDSA65_SECRET_CONTRIBUTION_BYTES  = 24 KiB
```

## Evidence Behavior

Malformed hazmat contributions produce
`EvidenceKind::InvalidPartialSignature` records with the canonical offending
wire frame attached. The actor does not automatically terminate a session after
one bad contribution if enough honest validators remain to reach quorum.

This distinction matters for consensus availability: one Byzantine validator
should be attributable without forcing a healthy round to abort.

## Current Security Boundary

Implemented and tested:

- local ML-DSA-65 arithmetic and verification compatibility
- VSS/interpolation algebraic reconstruction
- typed hazmat wire frames
- actor-driven round progression
- standard signature finalization
- malformed payload rejection
- invalid contribution evidence
- reproducible benchmark emission
- verified transcript artifact export for evaluation replay

Not yet production secure:

- DKG is deterministic scaffold code, not a cryptographic DKG
- raw contribution payloads reveal material unsuitable for production MPC
- commitment hiding/binding is not yet a formal proof-carrying transcript
- adaptive corruption and erasure security are not claimed
- side-channel resistance has not been audited

## Evaluation Limitations

The current evaluation establishes an engineered research artifact, not a full
cryptographic theorem. The tests show that the local actor can execute the
rounds in order, reject malformed encodings, emit attributable evidence, and
produce standard-verifying ML-DSA-65 signatures under deterministic simulated
network profiles.

The tests do not prove that the threshold protocol realizes ideal ML-DSA
signing in the presence of adaptive adversaries. They also do not hide partial
secret-dependent payloads, prove selective-abort resistance, or replace the
deterministic VSS scaffold with a malicious-secure DKG. Those properties require
a formal adversary model, proof relation, and audited implementation boundary.

## Next Proof Obligations

1. Replace raw contribution exposure with a commitment/opening or zero-knowledge
   proof relation.
2. Prove challenge unbiasability under selective abort.
3. Prove partial contribution soundness against Round 1 commitments.
4. Prove final `z` distribution compatibility with ML-DSA-65 rejection
   sampling.
5. Define a real DKG transcript with VSS commitments and complaint resolution.
