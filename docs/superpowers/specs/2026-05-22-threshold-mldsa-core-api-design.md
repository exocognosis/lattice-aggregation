# Threshold ML-DSA-65 Core and API Boundary Design

Date: 2026-05-22

## Status

Approved design direction for Phase 1 cryptographic core and Phase 2 public API boundary.

This document specifies a Rust crate, `lattice-aggregation`, that exposes a threshold ML-DSA-65 protocol surface suitable for consensus integration experiments. The crate must be treated as research-grade until the concrete threshold construction, bounds, backend implementation, and test vectors have received external cryptographic review.

## Scope

This spec covers:

- Mathematical and transcript constraints needed for threshold ML-DSA-65 signing.
- Public Rust types and type-state API boundaries.
- DKG, signing, and aggregation module responsibilities.
- Error handling, serialization, and test strategy.
- Explicit guardrails between production-shaped interfaces and unaudited cryptographic internals.

This spec does not cover:

- P2P wire integration.
- Consensus block pipeline changes.
- Gas pricing changes.
- Testnet deployment.
- A claim that the initial implementation is production-ready or cryptographically audited.

## Design Goals

The crate must provide:

- A type-state signing state machine that prevents protocol rounds from being called out of order.
- Canonical transcript construction so challenges cannot be biased by message ordering or mixed sessions.
- Backend traits that hide polynomial rings and ML-DSA internals from consensus code.
- Named opaque types for commitments, key shares, partial signatures, transcripts, and final signatures.
- Deterministic simulation support for testing DKG, signing, rejection, and aggregation flow.
- Clear separation between safe public APIs and experimental cryptographic backends.

## Cryptographic Model

ML-DSA-65 uses Fiat-Shamir with aborts and rejection sampling. In the threshold setting, the global masking vector `y` is derived from local masking vectors `y_i`. Directly adding independent participant outputs is not safe unless the protocol preserves the same distributional and norm-bound properties expected by ML-DSA verification.

The signing flow must therefore bind all participants to their commitments before the global challenge is derived:

1. Each validator samples or deterministically derives local secret masking material `y_i`.
2. Each validator commits to its local public contribution, conceptually `w_i = HighBits(A * y_i)`.
3. The ordered commitment set is bound into the transcript.
4. The global challenge `c` is derived from the transcript, not supplied by the aggregator.
5. Each validator computes a partial signing share and performs local rejection checks.
6. The aggregator validates share provenance, threshold cardinality, duplicate IDs, transcript consistency, and share-level checks before producing a standard-sized ML-DSA-65 signature.

The initial crate must not hard-code an unaudited threshold Dilithium construction into the consensus-facing API. Instead, the mathematical backend is abstracted behind traits and marked experimental until a specific audited protocol is selected.

## Constants

The crate targets ML-DSA-65, aligned with FIPS 204 byte encodings:

```rust
pub const MLDSA65_PUBLICKEY_BYTES: usize = 1952;
pub const MLDSA65_SIGNATURE_BYTES: usize = 3309;
pub const POLY_SEED_BYTES: usize = 32;
pub const SESSION_ID_BYTES: usize = 32;
pub const COMMITMENT_BYTES: usize = 32;
```

## Public Type Model

Primitive byte arrays must be wrapped in named types. This prevents consumers from mixing commitments, challenges, partial shares, public keys, and signatures.

```rust
pub type SessionId = [u8; SESSION_ID_BYTES];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorId(pub u16);

pub struct ThresholdPublicKey(pub [u8; MLDSA65_PUBLICKEY_BYTES]);

pub struct ThresholdSignature(pub [u8; MLDSA65_SIGNATURE_BYTES]);

pub struct Commitment(pub [u8; COMMITMENT_BYTES]);

pub struct Challenge(pub [u8; 32]);

pub struct PartialSignatureShare {
    pub signer: ValidatorId,
    pub bytes: Vec<u8>,
}

pub struct PrivateKeyShare {
    pub share_id: ValidatorId,
    // Backend-owned representation of local s1 and s2 polynomial shares.
}
```

`PartialSignatureShare` uses a named backend-defined encoding rather than `[u8; 64]`. A threshold ML-DSA partial share is not guaranteed to fit into 64 bytes, and exposing a small raw array would likely force an incorrect protocol shape.

## Module Layout

```text
lattice-aggregation/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── aggregation.rs
│   ├── backend.rs
│   ├── dkg.rs
│   ├── errors.rs
│   ├── protocol.rs
│   ├── transcript.rs
│   └── types.rs
└── tests/
    ├── aggregate_flow.rs
    ├── transcript_determinism.rs
    └── type_state.rs
```

## Backend Boundary

The public crate API must not expose polynomial internals to P2P or consensus code. Backends provide cryptographic operations through traits:

```rust
pub trait Mldsa65Backend {
    type Error;
    type KeyShare;
    type CommitmentSecret;

    fn derive_commitment(
        share: &Self::KeyShare,
        session: &SigningTranscript,
    ) -> Result<(Commitment, Self::CommitmentSecret), Self::Error>;

    fn partial_sign(
        share: &Self::KeyShare,
        secret: Self::CommitmentSecret,
        transcript: &SigningTranscript,
    ) -> Result<PartialSignatureShare, Self::Error>;

    fn aggregate(
        public_key: &ThresholdPublicKey,
        transcript: &SigningTranscript,
        shares: ValidatedPartialShares,
    ) -> Result<ThresholdSignature, Self::Error>;

    fn verify_standard(
        public_key: &ThresholdPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, Self::Error>;
}
```

Simulation backends may be used for deterministic tests. Real ML-DSA threshold backends must live behind an `experimental` or `hazmat` feature until audited.

## Transcript Construction

The challenge must be derived from a canonical transcript. It must bind:

- Protocol name and version.
- Domain separator.
- `SessionId`.
- Threshold value.
- Total validator count.
- Ordered validator set.
- Threshold public key.
- Message bytes or message digest.
- Ordered commitments by `ValidatorId`.

Commitment collections must reject:

- Duplicate validator IDs.
- Unknown validator IDs.
- Fewer than `threshold` valid commitments.
- More than `total_nodes` commitments.
- Non-canonical ordering when deserialized.
- Commitments from another session or protocol version.

The transcript API should accept unordered network input but internally canonicalize to a `BTreeMap<ValidatorId, Commitment>` before hashing.

## Signing Type-State API

Each participant owns an isolated `SigningSession<State>`. Round transitions consume the prior state and return the next state.

```rust
pub mod state {
    pub struct Initialized;

    pub struct AwaitingCommitments {
        pub local_commitment: Commitment,
    }

    pub struct AwaitingPartialSignatures {
        pub challenge: Challenge,
    }

    pub struct Finalized;
}

pub struct SigningSession<State = state::Initialized> {
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    local_share: PrivateKeyShare,
    public_key: ThresholdPublicKey,
    validator_set: Vec<ValidatorId>,
    internal_state: State,
}
```

The session constructor validates:

- `threshold > 0`.
- `threshold <= total_nodes`.
- `validator_set.len() == total_nodes`.
- The local share ID appears in the validator set.
- The validator set has no duplicates.

## Public Traits

The top-level traits define how consensus and P2P layers drive the cryptographic core.

```rust
pub trait ThresholdKeyGeneration {
    type Error;

    fn generate_share_commitment(
        session: SessionId,
        nodes: u16,
    ) -> Result<Commitment, Self::Error>;

    fn finalize_public_key(
        verified_shares: ValidatedDkgShares,
    ) -> Result<ThresholdPublicKey, Self::Error>;
}

pub trait ThresholdSigner {
    type Error;

    fn initiate_signing(
        self,
    ) -> Result<(SigningSession<state::AwaitingCommitments>, Commitment), Self::Error>;

    fn generate_partial_signature(
        session: SigningSession<state::AwaitingCommitments>,
        all_commitments: CommitmentSet,
        message: &[u8],
    ) -> Result<
        (
            SigningSession<state::AwaitingPartialSignatures>,
            PartialSignatureShare,
        ),
        Self::Error,
    >;
}

pub trait SignatureAggregator {
    type Error;

    fn aggregate_shares(
        transcript: ThresholdSigningTranscript,
        partial_shares: PartialShareSet,
    ) -> Result<ThresholdSignature, Self::Error>;
}
```

`aggregate_shares` receives a transcript instead of a bare challenge so it cannot combine shares from mixed messages, validator sets, public keys, or sessions.

## DKG Boundary

The first implementation should provide a simulated VSS/DKG engine with the same API shape expected by a future real backend:

- Generate participant commitments.
- Verify commitment openings.
- Produce `PrivateKeyShare` objects.
- Produce one `ThresholdPublicKey`.
- Serialize private shares with explicit versioning and backend identifiers.

The DKG module must not claim full active-adversary security until a concrete VSS/DKG construction and proof are selected.

## Serialization

All wire-facing types must use explicit versioned encodings:

- Protocol version.
- Message type.
- Session ID.
- Validator ID.
- Payload length.
- Payload bytes.

Serde support may be provided for application convenience, but canonical transcript bytes must be generated by crate-owned encoding functions, not generic map serialization.

## Error Model

The error type should distinguish:

- Invalid threshold parameters.
- Unknown validator ID.
- Duplicate validator ID.
- Insufficient commitments.
- Insufficient partial shares.
- Commitment verification failure.
- Partial share verification failure.
- Rejection sampling failure.
- Transcript mismatch.
- Malformed serialization.
- Backend unavailable or unaudited backend disabled.
- Standard ML-DSA verification failure.

Errors used for malicious validator tracking should include the validator ID when attributable.

## Constant-Time and Allocation Policy

Consensus-facing APIs should not expose variable-time polynomial operations. Backend implementations must document:

- Which operations are constant-time.
- Which operations allocate.
- Which operations depend on secret data.
- Which SIMD or target-specific paths are enabled.

The initial scaffold should include placeholders for `dudect` or equivalent timing tests, but timing-stability claims must only be made after those tests run against the concrete backend.

## Test Strategy

Phase 1 and the Phase 2 boundary require:

- Type-state compile tests proving invalid round calls do not compile.
- Transcript determinism tests with shuffled network inputs.
- Duplicate validator rejection tests.
- Unknown validator rejection tests.
- Invalid threshold parameter tests.
- Simulated DKG happy-path tests.
- Simulated signing happy-path tests.
- Simulated rejection-path tests.
- Aggregation rejection tests for mixed sessions and mixed messages.
- Standard verification integration test once a real ML-DSA backend exists.

Fuzzing targets should be added after the binary encoding exists:

- Commitment set decoding.
- Partial share set decoding.
- Transcript construction.
- Aggregation input validation.

## Audit and Production Readiness Gates

The crate cannot be considered production-ready until:

- A concrete threshold ML-DSA protocol is selected.
- The mathematical noise-bound model is completed for ML-DSA-65 parameters.
- The implementation passes deterministic, randomized, fuzz, and timing tests.
- A standard ML-DSA verifier accepts aggregated signatures.
- External cryptographic review confirms the construction and implementation.
- Consensus integration tests demonstrate timeout and malicious-share handling.

Until then, production-shaped APIs are acceptable, but cryptographic signing backends must remain explicitly experimental.

## References

- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard.
- NIST CSRC FIPS 204 publication page and errata tracking.
- Recent threshold ML-DSA research should be reviewed before selecting the concrete backend protocol.
