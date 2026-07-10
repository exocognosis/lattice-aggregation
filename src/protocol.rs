//! Type-state signing protocol.
//!
//! Sessions are parameterized by a [`SessionBackend`]. The default backend is
//! [`SimulatedBackend`]; enable `raw-real-mldsa` and construct sessions with
//! [`SigningSession::with_backend`] plus [`crate::RealMldsa65Backend`] for real
//! ML-DSA-65 seed-reconstruction crypto.

use core::{fmt, marker::PhantomData};

use crate::{
    backend::{Mldsa65Backend, SimulatedBackend},
    collections::{set_from_validators, validate_threshold, CommitmentSet},
    errors::ThresholdError,
    transcript::SigningTranscript,
    types::{
        Challenge, Commitment, PartialSignatureShare, PrivateKeyShare, SessionId,
        ThresholdPublicKey, ValidatorId,
    },
};

/// Signing session states.
pub mod state {
    use std::collections::HashMap;

    use crate::{
        low_level::poly::Poly,
        types::{Challenge, Commitment},
    };

    /// Initial signing session state.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct Initialized;

    /// Local commitment has been generated and peer commitments are needed.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AwaitingCommitments {
        /// Local masking polynomial placeholder for low-level integrations.
        pub local_y: Poly,
        /// Local commitment broadcast to peers.
        pub local_commitment: Commitment,
        /// Commitments collected from peer validators.
        pub received_commitments: HashMap<u16, [u8; 32]>,
    }

    /// Commitments are bound and partial signatures are being collected.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AwaitingPartialSignatures {
        /// Transcript-derived signing challenge.
        pub global_challenge: Challenge,
        /// Partial polynomial shares collected from validators.
        pub partial_shares: HashMap<u16, Poly>,
    }

    /// Finalized signing session state.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct Finalized;
}

/// Backend bound used by the type-state signing session.
///
/// Concrete backends must report [`ThresholdError`] and store key material as
/// [`PrivateKeyShare`] so the public session API stays stable across sim and
/// real constructions.
pub trait SessionBackend:
    Mldsa65Backend<Error = ThresholdError, KeyShare = PrivateKeyShare> + Default
{
}

impl<B> SessionBackend for B where
    B: Mldsa65Backend<Error = ThresholdError, KeyShare = PrivateKeyShare> + Default
{
}

/// Participant-local threshold signing session.
///
/// The second type parameter selects the cryptographic backend. Defaults to
/// [`SimulatedBackend`] for deterministic protocol tests.
pub struct SigningSession<State = state::Initialized, B = SimulatedBackend>
where
    B: SessionBackend,
{
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    local_share: PrivateKeyShare,
    public_key: ThresholdPublicKey,
    validator_set: Vec<ValidatorId>,
    internal_state: State,
    commitment_secret: Option<B::CommitmentSecret>,
    _backend: PhantomData<fn() -> B>,
}

impl<State, B> fmt::Debug for SigningSession<State, B>
where
    State: fmt::Debug,
    B: SessionBackend,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningSession")
            .field("session_id", &self.session_id)
            .field("threshold", &self.threshold)
            .field("total_nodes", &self.total_nodes)
            .field("local_share", &self.local_share)
            .field("public_key", &self.public_key)
            .field("validator_set", &self.validator_set)
            .field("internal_state", &self.internal_state)
            .field(
                "commitment_secret_present",
                &self.commitment_secret.is_some(),
            )
            .finish()
    }
}

impl<State, B> SigningSession<State, B>
where
    B: SessionBackend,
{
    /// Borrow the current type-state marker and its public buffers.
    pub fn internal_state(&self) -> &State {
        &self.internal_state
    }
}

impl<B> SigningSession<state::Initialized, B>
where
    B: SessionBackend,
{
    /// Construct and validate an initialized signing session for backend `B`.
    pub fn with_backend(
        session_id: SessionId,
        threshold: u16,
        validator_set: Vec<ValidatorId>,
        public_key: ThresholdPublicKey,
        local_share: PrivateKeyShare,
    ) -> Result<Self, ThresholdError> {
        let total_nodes = validator_set.len() as u16;
        validate_threshold(threshold, total_nodes)?;

        let validators = set_from_validators(validator_set.clone())?;
        if !validators.contains(&local_share.share_id) {
            return Err(ThresholdError::UnknownValidator {
                validator: local_share.share_id,
            });
        }

        Ok(Self {
            session_id,
            threshold,
            total_nodes,
            local_share,
            public_key,
            validator_set,
            internal_state: state::Initialized,
            commitment_secret: None,
            _backend: PhantomData,
        })
    }

    /// Generate the local commitment and advance to commitment collection.
    pub fn initiate_signing(
        self,
    ) -> Result<(SigningSession<state::AwaitingCommitments, B>, Commitment), ThresholdError> {
        let precommit_commitments = CommitmentSet::new(
            self.validator_set.clone(),
            1,
            vec![(self.local_share.share_id, Commitment([0; 32]))],
        )?;
        let precommit_transcript = SigningTranscript::new(
            self.session_id,
            1,
            self.validator_set.clone(),
            self.public_key.clone(),
            b"precommit",
            precommit_commitments,
        )?;
        let (commitment, secret) = B::derive_commitment(&self.local_share, &precommit_transcript)?;

        Ok((
            SigningSession {
                session_id: self.session_id,
                threshold: self.threshold,
                total_nodes: self.total_nodes,
                local_share: self.local_share,
                public_key: self.public_key,
                validator_set: self.validator_set,
                internal_state: state::AwaitingCommitments {
                    local_y: crate::Poly::zero(),
                    local_commitment: commitment,
                    received_commitments: std::collections::HashMap::new(),
                },
                commitment_secret: Some(secret),
                _backend: PhantomData,
            },
            commitment,
        ))
    }
}

impl SigningSession<state::Initialized, SimulatedBackend> {
    /// Construct a simulation-backend session (stable default entry point).
    pub fn new(
        session_id: SessionId,
        threshold: u16,
        validator_set: Vec<ValidatorId>,
        public_key: ThresholdPublicKey,
        local_share: PrivateKeyShare,
    ) -> Result<Self, ThresholdError> {
        Self::with_backend(
            session_id,
            threshold,
            validator_set,
            public_key,
            local_share,
        )
    }
}

impl<B> SigningSession<state::AwaitingCommitments, B>
where
    B: SessionBackend,
{
    /// Bind all commitments, derive the challenge, and emit the local partial signature.
    pub fn generate_partial_signature(
        self,
        all_commitments: CommitmentSet,
        message: &[u8],
    ) -> Result<
        (
            SigningSession<state::AwaitingPartialSignatures, B>,
            PartialSignatureShare,
        ),
        ThresholdError,
    > {
        let local_validator = self.local_share.share_id;
        let local_commitment = self.internal_state.local_commitment;
        if all_commitments.get(local_validator) != Some(&local_commitment) {
            return Err(ThresholdError::CommitmentVerificationFailed {
                validator: local_validator,
            });
        }

        let transcript = SigningTranscript::new(
            self.session_id,
            self.threshold,
            self.validator_set.clone(),
            self.public_key.clone(),
            message,
            all_commitments,
        )?;
        let secret = self
            .commitment_secret
            .ok_or(ThresholdError::TranscriptMismatch)?;
        let partial = B::partial_sign(&self.local_share, secret, &transcript)?;
        let challenge = transcript.challenge();

        Ok((
            SigningSession {
                session_id: self.session_id,
                threshold: self.threshold,
                total_nodes: self.total_nodes,
                local_share: self.local_share,
                public_key: self.public_key,
                validator_set: self.validator_set,
                internal_state: state::AwaitingPartialSignatures {
                    global_challenge: challenge,
                    partial_shares: std::collections::HashMap::new(),
                },
                commitment_secret: None,
                _backend: PhantomData,
            },
            partial,
        ))
    }
}

/// Public signing round interface for the initialized state.
pub trait ThresholdSigner: Sized {
    /// Error returned by the signing state machine.
    type Error;
    /// Cryptographic backend used by this signer.
    type Backend: SessionBackend;

    /// Generate the local commitment and advance to commitment collection.
    #[allow(clippy::type_complexity)]
    fn initiate_signing(
        self,
    ) -> Result<
        (
            SigningSession<state::AwaitingCommitments, Self::Backend>,
            Commitment,
        ),
        Self::Error,
    >;
}

impl<B> ThresholdSigner for SigningSession<state::Initialized, B>
where
    B: SessionBackend,
{
    type Error = ThresholdError;
    type Backend = B;

    fn initiate_signing(
        self,
    ) -> Result<(SigningSession<state::AwaitingCommitments, B>, Commitment), Self::Error> {
        SigningSession::<state::Initialized, B>::initiate_signing(self)
    }
}

impl<B> SigningSession<state::AwaitingPartialSignatures, B>
where
    B: SessionBackend,
{
    /// Return the transcript-derived challenge.
    pub fn challenge(&self) -> Challenge {
        self.internal_state.global_challenge
    }
}
