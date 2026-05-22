//! Type-state signing protocol.

use core::fmt;

use crate::{
    backend::{Mldsa65Backend, SimulatedBackend, SimulatedCommitmentSecret},
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
    use crate::types::{Challenge, Commitment};

    /// Initial signing session state.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct Initialized;

    /// Local commitment has been generated and peer commitments are needed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AwaitingCommitments {
        /// Local commitment broadcast to peers.
        pub local_commitment: Commitment,
    }

    /// Commitments are bound and partial signatures are being collected.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AwaitingPartialSignatures {
        /// Transcript-derived signing challenge.
        pub challenge: Challenge,
    }

    /// Finalized signing session state.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct Finalized;
}

/// Participant-local threshold signing session.
pub struct SigningSession<State = state::Initialized> {
    session_id: SessionId,
    threshold: u16,
    total_nodes: u16,
    local_share: PrivateKeyShare,
    public_key: ThresholdPublicKey,
    validator_set: Vec<ValidatorId>,
    internal_state: State,
    commitment_secret: Option<SimulatedCommitmentSecret>,
}

impl<State> fmt::Debug for SigningSession<State>
where
    State: fmt::Debug,
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

impl SigningSession<state::Initialized> {
    /// Construct and validate an initialized signing session.
    pub fn new(
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
        })
    }
}

/// Public signing round interface.
pub trait ThresholdSigner: Sized {
    /// Error returned by the signing state machine.
    type Error;

    /// Generate the local commitment and advance to commitment collection.
    fn initiate_signing(
        self,
    ) -> Result<(SigningSession<state::AwaitingCommitments>, Commitment), Self::Error>;

    /// Bind all commitments, derive the challenge, and emit the local partial signature.
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

impl ThresholdSigner for SigningSession<state::Initialized> {
    type Error = ThresholdError;

    fn initiate_signing(
        self,
    ) -> Result<(SigningSession<state::AwaitingCommitments>, Commitment), Self::Error> {
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
        let (commitment, secret) =
            SimulatedBackend::derive_commitment(&self.local_share, &precommit_transcript)?;

        Ok((
            SigningSession {
                session_id: self.session_id,
                threshold: self.threshold,
                total_nodes: self.total_nodes,
                local_share: self.local_share,
                public_key: self.public_key,
                validator_set: self.validator_set,
                internal_state: state::AwaitingCommitments {
                    local_commitment: commitment,
                },
                commitment_secret: Some(secret),
            },
            commitment,
        ))
    }

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
    > {
        let local_validator = session.local_share.share_id;
        let local_commitment = session.internal_state.local_commitment;
        if all_commitments.get(local_validator) != Some(&local_commitment) {
            return Err(ThresholdError::CommitmentVerificationFailed {
                validator: local_validator,
            });
        }

        let transcript = SigningTranscript::new(
            session.session_id,
            session.threshold,
            session.validator_set.clone(),
            session.public_key.clone(),
            message,
            all_commitments,
        )?;
        let secret = session
            .commitment_secret
            .ok_or(ThresholdError::TranscriptMismatch)?;
        let partial = SimulatedBackend::partial_sign(&session.local_share, secret, &transcript);
        let partial = partial?;
        let challenge = transcript.challenge();

        Ok((
            SigningSession {
                session_id: session.session_id,
                threshold: session.threshold,
                total_nodes: session.total_nodes,
                local_share: session.local_share,
                public_key: session.public_key,
                validator_set: session.validator_set,
                internal_state: state::AwaitingPartialSignatures { challenge },
                commitment_secret: None,
            },
            partial,
        ))
    }
}

impl SigningSession<state::AwaitingPartialSignatures> {
    /// Return the transcript-derived challenge.
    pub fn challenge(&self) -> Challenge {
        self.internal_state.challenge
    }
}
