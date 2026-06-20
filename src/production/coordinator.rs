//! Coordinator-assisted aggregate finalization gate.

use core::marker::PhantomData;

use crate::{ThresholdError, ThresholdSignature};

use super::{
    policy::ProductionPolicy, provider::StandardMldsa65Provider,
    transcript::ProductionSigningTranscript,
};

/// Aggregate finalization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateAttemptRequest {
    /// Bound production transcript.
    pub transcript: ProductionSigningTranscript,
    /// Candidate signature assembled by the coordinator profile.
    pub candidate_signature: ThresholdSignature,
    /// Runtime release policy.
    pub policy: ProductionPolicy,
}

/// Final standard-verifier gate for coordinator aggregates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoordinatorAggregateGate<P> {
    _provider: PhantomData<P>,
}

impl<P> CoordinatorAggregateGate<P>
where
    P: StandardMldsa65Provider,
{
    /// Finalize a candidate signature only after policy and standard verification pass.
    pub fn finalize(
        request: AggregateAttemptRequest,
    ) -> Result<ThresholdSignature, ThresholdError> {
        request.policy.require_production_release()?;
        let public_key = &request.transcript.input().public_key;
        let message = &request.transcript.input().application_message;
        if !P::verify(public_key, message, &request.candidate_signature)? {
            return Err(ThresholdError::StandardVerificationFailed);
        }
        Ok(request.candidate_signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        production::{
            policy::ProductionPolicy,
            provider::{StandardMldsa65Provider, UnavailableMldsa65Provider},
            transcript::{
                CommitmentDigest, ProductionSigningTranscript, ProductionTranscriptInput,
            },
            types::{
                ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
                ValidatorSetDigest,
            },
        },
        ThresholdError, ThresholdPublicKey, ThresholdSignature, ValidatorId,
    };

    use super::{AggregateAttemptRequest, CoordinatorAggregateGate};

    struct RejectingProvider;

    impl StandardMldsa65Provider for RejectingProvider {
        fn verify(
            public_key: &ThresholdPublicKey,
            message: &[u8],
            signature: &ThresholdSignature,
        ) -> Result<bool, ThresholdError> {
            assert_eq!(public_key, &ThresholdPublicKey([6; 1952]));
            assert_eq!(message, b"original application message");
            assert_eq!(signature, &ThresholdSignature([42; 3309]));
            Ok(false)
        }
    }

    struct AcceptingProvider;

    impl StandardMldsa65Provider for AcceptingProvider {
        fn verify(
            public_key: &ThresholdPublicKey,
            message: &[u8],
            signature: &ThresholdSignature,
        ) -> Result<bool, ThresholdError> {
            assert_eq!(public_key, &ThresholdPublicKey([6; 1952]));
            assert_eq!(message, b"original application message");
            assert_eq!(signature, &ThresholdSignature([42; 3309]));
            Ok(true)
        }
    }

    struct PanickingProvider;

    impl StandardMldsa65Provider for PanickingProvider {
        fn verify(
            _public_key: &ThresholdPublicKey,
            _message: &[u8],
            _signature: &ThresholdSignature,
        ) -> Result<bool, ThresholdError> {
            panic!("provider should not be called when policy blocks finalization");
        }
    }

    fn transcript() -> ProductionSigningTranscript {
        ProductionSigningTranscript::new(ProductionTranscriptInput {
            session_id: [1; 32],
            epoch: EpochId(2),
            key_id: KeyId([3; 32]),
            validator_set_digest: ValidatorSetDigest([4; 32]),
            dkg_transcript_digest: DkgTranscriptDigest([5; 32]),
            active_signers: ActiveSignerSet::new(vec![ValidatorId(1), ValidatorId(2)]).unwrap(),
            threshold: 2,
            public_key: ThresholdPublicKey([6; 1952]),
            application_message: b"original application message".to_vec(),
            message_binding: MessageBinding([7; 64]),
            attempt_id: AttemptId([8; 32]),
            coordinator_attestation_digest: [9; 32],
            retry_counter: 0,
            commitment_digests: vec![
                (ValidatorId(1), CommitmentDigest([1; 32])),
                (ValidatorId(2), CommitmentDigest([2; 32])),
            ],
        })
        .unwrap()
    }

    fn request(policy: ProductionPolicy) -> AggregateAttemptRequest {
        AggregateAttemptRequest {
            transcript: transcript(),
            candidate_signature: ThresholdSignature([42; 3309]),
            policy,
        }
    }

    #[test]
    fn aggregate_gate_requires_standard_verification() {
        let err = CoordinatorAggregateGate::<UnavailableMldsa65Provider>::finalize(request(
            ProductionPolicy::production_approved(),
        ))
        .unwrap_err();
        assert_eq!(
            err,
            ThresholdError::BackendUnavailable {
                reason: "standard ML-DSA provider is not enabled",
            }
        );
    }

    #[test]
    fn aggregate_gate_rejects_standard_verification_failure() {
        let err = CoordinatorAggregateGate::<RejectingProvider>::finalize(request(
            ProductionPolicy::production_approved(),
        ))
        .unwrap_err();
        assert_eq!(err, ThresholdError::StandardVerificationFailed);
    }

    #[test]
    fn aggregate_gate_returns_signature_after_standard_verification() {
        let signature = CoordinatorAggregateGate::<AcceptingProvider>::finalize(request(
            ProductionPolicy::production_approved(),
        ))
        .unwrap();
        assert_eq!(signature, ThresholdSignature([42; 3309]));
    }

    #[test]
    fn aggregate_gate_checks_policy_before_provider_verification() {
        let err = CoordinatorAggregateGate::<PanickingProvider>::finalize(request(
            ProductionPolicy::hazmat_unreviewed(),
        ))
        .unwrap_err();
        assert_eq!(
            err,
            ThresholdError::ProductionPolicyBlocked {
                reason: "coordinator profile has not passed production release gates",
            }
        );
    }
}
