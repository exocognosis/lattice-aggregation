#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        acceptance::{AcceptedPartialContribution, LocalAccept, LocalAcceptEvidence},
        epsilon::{EpsilonLedger, EpsilonUnit},
        partial_soundness::{
            EvidenceClass, LeakageBudget, LeakageLimits, LeakageModel, LocalProofEvidence,
            LocalProofSoundnessLabel, PartialContextBinding, PartialContributionSoundnessEvidence,
            PartialEvidenceRequirement, PartialVerifierBinding, ProofBackedLocalVerifier,
        },
        transcript::{CommitmentDigest, ProductionSigningTranscript, ProductionTranscriptInput},
        types::{
            ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
            ValidatorSetDigest,
        },
    },
    ThresholdError, ThresholdPublicKey, ValidatorId,
};

fn make_transcript(retry_counter: u32) -> ProductionSigningTranscript {
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
        retry_counter,
        commitment_digests: vec![
            (ValidatorId(1), CommitmentDigest([11; 32])),
            (ValidatorId(2), CommitmentDigest([12; 32])),
        ],
    })
    .unwrap()
}

fn accepted_partial(transcript: &ProductionSigningTranscript) -> AcceptedPartialContribution {
    LocalAccept::accept(
        transcript,
        LocalAcceptEvidence {
            signer: ValidatorId(1),
            commitment_digest: CommitmentDigest([11; 32]),
            partial_share_digest: [21; 32],
            local_bounds_proof_digest: [22; 32],
        },
    )
    .unwrap()
}

fn binding(
    transcript: &ProductionSigningTranscript,
    partial: &AcceptedPartialContribution,
) -> PartialVerifierBinding {
    PartialVerifierBinding::new(
        partial.signer(),
        partial.commitment_digest(),
        *partial.challenge_digest(),
        *partial.partial_share_digest(),
        *partial.local_bounds_proof_digest(),
        [31; 32],
        *transcript.challenge_digest(),
    )
}

fn leakage_budget() -> LeakageBudget {
    let mut ledger = EpsilonLedger::default();
    ledger.increment_mask(EpsilonUnit::from_units(3));
    ledger.increment_rejection(EpsilonUnit::from_units(5));
    ledger.increment_withholding(EpsilonUnit::from_units(7));
    LeakageBudget::new(
        LeakageModel::PublicDigestOnly,
        ledger,
        LeakageLimits::new(
            EpsilonUnit::from_units(3),
            EpsilonUnit::from_units(5),
            EpsilonUnit::from_units(7),
        ),
    )
}

#[test]
fn digest_scaffold_partial_soundness_records_bindings_without_claiming_real_proof() {
    let transcript = make_transcript(0);
    let partial = accepted_partial(&transcript);

    let evidence = PartialContributionSoundnessEvidence::verify(
        &transcript,
        &partial,
        binding(&transcript, &partial),
        PartialContextBinding::from_transcript(&transcript),
        LocalProofEvidence::scaffold_digest_only(*partial.local_bounds_proof_digest()),
        leakage_budget(),
        PartialEvidenceRequirement::ScaffoldDigestOrProofBacked,
    )
    .unwrap();

    assert_eq!(evidence.signer(), ValidatorId(1));
    assert_eq!(evidence.evidence_class(), EvidenceClass::ScaffoldDigestOnly);
    assert_eq!(
        evidence.local_proof_soundness_label(),
        LocalProofSoundnessLabel::ScaffoldDigestOnly
    );
    assert!(!evidence.is_proof_backed());
    assert_eq!(
        evidence.leakage_budget().model(),
        LeakageModel::PublicDigestOnly
    );
    assert_eq!(
        evidence.leakage_budget().observed().epsilon_mask(),
        EpsilonUnit::from_units(3)
    );
    assert_eq!(
        evidence.leakage_budget().limits().epsilon_withhold(),
        EpsilonUnit::from_units(7)
    );
    assert_eq!(
        evidence.context_binding(),
        &PartialContextBinding::from_transcript(&transcript)
    );
}

#[test]
fn proof_backed_partial_soundness_satisfies_proof_backed_requirement() {
    let transcript = make_transcript(0);
    let partial = accepted_partial(&transcript);
    let proof = ProofBackedLocalVerifier::new(
        "zk-local-bounds-v1",
        [41; 32],
        [42; 32],
        *partial.local_bounds_proof_digest(),
        [44; 32],
    )
    .unwrap();
    assert_eq!(proof.verifier_transcript_digest(), &[44; 32]);

    let evidence = PartialContributionSoundnessEvidence::verify(
        &transcript,
        &partial,
        binding(&transcript, &partial),
        PartialContextBinding::from_transcript(&transcript),
        LocalProofEvidence::proof_backed(proof),
        leakage_budget(),
        PartialEvidenceRequirement::ProofBackedOnly,
    )
    .unwrap();

    assert_eq!(evidence.evidence_class(), EvidenceClass::ProofBacked);
    assert_eq!(
        evidence.local_proof_soundness_label(),
        LocalProofSoundnessLabel::ProofBacked {
            proof_system: "zk-local-bounds-v1",
            verifier_key_digest: [41; 32],
            soundness_theorem_digest: [42; 32],
        }
    );
    assert!(evidence.is_proof_backed());
}

#[test]
fn scaffold_digest_only_evidence_cannot_satisfy_proof_backed_requirement() {
    let transcript = make_transcript(0);
    let partial = accepted_partial(&transcript);

    let err = PartialContributionSoundnessEvidence::verify(
        &transcript,
        &partial,
        binding(&transcript, &partial),
        PartialContextBinding::from_transcript(&transcript),
        LocalProofEvidence::scaffold_digest_only(*partial.local_bounds_proof_digest()),
        leakage_budget(),
        PartialEvidenceRequirement::ProofBackedOnly,
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::ProductionPolicyBlocked {
            reason: "proof-backed partial evidence required",
        }
    );
}

#[test]
fn partial_verifier_binding_rejects_mismatched_partial_digest() {
    let transcript = make_transcript(0);
    let partial = accepted_partial(&transcript);
    let mut binding = binding(&transcript, &partial);
    binding.partial_share_digest = [99; 32];

    let err = PartialContributionSoundnessEvidence::verify(
        &transcript,
        &partial,
        binding,
        PartialContextBinding::from_transcript(&transcript),
        LocalProofEvidence::scaffold_digest_only(*partial.local_bounds_proof_digest()),
        leakage_budget(),
        PartialEvidenceRequirement::ScaffoldDigestOrProofBacked,
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1),
        }
    );
}

#[test]
fn context_binding_rejects_stale_transcript_attempt() {
    let transcript = make_transcript(0);
    let stale_transcript = make_transcript(1);
    let partial = accepted_partial(&transcript);

    let err = PartialContributionSoundnessEvidence::verify(
        &transcript,
        &partial,
        binding(&transcript, &partial),
        PartialContextBinding::from_transcript(&stale_transcript),
        LocalProofEvidence::scaffold_digest_only(*partial.local_bounds_proof_digest()),
        leakage_budget(),
        PartialEvidenceRequirement::ScaffoldDigestOrProofBacked,
    )
    .unwrap_err();

    assert_eq!(err, ThresholdError::TranscriptMismatch);
}

#[test]
fn leakage_budget_rejects_ledger_that_exceeds_chosen_model() {
    let transcript = make_transcript(0);
    let partial = accepted_partial(&transcript);
    let mut ledger = EpsilonLedger::default();
    ledger.increment_mask(EpsilonUnit::from_units(4));
    let budget = LeakageBudget::new(
        LeakageModel::RenyiBounded,
        ledger,
        LeakageLimits::new(
            EpsilonUnit::from_units(3),
            EpsilonUnit::ZERO,
            EpsilonUnit::ZERO,
        ),
    );

    let err = PartialContributionSoundnessEvidence::verify(
        &transcript,
        &partial,
        binding(&transcript, &partial),
        PartialContextBinding::from_transcript(&transcript),
        LocalProofEvidence::scaffold_digest_only(*partial.local_bounds_proof_digest()),
        budget,
        PartialEvidenceRequirement::ScaffoldDigestOrProofBacked,
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::ProductionPolicyBlocked {
            reason: "partial leakage budget exceeded",
        }
    );
}
