#![cfg(feature = "coordinator-assisted")]

use lattice_aggregation::{
    production::{
        acceptance::{AcceptedPartialContribution, LocalAccept, LocalAcceptEvidence},
        epsilon::{EpsilonLedger, EpsilonUnit},
        partial_soundness::{
            ClosureProofRequirement, EvidenceClass, LeakageBudget, LeakageLimits, LeakageModel,
            LocalProofEvidence, LocalProofSoundnessLabel, PartialContextBinding,
            PartialContributionSoundnessEvidence, PartialEvidenceRequirement,
            PartialSoundnessClosurePackage, PartialSoundnessClosureStatus, PartialVerifierBinding,
            ProofBackedLocalVerifier,
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

fn proof_backed_local_verifier(partial: &AcceptedPartialContribution) -> ProofBackedLocalVerifier {
    ProofBackedLocalVerifier::new(
        "zk-local-bounds-v1",
        [41; 32],
        [42; 32],
        *partial.local_bounds_proof_digest(),
        [44; 32],
    )
    .unwrap()
}

fn closure_package(context: &PartialContextBinding) -> PartialSoundnessClosurePackage {
    PartialSoundnessClosurePackage::new(
        "zk-local-bounds-v1",
        [51; 32],
        [52; 32],
        [53; 32],
        context.closure_digest(),
        ClosureProofRequirement::ProofBackedLocalVerifierRequired,
        [54; 32],
    )
    .unwrap()
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
    let proof = proof_backed_local_verifier(&partial);
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
    assert_eq!(
        evidence.closure_status(),
        PartialSoundnessClosureStatus::ConformanceOnly
    );
    assert!(!evidence.is_closure_ready());
    assert_eq!(evidence.closure_package(), None);
}

#[test]
fn complete_closure_package_marks_partial_evidence_closure_ready() {
    let transcript = make_transcript(0);
    let partial = accepted_partial(&transcript);
    let context = PartialContextBinding::from_transcript(&transcript);
    let package = closure_package(&context);

    let evidence = PartialContributionSoundnessEvidence::verify_closure_package(
        &transcript,
        &partial,
        binding(&transcript, &partial),
        context,
        LocalProofEvidence::proof_backed(proof_backed_local_verifier(&partial)),
        leakage_budget(),
        package,
    )
    .unwrap();

    assert_eq!(evidence.evidence_class(), EvidenceClass::ProofBacked);
    assert_eq!(
        evidence.closure_status(),
        PartialSoundnessClosureStatus::ClosureReady
    );
    assert!(evidence.is_closure_ready());
    assert_eq!(evidence.closure_package(), Some(package));
    assert_eq!(package.proof_system_label(), "zk-local-bounds-v1");
    assert_eq!(package.audited_local_verifier_digest(), &[51; 32]);
    assert_eq!(package.vss_dkg_binding_proof_digest(), &[52; 32]);
    assert_eq!(package.hiding_leakage_proof_digest(), &[53; 32]);
    assert_eq!(
        package.proof_requirement(),
        ClosureProofRequirement::ProofBackedLocalVerifierRequired
    );
    assert_eq!(package.external_review_digest(), &[54; 32]);
}

#[test]
fn closure_request_rejects_digest_only_partial_evidence() {
    let transcript = make_transcript(0);
    let partial = accepted_partial(&transcript);
    let context = PartialContextBinding::from_transcript(&transcript);
    let package = closure_package(&context);

    let err = PartialContributionSoundnessEvidence::verify_closure_package(
        &transcript,
        &partial,
        binding(&transcript, &partial),
        context,
        LocalProofEvidence::scaffold_digest_only(*partial.local_bounds_proof_digest()),
        leakage_budget(),
        package,
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::ProductionPolicyBlocked {
            reason: "closure package requires proof-backed partial evidence",
        }
    );
}

#[test]
fn closure_package_rejects_mismatched_transcript_context_digest() {
    let transcript = make_transcript(0);
    let partial = accepted_partial(&transcript);
    let context = PartialContextBinding::from_transcript(&transcript);
    let package = PartialSoundnessClosurePackage::new(
        "zk-local-bounds-v1",
        [51; 32],
        [52; 32],
        [53; 32],
        [99; 32],
        ClosureProofRequirement::ProofBackedLocalVerifierRequired,
        [54; 32],
    )
    .unwrap();

    let err = PartialContributionSoundnessEvidence::verify_closure_package(
        &transcript,
        &partial,
        binding(&transcript, &partial),
        context,
        LocalProofEvidence::proof_backed(proof_backed_local_verifier(&partial)),
        leakage_budget(),
        package,
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::ProductionPolicyBlocked {
            reason: "partial closure transcript context digest mismatch",
        }
    );
}

#[test]
fn closure_package_rejects_proof_system_label_mismatch() {
    let transcript = make_transcript(0);
    let partial = accepted_partial(&transcript);
    let context = PartialContextBinding::from_transcript(&transcript);
    let package = PartialSoundnessClosurePackage::new(
        "other-local-proof-v1",
        [51; 32],
        [52; 32],
        [53; 32],
        context.closure_digest(),
        ClosureProofRequirement::ProofBackedLocalVerifierRequired,
        [54; 32],
    )
    .unwrap();

    let err = PartialContributionSoundnessEvidence::verify_closure_package(
        &transcript,
        &partial,
        binding(&transcript, &partial),
        context,
        LocalProofEvidence::proof_backed(proof_backed_local_verifier(&partial)),
        leakage_budget(),
        package,
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::ProductionPolicyBlocked {
            reason: "partial closure proof system label mismatch",
        }
    );
}

#[test]
fn closure_package_rejects_missing_digest_component() {
    let context = PartialContextBinding::from_transcript(&make_transcript(0));

    let err = PartialSoundnessClosurePackage::new(
        "zk-local-bounds-v1",
        [51; 32],
        [52; 32],
        [53; 32],
        context.closure_digest(),
        ClosureProofRequirement::ProofBackedLocalVerifierRequired,
        [0; 32],
    )
    .unwrap_err();

    assert_eq!(
        err,
        ThresholdError::MalformedSerialization {
            reason: "partial closure package digest is all zero",
        }
    );
}

#[test]
fn closure_package_rejects_digest_only_requirement() {
    let package = PartialSoundnessClosurePackage::new(
        "zk-local-bounds-v1",
        [51; 32],
        [52; 32],
        [53; 32],
        [55; 32],
        ClosureProofRequirement::DigestOnlyEvidenceAllowed,
        [54; 32],
    )
    .unwrap();

    let err = package.verify_proof_requirement().unwrap_err();

    assert_eq!(
        err,
        ThresholdError::ProductionPolicyBlocked {
            reason: "partial closure package must require proof-backed evidence",
        }
    );
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
