#![cfg(feature = "production-mldsa65-coordinator")]

//! Criterion 4 (`partial_contribution_soundness`) advancement — executable
//! evidence for the SOUNDNESS leg only.
//!
//! The existing `partial_soundness` evidence surface
//! (`src/production/partial_soundness.rs`) checks that public *digests* carried
//! by an accepted partial are bound to the transcript context. It never
//! recomputes the underlying algebraic partial, so a digest is trusted as-is.
//!
//! These tests exercise a *real* local partial-share validity gate over Stack B
//! module-vector partials (`z_i = y_i + c · s1_i` over `R_q^L`), using genuine
//! negacyclic ring arithmetic and the real ML-DSA-65 acceptance bound
//! `‖z_i‖_∞ < γ₁ − β`. They show the gate:
//!
//! 1. accepts an honest partial and mints a real validity digest;
//! 2. rejects four genuine fault classes (tampered response, wrong/rebound
//!    challenge, share not bound to the signer, out-of-bound response);
//! 3. can feed its *real* digest into the criterion-4 typed evidence surface,
//!    which still classifies it as `ScaffoldDigestOnly` / `ConformanceOnly` and
//!    refuses to promote it to proof-backed evidence.
//!
//! Honest boundary: this gate is NOT zero-knowledge — it consumes `y_i` and
//! `s1_i` in the clear, so it does not discharge the hiding/leakage obligation,
//! the research expanders are not CAVP-identical, and it does not replace the
//! audited proof-backed local verifier or external review. Criterion 4 remains
//! `partially_met`. See
//! `docs/cryptography/partial-soundness-advancement-2026-07-12.md`.

use lattice_aggregation::{
    backend::module_partial::{verify_module_partial_local_validity, ModulePartialLocalValidity},
    compute_z, emit_module_partial_zi,
    production::{
        acceptance::{AcceptedPartialContribution, LocalAccept, LocalAcceptEvidence},
        epsilon::{EpsilonLedger, EpsilonUnit},
        partial_soundness::{
            EvidenceClass, LeakageBudget, LeakageLimits, LeakageModel, LocalProofEvidence,
            PartialContextBinding, PartialContributionSoundnessEvidence,
            PartialEvidenceRequirement, PartialSoundnessClosureStatus, PartialVerifierBinding,
        },
        transcript::{CommitmentDigest, ProductionSigningTranscript, ProductionTranscriptInput},
        types::{
            ActiveSignerSet, AttemptId, DkgTranscriptDigest, EpochId, KeyId, MessageBinding,
            ValidatorSetDigest,
        },
    },
    sample_in_ball, ModulePartialZi, ModuleVecL, Poly, ThresholdError, ThresholdPublicKey,
    ValidatorId, GAMMA1, TAU, Z_BOUND,
};

/// Build η-bounded secret and small mask vectors so `‖z‖_∞` stays far under
/// `γ₁ − β`. Distinct `seed` values produce independent share/mask material.
fn small_secret_and_mask(seed: i32) -> (ModuleVecL, ModuleVecL) {
    let mut s1 = ModuleVecL::zero();
    let mut y = ModuleVecL::zero();
    for (component_index, component) in s1.components.iter_mut().enumerate() {
        for (i, coeff) in component.coeffs.iter_mut().enumerate() {
            // Coefficients in [-4, 4] = the ML-DSA-65 η bound.
            *coeff = ((i as i32 + component_index as i32 + seed).rem_euclid(9)) - 4;
        }
    }
    for (component_index, component) in y.components.iter_mut().enumerate() {
        for (i, coeff) in component.coeffs.iter_mut().enumerate() {
            *coeff = (i as i32 * 3 + component_index as i32 + seed).rem_euclid(500);
        }
    }
    (s1, y)
}

/// Build an honest, in-bound module partial and return it with its openings.
fn honest_partial(
    signer: ValidatorId,
    x: u16,
    seed: i32,
    challenge: &[u8],
) -> (ModulePartialZi, ModuleVecL, ModuleVecL, Poly) {
    let (s1, y) = small_secret_and_mask(seed);
    let c = sample_in_ball(challenge, TAU);
    let partial = emit_module_partial_zi(signer, x, &s1, &y, &c).expect("honest partial in bound");
    (partial, y, s1, c)
}

#[test]
fn gate_accepts_honest_module_partial_and_mints_real_digest() {
    let (partial, y, s1, c) = honest_partial(ValidatorId(7), 3, 11, b"honest-accept");

    let validity: ModulePartialLocalValidity =
        verify_module_partial_local_validity(&partial, &y, &s1, &c).expect("honest partial valid");

    assert_eq!(validity.signer, ValidatorId(7));
    assert_eq!(validity.x, 3);
    assert!(validity.infinity_norm >= 0 && validity.infinity_norm < Z_BOUND);
    assert_ne!(validity.local_validity_digest, [0u8; 32]);

    // The digest is a deterministic function of the checked (signer, x, z_i, c).
    let again = verify_module_partial_local_validity(&partial, &y, &s1, &c).unwrap();
    assert_eq!(validity.local_validity_digest, again.local_validity_digest);
}

#[test]
fn gate_rejects_tampered_response() {
    let (mut partial, y, s1, c) = honest_partial(ValidatorId(2), 5, 22, b"tamper-response");
    // Flip one response coefficient: the algebraic relation no longer holds.
    partial.z_i.components[0].coeffs[0] += 1;

    let err = verify_module_partial_local_validity(&partial, &y, &s1, &c).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(2),
        }
    );
}

#[test]
fn gate_rejects_wrong_or_rebound_challenge() {
    let (partial, y, s1, _c) = honest_partial(ValidatorId(4), 2, 33, b"challenge-a");
    // Verify the same response against a different challenge (stale / rebound).
    let other_c = sample_in_ball(b"challenge-b", TAU);
    assert_ne!(other_c.coeffs, _c.coeffs);

    let err = verify_module_partial_local_validity(&partial, &y, &s1, &other_c).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(4),
        }
    );
}

#[test]
fn gate_rejects_share_not_bound_to_signer() {
    let (partial, _y_a, _s1_a, c) = honest_partial(ValidatorId(1), 1, 44, b"cross-signer");
    // Present a *different* signer's opened share/mask against this response.
    let (s1_b, y_b) = small_secret_and_mask(45);

    let err = verify_module_partial_local_validity(&partial, &y_b, &s1_b, &c).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1),
        }
    );
}

#[test]
fn gate_rejects_out_of_bound_response() {
    // c = 0 and s1 = 0 so the claimed response equals y exactly (relation holds),
    // but one coefficient sits just below γ₁, above the γ₁ − β acceptance bound.
    let zero_s1 = ModuleVecL::zero();
    let zero_c = Poly::zero();
    let mut y = ModuleVecL::zero();
    y.components[0].coeffs[0] = GAMMA1 - 1;
    let z_i = compute_z(&y, &zero_s1, &zero_c);
    let partial = ModulePartialZi {
        signer: ValidatorId(9),
        x: 4,
        z_i,
    };

    let err = verify_module_partial_local_validity(&partial, &y, &zero_s1, &zero_c).unwrap_err();
    assert_eq!(
        err,
        ThresholdError::RejectionSamplingFailed {
            validator: ValidatorId(9),
        }
    );
}

fn make_transcript() -> ProductionSigningTranscript {
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
            (ValidatorId(1), CommitmentDigest([11; 32])),
            (ValidatorId(2), CommitmentDigest([12; 32])),
        ],
    })
    .unwrap()
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

/// The real gate digest flows into the criterion-4 typed evidence surface, but
/// the surface still classifies it as digest-only scaffold and refuses to
/// promote it to proof-backed. This binds real arithmetic to the criterion
/// without over-claiming closure.
#[test]
fn real_gate_digest_backs_scaffold_evidence_but_stays_partially_met() {
    let (partial, y, s1, c) = honest_partial(ValidatorId(1), 1, 55, b"typed-evidence");
    let validity = verify_module_partial_local_validity(&partial, &y, &s1, &c).unwrap();
    let real_digest = validity.local_validity_digest;

    let transcript = make_transcript();
    let accepted: AcceptedPartialContribution = LocalAccept::accept(
        &transcript,
        LocalAcceptEvidence {
            signer: ValidatorId(1),
            commitment_digest: CommitmentDigest([11; 32]),
            partial_share_digest: [21; 32],
            // The real, recomputed local-validity digest backs the local-bounds slot.
            local_bounds_proof_digest: real_digest,
        },
    )
    .unwrap();

    let binding = PartialVerifierBinding::new(
        accepted.signer(),
        accepted.commitment_digest(),
        *accepted.challenge_digest(),
        *accepted.partial_share_digest(),
        *accepted.local_bounds_proof_digest(),
        [31; 32],
        *transcript.challenge_digest(),
    );

    let evidence = PartialContributionSoundnessEvidence::verify(
        &transcript,
        &accepted,
        binding,
        PartialContextBinding::from_transcript(&transcript),
        LocalProofEvidence::scaffold_digest_only(real_digest),
        leakage_budget(),
        PartialEvidenceRequirement::ScaffoldDigestOrProofBacked,
    )
    .unwrap();

    // Real arithmetic backs the digest, yet the typed surface keeps it scaffold.
    assert_eq!(evidence.evidence_class(), EvidenceClass::ScaffoldDigestOnly);
    assert!(!evidence.is_proof_backed());
    assert_eq!(
        evidence.closure_status(),
        PartialSoundnessClosureStatus::ConformanceOnly
    );
    assert!(!evidence.is_closure_ready());

    // Honest boundary: a real soundness digest is NOT proof-backed hiding
    // evidence, so the proof-backed requirement rejects it.
    let err = PartialContributionSoundnessEvidence::verify(
        &transcript,
        &accepted,
        binding,
        PartialContextBinding::from_transcript(&transcript),
        LocalProofEvidence::scaffold_digest_only(real_digest),
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
