//! Committee-of-eight acceptance contract for the no-reconstruction path.

use lattice_aggregation::{
    crypto::{
        distributed_nonce,
        fips_public_key::{
            evaluate_public_t_share, FipsKeygenMissingPrimitive, FipsModuleSecretShare65,
            FipsPublicKeyContext65, MLDSA65_K, MLDSA65_L,
        },
        mldsa_module::expand_matrix_a,
        poly::Poly,
    },
    derive_committee8_fips_public_key_from_t_shares, Committee8FipsKeygenCapabilities,
    Committee8Session, Committee8Uninitialized, NoReconstructionCapabilities,
    NoReconstructionError, NoReconstructionPrimitive, ThresholdError, ValidatorId,
    COMMITTEE8_MIN_DKG_DEALERS, COMMITTEE8_SIZE, COMMITTEE8_THRESHOLD,
};

fn dealer_seeds() -> [[u8; 32]; COMMITTEE8_MIN_DKG_DEALERS] {
    core::array::from_fn(|index| [0x10 + index as u8; 32])
}

fn signer_seeds() -> [[u8; 32]; COMMITTEE8_SIZE] {
    core::array::from_fn(|index| [0x80 + index as u8; 32])
}

#[test]
fn committee8_real_dkg_and_nonce_round_reach_the_standard_signature_gate() {
    assert_eq!(COMMITTEE8_SIZE, 8);
    assert_eq!(COMMITTEE8_THRESHOLD, 6);

    let rho = [0x42; 32];
    let dkg = Committee8Session::<Committee8Uninitialized>::new()
        .run_dkg(rho, b"committee8-public-bdlop-key", &dealer_seeds())
        .expect("both independently seeded DKG dealers must be accepted");

    assert_eq!(dkg.accepted_dealers(), &[0, 1]);
    assert_ne!(dkg.public_key_digest(), &[0; 32]);
    assert_ne!(dkg.dkg_transcript_digest(), &[0; 32]);

    // Each call represents local signer work. The committee session receives
    // public commitments/openings only; it never receives the secret masks.
    let matrix = expand_matrix_a(dkg.rho());
    let signer_rounds: Vec<_> = signer_seeds()
        .iter()
        .map(|seed| distributed_nonce::commit(&matrix, seed))
        .collect();
    let commitments = signer_rounds
        .iter()
        .map(|(_, commitment)| commitment.clone())
        .collect::<Vec<_>>()
        .try_into()
        .expect("exactly eight commitments");
    let openings = signer_rounds
        .iter()
        .map(|(secret_state, _)| secret_state.open())
        .collect::<Vec<_>>()
        .try_into()
        .expect("exactly eight openings");

    let message = b"committee-8 no-reconstruction standard signature contract";
    let ready = dkg
        .record_nonce_commitments(commitments)
        .verify_nonce_openings(openings, message)
        .expect("all eight real nonce openings must verify");
    assert_ne!(ready.challenge_seed(), &[0; 32]);
    assert_ne!(ready.joint_nonce_digest(), &[0; 32]);
    assert_eq!(
        ready.capabilities(),
        NoReconstructionCapabilities::current()
    );
    assert!(!ready.capabilities().reconstruction_signing_bridge_used);

    // This is a passing fail-closed contract, not a placeholder signature. The
    // current research DKG does not produce a byte-exact FIPS public key, so the
    // API must stop before partial signing or wire packing.
    assert_eq!(
        ready.try_standard_signature(message),
        Err(NoReconstructionError::MissingPrimitive {
            primitive: NoReconstructionPrimitive::Fips204ExactDistributedKeyGeneration,
        })
    );
}

#[test]
fn committee8_contract_lists_current_standard_output_blockers() {
    assert_eq!(
        NoReconstructionCapabilities::current().missing_primitives(),
        &[
            NoReconstructionPrimitive::Fips204ExactDistributedKeyGeneration,
            NoReconstructionPrimitive::PrivatePerReceiverShareCustody,
            NoReconstructionPrimitive::ExactDistributedExpandMask,
            NoReconstructionPrimitive::DistributedRejectionAndHintMpc,
            NoReconstructionPrimitive::StandardWireSignatureFromPartials,
        ]
    );
}

#[test]
fn committee8_fips_public_key_gate_accepts_only_public_threshold_contributions() {
    let context = FipsPublicKeyContext65::new([0x31; 32], [0x91; 32]);
    let shares: Vec<_> = (1..=COMMITTEE8_SIZE as u16)
        .map(|receiver_index| {
            let secret = FipsModuleSecretShare65::new(
                receiver_index,
                [Poly::zero(); MLDSA65_L],
                [Poly::zero(); MLDSA65_K],
            )
            .expect("valid committee index");
            evaluate_public_t_share(&context, &secret)
        })
        .collect();

    let derived = derive_committee8_fips_public_key_from_t_shares(&context, &shares[..6])
        .expect("six public contributions satisfy the committee threshold");
    assert_eq!(derived.context(), &context);
    assert_eq!(derived.public_key().0.len(), 1_952);

    assert_eq!(
        derive_committee8_fips_public_key_from_t_shares(&context, &shares[..5]),
        Err(ThresholdError::InsufficientPartialShares {
            required: COMMITTEE8_THRESHOLD,
            received: 5,
        })
    );

    let out_of_committee_secret =
        FipsModuleSecretShare65::new(9, [Poly::zero(); MLDSA65_L], [Poly::zero(); MLDSA65_K])
            .unwrap();
    let out_of_committee = evaluate_public_t_share(&context, &out_of_committee_secret);
    let mut invalid = shares[..5].to_vec();
    invalid.push(out_of_committee);
    assert_eq!(
        derive_committee8_fips_public_key_from_t_shares(&context, &invalid),
        Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(9),
        })
    );

    let capabilities = Committee8FipsKeygenCapabilities::current();
    assert!(capabilities.exact_public_key_from_supplied_shares);
    assert!(capabilities.ceremony_bound_public_contributions);
    assert!(capabilities.encrypted_receiver_custody_seam);
    assert!(!capabilities.joint_exact_expand_s_sampling);
    assert!(!capabilities.process_isolated_receiver_custody);
    assert!(!capabilities.exact_distributed_key_generation);
    assert_eq!(
        capabilities.first_missing(),
        FipsKeygenMissingPrimitive::JointExactExpandSSampling
    );
    assert!(capabilities
        .missing_primitives()
        .contains(&FipsKeygenMissingPrimitive::ReceiverPrivateShareCustody));
}
