use dytallix_pq_threshold::{
    crypto::{
        interpolation::{try_reconstruct_secret_poly, try_reconstruct_secret_poly_with_threshold},
        vss::{
            commit_share_contribution, require_production_vss_backend, split_secret_poly,
            try_split_secret_poly, verify_share_contribution_commitment,
            verify_share_contribution_commitments, ProductionVssRelationStatement,
            TranscriptHashVssCommitmentBackend, VssCommitmentBackend, VssCommitmentSecurityProfile,
            VssShareCommitment, VssShareProof, VSS_SHARE_COMMITMENT_BYTES,
        },
    },
    Poly, SessionId, ThresholdError, ValidatorId, Q,
};

#[cfg(feature = "experimental-vss")]
use dytallix_pq_threshold::crypto::vss::{
    verify_experimental_vss_complaint_evidence, ExperimentalVssCommitmentBackend,
    ExperimentalVssComplaintEvidence, ExperimentalVssOpening, ExperimentalVssProof,
    ExperimentalVssStatement, EXPERIMENTAL_VSS_COMPLAINT_EVIDENCE_BYTES,
    EXPERIMENTAL_VSS_OPENING_BYTES, EXPERIMENTAL_VSS_PROOF_BYTES, EXPERIMENTAL_VSS_STATEMENT_BYTES,
};

#[cfg(feature = "experimental-vss")]
use sha3::{Digest, Sha3_256};

#[test]
fn checked_vss_split_rejects_invalid_threshold_parameters() {
    let secret = Poly::zero();

    assert_eq!(
        try_split_secret_poly(&secret, 0, 3),
        Err(ThresholdError::InvalidThresholdParameters {
            threshold: 0,
            total_nodes: 3
        })
    );
    assert_eq!(
        try_split_secret_poly(&secret, 1, 0),
        Err(ThresholdError::InvalidThresholdParameters {
            threshold: 1,
            total_nodes: 0
        })
    );
    assert_eq!(
        try_split_secret_poly(&secret, 4, 3),
        Err(ThresholdError::InvalidThresholdParameters {
            threshold: 4,
            total_nodes: 3
        })
    );
}

#[test]
fn checked_reconstruction_rejects_empty_or_malformed_indices() {
    assert!(matches!(
        try_reconstruct_secret_poly(&[]),
        Err(ThresholdError::MalformedSerialization { .. })
    ));

    assert!(matches!(
        try_reconstruct_secret_poly(&[(0, Poly::zero())]),
        Err(ThresholdError::MalformedSerialization { .. })
    ));

    assert_eq!(
        try_reconstruct_secret_poly(&[(2, Poly::zero()), (2, Poly::zero())]),
        Err(ThresholdError::DuplicateValidator {
            validator: ValidatorId(2)
        })
    );
}

#[test]
fn checked_reconstruction_round_trips_threshold_subset() {
    let mut secret = Poly::zero();
    for (index, coeff) in secret.coeffs.iter_mut().enumerate() {
        *coeff = ((index as i32 * 31) + 7) % Q;
    }

    let shares = split_secret_poly(&secret, 3, 5);
    let subset = vec![
        (shares[0].receiver_index, shares[0].polynomial_share),
        (shares[2].receiver_index, shares[2].polynomial_share),
        (shares[4].receiver_index, shares[4].polynomial_share),
    ];

    let reconstructed = try_reconstruct_secret_poly(&subset).expect("reconstruct checked shares");

    assert_eq!(reconstructed, secret);
}

#[test]
fn checked_threshold_reconstruction_rejects_too_few_shares() {
    let shares = split_secret_poly(&fixture_secret(), 3, 5);
    let subset = vec![
        (shares[0].receiver_index, shares[0].polynomial_share),
        (shares[2].receiver_index, shares[2].polynomial_share),
    ];

    assert_eq!(
        try_reconstruct_secret_poly_with_threshold(&subset, 3),
        Err(ThresholdError::InsufficientPartialShares {
            required: 3,
            received: 2
        })
    );
}

#[test]
fn checked_threshold_reconstruction_rejects_zero_threshold() {
    assert_eq!(
        try_reconstruct_secret_poly_with_threshold(&[(1, Poly::zero())], 0),
        Err(ThresholdError::InvalidThresholdParameters {
            threshold: 0,
            total_nodes: 1
        })
    );
}

#[test]
fn vss_share_commitment_verifies_for_matching_public_context() {
    let session_id = fixture_session_id(7);
    let share = split_secret_poly(&fixture_secret(), 3, 5)
        .into_iter()
        .nth(1)
        .expect("share for validator 2");

    let commitment = commit_share_contribution(session_id, 3, 5, &share).expect("commit VSS share");

    verify_share_contribution_commitment(session_id, 3, 5, &share, &commitment)
        .expect("verify VSS share commitment");
}

#[test]
fn custom_vss_commitment_backend_can_be_called_through_trait_boundary() {
    let backend = CountingVssCommitmentBackend;
    let session_id = fixture_session_id(29);
    let shares = split_secret_poly(&fixture_secret(), 3, 5);
    let share = shares[2].clone();

    let commitment = backend
        .commit_share_contribution(session_id, 3, 5, &share)
        .expect("custom backend should produce commitment");

    assert_eq!(commitment.receiver_index, 3);
    assert_eq!(
        commitment.commitment_digest,
        [3; VSS_SHARE_COMMITMENT_BYTES]
    );
    assert_eq!(
        commitment.proof.proof_digest,
        [share.polynomial_share.coeffs[0] as u8; VSS_SHARE_COMMITMENT_BYTES]
    );
    backend
        .verify_share_contribution_commitment(session_id, 3, 5, &share, &commitment)
        .expect("custom backend should verify its commitment");

    let mut mismatched = commitment;
    mismatched.commitment_digest[0] ^= 0x01;
    assert_eq!(
        backend.verify_share_contribution_commitment(session_id, 3, 5, &share, &mismatched),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(3)
        })
    );

    let entries = shares
        .into_iter()
        .map(|share| {
            let commitment = backend
                .commit_share_contribution(session_id, 3, 5, &share)
                .expect("custom backend should commit each share");
            (share, commitment)
        })
        .collect::<Vec<_>>();
    backend
        .verify_share_contribution_commitments(session_id, 3, 5, &entries)
        .expect("custom backend should batch-verify commitments");
}

#[test]
fn free_functions_match_default_vss_commitment_backend() {
    let backend = TranscriptHashVssCommitmentBackend;
    let session_id = fixture_session_id(31);
    let shares = split_secret_poly(&fixture_secret(), 3, 5);
    let share = shares[1].clone();

    let wrapper_commitment =
        commit_share_contribution(session_id, 3, 5, &share).expect("wrapper should commit share");
    let backend_commitment = backend
        .commit_share_contribution(session_id, 3, 5, &share)
        .expect("backend should commit share");

    assert_eq!(wrapper_commitment, backend_commitment);
    verify_share_contribution_commitment(session_id, 3, 5, &share, &wrapper_commitment)
        .expect("wrapper should verify commitment");
    backend
        .verify_share_contribution_commitment(session_id, 3, 5, &share, &wrapper_commitment)
        .expect("backend should verify commitment");

    let wrapper_entries = shares
        .iter()
        .map(|share| {
            let commitment =
                commit_share_contribution(session_id, 3, 5, share).expect("wrapper commit");
            (share.clone(), commitment)
        })
        .collect::<Vec<_>>();
    let backend_entries = shares
        .iter()
        .map(|share| {
            let commitment = backend
                .commit_share_contribution(session_id, 3, 5, share)
                .expect("backend commit");
            (share.clone(), commitment)
        })
        .collect::<Vec<_>>();

    assert_eq!(wrapper_entries, backend_entries);
    verify_share_contribution_commitments(session_id, 3, 5, &wrapper_entries)
        .expect("wrapper should batch-verify commitments");
    backend
        .verify_share_contribution_commitments(session_id, 3, 5, &wrapper_entries)
        .expect("backend should batch-verify commitments");
}

#[test]
fn vss_security_profile_rejects_transcript_hash_scaffold_for_production_claims() {
    let backend = TranscriptHashVssCommitmentBackend;

    assert_eq!(
        backend.security_profile(),
        VssCommitmentSecurityProfile::DeterministicTranscriptScaffold
    );
    assert!(!backend
        .security_profile()
        .supports_production_security_claim());
    assert_eq!(
        require_production_vss_backend(&backend),
        Err(ThresholdError::BackendUnavailable {
            reason:
                "VSS backend is deterministic scaffold; production VSS commitment backend required"
        })
    );
}

#[test]
fn vss_security_profile_allows_explicit_production_backend_boundary() {
    let backend = DeclaredProductionVssCommitmentBackend;

    assert_eq!(
        backend.security_profile(),
        VssCommitmentSecurityProfile::ProductionBindingHiding
    );
    assert!(backend
        .security_profile()
        .supports_production_security_claim());
    require_production_vss_backend(&backend)
        .expect("declared production backend should pass the policy gate");
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_backend_declares_candidate_scaffold_not_production() {
    let backend = ExperimentalVssCommitmentBackend;

    assert_eq!(
        backend.security_profile(),
        VssCommitmentSecurityProfile::ProductionCandidateScaffold
    );
    assert_ne!(
        backend.security_profile(),
        VssCommitmentSecurityProfile::ProductionBindingHiding
    );
    assert!(!backend
        .security_profile()
        .supports_production_security_claim());
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_backend_is_rejected_by_production_gate() {
    let backend = ExperimentalVssCommitmentBackend;

    assert!(matches!(
        require_production_vss_backend(&backend),
        Err(ThresholdError::BackendUnavailable { .. })
    ));
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_backend_commit_and_verify_fail_closed() {
    let backend = ExperimentalVssCommitmentBackend;
    let session_id = fixture_session_id(41);
    let share = split_secret_poly(&fixture_secret(), 3, 5)
        .into_iter()
        .next()
        .expect("share for validator 1");
    let scaffold_commitment = TranscriptHashVssCommitmentBackend
        .commit_share_contribution(session_id, 3, 5, &share)
        .expect("scaffold backend should provide a verification fixture");

    assert!(matches!(
        backend.commit_share_contribution(session_id, 3, 5, &share),
        Err(ThresholdError::BackendUnavailable { .. })
    ));
    assert!(matches!(
        backend.verify_share_contribution_commitment(
            session_id,
            3,
            5,
            &share,
            &scaffold_commitment
        ),
        Err(ThresholdError::BackendUnavailable { .. })
    ));
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_statement_canonical_bytes_round_trip() {
    let statement = fixture_experimental_statement();

    let bytes = statement
        .to_canonical_bytes()
        .expect("statement should encode");

    assert_eq!(bytes.len(), EXPERIMENTAL_VSS_STATEMENT_BYTES);
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[33..35], &3u16.to_be_bytes());
    assert_eq!(&bytes[35..37], &5u16.to_be_bytes());
    assert_eq!(&bytes[37..39], &4u16.to_be_bytes());
    assert_eq!(&bytes[39..41], &7u16.to_be_bytes());
    assert_eq!(
        ExperimentalVssStatement::from_canonical_bytes(&bytes).expect("decode statement"),
        statement
    );
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_statement_rejects_malformed_context_and_indices() {
    let mut statement = fixture_experimental_statement();
    statement.context_digest = [0u8; 32];
    assert!(matches!(
        statement.to_canonical_bytes(),
        Err(ThresholdError::MalformedSerialization { .. })
    ));

    let mut statement = fixture_experimental_statement();
    statement.receiver_index = 8;
    assert_eq!(
        statement.to_canonical_bytes(),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(8)
        })
    );

    let mut bytes = fixture_experimental_statement()
        .to_canonical_bytes()
        .expect("statement should encode");
    bytes[0] = 2;
    assert!(matches!(
        ExperimentalVssStatement::from_canonical_bytes(&bytes),
        Err(ThresholdError::MalformedSerialization { .. })
    ));
    assert!(matches!(
        ExperimentalVssStatement::from_canonical_bytes(&bytes[..bytes.len() - 1]),
        Err(ThresholdError::MalformedSerialization { .. })
    ));
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_opening_and_proof_canonical_bytes_round_trip() {
    let opening = ExperimentalVssOpening {
        context_digest: digest_fixture(0x51),
        dealer_index: 3,
        receiver_index: 5,
        encrypted_share_digest: digest_fixture(0x52),
        opening_digest: digest_fixture(0x53),
        encrypted_share_len: 4096,
    };
    let proof = ExperimentalVssProof {
        statement_digest: digest_fixture(0x61),
        proof_digest: digest_fixture(0x62),
    };

    let opening_bytes = opening.to_canonical_bytes().expect("opening should encode");
    let proof_bytes = proof.to_canonical_bytes().expect("proof should encode");

    assert_eq!(opening_bytes.len(), EXPERIMENTAL_VSS_OPENING_BYTES);
    assert_eq!(proof_bytes.len(), EXPERIMENTAL_VSS_PROOF_BYTES);
    assert_eq!(
        ExperimentalVssOpening::from_canonical_bytes(&opening_bytes).expect("decode opening"),
        opening
    );
    assert_eq!(
        ExperimentalVssProof::from_canonical_bytes(&proof_bytes).expect("decode proof"),
        proof
    );
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_opening_and_proof_reject_empty_digests_and_payloads() {
    let mut opening = ExperimentalVssOpening {
        context_digest: digest_fixture(0x71),
        dealer_index: 3,
        receiver_index: 5,
        encrypted_share_digest: digest_fixture(0x72),
        opening_digest: digest_fixture(0x73),
        encrypted_share_len: 0,
    };
    assert!(matches!(
        opening.to_canonical_bytes(),
        Err(ThresholdError::MalformedSerialization { .. })
    ));

    opening.encrypted_share_len = 1;
    opening.opening_digest = [0u8; 32];
    assert!(matches!(
        opening.to_canonical_bytes(),
        Err(ThresholdError::MalformedSerialization { .. })
    ));

    let proof = ExperimentalVssProof {
        statement_digest: digest_fixture(0x81),
        proof_digest: [0u8; 32],
    };
    assert!(matches!(
        proof.to_canonical_bytes(),
        Err(ThresholdError::MalformedSerialization { .. })
    ));
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_complaint_evidence_canonical_bytes_round_trip() {
    let evidence = fixture_experimental_complaint_evidence();

    let bytes = evidence
        .to_canonical_bytes()
        .expect("complaint evidence should encode");

    assert_eq!(bytes.len(), EXPERIMENTAL_VSS_COMPLAINT_EVIDENCE_BYTES);
    assert_eq!(bytes[0], 1);
    assert_eq!(
        ExperimentalVssComplaintEvidence::from_canonical_bytes(&bytes)
            .expect("decode complaint evidence"),
        evidence
    );
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_complaint_evidence_rejects_mismatched_statement_opening_context() {
    let mut evidence = fixture_experimental_complaint_evidence();
    evidence.opening.context_digest = digest_fixture(0xa1);

    assert!(matches!(
        verify_experimental_vss_complaint_evidence(&evidence),
        Err(ThresholdError::MalformedSerialization { .. })
    ));
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_complaint_evidence_rejects_mismatched_dealer_or_receiver() {
    let mut wrong_dealer = fixture_experimental_complaint_evidence();
    wrong_dealer.opening.dealer_index = wrong_dealer.statement.dealer_index + 1;
    assert_eq!(
        verify_experimental_vss_complaint_evidence(&wrong_dealer),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(3)
        })
    );

    let mut wrong_receiver = fixture_experimental_complaint_evidence();
    wrong_receiver.opening.receiver_index = wrong_receiver.statement.receiver_index - 1;
    assert_eq!(
        verify_experimental_vss_complaint_evidence(&wrong_receiver),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(5)
        })
    );
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_complaint_evidence_rejects_wrong_proof_statement_digest() {
    let mut evidence = fixture_experimental_complaint_evidence();
    evidence.proof.statement_digest[0] ^= 0x80;

    assert_eq!(
        verify_experimental_vss_complaint_evidence(&evidence),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(3)
        })
    );
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_complaint_evidence_rejects_malformed_length_and_version() {
    let bytes = fixture_experimental_complaint_evidence()
        .to_canonical_bytes()
        .expect("complaint evidence should encode");

    assert!(matches!(
        ExperimentalVssComplaintEvidence::from_canonical_bytes(&bytes[..bytes.len() - 1]),
        Err(ThresholdError::MalformedSerialization { .. })
    ));

    let mut wrong_version = bytes;
    wrong_version[0] = 2;
    assert!(matches!(
        ExperimentalVssComplaintEvidence::from_canonical_bytes(&wrong_version),
        Err(ThresholdError::MalformedSerialization { .. })
    ));
}

#[cfg(feature = "experimental-vss")]
#[test]
fn experimental_vss_complaint_structural_verifier_rejects_malformed_but_not_production_validity() {
    let malformed = ExperimentalVssComplaintEvidence {
        statement: fixture_experimental_statement(),
        opening: ExperimentalVssOpening {
            context_digest: [0u8; 32],
            dealer_index: 3,
            receiver_index: 5,
            encrypted_share_digest: digest_fixture(0xb1),
            opening_digest: digest_fixture(0xb2),
            encrypted_share_len: 64,
        },
        proof: ExperimentalVssProof {
            statement_digest: digest_fixture(0xb3),
            proof_digest: digest_fixture(0xb4),
        },
    };

    assert!(matches!(
        verify_experimental_vss_complaint_evidence(&malformed),
        Err(ThresholdError::MalformedSerialization { .. })
            | Err(ThresholdError::PartialShareVerificationFailed { .. })
    ));

    let structurally_valid_placeholder = fixture_experimental_complaint_evidence();
    verify_experimental_vss_complaint_evidence(&structurally_valid_placeholder)
        .expect("structural verifier should accept consistent containers");
    assert!(
        !ExperimentalVssCommitmentBackend
            .security_profile()
            .supports_production_security_claim(),
        "structural complaint evidence verification must not imply production VSS proof validity"
    );
}

#[test]
fn custom_vss_commitment_backend_default_batch_enforces_structural_invariants() {
    let backend = CountingVssCommitmentBackend;
    let session_id = fixture_session_id(37);
    let shares = split_secret_poly(&fixture_secret(), 3, 5);
    let mut entries = shares
        .iter()
        .map(|share| {
            let commitment = backend
                .commit_share_contribution(session_id, 3, 5, share)
                .expect("custom backend should commit each share");
            (share.clone(), commitment)
        })
        .collect::<Vec<_>>();

    entries[4].0.receiver_index = 6;
    entries[4].1.receiver_index = 6;
    entries[4].1.commitment_digest = [6; VSS_SHARE_COMMITMENT_BYTES];
    assert_eq!(
        backend.verify_share_contribution_commitments(session_id, 3, 5, &entries),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(6)
        })
    );

    let mut entries = shares
        .iter()
        .map(|share| {
            let commitment = backend
                .commit_share_contribution(session_id, 3, 5, share)
                .expect("custom backend should commit each share");
            (share.clone(), commitment)
        })
        .collect::<Vec<_>>();
    entries[2].1.receiver_index = 4;
    assert_eq!(
        backend.verify_share_contribution_commitments(session_id, 3, 5, &entries),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(3)
        })
    );

    let mut entries = shares
        .iter()
        .map(|share| {
            let commitment = backend
                .commit_share_contribution(session_id, 3, 5, share)
                .expect("custom backend should commit each share");
            (share.clone(), commitment)
        })
        .collect::<Vec<_>>();
    entries[1].1.session_id = fixture_session_id(38);
    assert_eq!(
        backend.verify_share_contribution_commitments(session_id, 3, 5, &entries),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(2)
        })
    );
}

#[test]
fn vss_share_commitment_rejects_tampered_share() {
    let session_id = fixture_session_id(11);
    let mut share = split_secret_poly(&fixture_secret(), 3, 5)
        .into_iter()
        .nth(2)
        .expect("share for validator 3");
    let commitment = commit_share_contribution(session_id, 3, 5, &share).expect("commit VSS share");

    share.polynomial_share.coeffs[0] = (share.polynomial_share.coeffs[0] + 1) % Q;

    assert_eq!(
        verify_share_contribution_commitment(session_id, 3, 5, &share, &commitment),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(3)
        })
    );
}

#[test]
fn vss_share_commitment_rejects_wrong_public_context() {
    let session_id = fixture_session_id(13);
    let share = split_secret_poly(&fixture_secret(), 3, 5)
        .into_iter()
        .next()
        .expect("share for validator 1");
    let commitment = commit_share_contribution(session_id, 3, 5, &share).expect("commit VSS share");

    assert!(matches!(
        verify_share_contribution_commitment(fixture_session_id(14), 3, 5, &share, &commitment),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        })
    ));
    assert!(matches!(
        verify_share_contribution_commitment(session_id, 2, 5, &share, &commitment),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        })
    ));
    assert!(matches!(
        verify_share_contribution_commitment(session_id, 3, 6, &share, &commitment),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        })
    ));

    let mut wrong_receiver = commitment.clone();
    wrong_receiver.receiver_index = 2;
    assert_eq!(
        verify_share_contribution_commitment(session_id, 3, 5, &share, &wrong_receiver),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(1)
        })
    );
}

#[test]
fn vss_share_commitment_rejects_zero_receiver() {
    let session_id = fixture_session_id(17);
    let mut share = split_secret_poly(&fixture_secret(), 3, 5)
        .into_iter()
        .next()
        .expect("share for validator 1");
    share.receiver_index = 0;

    assert_eq!(
        commit_share_contribution(session_id, 3, 5, &share),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(0)
        })
    );

    let valid_share = split_secret_poly(&fixture_secret(), 3, 5)
        .into_iter()
        .next()
        .expect("share for validator 1");
    let mut commitment =
        commit_share_contribution(session_id, 3, 5, &valid_share).expect("commit VSS share");
    commitment.receiver_index = 0;

    assert_eq!(
        verify_share_contribution_commitment(session_id, 3, 5, &valid_share, &commitment),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(0)
        })
    );
}

#[test]
fn vss_share_commitment_batch_rejects_one_invalid_share() {
    let session_id = fixture_session_id(19);
    let shares = split_secret_poly(&fixture_secret(), 3, 5);
    let mut entries = shares
        .iter()
        .map(|share| {
            let commitment =
                commit_share_contribution(session_id, 3, 5, share).expect("commit VSS share");
            (share.clone(), commitment)
        })
        .collect::<Vec<_>>();

    entries[3].0.polynomial_share.coeffs[8] = (entries[3].0.polynomial_share.coeffs[8] + 9) % Q;

    assert_eq!(
        verify_share_contribution_commitments(session_id, 3, 5, &entries),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(4)
        })
    );
}

#[test]
fn vss_share_commitment_batch_requires_complete_unique_validator_set() {
    let session_id = fixture_session_id(23);
    let shares = split_secret_poly(&fixture_secret(), 3, 5);
    let mut entries = shares
        .iter()
        .map(|share| {
            let commitment =
                commit_share_contribution(session_id, 3, 5, share).expect("commit VSS share");
            (share.clone(), commitment)
        })
        .collect::<Vec<_>>();

    let missing = entries[..4].to_vec();
    assert_eq!(
        verify_share_contribution_commitments(session_id, 3, 5, &missing),
        Err(ThresholdError::InsufficientCommitments {
            required: 5,
            received: 4
        })
    );

    entries[4] = entries[3].clone();
    assert_eq!(
        verify_share_contribution_commitments(session_id, 3, 5, &entries),
        Err(ThresholdError::DuplicateValidator {
            validator: ValidatorId(4)
        })
    );
}

#[test]
fn production_vss_relation_statement_canonical_bytes_round_trip() {
    let statement = fixture_production_vss_statement();
    let encoded = statement.to_canonical_bytes().expect("encode statement");

    assert_eq!(
        ProductionVssRelationStatement::from_canonical_bytes(&encoded).expect("decode statement"),
        statement
    );

    let digest = statement.statement_digest().expect("digest statement");
    assert_ne!(digest, [0; 32]);

    let mut tampered = encoded;
    tampered[0] ^= 0x01;
    assert_ne!(
        ProductionVssRelationStatement::from_canonical_bytes(&tampered)
            .expect("decode tampered statement")
            .statement_digest()
            .expect("digest tampered statement"),
        digest
    );
}

#[test]
fn production_vss_relation_statement_rejects_invalid_participants() {
    let mut zero_dealer = fixture_production_vss_statement();
    zero_dealer.dealer_index = 0;
    assert_eq!(
        zero_dealer.to_canonical_bytes(),
        Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(0)
        })
    );

    let mut zero_receiver = fixture_production_vss_statement();
    zero_receiver.receiver_index = 0;
    assert_eq!(
        zero_receiver.to_canonical_bytes(),
        Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(0)
        })
    );

    let mut invalid_threshold = fixture_production_vss_statement();
    invalid_threshold.threshold = invalid_threshold.total_nodes + 1;
    assert_eq!(
        invalid_threshold.to_canonical_bytes(),
        Err(ThresholdError::InvalidThresholdParameters {
            threshold: invalid_threshold.threshold,
            total_nodes: invalid_threshold.total_nodes,
        })
    );
}

fn fixture_secret() -> Poly {
    let mut secret = Poly::zero();
    for (index, coeff) in secret.coeffs.iter_mut().enumerate() {
        *coeff = ((index as i32 * 31) + 7) % Q;
    }
    secret
}

fn fixture_production_vss_statement() -> ProductionVssRelationStatement {
    ProductionVssRelationStatement {
        protocol_version: 1,
        epoch_id: [0x81; 32],
        session_id: fixture_session_id(37),
        validator_set_digest: [0x82; 32],
        backend_id: [0x83; 32],
        dealer_index: 2,
        receiver_index: 4,
        threshold: 3,
        total_nodes: 5,
        dealer_commitment_digest: [0x84; 32],
        encrypted_share_digest: [0x85; 32],
        opening_digest: [0x86; 32],
        public_key_contribution_digest: [0x87; 32],
    }
}

fn fixture_session_id(seed: u8) -> SessionId {
    let mut session_id = [0u8; 32];
    for (index, byte) in session_id.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    session_id
}

#[cfg(feature = "experimental-vss")]
fn fixture_experimental_statement() -> ExperimentalVssStatement {
    ExperimentalVssStatement {
        context_digest: digest_fixture(0x31),
        dealer_index: 3,
        receiver_index: 5,
        threshold: 4,
        total_nodes: 7,
        dealer_commitment_digest: digest_fixture(0x32),
        share_digest: digest_fixture(0x33),
    }
}

#[cfg(feature = "experimental-vss")]
fn fixture_experimental_complaint_evidence() -> ExperimentalVssComplaintEvidence {
    let statement = fixture_experimental_statement();
    let opening = ExperimentalVssOpening {
        context_digest: statement.context_digest,
        dealer_index: statement.dealer_index,
        receiver_index: statement.receiver_index,
        encrypted_share_digest: digest_fixture(0x91),
        opening_digest: digest_fixture(0x92),
        encrypted_share_len: 2048,
    };
    let proof = ExperimentalVssProof {
        statement_digest: experimental_statement_digest(&statement),
        proof_digest: digest_fixture(0x93),
    };

    ExperimentalVssComplaintEvidence {
        statement,
        opening,
        proof,
    }
}

#[cfg(feature = "experimental-vss")]
fn experimental_statement_digest(statement: &ExperimentalVssStatement) -> [u8; 32] {
    let bytes = statement
        .to_canonical_bytes()
        .expect("statement fixture should encode");
    Sha3_256::digest(bytes).into()
}

#[cfg(feature = "experimental-vss")]
fn digest_fixture(seed: u8) -> [u8; 32] {
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    digest
}

struct CountingVssCommitmentBackend;

impl VssCommitmentBackend for CountingVssCommitmentBackend {
    fn security_profile(&self) -> VssCommitmentSecurityProfile {
        VssCommitmentSecurityProfile::DeterministicTranscriptScaffold
    }

    fn commit_share_contribution(
        &self,
        session_id: SessionId,
        threshold: u16,
        total_nodes: u16,
        share: &dytallix_pq_threshold::crypto::vss::ShareContribution,
    ) -> Result<VssShareCommitment, ThresholdError> {
        Ok(VssShareCommitment {
            session_id,
            threshold,
            total_nodes,
            receiver_index: share.receiver_index,
            commitment_digest: [share.receiver_index as u8; VSS_SHARE_COMMITMENT_BYTES],
            proof: VssShareProof {
                proof_digest: [share.polynomial_share.coeffs[0] as u8; VSS_SHARE_COMMITMENT_BYTES],
            },
        })
    }

    fn verify_share_contribution_commitment(
        &self,
        _session_id: SessionId,
        _threshold: u16,
        _total_nodes: u16,
        share: &dytallix_pq_threshold::crypto::vss::ShareContribution,
        commitment: &VssShareCommitment,
    ) -> Result<(), ThresholdError> {
        if commitment.commitment_digest == [share.receiver_index as u8; VSS_SHARE_COMMITMENT_BYTES]
        {
            Ok(())
        } else {
            Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(share.receiver_index),
            })
        }
    }
}

struct DeclaredProductionVssCommitmentBackend;

impl VssCommitmentBackend for DeclaredProductionVssCommitmentBackend {
    fn security_profile(&self) -> VssCommitmentSecurityProfile {
        VssCommitmentSecurityProfile::ProductionBindingHiding
    }

    fn commit_share_contribution(
        &self,
        _session_id: SessionId,
        _threshold: u16,
        _total_nodes: u16,
        _share: &dytallix_pq_threshold::crypto::vss::ShareContribution,
    ) -> Result<VssShareCommitment, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test-only production marker does not implement commitments",
        })
    }

    fn verify_share_contribution_commitment(
        &self,
        _session_id: SessionId,
        _threshold: u16,
        _total_nodes: u16,
        _share: &dytallix_pq_threshold::crypto::vss::ShareContribution,
        _commitment: &VssShareCommitment,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test-only production marker does not implement verification",
        })
    }
}
