use dytallix_pq_threshold::{
    crypto::contribution_proof::{
        prove_contribution, require_production_contribution_proof_backend,
        verify_contribution_proof, ContributionProof, ContributionProofBackend,
        ContributionProofSecurityProfile, ContributionStatement, ContributionWitness,
        ProductionContributionStatement, TranscriptHashContributionProofBackend,
        CONTRIBUTION_CHALLENGE_BYTES, CONTRIBUTION_PROOF_BYTES, CONTRIBUTION_STATEMENT_BYTES,
    },
    ThresholdError, ValidatorId,
};

#[test]
fn contribution_proof_binds_statement_and_witness_payload() {
    let statement = fixture_statement();
    let witness = ContributionWitness::from_payload(vec![0xDE, 0xAD, 0xBE, 0xEF]);

    let proof = prove_contribution(&statement, &witness).expect("proof should be built");

    verify_contribution_proof(&statement, &proof).expect("proof should verify");

    let mut wrong_challenge = statement.clone();
    wrong_challenge.challenge[0] ^= 0x01;
    assert_eq!(
        verify_contribution_proof(&wrong_challenge, &proof),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(statement.validator_index)
        })
    );

    let mut wrong_validator = statement;
    wrong_validator.validator_index += 1;
    assert_eq!(
        verify_contribution_proof(&wrong_validator, &proof),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(wrong_validator.validator_index)
        })
    );
}

#[test]
fn contribution_proof_binds_all_statement_digest_fields() {
    let statement = fixture_statement();
    let witness = ContributionWitness::from_payload(vec![0xFE, 0xED, 0xFA, 0xCE]);
    let proof = prove_contribution(&statement, &witness).expect("proof should be built");

    let mut wrong_block = statement.clone();
    wrong_block.block_height += 1;
    assert_rejects_for_validator(&wrong_block, &proof, statement.validator_index);

    let mut wrong_attempt = statement.clone();
    wrong_attempt.attempt += 1;
    assert_rejects_for_validator(&wrong_attempt, &proof, statement.validator_index);

    let mut wrong_masking = statement.clone();
    wrong_masking.masking_commitment_digest[0] ^= 0x01;
    assert_rejects_for_validator(&wrong_masking, &proof, statement.validator_index);

    let mut wrong_secret = statement.clone();
    wrong_secret.secret_commitment_digest[0] ^= 0x01;
    assert_rejects_for_validator(&wrong_secret, &proof, statement.validator_index);

    let mut wrong_dkg = statement.clone();
    wrong_dkg.dkg_commitment_digest[0] ^= 0x01;
    assert_rejects_for_validator(&wrong_dkg, &proof, statement.validator_index);
}

#[test]
fn production_contribution_statement_canonical_bytes_round_trip() {
    let statement = fixture_production_statement();
    let encoded = statement.to_canonical_bytes().expect("encode statement");

    assert_eq!(
        ProductionContributionStatement::from_canonical_bytes(&encoded).expect("decode statement"),
        statement
    );

    let digest = statement.statement_digest().expect("digest statement");
    assert_ne!(digest, [0; 32]);

    let mut tampered = encoded;
    let last = tampered.last_mut().expect("encoded statement is non-empty");
    *last ^= 0x01;
    assert_ne!(
        ProductionContributionStatement::from_canonical_bytes(&tampered)
            .expect("decode tampered statement")
            .statement_digest()
            .expect("digest tampered statement"),
        digest
    );
}

#[test]
fn production_contribution_statement_digest_binds_every_field() {
    let statement = fixture_production_statement();
    let baseline = statement.statement_digest().expect("digest baseline");

    let mut cases: Vec<(&str, ProductionContributionStatement)> = Vec::new();

    let mut mutated = statement.clone();
    mutated.protocol_version = 2;
    cases.push(("protocol_version", mutated));

    let mut mutated = statement.clone();
    mutated.epoch_id[0] ^= 0x01;
    cases.push(("epoch_id", mutated));

    let mut mutated = statement.clone();
    mutated.session_id[0] ^= 0x01;
    cases.push(("session_id", mutated));

    let mut mutated = statement.clone();
    mutated.block_height += 1;
    cases.push(("block_height", mutated));

    let mut mutated = statement.clone();
    mutated.attempt += 1;
    cases.push(("attempt", mutated));

    let mut mutated = statement.clone();
    mutated.validator_index += 1;
    cases.push(("validator_index", mutated));

    let mut mutated = statement.clone();
    mutated.threshold -= 1;
    cases.push(("threshold", mutated));

    let mut mutated = statement.clone();
    mutated.total_nodes += 1;
    cases.push(("total_nodes", mutated));

    let mut mutated = statement.clone();
    mutated.validator_set_digest[0] ^= 0x01;
    cases.push(("validator_set_digest", mutated));

    let mut mutated = statement.clone();
    mutated.public_key_digest[0] ^= 0x01;
    cases.push(("public_key_digest", mutated));

    let mut mutated = statement.clone();
    mutated.parameter_set_digest[0] ^= 0x01;
    cases.push(("parameter_set_digest", mutated));

    let mut mutated = statement.clone();
    mutated.mu[0] ^= 0x01;
    cases.push(("mu", mutated));

    let mut mutated = statement.clone();
    mutated.challenge[0] ^= 0x01;
    cases.push(("challenge", mutated));

    let mut mutated = statement.clone();
    mutated.dkg_commitment_digest[0] ^= 0x01;
    cases.push(("dkg_commitment_digest", mutated));

    let mut mutated = statement.clone();
    mutated.masking_commitment_digest[0] ^= 0x01;
    cases.push(("masking_commitment_digest", mutated));

    let mut mutated = statement.clone();
    mutated.secret_commitment_digest[0] ^= 0x01;
    cases.push(("secret_commitment_digest", mutated));

    let mut mutated = statement;
    mutated.contribution_commitment_digest[0] ^= 0x01;
    cases.push(("contribution_commitment_digest", mutated));

    for (field, mutated) in cases {
        assert_ne!(
            mutated.statement_digest().unwrap_or_else(|err| {
                panic!("mutated {field} should remain structurally valid: {err}")
            }),
            baseline,
            "digest did not bind field {field}"
        );
    }
}

#[test]
fn production_contribution_statement_rejects_invalid_threshold_or_validator() {
    let mut zero_protocol = fixture_production_statement();
    zero_protocol.protocol_version = 0;
    assert_eq!(
        zero_protocol.to_canonical_bytes(),
        Err(ThresholdError::MalformedSerialization {
            reason: "invalid production contribution statement version"
        })
    );

    let mut zero_validator = fixture_production_statement();
    zero_validator.validator_index = 0;
    assert_eq!(
        zero_validator.to_canonical_bytes(),
        Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(0)
        })
    );

    let mut zero_threshold = fixture_production_statement();
    zero_threshold.threshold = 0;
    assert_eq!(
        zero_threshold.to_canonical_bytes(),
        Err(ThresholdError::InvalidThresholdParameters {
            threshold: zero_threshold.threshold,
            total_nodes: zero_threshold.total_nodes,
        })
    );

    let mut zero_total = fixture_production_statement();
    zero_total.total_nodes = 0;
    assert_eq!(
        zero_total.to_canonical_bytes(),
        Err(ThresholdError::InvalidThresholdParameters {
            threshold: zero_total.threshold,
            total_nodes: zero_total.total_nodes,
        })
    );

    let mut invalid_threshold = fixture_production_statement();
    invalid_threshold.threshold = invalid_threshold.total_nodes + 1;
    assert_eq!(
        invalid_threshold.to_canonical_bytes(),
        Err(ThresholdError::InvalidThresholdParameters {
            threshold: invalid_threshold.threshold,
            total_nodes: invalid_threshold.total_nodes,
        })
    );

    let mut outside_set = fixture_production_statement();
    outside_set.validator_index = outside_set.total_nodes + 1;
    assert_eq!(
        outside_set.to_canonical_bytes(),
        Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(outside_set.validator_index)
        })
    );
}

#[test]
fn contribution_proof_rejects_payload_binding_tampering() {
    let statement = fixture_statement();
    let witness = ContributionWitness::from_payload(vec![0xAA, 0xBB, 0xCC]);
    let mut proof = prove_contribution(&statement, &witness).expect("proof should be built");

    proof.payload_len += 1;
    assert_rejects_for_validator(&statement, &proof, statement.validator_index);

    let mut proof = prove_contribution(&statement, &witness).expect("proof should be built");
    proof.payload_digest[0] ^= 0x01;
    assert_rejects_for_validator(&statement, &proof, statement.validator_index);

    let mut proof = prove_contribution(&statement, &witness).expect("proof should be built");
    proof.proof_digest[0] ^= 0x01;
    assert_rejects_for_validator(&statement, &proof, statement.validator_index);
}

#[test]
fn custom_contribution_proof_backend_can_be_called_through_trait_boundary() {
    let backend = CountingContributionProofBackend;
    let statement = fixture_statement();
    let witness = ContributionWitness::from_payload(vec![0xAA, 0xBB, 0xCC]);

    let proof = backend
        .prove(&statement, &witness)
        .expect("custom backend should produce proof");

    assert_eq!(proof.payload_len, 3);
    assert_eq!(proof.payload_digest, [statement.validator_index as u8; 32]);
    assert_eq!(proof.proof_digest, [witness.payload_len() as u8; 32]);
    backend
        .verify(&statement, &proof)
        .expect("custom backend should verify its proof");

    let mut mismatched = proof;
    mismatched.payload_len += 1;
    assert_eq!(
        backend.verify(&statement, &mismatched),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(statement.validator_index)
        })
    );
}

#[test]
fn free_functions_match_default_transcript_hash_backend() {
    let statement = fixture_statement();
    let witness = ContributionWitness::from_payload(vec![0x10, 0x20, 0x30, 0x40]);
    let backend = TranscriptHashContributionProofBackend;

    let wrapper_proof =
        prove_contribution(&statement, &witness).expect("wrapper should produce proof");
    let backend_proof = backend
        .prove(&statement, &witness)
        .expect("backend should produce proof");

    assert_eq!(wrapper_proof, backend_proof);
    assert_eq!(
        wrapper_proof.to_canonical_bytes(),
        backend_proof.to_canonical_bytes()
    );
    verify_contribution_proof(&statement, &wrapper_proof).expect("wrapper should verify proof");
    backend
        .verify(&statement, &wrapper_proof)
        .expect("backend should verify proof");
}

#[test]
fn contribution_proof_security_profile_rejects_transcript_hash_scaffold_for_production_claims() {
    let backend = TranscriptHashContributionProofBackend;

    assert_eq!(
        backend.security_profile(),
        ContributionProofSecurityProfile::TranscriptHashScaffold
    );
    assert!(!backend
        .security_profile()
        .supports_production_security_claim());
    assert_eq!(
        require_production_contribution_proof_backend(&backend),
        Err(ThresholdError::BackendUnavailable {
            reason:
                "contribution proof backend is transcript-hash scaffold; production proof relation required"
        })
    );
}

#[test]
fn contribution_proof_security_profile_rejects_candidate_scaffold_for_production_claims() {
    let backend = CandidateContributionProofBackend;

    assert_eq!(
        backend.security_profile(),
        ContributionProofSecurityProfile::ProductionCandidateScaffold
    );
    assert!(!backend
        .security_profile()
        .supports_production_security_claim());
    assert_eq!(
        require_production_contribution_proof_backend(&backend),
        Err(ThresholdError::BackendUnavailable {
            reason:
                "contribution proof backend is transcript-hash scaffold; production proof relation required"
        })
    );
}

#[test]
fn contribution_proof_security_profile_allows_declared_production_backend_boundary() {
    let backend = DeclaredProductionContributionProofBackend;

    assert_eq!(
        backend.security_profile(),
        ContributionProofSecurityProfile::ProductionProofRelation
    );
    assert!(backend
        .security_profile()
        .supports_production_security_claim());
    require_production_contribution_proof_backend(&backend)
        .expect("declared production proof backend should pass the policy gate");
}

#[test]
fn contribution_witness_debug_redacts_raw_payload() {
    let witness = ContributionWitness::from_payload(b"secret-dependent-payload".to_vec());
    let rendered = format!("{witness:?}");

    assert!(rendered.contains("payload_len"));
    assert!(!rendered.contains("secret-dependent-payload"));
}

#[test]
fn contribution_proof_rejects_malformed_statement_or_empty_witness() {
    let mut statement = fixture_statement();
    statement.validator_index = 0;
    let witness = ContributionWitness::from_payload(vec![1, 2, 3]);

    assert_eq!(
        prove_contribution(&statement, &witness),
        Err(ThresholdError::UnknownValidator {
            validator: ValidatorId(statement.validator_index)
        })
    );

    let statement = fixture_statement();
    let empty_witness = ContributionWitness::from_payload(Vec::new());
    assert!(matches!(
        prove_contribution(&statement, &empty_witness),
        Err(ThresholdError::MalformedSerialization { .. })
    ));
}

#[test]
fn contribution_statement_canonical_bytes_round_trip() {
    let statement = fixture_statement();
    let encoded = statement.to_canonical_bytes();

    assert_eq!(encoded.len(), CONTRIBUTION_STATEMENT_BYTES);
    assert_eq!(
        ContributionStatement::from_canonical_bytes(&encoded).expect("decode statement"),
        statement
    );

    let mut truncated = encoded;
    truncated.pop();
    assert!(matches!(
        ContributionStatement::from_canonical_bytes(&truncated),
        Err(ThresholdError::MalformedSerialization { .. })
    ));
}

#[test]
fn contribution_proof_canonical_bytes_round_trip() {
    let statement = fixture_statement();
    let witness = ContributionWitness::from_payload(vec![1, 2, 3, 4, 5]);
    let proof = prove_contribution(&statement, &witness).expect("proof should be built");
    let encoded = proof.to_canonical_bytes();

    assert_eq!(encoded.len(), CONTRIBUTION_PROOF_BYTES);
    assert_eq!(
        dytallix_pq_threshold::crypto::contribution_proof::ContributionProof::from_canonical_bytes(
            &encoded
        )
        .expect("decode proof"),
        proof
    );

    let mut extended = encoded;
    extended.push(0);
    assert!(matches!(
        dytallix_pq_threshold::crypto::contribution_proof::ContributionProof::from_canonical_bytes(
            &extended
        ),
        Err(ThresholdError::MalformedSerialization { .. })
    ));
}

fn fixture_statement() -> ContributionStatement {
    ContributionStatement {
        session_id: [0xA1; 32],
        block_height: 42,
        attempt: 3,
        validator_index: 7,
        challenge: [0xB2; CONTRIBUTION_CHALLENGE_BYTES],
        masking_commitment_digest: [0xC3; 32],
        secret_commitment_digest: [0xD4; 32],
        dkg_commitment_digest: [0xE5; 32],
    }
}

fn fixture_production_statement() -> ProductionContributionStatement {
    ProductionContributionStatement {
        protocol_version: 1,
        epoch_id: [0x91; 32],
        session_id: [0xA1; 32],
        block_height: 42,
        attempt: 3,
        validator_index: 7,
        threshold: 5,
        total_nodes: 9,
        validator_set_digest: [0x92; 32],
        public_key_digest: [0x93; 32],
        parameter_set_digest: [0x94; 32],
        mu: [0x95; 64],
        challenge: [0xB2; CONTRIBUTION_CHALLENGE_BYTES],
        dkg_commitment_digest: [0xE5; 32],
        masking_commitment_digest: [0xC3; 32],
        secret_commitment_digest: [0xD4; 32],
        contribution_commitment_digest: [0x96; 32],
    }
}

fn assert_rejects_for_validator(
    statement: &ContributionStatement,
    proof: &ContributionProof,
    validator_index: u16,
) {
    assert_eq!(
        verify_contribution_proof(statement, proof),
        Err(ThresholdError::PartialShareVerificationFailed {
            validator: ValidatorId(validator_index)
        })
    );
}

struct CountingContributionProofBackend;

impl ContributionProofBackend for CountingContributionProofBackend {
    fn prove(
        &self,
        statement: &ContributionStatement,
        witness: &ContributionWitness,
    ) -> Result<ContributionProof, ThresholdError> {
        Ok(ContributionProof {
            payload_len: u32::try_from(witness.payload_len()).map_err(|_| {
                ThresholdError::MalformedSerialization {
                    reason: "test witness payload too large",
                }
            })?,
            payload_digest: [statement.validator_index as u8; 32],
            proof_digest: [witness.payload_len() as u8; 32],
        })
    }

    fn verify(
        &self,
        statement: &ContributionStatement,
        proof: &ContributionProof,
    ) -> Result<(), ThresholdError> {
        if proof.payload_len == u32::from(statement.attempt) {
            Ok(())
        } else {
            Err(ThresholdError::PartialShareVerificationFailed {
                validator: ValidatorId(statement.validator_index),
            })
        }
    }
}

struct DeclaredProductionContributionProofBackend;

impl ContributionProofBackend for DeclaredProductionContributionProofBackend {
    fn security_profile(&self) -> ContributionProofSecurityProfile {
        ContributionProofSecurityProfile::ProductionProofRelation
    }

    fn prove(
        &self,
        _statement: &ContributionStatement,
        _witness: &ContributionWitness,
    ) -> Result<ContributionProof, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test production backend does not implement proving",
        })
    }

    fn verify(
        &self,
        _statement: &ContributionStatement,
        _proof: &ContributionProof,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test production backend does not implement verification",
        })
    }
}

struct CandidateContributionProofBackend;

impl ContributionProofBackend for CandidateContributionProofBackend {
    fn security_profile(&self) -> ContributionProofSecurityProfile {
        ContributionProofSecurityProfile::ProductionCandidateScaffold
    }

    fn prove(
        &self,
        _statement: &ContributionStatement,
        _witness: &ContributionWitness,
    ) -> Result<ContributionProof, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test candidate backend does not implement proving",
        })
    }

    fn verify(
        &self,
        _statement: &ContributionStatement,
        _proof: &ContributionProof,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test candidate backend does not implement verification",
        })
    }
}
