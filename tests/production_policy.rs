use dytallix_pq_threshold::{
    adapter::actor::ActorConfig,
    crypto::vss::ShareContribution,
    crypto::{
        contribution_proof::{
            ContributionProof, ContributionProofBackend, ContributionProofSecurityProfile,
            ContributionStatement, ContributionWitness, TranscriptHashContributionProofBackend,
        },
        production_policy::{require_production_threshold_backends, ProductionBackendPolicyReport},
        vss::{
            TranscriptHashVssCommitmentBackend, VssCommitmentBackend, VssCommitmentSecurityProfile,
            VssShareCommitment,
        },
    },
    PrivateKeyShare, SessionId, ThresholdError, ThresholdPublicKey, ValidatorId,
};
use std::time::Duration;

#[test]
fn combined_production_policy_rejects_default_scaffold_backends() {
    let report = ProductionBackendPolicyReport::from_backends(
        &TranscriptHashVssCommitmentBackend,
        &TranscriptHashContributionProofBackend,
    );

    assert_eq!(
        report.vss_profile,
        VssCommitmentSecurityProfile::DeterministicTranscriptScaffold
    );
    assert_eq!(
        report.contribution_profile,
        ContributionProofSecurityProfile::TranscriptHashScaffold
    );
    assert!(!report.supports_production_security_claim());
    assert_eq!(
        require_production_threshold_backends(
            &TranscriptHashVssCommitmentBackend,
            &TranscriptHashContributionProofBackend,
        ),
        Err(ThresholdError::BackendUnavailable {
            reason:
                "threshold production policy requires production VSS and contribution proof backends",
        })
    );
}

#[test]
fn combined_production_policy_requires_both_backend_families_to_be_production() {
    let vss = DeclaredProductionVssBackend;
    let proof = DeclaredProductionContributionProofBackend;

    let report = ProductionBackendPolicyReport::from_backends(&vss, &proof);

    assert_eq!(
        report.vss_profile,
        VssCommitmentSecurityProfile::ProductionBindingHiding
    );
    assert_eq!(
        report.contribution_profile,
        ContributionProofSecurityProfile::ProductionProofRelation
    );
    assert!(report.supports_production_security_claim());
    require_production_threshold_backends(&vss, &proof)
        .expect("declared production backend families should pass together");
}

#[test]
fn combined_production_policy_rejects_mixed_scaffold_and_production_backends() {
    let vss = DeclaredProductionVssBackend;
    let proof = DeclaredProductionContributionProofBackend;

    assert_eq!(
        require_production_threshold_backends(&vss, &TranscriptHashContributionProofBackend),
        Err(ThresholdError::BackendUnavailable {
            reason:
                "threshold production policy requires production VSS and contribution proof backends",
        })
    );
    assert_eq!(
        require_production_threshold_backends(&TranscriptHashVssCommitmentBackend, &proof),
        Err(ThresholdError::BackendUnavailable {
            reason:
                "threshold production policy requires production VSS and contribution proof backends",
        })
    );
}

#[test]
fn combined_production_policy_rejects_candidate_contribution_proof_backend() {
    let report = ProductionBackendPolicyReport::from_backends(
        &DeclaredProductionVssBackend,
        &CandidateContributionProofBackend,
    );

    assert_eq!(
        report.vss_profile,
        VssCommitmentSecurityProfile::ProductionBindingHiding
    );
    assert_eq!(
        report.contribution_profile,
        ContributionProofSecurityProfile::ProductionCandidateScaffold
    );
    assert!(!report.supports_production_security_claim());
    assert_eq!(
        require_production_threshold_backends(
            &DeclaredProductionVssBackend,
            &CandidateContributionProofBackend,
        ),
        Err(ThresholdError::BackendUnavailable {
            reason:
                "threshold production policy requires production VSS and contribution proof backends",
        })
    );
}

#[test]
fn combined_production_policy_rejects_candidate_vss_backend_without_experimental_feature() {
    let report = ProductionBackendPolicyReport::from_backends(
        &CandidateVssBackend,
        &DeclaredProductionContributionProofBackend,
    );

    assert_eq!(
        report.vss_profile,
        VssCommitmentSecurityProfile::ProductionCandidateScaffold
    );
    assert_eq!(
        report.contribution_profile,
        ContributionProofSecurityProfile::ProductionProofRelation
    );
    assert!(!report.supports_production_security_claim());
    assert_eq!(
        require_production_threshold_backends(
            &CandidateVssBackend,
            &DeclaredProductionContributionProofBackend,
        ),
        Err(ThresholdError::BackendUnavailable {
            reason:
                "threshold production policy requires production VSS and contribution proof backends",
        })
    );
}

#[test]
fn production_actor_config_constructor_rejects_scaffold_backend_selection() {
    let err = ActorConfig::new_production_checked(
        ValidatorId(1),
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
        2,
        ThresholdPublicKey([4; 1952]),
        PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec()),
        Duration::from_secs(1),
        4,
        &TranscriptHashVssCommitmentBackend,
        &TranscriptHashContributionProofBackend,
    )
    .expect_err("scaffold backend selection must fail closed");

    assert_eq!(
        err,
        ThresholdError::BackendUnavailable {
            reason:
                "threshold production policy requires production VSS and contribution proof backends",
        }
    );
}

#[test]
fn production_actor_config_constructor_allows_declared_production_backend_selection() {
    let config = ActorConfig::new_production_checked(
        ValidatorId(1),
        vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
        2,
        ThresholdPublicKey([4; 1952]),
        PrivateKeyShare::new(ValidatorId(1), b"share-1".to_vec()),
        Duration::from_secs(1),
        4,
        &DeclaredProductionVssBackend,
        &DeclaredProductionContributionProofBackend,
    )
    .expect("declared production backend families should permit production config construction");

    assert_eq!(config.local_validator, ValidatorId(1));
    assert_eq!(config.threshold, 2);
    assert_eq!(config.max_sessions, 4);
}

#[cfg(feature = "experimental-vss")]
#[test]
fn combined_production_policy_rejects_experimental_vss_candidate_backend() {
    use dytallix_pq_threshold::crypto::vss::ExperimentalVssCommitmentBackend;

    let report = ProductionBackendPolicyReport::from_backends(
        &ExperimentalVssCommitmentBackend,
        &DeclaredProductionContributionProofBackend,
    );

    assert_eq!(
        report.vss_profile,
        VssCommitmentSecurityProfile::ProductionCandidateScaffold
    );
    assert!(!report.supports_production_security_claim());
    assert!(matches!(
        require_production_threshold_backends(
            &ExperimentalVssCommitmentBackend,
            &DeclaredProductionContributionProofBackend,
        ),
        Err(ThresholdError::BackendUnavailable { .. })
    ));
}

struct DeclaredProductionVssBackend;

impl VssCommitmentBackend for DeclaredProductionVssBackend {
    fn security_profile(&self) -> VssCommitmentSecurityProfile {
        VssCommitmentSecurityProfile::ProductionBindingHiding
    }

    fn commit_share_contribution(
        &self,
        _session_id: SessionId,
        _threshold: u16,
        _total_nodes: u16,
        _share: &ShareContribution,
    ) -> Result<VssShareCommitment, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test production VSS backend does not implement commitment",
        })
    }

    fn verify_share_contribution_commitment(
        &self,
        _session_id: SessionId,
        _threshold: u16,
        _total_nodes: u16,
        _share: &ShareContribution,
        _commitment: &VssShareCommitment,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test production VSS backend does not implement verification",
        })
    }
}

struct CandidateVssBackend;

impl VssCommitmentBackend for CandidateVssBackend {
    fn security_profile(&self) -> VssCommitmentSecurityProfile {
        VssCommitmentSecurityProfile::ProductionCandidateScaffold
    }

    fn commit_share_contribution(
        &self,
        _session_id: SessionId,
        _threshold: u16,
        _total_nodes: u16,
        _share: &ShareContribution,
    ) -> Result<VssShareCommitment, ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test candidate VSS backend does not implement commitment",
        })
    }

    fn verify_share_contribution_commitment(
        &self,
        _session_id: SessionId,
        _threshold: u16,
        _total_nodes: u16,
        _share: &ShareContribution,
        _commitment: &VssShareCommitment,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test candidate VSS backend does not implement verification",
        })
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
            reason: "test production proof backend does not implement proving",
        })
    }

    fn verify(
        &self,
        _statement: &ContributionStatement,
        _proof: &ContributionProof,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test production proof backend does not implement verification",
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
            reason: "test candidate proof backend does not implement proving",
        })
    }

    fn verify(
        &self,
        _statement: &ContributionStatement,
        _proof: &ContributionProof,
    ) -> Result<(), ThresholdError> {
        Err(ThresholdError::BackendUnavailable {
            reason: "test candidate proof backend does not implement verification",
        })
    }
}
