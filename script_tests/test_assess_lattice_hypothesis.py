import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "assess_lattice_hypothesis.py"


def load_module():
    spec = importlib.util.spec_from_file_location("assess_lattice_hypothesis", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerdictRuleTests(unittest.TestCase):
    def test_default_criteria_cover_the_five_hypothesis_requirements(self):
        module = load_module()

        criteria = module.default_criteria()

        self.assertEqual(len(criteria), 5)
        self.assertEqual(criteria[0]["id"], "aggregate_mask_distribution")
        self.assertEqual(criteria[1]["id"], "aggregate_rejection_equivalence")
        self.assertEqual(criteria[2]["id"], "abort_retry_bias")
        self.assertEqual(criteria[3]["id"], "partial_contribution_soundness")
        self.assertEqual(criteria[4]["id"], "unauthorized_aggregate_reduction")

    def test_overall_verdict_rolls_up_criterion_statuses(self):
        module = load_module()

        self.assertEqual(
            module.overall_verdict([{"status": "met"}] * 5),
            "completely_proven",
        )
        self.assertEqual(
            module.overall_verdict(
                [{"status": "partially_met"}, {"status": "blocked"}]
            ),
            "partially_proven",
        )
        self.assertEqual(
            module.overall_verdict([{"status": "failed"}, {"status": "blocked"}]),
            "partially_disproven",
        )
        self.assertEqual(
            module.overall_verdict([{"status": "failed"}] * 5),
            "completely_disproven",
        )

    def test_default_commands_run_production_acceptance_checks(self):
        module = load_module()

        coordinator_command = next(
            command
            for command in module.default_commands()
            if "--features" in command and "coordinator-assisted" in command
        )

        self.assertIn("production_acceptance", coordinator_command)

    def test_default_commands_run_all_blocker_evidence_checks(self):
        module = load_module()

        coordinator_command = next(
            command
            for command in module.default_commands()
            if "--features" in command and "coordinator-assisted" in command
        )
        commands = [" ".join(command) for command in module.default_commands()]

        for test_name in [
            "production_mask_distribution",
            "production_rejection_equivalence",
            "production_abort_bias",
            "production_partial_soundness",
        ]:
            self.assertIn(test_name, coordinator_command)
        self.assertTrue(
            any("unauthorized_aggregate_reduction_manifest" in command for command in commands)
        )


class DocumentClassificationTests(unittest.TestCase):
    def test_scan_documents_finds_claim_boundaries_and_blockers(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "docs" / "cryptography").mkdir(parents=True)
            (root / "docs" / "benchmarks").mkdir(parents=True)
            (root / "README.md").write_text(
                "Research status: deterministic simulation machinery.\n"
                "If the hypothesis is proven, implemented with a reviewed "
                "threshold backend, and validated against standard ML-DSA "
                "verification.\n",
                encoding="utf-8",
            )
            (root / "docs" / "cryptography" / "proof-obligations.md").write_text(
                "| Noise Lemma B aggregate mask distribution | open |\n"
                "| Noise Lemma D aggregate rejection bound preservation | open |\n"
                "| Noise Lemma G abort distribution | open |\n"
                "| FST-L4 partial-share validity | open |\n"
                "| FST-L6 no subthreshold signing | open |\n",
                encoding="utf-8",
            )
            (root / "docs" / "cryptography" / "noise-rejection-proof-plan.md").write_text(
                "SimulatedAggregator checks threshold and validator-universe "
                "matching. It does not perform real ML-DSA aggregate rejection "
                "checks.\nQuantify Renyi divergence from the standard ML-DSA "
                "mask distribution for epsilon_mask.\n",
                encoding="utf-8",
            )
            (root / "docs" / "cryptography" / "formal-security-theorem.md").write_text(
                "FST-L6 no subthreshold signing. Proof status: not proved in "
                "this repository.\n",
                encoding="utf-8",
            )
            (root / "docs" / "cryptography" / "ideal-functionality.md").write_text(
                "unauthorized aggregate output would imply a forgery against "
                "ML-DSA-65 or a violation of a threshold assumption.\n",
                encoding="utf-8",
            )
            (
                root
                / "docs"
                / "cryptography"
                / "proof-implementation-crosswalk.md"
            ).write_text(
                "# Proof Implementation Crosswalk\n\n"
                "Current proof implementation crosswalk placeholder.\n",
                encoding="utf-8",
            )
            (
                root
                / "docs"
                / "cryptography"
                / "protocol-code-crosswalk.md"
            ).write_text(
                "# Protocol Code Crosswalk\n\n"
                "Current protocol code crosswalk placeholder.\n",
                encoding="utf-8",
            )
            (
                root
                / "docs"
                / "benchmarks"
                / "release-readiness-checklist.md"
            ).write_text(
                "Add standard-verifier bridge tests for accepted aggregate "
                "signatures.\n",
                encoding="utf-8",
            )

            scan = module.scan_documents(root)
            classified = module.classify_criteria(module.default_criteria(), scan)

        self.assertTrue(scan["readme_research_boundary"])
        self.assertTrue(scan["standard_verifier_blocked"])
        self.assertTrue(scan["renyi_evidence_blocked"])
        self.assertEqual(classified[0]["status"], "blocked")
        self.assertEqual(classified[1]["status"], "blocked")
        self.assertEqual(classified[2]["status"], "blocked")
        self.assertEqual(classified[3]["status"], "partially_met")
        self.assertEqual(classified[4]["status"], "blocked")
        self.assertIn("README keeps the hypothesis conditional", classified[0]["blockers"][0])

    def test_missing_required_documents_block_dependent_criteria(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)

            scan = module.scan_documents(root)
            classified = module.classify_criteria(module.default_criteria(), scan)

        self.assertTrue(scan["missing_documents"])
        self.assertTrue(all(criterion["status"] == "blocked" for criterion in classified))
        self.assertIn("README.md", scan["missing_documents"])

    def test_p1_aggregate_recomputation_gate_is_reported_without_promoting_claim(self):
        module = load_module()
        criteria = module.default_criteria()
        scan = {
            "missing_documents": [],
            "selected_backend_direction": {
                "status": "observed_selection_artifact",
                "direction": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
                "assumption": "TEE/HSM",
                "output": "standard-verifier-compatible output",
                "migration_candidates": ["P2/MPC", "TALUS"],
            },
            "aggregate_acceptance_conformance_scaffold": True,
            "rejection_equivalence_bridge_gate": True,
            "rejection_equivalence_closure_framework": True,
            "p1_aggregate_recomputation_artifact_gate": True,
            "hazmat_standard_verifier_bridge": True,
            "acvp_mldsa65_sample_kat": True,
            "standard_verifier_blocked": True,
            "mask_distribution_evidence_gate": False,
            "mask_distribution_closure_framework": False,
            "readme_research_boundary": False,
            "renyi_evidence_blocked": False,
            "abort_bias_evidence_gate": False,
            "abort_bias_closure_framework": False,
            "abort_bias_blocked": False,
            "partial_soundness_scaffold": False,
            "local_acceptance_conformance_scaffold": False,
            "partial_soundness_evidence_gate": False,
            "partial_soundness_closure_framework": False,
            "partial_soundness_blocked": False,
            "unauthorized_reduction_manifest_gate": False,
            "unauthorized_reduction_closure_framework": False,
            "unforgeability_reduction_blocked": False,
        }

        classified = module.classify_criteria(criteria, scan)
        rejection = classified[1]

        self.assertEqual(rejection["status"], "partially_met")
        self.assertTrue(
            any("P1 aggregate recomputation artifact gate" in item for item in rejection["observed_evidence"])
        )
        self.assertTrue(
            any("Real P1 aggregate recomputation artifacts" in item for item in rejection["blockers"])
        )


class ReportGenerationTests(unittest.TestCase):
    def write_minimal_repo_docs(self, root):
        (root / "docs" / "cryptography").mkdir(parents=True)
        (root / "docs" / "benchmarks").mkdir(parents=True)
        (root / "README.md").write_text(
            "Research status: deterministic simulation machinery.\n"
            "If the hypothesis is proven, implemented with a reviewed "
            "threshold backend, and validated against standard ML-DSA "
            "verification.\n",
            encoding="utf-8",
        )
        (root / "docs" / "cryptography" / "proof-obligations.md").write_text(
            "| Noise Lemma B aggregate mask distribution | open |\n"
            "| Noise Lemma D aggregate rejection bound preservation | open |\n"
            "| Noise Lemma G abort distribution | open |\n"
            "| FST-L4 partial-share validity | open |\n"
            "| FST-L6 no subthreshold signing | open |\n",
            encoding="utf-8",
        )
        (root / "docs" / "cryptography" / "noise-rejection-proof-plan.md").write_text(
            "SimulatedAggregator checks threshold and validator-universe "
            "matching. It does not perform real ML-DSA aggregate rejection "
            "checks.\nQuantify Renyi divergence from the standard ML-DSA "
            "mask distribution for epsilon_mask.\n",
            encoding="utf-8",
        )
        (root / "docs" / "cryptography" / "formal-security-theorem.md").write_text(
            "FST-L6 no subthreshold signing. Proof status: not proved in "
            "this repository.\n",
            encoding="utf-8",
        )
        (root / "docs" / "cryptography" / "ideal-functionality.md").write_text(
            "unauthorized aggregate output would imply a forgery against "
            "ML-DSA-65 or a violation of a threshold assumption.\n",
            encoding="utf-8",
        )
        (
            root
            / "docs"
            / "cryptography"
            / "proof-implementation-crosswalk.md"
        ).write_text(
            "# Proof Implementation Crosswalk\n\n"
            "Current proof implementation crosswalk placeholder.\n",
            encoding="utf-8",
        )
        (
            root
            / "docs"
            / "cryptography"
            / "protocol-code-crosswalk.md"
        ).write_text(
            "# Protocol Code Crosswalk\n\n"
            "Current protocol code crosswalk placeholder.\n",
            encoding="utf-8",
        )
        (root / "docs" / "benchmarks" / "release-readiness-checklist.md").write_text(
            "Add standard-verifier bridge tests for accepted aggregate "
            "signatures.\n",
            encoding="utf-8",
        )

    def write_selected_backend_docs(self, root):
        selected_backend_text = (
            "## Selected Backend Direction\n\n"
            "The selected real-backend direction is ML-DSA-65 "
            "coordinator-assisted Shamir nonce DKG P1 with a TEE/HSM "
            "coordinator assumption and standard-verifier-compatible output. "
            "Later migration candidates remain P2/MPC and TALUS.\n\n"
            "This is a selection artifact only, not proof closure, not a "
            "completed backend implementation, and not production approval.\n"
        )
        (
            root
            / "docs"
            / "cryptography"
            / "proof-implementation-crosswalk.md"
        ).write_text(
            "# Proof Implementation Crosswalk\n\n" + selected_backend_text,
            encoding="utf-8",
        )
        (
            root
            / "docs"
            / "cryptography"
            / "protocol-code-crosswalk.md"
        ).write_text(
            "# Protocol Code Crosswalk\n\n" + selected_backend_text,
            encoding="utf-8",
        )

    def write_acceptance_predicate_scaffold(self, root):
        (root / "src" / "production").mkdir(parents=True, exist_ok=True)
        (root / "tests").mkdir(parents=True, exist_ok=True)
        (root / "src" / "production" / "acceptance.rs").write_text(
            "pub struct LocalAccept;\n"
            "pub struct AggregateAccept;\n"
            "pub struct AcceptedPartialContribution;\n"
            "pub struct AggregateAcceptEvidence;\n",
            encoding="utf-8",
        )
        (root / "tests" / "production_acceptance.rs").write_text(
            "#[test]\n"
            "fn local_accept_conformance_token_is_stable() {\n"
            "    let _ = \"LocalAccept AcceptedPartialContribution\";\n"
            "}\n"
            "#[test]\n"
            "fn aggregate_accept_conformance_token_is_stable() {\n"
            "    let _ = \"AggregateAccept AggregateAcceptEvidence\";\n"
            "}\n",
            encoding="utf-8",
        )

    def write_hazmat_standard_verifier_bridge(self, root):
        (root / "src" / "production").mkdir(parents=True, exist_ok=True)
        (root / "tests").mkdir(parents=True, exist_ok=True)
        (root / "tests" / "fixtures").mkdir(parents=True, exist_ok=True)
        (root / "src" / "production" / "provider.rs").write_text(
            "pub trait StandardMldsa65Provider {}\n"
            "pub struct HazmatMldsa65Provider;\n"
            "impl HazmatMldsa65Provider { pub fn verify_with_context() {} }\n",
            encoding="utf-8",
        )
        (root / "tests" / "production_provider.rs").write_text(
            "#[test]\n"
            "fn hazmat_provider_verifies_mldsa65_signature_from_fixed_seed() {}\n"
            "#[test]\n"
            "fn hazmat_provider_rejects_mutated_message_and_signature() {}\n"
            "#[test]\n"
            "fn hazmat_provider_verifies_mldsa65_kats() {}\n",
            encoding="utf-8",
        )
        (
            root / "tests" / "fixtures" / "acvp_mldsa65_sigver_fips204_sample.json"
        ).write_text(
            "{\n"
            "  \"name\": \"nist-acvp-server-mldsa65-sigver-fips204-sample\",\n"
            "  \"source_prompt_sha256\": \"abc\",\n"
            "  \"source_expected_results_sha256\": \"def\",\n"
            "  \"tests\": [\n"
            "    {\"testPassed\": true},\n"
            "    {\"testPassed\": false}\n"
            "  ]\n"
            "}\n",
            encoding="utf-8",
        )

    def write_blocker_evidence_gates(self, root):
        (root / "src" / "production").mkdir(parents=True, exist_ok=True)
        (root / "tests").mkdir(parents=True, exist_ok=True)
        (root / "docs" / "cryptography").mkdir(parents=True, exist_ok=True)
        (root / "src" / "production" / "mask_distribution.rs").write_text(
            "pub struct MaskDistributionEvidence;\n"
            "pub struct AcceptedMaskDistributionCertificate;\n"
            "pub struct MaskDistributionClosurePackage;\n"
            "pub struct MaskDistributionClosureReport;\n"
            "pub fn assess_mask_distribution() {}\n",
            encoding="utf-8",
        )
        (root / "tests" / "production_mask_distribution.rs").write_text(
            "#[test]\n"
            "fn mask_distribution_evidence_gate_records_renyi_bound() {}\n"
            "#[test]\n"
            "fn complete_closure_package_reports_ready_without_production_proof_claim() {}\n",
            encoding="utf-8",
        )
        (root / "src" / "production" / "rejection_equivalence.rs").write_text(
            "pub enum AggregateRejectionEvidenceStrength { ScaffoldOnly }\n"
            "pub enum AggregateRejectionClosureStatus { ClosureReady }\n"
            "pub struct AggregateRejectionEquivalenceGate;\n"
            "pub struct AggregateRecomputationTranscript;\n"
            "pub struct AggregateRejectionClosurePackage;\n"
            "pub struct AggregateRejectionClosureCertificate;\n"
            "pub enum AcvpFips204EvidenceSource { NistAcvpServerFips204 }\n"
            "pub struct Mldsa65ProviderKatEvidence;\n"
            "pub struct P1RejectionProofArtifacts;\n"
            "pub struct P1AggregateRecomputationClosurePackage;\n"
            "pub enum P1AggregateRecomputationAssessment { ArtifactReady }\n"
            "pub fn standard_verifier_bridge_fixture_package_digest() {}\n"
            "pub fn assess_rejection_equivalence_closure() {}\n"
            "pub fn assess_p1_aggregate_recomputation_closure() {}\n",
            encoding="utf-8",
        )
        (root / "tests" / "production_rejection_equivalence.rs").write_text(
            "#[test]\n"
            "fn aggregate_rejection_equivalence_bridge_gate_requires_recomputation() {}\n"
            "#[test]\n"
            "fn complete_closure_package_exposes_closure_ready_status_without_production_claims() {}\n"
            "#[test]\n"
            "fn p1_recomputation_closure_rejects_smoke_only_kat_evidence() {}\n"
            "#[test]\n"
            "fn standard_verifier_bridge_fixture_package_digest_fails_loudly_on_drift() {}\n",
            encoding="utf-8",
        )
        (root / "src" / "production" / "abort_bias.rs").write_text(
            "pub struct AbortBiasEvidence;\n"
            "pub struct RetryBiasEvidenceReport;\n"
            "pub enum AbortBiasClosureStatus { ClosureReady }\n"
            "pub struct AbortRetryBiasProofPackage;\n"
            "pub struct AbortBiasClosureReport;\n",
            encoding="utf-8",
        )
        (root / "tests" / "production_abort_bias.rs").write_text(
            "#[test]\n"
            "fn abort_retry_bias_evidence_rejects_unbounded_leakage() {}\n"
            "#[test]\n"
            "fn complete_proof_package_reports_closure_ready_status() {}\n",
            encoding="utf-8",
        )
        (root / "src" / "production" / "partial_soundness.rs").write_text(
            "pub struct PartialContributionSoundnessEvidence;\n"
            "pub struct ProofBackedLocalVerifier;\n"
            "pub enum PartialSoundnessClosureStatus { ClosureReady }\n"
            "pub struct PartialSoundnessClosurePackage;\n",
            encoding="utf-8",
        )
        (root / "tests" / "production_partial_soundness.rs").write_text(
            "#[test]\n"
            "fn partial_soundness_evidence_rejects_digest_only_when_proof_required() {}\n"
            "#[test]\n"
            "fn complete_closure_package_marks_partial_evidence_closure_ready() {}\n",
            encoding="utf-8",
        )
        (root / "docs" / "cryptography" / "unauthorized-aggregate-reduction.md").write_text(
            "# Unauthorized Aggregate Reduction Manifest\n"
            "Status: reduction-case manifest, not a completed proof.\n"
            "## Closure Package Framework\n"
            "Protocol event grammar.\n"
            "Deterministic UAR classifier.\n"
            "Base ML-DSA theorem citation slot.\n"
            "Hybrid bound table.\n"
            "External review signoff.\n"
            "UAR-C0 base ML-DSA forgery.\n"
            "UAR-C1 UAR-C2 UAR-C3 UAR-C4 UAR-C5 UAR-C6 UAR-C7 UAR-C8.\n"
            "Do not claim threshold EUF-CMA security from this manifest.\n",
            encoding="utf-8",
        )
        (root / "tests" / "unauthorized_aggregate_reduction_manifest.rs").write_text(
            "#[test]\n"
            "fn unauthorized_aggregate_reduction_manifest_names_cases() {}\n",
            encoding="utf-8",
        )

    def write_selected_backend_aggregate_artifact_gate(self, root):
        rejection_equivalence_path = (
            root / "src" / "production" / "rejection_equivalence.rs"
        )
        rejection_equivalence_path.write_text(
            rejection_equivalence_path.read_text(encoding="utf-8")
            + "pub struct P1SelectedBackendAggregateArtifactPackage;\n"
            + "pub struct P1SelectedBackendAggregateArtifactCertificate;\n"
            + "pub enum P1SelectedBackendAggregateArtifactAssessment { ArtifactReady }\n"
            + "pub fn assess_p1_selected_backend_aggregate_artifact() {}\n"
            + "pub fn derive_p1_selected_backend_aggregate_artifact_package() {}\n"
            + "pub fn derive_p1_real_recomputation_evidence_digest() {}\n"
            + "pub fn derive_p1_selected_backend_transcript_binding_digest() {}\n"
            + "pub fn derive_p1_selected_backend_signer_set_digest() {}\n"
            + "pub fn derive_p1_selected_backend_attempt_binding_digest() {}\n",
            encoding="utf-8",
        )
        production_rejection_test_path = (
            root / "tests" / "production_rejection_equivalence.rs"
        )
        production_rejection_test_path.write_text(
            production_rejection_test_path.read_text(encoding="utf-8")
            + "#[test]\n"
            + "fn p1_selected_backend_aggregate_artifact_accepts_bound_acceptance_and_recomputation() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_aggregate_artifact_rejects_stale_bridge_for_changed_outputs() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_aggregate_artifact_accepts_real_mldsa_output_package() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_aggregate_artifact_deriver_rejects_stale_recomputation_output() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_aggregate_artifact_rejects_unreviewed_package() {}\n",
            encoding="utf-8",
        )

    def test_scan_documents_finds_acceptance_predicate_scaffold_anchors(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)

            scan = module.scan_documents(root)

        self.assertTrue(scan["acceptance_predicate_source_scaffold"])
        self.assertTrue(scan["production_acceptance_tests_scaffold"])

    def test_acceptance_scaffold_requires_structural_source_and_test_anchors(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            (root / "src" / "production").mkdir(parents=True)
            (root / "tests").mkdir(parents=True)
            (root / "src" / "production" / "acceptance.rs").write_text(
                "// pub struct LocalAccept;\n"
                "// pub struct AcceptedPartialContribution;\n"
                "const COMMENTED_AGGREGATE: &str = "
                "\"pub struct AggregateAccept; pub struct AggregateAcceptEvidence;\";\n",
                encoding="utf-8",
            )
            (root / "tests" / "production_acceptance.rs").write_text(
                "#[test]\n"
                "fn unrelated_string_literals_do_not_count() {\n"
                "    let _ = \"LocalAccept AggregateAccept "
                "AcceptedPartialContribution AggregateAcceptEvidence\";\n"
                "}\n",
                encoding="utf-8",
            )

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)

        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        self.assertFalse(scan["acceptance_predicate_source_scaffold"])
        self.assertFalse(scan["production_acceptance_tests_scaffold"])
        self.assertFalse(scan["local_acceptance_conformance_scaffold"])
        self.assertFalse(scan["aggregate_acceptance_conformance_scaffold"])
        self.assertNotIn(
            "LocalAccept",
            "\n".join(
                criteria_by_id["partial_contribution_soundness"]["observed_evidence"]
            ),
        )
        self.assertNotIn(
            "AggregateAccept",
            "\n".join(
                criteria_by_id["aggregate_rejection_equivalence"]["observed_evidence"]
            ),
        )
        self.assertEqual(
            [criterion["status"] for criterion in report["criteria"]],
            ["blocked", "blocked", "blocked", "partially_met", "blocked"],
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")

    def test_acceptance_predicate_scaffold_updates_evidence_without_unblocking_proofs(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)

            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        self.assertEqual(
            [criterion["status"] for criterion in report["criteria"]],
            ["blocked", "blocked", "blocked", "partially_met", "blocked"],
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")

        partial_evidence = "\n".join(
            criteria_by_id["partial_contribution_soundness"]["observed_evidence"]
        )
        self.assertIn("LocalAccept", partial_evidence)
        self.assertIn("AcceptedPartialContribution", partial_evidence)

        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])
        aggregate_blockers = "\n".join(aggregate["blockers"])
        self.assertEqual(aggregate["status"], "blocked")
        self.assertIn("AggregateAccept", aggregate_evidence)
        self.assertIn("conformance checks", aggregate_evidence)
        self.assertIn("Standard ML-DSA verifier bridge", aggregate_blockers)
        self.assertIn("real aggregate rejection checks", aggregate_blockers)

        self.assertIn("- Evidence: AggregateAccept", markdown)
        self.assertIn("- Blocker: Standard ML-DSA verifier bridge", markdown)

    def test_blocker_evidence_gates_update_partial_progress_without_closing_proofs(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_blocker_evidence_gates(root)

            report = module.build_report(root, run_commands=False)

        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        self.assertEqual(
            [criterion["status"] for criterion in report["criteria"]],
            [
                "partially_met",
                "partially_met",
                "partially_met",
                "partially_met",
                "partially_met",
            ],
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")

        self.assertIn(
            "MaskDistributionEvidence",
            "\n".join(criteria_by_id["aggregate_mask_distribution"]["observed_evidence"]),
        )
        self.assertIn(
            "AggregateRejectionEquivalenceGate",
            "\n".join(criteria_by_id["aggregate_rejection_equivalence"]["observed_evidence"]),
        )
        self.assertIn(
            "AbortBiasEvidence",
            "\n".join(criteria_by_id["abort_retry_bias"]["observed_evidence"]),
        )
        self.assertIn(
            "PartialContributionSoundnessEvidence",
            "\n".join(criteria_by_id["partial_contribution_soundness"]["observed_evidence"]),
        )
        self.assertIn(
            "Unauthorized aggregate reduction manifest",
            "\n".join(criteria_by_id["unauthorized_aggregate_reduction"]["observed_evidence"]),
        )
        self.assertIn(
            "MaskDistributionClosurePackage",
            "\n".join(criteria_by_id["aggregate_mask_distribution"]["observed_evidence"]),
        )
        self.assertIn(
            "AggregateRejectionClosurePackage",
            "\n".join(criteria_by_id["aggregate_rejection_equivalence"]["observed_evidence"]),
        )
        self.assertIn(
            "AbortRetryBiasProofPackage",
            "\n".join(criteria_by_id["abort_retry_bias"]["observed_evidence"]),
        )
        self.assertIn(
            "PartialSoundnessClosurePackage",
            "\n".join(criteria_by_id["partial_contribution_soundness"]["observed_evidence"]),
        )
        self.assertIn(
            "closure package framework",
            "\n".join(criteria_by_id["unauthorized_aggregate_reduction"]["observed_evidence"]),
        )
        for criterion in report["criteria"]:
            self.assertTrue(criterion["blockers"])

    def test_selected_backend_aggregate_artifact_gate_updates_report_without_closing_proofs(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_selected_backend_aggregate_artifact_gate"])
        self.assertTrue(scan["p1_selected_backend_real_output_package"])
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])
        aggregate_blockers = "\n".join(aggregate["blockers"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertEqual(report["overall_verdict"], "partially_proven")
        self.assertIn("Selected-backend aggregate-output artifact gate", aggregate_evidence)
        self.assertIn("Real standard-provider selected-backend aggregate-output package", aggregate_evidence)
        self.assertIn("stronger than fixture-only bridge confidence", aggregate_evidence)
        self.assertIn("conformance/proof-review", aggregate_evidence)
        self.assertIn("not selected-backend proof closure", aggregate_evidence)
        self.assertIn("Real threshold selected-backend aggregate outputs", aggregate_blockers)
        self.assertIn("real standard-provider aggregate-output package", aggregate_blockers)
        self.assertIn("selected-backend proof closure", aggregate_blockers)
        self.assertIn("selected-backend aggregate-output artifact gate", markdown)
        self.assertNotIn("completely_proven", markdown)

    def test_selected_backend_direction_updates_report_without_closing_proofs(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)

            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertEqual(
            report["selected_backend"]["status"],
            "observed_selection_artifact",
        )
        self.assertEqual(
            report["selected_backend"]["direction"],
            "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
        )
        self.assertEqual(report["selected_backend"]["assumption"], "TEE/HSM")
        self.assertEqual(
            report["selected_backend"]["output"],
            "standard-verifier-compatible output",
        )
        self.assertEqual(
            report["selected_backend"]["migration_candidates"],
            ["P2/MPC", "TALUS"],
        )
        self.assertEqual(
            [criterion["status"] for criterion in report["criteria"]],
            [
                "partially_met",
                "partially_met",
                "partially_met",
                "partially_met",
                "partially_met",
            ],
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")
        for criterion in report["criteria"]:
            self.assertIn(
                "Selected backend direction",
                "\n".join(criterion["observed_evidence"]),
            )
            self.assertIn(
                "selection artifact",
                "\n".join(criterion["blockers"]),
            )
        self.assertIn("## Selected Backend Direction", markdown)
        self.assertIn("ML-DSA-65 coordinator-assisted Shamir nonce DKG P1", markdown)
        self.assertIn("not proof closure or production approval", markdown)
        aggregate = next(
            criterion
            for criterion in report["criteria"]
            if criterion["id"] == "aggregate_rejection_equivalence"
        )
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])
        aggregate_blockers = "\n".join(aggregate["blockers"])
        self.assertIn("HazmatMldsa65Provider", aggregate_evidence)
        self.assertIn("bounded ACVP/FIPS204 sample-vector KAT", aggregate_evidence)
        self.assertIn("real p1 aggregate recomputation", aggregate_blockers.lower())
        self.assertNotIn("Standard ML-DSA verifier bridge and real aggregate", aggregate_blockers)

    def test_build_report_writes_json_and_markdown(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)

            report = module.build_report(root, run_commands=False)
            out_dir = root / "artifacts" / "hypothesis" / "latest"
            module.write_reports(report, out_dir)

            saved = json.loads((out_dir / "assessment.json").read_text(encoding="utf-8"))
            markdown = (out_dir / "assessment.md").read_text(encoding="utf-8")

        self.assertIn("testing_statement", report)
        self.assertEqual(report["overall_verdict"], "partially_proven")
        self.assertEqual(report["claim_boundary"], "research scaffold only")
        self.assertEqual(report["commands"], [])
        self.assertEqual(saved["overall_verdict"], "partially_proven")
        self.assertIn("# Lattice Aggregation Hypothesis Assessment", markdown)
        self.assertIn("partially_proven", markdown)

    def test_build_report_uses_command_runner_when_enabled(self):
        module = load_module()

        def fake_runner(command, root, env):
            return {
                "command": command,
                "exit_code": 0,
                "duration_seconds": 0.01,
                "stdout": "test result: ok\nsession_id,duration_ms,aborts,bandwidth_bytes\n",
                "stderr": "",
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)

            report = module.build_report(
                root,
                run_commands=True,
                command_runner=fake_runner,
                commands=[["cargo", "test", "--test", "simulated_flow"]],
            )

        self.assertEqual(len(report["commands"]), 1)
        self.assertTrue(report["command_summary"]["all_passed"])
        self.assertIn("Cargo scaffold checks completed", report["execution_evidence"])

    def test_main_returns_two_for_strict_incomplete_assessment(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            out_dir = root / "out"

            code = module.main(
                [
                    "--root",
                    str(root),
                    "--out",
                    str(out_dir),
                    "--skip-commands",
                    "--strict",
                ]
            )

        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
