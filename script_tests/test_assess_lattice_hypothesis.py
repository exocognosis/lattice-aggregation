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
        self.assertTrue(
            any(
                "thesis_operating_parameters_manifest" in command
                for command in commands
            )
        )
        self.assertTrue(
            any(
                "criterion2_proof_substance_manifest" in command
                for command in commands
            )
        )
        self.assertTrue(
            any(
                "criterion3_proof_substance_manifest" in command
                for command in commands
            )
        )
        self.assertTrue(
            any(
                "criterion1_proof_substance_manifest" in command
                for command in commands
            )
        )
        self.assertTrue(
            any(
                "validator_10000_standard_verifier_gate" in command
                for command in commands
            )
        )


class DocumentClassificationTests(unittest.TestCase):
    def test_scan_documents_accepts_current_readme_boundary_wording(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "README.md").write_text(
                "## Current Status\n\n"
                "This repository is publishable as a research artifact and "
                "exploratory implementation.\n"
                "It is not publishable as production cryptography, a completed "
                "threshold ML-DSA construction, or a finished "
                "standard-verifier-compatible aggregate signature scheme.\n"
                "Current merged-main assessment status: `partially_proven`.\n",
                encoding="utf-8",
            )

            scan = module.scan_documents(root)

        self.assertTrue(scan["readme_research_boundary"])

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
        self.assertIn("README points the run", classified[0]["blockers"][0])

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

    def test_criterion2_status_surfaces_real_recomputation_fixture_reference(self):
        module = load_module()
        markdown = (
            (ROOT / "docs" / "cryptography" / "criterion-2-proof-substance.md")
            .read_text(encoding="utf-8")
        )
        manifest = (
            (ROOT / "docs" / "cryptography" / "criterion-2-proof-substance.json")
            .read_text(encoding="utf-8")
        )

        status = module.criterion2_proof_substance_status(markdown, manifest)

        self.assertEqual(status["status"], "criterion2_proof_payload_formalized")
        self.assertIn(
            {
                "slot_id": "real_recomputation_evidence_digest",
                "fixture_path": "tests/fixtures/p1_real_recomputation_artifact_fixture.json",
                "schema": "lattice-aggregation:p1-real-recomputation-artifact:v1",
                "current_status": "evidence_present_unclosed",
                "claim_boundary": "conformance/proof-review evidence",
            },
            status["artifact_fixture_refs"],
        )
        self.assertIn(
            {
                "slot_id": "standard_verifier_compatibility_artifact_digest",
                "fixture_path": (
                    "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
                ),
                "schema": (
                    "lattice-aggregation:p1-standard-verifier-compatibility-artifact:v1"
                ),
                "current_status": "evidence_present_unclosed",
                "claim_boundary": "conformance/proof-review evidence",
            },
            status["artifact_fixture_refs"],
        )
        self.assertIn(
            {
                "slot_id": "threshold_output_certificate_digest",
                "fixture_path": (
                    "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json"
                ),
                "schema": (
                    "lattice-aggregation:p1-threshold-output-certificate-artifact:v1"
                ),
                "current_status": "evidence_present_unclosed",
                "claim_boundary": "conformance/proof-review evidence",
            },
            status["artifact_fixture_refs"],
        )
        self.assertIn(
            {
                "slot_id": "rejection_distribution_review_digest",
                "fixture_path": (
                    "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json"
                ),
                "schema": (
                    "lattice-aggregation:p1-rejection-distribution-review-artifact:v1"
                ),
                "current_status": "evidence_present_unclosed",
                "claim_boundary": "conformance/proof-review evidence",
            },
            status["artifact_fixture_refs"],
        )
        self.assertIn(
            {
                "slot_id": "theorem_linkage_artifact_digest",
                "fixture_path": (
                    "tests/fixtures/p1_theorem_linkage_artifact_fixture.json"
                ),
                "schema": "lattice-aggregation:p1-theorem-linkage-artifact:v1",
                "current_status": "evidence_present_unclosed",
                "claim_boundary": "conformance/proof-review evidence",
            },
            status["artifact_fixture_refs"],
        )
        self.assertIn(
            {
                "slot_id": "distributed_nonce_producer_artifact_digest",
                "fixture_path": (
                    "artifacts/nonce-producer-handoff/latest/capture/capture.json"
                ),
                "schema": (
                    "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
                ),
                "current_status": (
                    "checked_handoff_replay_importable_until_actual_backend_evidence"
                ),
                "claim_boundary": "conformance/proof-review evidence",
            },
            status["artifact_fixture_refs"],
        )
        self.assertEqual(
            status["artifact_slot_statuses"][
                "distributed_nonce_producer_artifact_digest"
            ],
            "evidence_present_unclosed",
        )
        self.assertEqual(
            status["artifact_slot_sources"][
                "distributed_nonce_producer_artifact_digest"
            ],
            "p1_criterion2_distributed_nonce_producer_artifact_gate",
        )

    def test_criterion1_status_formalizes_open_mask_distribution_payload(self):
        module = load_module()
        markdown = (
            (ROOT / "docs" / "cryptography" / "criterion-1-proof-substance.md")
            .read_text(encoding="utf-8")
        )
        manifest = (
            (ROOT / "docs" / "cryptography" / "criterion-1-proof-substance.json")
            .read_text(encoding="utf-8")
        )

        status = module.criterion1_proof_substance_status(markdown, manifest)

        self.assertEqual(status["status"], "criterion1_proof_payload_formalized")
        self.assertEqual(status["criterion_id"], "aggregate_mask_distribution")
        self.assertEqual(status["payload_status"], "formalized_open_proof_payload")
        self.assertEqual(status["scope"], "criterion-1 proof payload only")
        self.assertIn(
            "renyi_bound_proof_digest",
            status["artifact_slot_statuses"],
        )
        self.assertEqual(
            status["artifact_slot_statuses"]["renyi_bound_proof_digest"],
            "required_unclosed",
        )
        self.assertIn("Noise Lemma B", status["theorem_links"])

    def test_criterion3_status_formalizes_open_abort_retry_payload(self):
        module = load_module()
        markdown = (
            (ROOT / "docs" / "cryptography" / "criterion-3-proof-substance.md")
            .read_text(encoding="utf-8")
        )
        manifest = (
            (ROOT / "docs" / "cryptography" / "criterion-3-proof-substance.json")
            .read_text(encoding="utf-8")
        )

        status = module.criterion3_proof_substance_status(markdown, manifest)

        self.assertEqual(status["status"], "criterion3_proof_payload_formalized")
        self.assertEqual(status["criterion_id"], "abort_retry_bias")
        self.assertEqual(status["payload_status"], "formalized_open_proof_payload")
        self.assertEqual(status["scope"], "criterion-3 proof payload only")
        self.assertIn(
            "retry_domain_separation_proof_digest",
            status["artifact_slot_statuses"],
        )
        self.assertEqual(
            status["artifact_slot_statuses"][
                "retry_domain_separation_proof_digest"
            ],
            "required_unclosed",
        )
        self.assertIn("Noise Lemma G", status["theorem_links"])

    def test_p1_nonce_producer_selection_status_selects_shamir_nonce_dkg_route(self):
        module = load_module()
        markdown = (
            (ROOT / "docs" / "cryptography" / "p1-nonce-producer-selection.md")
            .read_text(encoding="utf-8")
        )
        manifest = (
            (ROOT / "docs" / "cryptography" / "p1-nonce-producer-selection.json")
            .read_text(encoding="utf-8")
        )

        status = module.p1_nonce_producer_selection_status(markdown, manifest)

        self.assertEqual(status["status"], "p1_nonce_producer_route_selected")
        self.assertEqual(
            status["selected_route"],
            "FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG P1",
        )
        self.assertEqual(status["profile"], "P1 TEE/HSM coordinator")
        self.assertEqual(
            status["replacement_target"],
            "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key",
        )
        self.assertEqual(
            status["required_artifact_slot"],
            "distributed_nonce_producer_artifact_digest",
        )
        self.assertFalse(status["claims_theorem_closure"])
        self.assertIn(
            "shamir_nonce_dkg_transcript_digest",
            status["required_backend_artifacts"],
        )
        self.assertIn("https://arxiv.org/abs/2601.20917", status["sources"])


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
            "This is the closure-run implementation direction. It names the "
            "implementation evidence, proof artifacts, validation artifacts, "
            "and release approvals required for promotion.\n"
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

    def write_validator_10000_standard_verifier_gate(self, root):
        (root / "docs" / "cryptography").mkdir(parents=True, exist_ok=True)
        (root / "tests").mkdir(parents=True, exist_ok=True)
        for relative in [
            "docs/cryptography/validator-10000-standard-verifier-gate.md",
            "tests/validator_10000_standard_verifier_gate.rs",
        ]:
            (root / relative).write_text(
                (ROOT / relative).read_text(encoding="utf-8"),
                encoding="utf-8",
            )

    def write_p1_real_threshold_backend_output_gate(self, root):
        (root / "docs" / "cryptography").mkdir(parents=True, exist_ok=True)
        (root / "src" / "production").mkdir(parents=True, exist_ok=True)
        (root / "tests").mkdir(parents=True, exist_ok=True)
        (root / "tests" / "fixtures").mkdir(parents=True, exist_ok=True)
        rejection_equivalence_path = (
            root / "src" / "production" / "rejection_equivalence.rs"
        )
        rejection_equivalence_path.write_text(
            rejection_equivalence_path.read_text(encoding="utf-8")
            + "pub enum P1RealThresholdVerifierClosureBackendEvidence { "
            + "SimulatedDeterministic, StandardProviderSingleKey, FixtureHarness, RealThresholdMldsa }\n"
            + "pub enum P1RealThresholdVerifierClosureClaimBoundary { "
            + "ProofReviewOnly, ProductionClaim }\n"
            + "pub struct P1RealThresholdBackendEmissionArtifactPackage {\n"
            + "pub backend_source_package_digest: [u8; 32],\n"
            + "pub backend_implementation_digest: [u8; 32],\n"
            + "pub backend_transcript_digest: [u8; 32],\n"
            + "pub artifact_digest: [u8; 32],\n"
            + "}\n"
            + "pub struct P1RealThresholdBackendEmissionOutput<'a> {\n"
            + "pub backend_source_package: &'a [u8],\n"
            + "pub backend_implementation: &'a [u8],\n"
            + "pub backend_transcript: &'a [u8],\n"
            + "pub aggregate_signature: &'a [u8],\n"
            + "}\n"
            + "pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA: &str = "
            + "\"lattice-aggregation:p1-real-threshold-backend-emission-capture:v1\";\n"
            + "pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_REQUEST_SCHEMA: &str = "
            + "\"lattice-aggregation:p1-real-threshold-backend-emission-request:v1\";\n"
            + "pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_EXTERNAL_EVIDENCE: &str = "
            + "\"real_threshold_mldsa_external_capture\";\n"
            + "pub struct P1RealThresholdBackendEmissionCaptureRequestBinding { request_sha256: String }\n"
            + "pub struct P1RealThresholdBackendEmissionCapture;\n"
            + "pub struct P1OwnedRealThresholdBackendEmissionOutput;\n"
            + "impl P1RealThresholdBackendEmissionCapture {\n"
            + "pub fn decode_json(&self) {}\n"
            + "pub fn to_backend_output_material(&self) {}\n"
            + "fn validate_request_binding(&self) {}\n"
            + "fn validate_predecessors(&self) {}\n"
            + "fn validate_expected_digests(&self) {}\n"
            + "}\n"
            + "const REQUEST_BINDING_REASON: &str = \"P1 real-threshold backend emission capture requires request digest binding\";\n"
            + "pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_SCHEMA_FIXTURE_EVIDENCE: &str = "
            + "\"real_threshold_mldsa_capture_schema_fixture\";\n"
            + "pub struct P1RealThresholdBackendEmissionArtifactCertificate;\n"
            + "impl P1RealThresholdBackendEmissionArtifactCertificate {\n"
            + "pub fn backend_source_package_digest(&self) {}\n"
            + "pub fn backend_implementation_digest(&self) {}\n"
            + "pub fn backend_transcript_digest(&self) {}\n"
            + "pub fn to_verifier_closure_package(&self) {}\n"
            + "pub fn claims_real_threshold_backend_implemented(&self) {}\n"
            + "pub fn claims_production_threshold_mldsa_security(&self) {}\n"
            + "pub fn claims_completed_cryptographic_proof(&self) {}\n"
            + "}\n"
            + "pub enum P1RealThresholdBackendEmissionArtifactAssessment { "
            + "BlockedFailClosed, Invalid, ArtifactReady }\n"
            + "pub struct P1RealThresholdVerifierClosurePackage {\n"
            + "pub validator_count: u32,\n"
            + "pub threshold: u32,\n"
            + "pub aggregate_signature_len: usize,\n"
            + "pub backend_evidence_digest: [u8; 32],\n"
            + "pub mutated_message_rejected: bool,\n"
            + "pub mutated_public_key_rejected: bool,\n"
            + "pub mutated_signature_rejected: bool,\n"
            + "}\n"
            + "pub struct P1RealThresholdVerifierClosureCertificate;\n"
            + "impl P1RealThresholdVerifierClosureCertificate {\n"
            + "pub fn mutation_rejection_corpus_complete(&self) {}\n"
            + "pub fn claims_production_threshold_mldsa_security(&self) {}\n"
            + "pub fn claims_cavp_acvts_validation(&self) {}\n"
            + "pub fn claims_fips_validation(&self) {}\n"
            + "pub fn claims_completed_cryptographic_proof(&self) {}\n"
            + "}\n"
            + "pub enum P1RealThresholdVerifierClosureAssessment { "
            + "BlockedFailClosed, Invalid, ClosureReady }\n"
            + "pub fn assess_p1_real_threshold_backend_emission_artifact() {}\n"
            + "pub fn derive_p1_real_threshold_backend_emission_artifact_package() {}\n"
            + "pub fn derive_p1_real_threshold_backend_emission_artifact_package_from_backend_output() {}\n"
            + "pub fn derive_p1_verified_real_threshold_backend_emission_artifact_package() {}\n"
            + "pub fn derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture() {}\n"
            + "pub fn derive_p1_real_threshold_backend_emission_evidence_digest() {}\n"
            + "pub fn derive_p1_real_threshold_backend_emission_artifact_digest() {}\n"
            + "pub fn assess_p1_real_threshold_verifier_closure_contract() {}\n",
            encoding="utf-8",
        )
        test_path = root / "tests" / "production_rejection_equivalence.rs"
        test_path.write_text(
            test_path.read_text(encoding="utf-8")
            + "#[test]\n"
            + "fn real_threshold_backend_output_material_derives_artifact_ready_package() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_output_material_rejects_tuple_digest_mismatch() {}\n"
            + "#[test]\n"
            + "fn verified_real_threshold_backend_output_material_requires_standard_verifier_acceptance() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_schema_fixture_parses_but_remains_blocked_until_actual_capture() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_json_feeds_verified_ingestion_gate_when_actual_evidence_is_present() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_json_requires_standard_verifier_acceptance() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_json_rejects_stale_predecessor_digest() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_json_rejects_expected_artifact_digest_drift() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_json_rejects_missing_predecessor_digests() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_json_rejects_missing_request_binding() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_json_rejects_missing_expected_digests() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_json_rejects_malformed_signature_length() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_json_rejects_unsupported_byte_encoding() {}\n"
            + "#[test]\n"
            + "fn p1_real_threshold_backend_emission_ingestion_accepts_reviewed_external_threshold_output() {}\n"
            + "#[test]\n"
            + "fn p1_real_threshold_backend_emission_ingestion_blocks_simulated_backend() {}\n"
            + "#[test]\n"
            + "fn p1_real_threshold_backend_emission_ingestion_rejects_standard_provider_single_key_output() {}\n"
            + "#[test]\n"
            + "fn p1_real_threshold_backend_emission_ingestion_rejects_stale_threshold_certificate_digest() {}\n"
            + "#[test]\n"
            + "fn p1_real_threshold_backend_emission_ingestion_rejects_unreviewed_external_backend_evidence() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_emission_artifact_fixture_parses_and_remains_blocked_until_actual_backend_evidence_replaces_it() {}\n"
            + "#[test]\n"
            + "fn standard_provider_single_key_emission_fixture_verifies_real_mldsa_but_cannot_replace_threshold_backend_evidence() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_emission_artifact_fixture_package_digest_fails_loudly_on_drift() {}\n"
            + "#[test]\n"
            + "fn p1_real_threshold_verifier_closure_contract_blocks_simulated_backend() {}\n"
            + "#[test]\n"
            + "fn p1_real_threshold_verifier_closure_contract_rejects_standard_provider_single_key_output() {}\n"
            + "#[test]\n"
            + "fn p1_real_threshold_verifier_closure_contract_accepts_reviewed_verifier_tuple() {}\n"
            + "#[test]\n"
            + "fn p1_real_threshold_verifier_closure_contract_rejects_missing_mutation_corpus() {}\n",
            encoding="utf-8",
        )
        (
            root
            / "tests"
            / "fixtures"
            / "p1_real_threshold_backend_emission_capture_schema_fixture.json"
        ).write_text(
            "{\n"
            "  \"schema\": \"lattice-aggregation:p1-real-threshold-backend-emission-capture:v1\",\n"
            "  \"request\": {\n"
            "    \"schema\": \"lattice-aggregation:p1-real-threshold-backend-emission-request:v1\",\n"
            "    \"name\": \"fixture-request\",\n"
            "    \"request_sha256\": \"1212121212121212121212121212121212121212121212121212121212121212\"\n"
            "  },\n"
            "  \"note\": \"not actual real threshold backend emission evidence\"\n"
            "}\n",
            encoding="utf-8",
        )
        (
            root
            / "docs"
            / "cryptography"
            / "validator-10000-standard-verifier-gate.md"
        ).write_text(
            "real threshold backend emission ingestion artifact\n"
            "canonical backend-emission capture schema/importer\n"
            "threshold verifier closure contract\n"
            "real threshold ML-DSA acceptance contract\n"
            "fail-closed\n"
            "not ordinary single-key standard-provider output\n"
            "framework/conformance evidence\n"
            "does not claim production threshold ML-DSA security\n"
            "blocked until a real threshold ML-DSA backend emits a verifier-accepted aggregate signature\n",
            encoding="utf-8",
        )

    def write_p1_distributed_nonce_producer_capture_runner_gate(self, root):
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "script_tests").mkdir(parents=True, exist_ok=True)
        rejection_equivalence_path = (
            root / "src" / "production" / "rejection_equivalence.rs"
        )
        rejection_equivalence_path.write_text(
            rejection_equivalence_path.read_text(encoding="utf-8")
            + "pub enum P1Criterion2DistributedNonceProducerSlotKind { "
            + "DistributedNonceProducer }\n"
            + "pub struct P1Criterion2DistributedNonceProducerSlotTokens {\n"
            + "pub distributed_nonce_producer_artifact: P1Criterion2ProofSlotArtifact,\n"
            + "pub distributed_nonce_producer_artifact_digest: [u8; 32],\n"
            + "}\n"
            + "pub enum P1DistributedNonceProducerEvidence { "
            + "HazmatPrfOutputOracle, CentralizedExpandedSecretKeyHelper, "
            + "FixtureHarness, StandardProviderSingleKey, "
            + "ReviewedP1ShamirNonceDkgTee }\n"
            + "pub enum P1DistributedNonceProducerClaimBoundary { "
            + "ProofReviewOnly, ProductionClaim }\n"
            + "pub struct P1DistributedNonceProducerArtifactPackage {\n"
            + "pub source_reference_digest: [u8; 32],\n"
            + "pub backend_implementation_digest: [u8; 32],\n"
            + "pub coordinator_attestation_digest: [u8; 32],\n"
            + "pub shamir_nonce_dkg_transcript_digest: [u8; 32],\n"
            + "pub pairwise_mask_seed_commitment_digest: [u8; 32],\n"
            + "pub nonce_share_commitment_digest: [u8; 32],\n"
            + "pub abort_accountability_digest: [u8; 32],\n"
            + "}\n"
            + "pub struct Mldsa65DistributedNonceProducerArtifact;\n"
            + "pub struct P1DistributedNonceProducerCapture;\n"
            + "pub struct P1OwnedMldsa65DistributedNonceProducerArtifact;\n"
            + "pub struct P1DistributedNonceProducerArtifactCertificate;\n"
            + "pub struct P1DistributedNonceProducerCaptureRequestBinding { "
            + "pub request_sha256: [u8; 32] }\n"
            + "pub struct P1DistributedNonceProducerCaptureExpectedDigests;\n"
            + "pub enum P1DistributedNonceProducerArtifactAssessment { "
            + "BlockedFailClosed, ArtifactReady }\n"
            + "pub const P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_SCHEMA: &str = "
            + "\"lattice-aggregation:p1-distributed-nonce-producer-capture:v1\";\n"
            + "pub const P1_DISTRIBUTED_NONCE_PRODUCER_REQUEST_SCHEMA: &str = "
            + "\"lattice-aggregation:p1-distributed-nonce-producer-request:v1\";\n"
            + "pub const P1_DISTRIBUTED_NONCE_PRODUCER_CAPTURE_EXTERNAL_EVIDENCE: &str = "
            + "\"p1_shamir_nonce_dkg_tee_external_capture\";\n"
            + "impl P1DistributedNonceProducerArtifactCertificate {\n"
            + "pub fn claims_theorem_closure(&self) {}\n"
            + "pub fn claims_standard_verifier_compatibility_complete(&self) {}\n"
            + "}\n"
            + "pub fn assess_p1_distributed_nonce_producer_artifact() {}\n"
            + "pub fn derive_p1_distributed_nonce_producer_artifact_package() {}\n"
            + "pub fn derive_p1_distributed_nonce_producer_artifact_package_from_backend_output() {}\n"
            + "pub fn derive_p1_distributed_nonce_producer_artifact_package_from_capture() {}\n"
            + "pub fn derive_p1_distributed_nonce_producer_artifact_digest() {}\n",
            encoding="utf-8",
        )
        test_path = root / "tests" / "production_rejection_equivalence.rs"
        test_path.write_text(
            test_path.read_text(encoding="utf-8")
            + "#[test]\n"
            + "fn p1_criterion2_typed_slot_kind_drift_is_rejected() {}\n"
            + "#[test]\n"
            + "fn p1_criterion2_unreviewed_typed_slot_is_rejected() {}\n"
            + "#[test]\n"
            + "fn p1_criterion2_typed_slot_digest_drift_is_rejected() {}\n"
            + "#[test]\n"
            + "fn distributed_nonce_producer_accepts_reviewed_shamir_nonce_dkg_tee_evidence() {}\n"
            + "#[test]\n"
            + "fn distributed_nonce_producer_rejects_hazmat_prf_output_oracle() {}\n"
            + "#[test]\n"
            + "fn distributed_nonce_producer_rejects_centralized_expanded_secret_key_helper() {}\n"
            + "#[test]\n"
            + "fn distributed_nonce_producer_rejects_standard_provider_single_key() {}\n"
            + "#[test]\n"
            + "fn distributed_nonce_producer_capture_json_feeds_artifact_gate_actual_evidence() {}\n",
            encoding="utf-8",
        )
        (root / "scripts" / "build_nonce_producer_request.py").write_text(
            "REQUEST_SCHEMA = \"lattice-aggregation:p1-distributed-nonce-producer-request:v1\"\n"
            "CAPTURE_SCHEMA = \"lattice-aggregation:p1-distributed-nonce-producer-capture:v1\"\n"
            "EXTERNAL_PRODUCER_EVIDENCE = \"p1_shamir_nonce_dkg_tee_external_capture\"\n"
            "REQUEST_STATUS = \"evidence_present_unclosed\"\n"
            "SELECTED_PROFILE = \"ML-DSA-65 coordinator-assisted Shamir nonce DKG P1\"\n"
            "FORBIDDEN_REQUEST_NAME_TOKENS = ('localnet', 'simulation', 'fixture')\n"
            "required_capture = ['shamir_nonce_dkg_transcript']\n"
            "forbidden_capture_sources = ['hazmat PRF-output oracle', 'centralized expanded-secret-key helper']\n"
            "def build_request(): pass\n"
            "def write_artifacts(): pass\n"
            "def validate_digest(value, field): pass\n",
            encoding="utf-8",
        )
        (root / "script_tests" / "test_build_nonce_producer_request.py").write_text(
            "def test_build_request_manifest_writes_external_nonce_producer_challenge_contract(): pass\n"
            "def test_build_request_manifest_rejects_simulation_names_and_bad_digests(): pass\n"
            "lattice-aggregation:p1-distributed-nonce-producer-request:v1\n"
            "p1_shamir_nonce_dkg_tee_external_capture\n"
            "evidence_present_unclosed\n",
            encoding="utf-8",
        )
        (root / "scripts" / "run_nonce_producer_capture.py").write_text(
            "CAPTURE_SCHEMA = \"lattice-aggregation:p1-distributed-nonce-producer-capture:v1\"\n"
            "REQUEST_SCHEMA = \"lattice-aggregation:p1-distributed-nonce-producer-request:v1\"\n"
            "EXTERNAL_PRODUCER_EVIDENCE = \"p1_shamir_nonce_dkg_tee_external_capture\"\n"
            "RUNNER_STATUS = \"evidence_present_unclosed\"\n"
            "CAPTURE_SOURCE_PROFILE_EXTERNAL = \"admissible_external_backend_capture\"\n"
            "CAPTURE_SOURCE_PROFILE_QUARANTINED_REPLAY = \"quarantined_local_schema_replay\"\n"
            "COMMAND_ORIGIN_EXTERNAL = \"outside_repo_executable_or_script\"\n"
            "COMMAND_ORIGIN_REPO_LOCAL = \"repo_local_executable_or_script\"\n"
            "QUARANTINED_LOCAL_REPLAY_TOKENS = ('emit_reviewed_nonce_producer_capture.py',)\n"
            "FORBIDDEN_BACKEND_COMMAND_TOKENS = ('localnet', 'hazmat', 'centralized')\n"
            "def validate_backend_command(command): pass\n"
            "def backend_command_path_candidates(command): pass\n"
            "def backend_command_origin(root, command):\n"
            "    return 'outside_repo_executable_or_script'\n"
            "def validate_capture_source_profile(root, command):\n"
            "    raise ValueError('quarantined local replay')\n"
            "raise ValueError('repo-local backend command')\n"
            "def load_request(path): pass\n"
            "def validate_request_binding(binding): pass\n"
            "def validate_capture_matches_request(capture, request):\n"
            "    raise ValueError('request digest mismatch')\n"
            "def validate_no_unknown_fields(value, allowed_fields, label): pass\n"
            "def validate_digest_object(value, required_fields, label):\n"
            "    raise ValueError('missing {label} digest')\n"
            "def validate_capture_bytes(value, field): pass\n"
            "def parse_capture_json(stdout):\n"
            "    raise ValueError('actual external nonce-producer evidence')\n"
            "def build_report(): pass\n"
            "def write_artifacts(): pass\n",
            encoding="utf-8",
        )
        (root / "docs" / "cryptography" / "unauthorized-aggregate-reduction.md").write_text(
            "# Unauthorized Aggregate Reduction Manifest\n"
            "Status: reduction-case manifest with required proof slots.\n"
            "## Closure Package Framework\n"
            "Protocol event grammar.\n"
            "Deterministic UAR classifier.\n"
            "Base ML-DSA theorem citation slot.\n"
            "Hybrid bound table.\n"
            "External review signoff.\n"
            "UAR-C0 base ML-DSA forgery.\n"
            "UAR-C1 UAR-C2 UAR-C3 UAR-C4 UAR-C5 UAR-C6 UAR-C7 UAR-C8.\n"
            "Complete threshold EUF-CMA reduction claims require the filled "
            "proof, citation, and bound slots in this manifest.\n",
            encoding="utf-8",
        )
        (root / "script_tests" / "test_run_nonce_producer_capture.py").write_text(
            "def test_build_report_invokes_nonce_producer_capture_runner_and_writes_importable_capture_json(): pass\n"
            "def test_build_report_rejects_capture_that_omits_or_stales_request_binding(): pass\n"
            "def test_build_report_rejects_hazmat_localnet_or_fixture_sources(): pass\n"
            "def test_build_report_rejects_local_replay_emitter_as_external_capture(): pass\n"
            "def test_build_report_can_mark_local_replay_emitter_as_quarantined(): pass\n"
            "def test_build_report_rejects_repo_local_wrapper_as_actual_external_backend(): pass\n"
            "def test_build_report_records_outside_repo_command_origin_for_external_backend(): pass\n"
            "backend_command_origin\n"
            "repo-local backend command\n"
            "outside_repo_executable_or_script\n"
            "quarantined_local_schema_replay\n"
            "def test_build_report_rejects_non_importable_capture_shape_before_artifact_write(): pass\n"
            "request_sha256\n"
            "request digest mismatch\n"
            "hazmat-centralized-prf\n"
            "fixture_harness\n",
            encoding="utf-8",
        )
        (root / "scripts" / "run_nonce_producer_handoff_replay.py").write_text(
            "READINESS_SCHEMA = \"lattice-aggregation:p1-nonce-producer-backend-readiness:v1\"\n"
            "HANDOFF_SOURCE_PROFILE_EXTERNAL = \"admissible_external_backend_capture\"\n"
            "HANDOFF_SOURCE_PROFILE_QUARANTINED_REPLAY = \"quarantined_local_schema_replay\"\n"
            "def validate_backend_readiness(backend_readiness, request_report):\n"
            "    raise ValueError('backend readiness is not admissible')\n"
            "backend_readiness = 'backend_readiness'\n"
            "backend_readiness_report = 'backend_readiness_report'\n"
            "reuse_request = 'reuse_request'\n"
            "allow_quarantined_replay = True\n"
            "handoff_source_profile = 'handoff_source_profile'\n"
            "raise ValueError('requires admissible backend readiness')\n"
            "backend_candidate_admissible_pending_capture = 'backend_candidate_admissible_pending_capture'\n",
            encoding="utf-8",
        )
        (
            root / "script_tests" / "test_run_nonce_producer_handoff_replay.py"
        ).write_text(
            "def test_handoff_replay_requires_readiness_for_explicit_backend_command(): pass\n"
            "def test_handoff_replay_rejects_blocked_backend_readiness(): pass\n"
            "def test_handoff_replay_accepts_admissible_readiness_bound_to_reused_request(): pass\n"
            "def test_handoff_replay_rejects_quarantined_local_replay_as_external_backend(): pass\n"
            "quarantined_local_schema_replay\n"
            "admissible_external_backend_capture\n"
            "requires admissible backend readiness\n"
            "backend readiness is not admissible\n",
            encoding="utf-8",
        )
        (
            root / "scripts" / "check_nonce_producer_backend_readiness.py"
        ).write_text(
            "READINESS_SCHEMA = \"lattice-aggregation:p1-nonce-producer-backend-readiness:v1\"\n"
            "ENV_BACKEND_CRATE = \"LATTICE_NONCE_PRODUCER_BACKEND_CRATE\"\n"
            "def quarantine_record(blockers, blocker_records, remediation):\n"
            "    quarantined_sources = blockers\n"
            "    safe_replacement_requirements = remediation\n"
            "    return {'quarantined_sources': quarantined_sources, 'safe_replacement_requirements': safe_replacement_requirements}\n"
            "def detect_capabilities(cargo, source_blob):\n"
            "    return {'centralized_nonce_prf_oracle': True, 'simulated_default_feature': True, 'hazmat_feature': True, 'reviewed_external_capture_contract': False}\n"
            "def detected_blockers(capabilities):\n"
            "    return ['centralized nonce PRF oracle present', 'simulated default feature present', 'hazmat feature present']\n"
            "admissible_for_p1_nonce_handoff = False\n"
            "backend_detected_not_admissible = 'backend_detected_not_admissible'\n"
            "backend_candidate_admissible_pending_capture = 'backend_candidate_admissible_pending_capture'\n",
            encoding="utf-8",
        )
        (
            root / "script_tests" / "test_check_nonce_producer_backend_readiness.py"
        ).write_text(
            "def test_readiness_report_blocks_hazmat_backend_but_records_nonce_capabilities(): pass\n"
            "def test_readiness_report_marks_clean_reviewed_candidate_as_capture_admissible(): pass\n"
            "def test_readiness_report_rejects_missing_backend_crate(): pass\n"
            "backend_detected_not_admissible\n"
            "centralized nonce PRF oracle\n"
            "simulated default feature\n"
            "hazmat feature\n"
            "quarantined_sources\n",
            encoding="utf-8",
        )
        readiness_dir = (
            root / "artifacts" / "nonce-producer-backend-readiness" / "latest"
        )
        readiness_dir.mkdir(parents=True, exist_ok=True)
        (readiness_dir / "manifest.json").write_text(
            "{\n"
            "  \"schema\": \"lattice-aggregation:p1-nonce-producer-backend-readiness:v1\",\n"
            "  \"readiness_status\": \"backend_candidate_admissible_pending_capture\",\n"
            "  \"backend\": {\"package_name\": \"lattice-aggregation\", \"source_tree_sha256\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\n"
            "  \"capabilities\": {\"distributed_nonce_prf_output_share_interface\": true, \"distributed_nonce_prf_output_splitter\": true, \"distributed_nonce_masking_contribution\": true},\n"
            "  \"quarantine\": {\"quarantined_sources\": [], \"safe_replacement_requirements\": []},\n"
            "  \"admissibility\": {\n"
            "    \"admissible_for_p1_nonce_handoff\": true,\n"
            "    \"detected_blockers\": []\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        (
            root / "scripts" / "run_admissible_nonce_producer_capture_attempt.py"
        ).write_text(
            "ATTEMPT_SCHEMA = \"lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1\"\n"
            "ATTEMPT_STATUS_BLOCKED = \"backend_readiness_blocked\"\n"
            "ATTEMPT_STATUS_PROMOTED = \"capture_promoted\"\n"
            "ATTEMPT_STATUS_EXECUTION_FAILED = \"capture_execution_failed\"\n"
            "ATTEMPT_STATUS_VALIDATION_FAILED = \"capture_validation_failed\"\n"
            "REQUEST_PLACEHOLDER = \"{request}\"\n"
            "def substitute_request_placeholder(backend_command, request_path): pass\n"
            "backend_command_executed = False\n"
            "def build_attempt():\n"
            "    reuse_request=True\n",
            encoding="utf-8",
        )
        (
            root
            / "script_tests"
            / "test_run_admissible_nonce_producer_capture_attempt.py"
        ).write_text(
            "def test_attempt_blocks_hazmat_style_backend_before_capture_command_runs(): pass\n"
            "def test_attempt_promotes_capture_only_after_admissible_readiness(): pass\n"
            "def test_attempt_requires_request_placeholder_in_backend_command(): pass\n"
            "def test_attempt_records_execution_failure_after_admissible_readiness(): pass\n"
            "def test_attempt_records_validation_failure_after_admissible_readiness(): pass\n"
            "backend_readiness_blocked\n"
            "capture_promoted\n"
            "capture_execution_failed\n"
            "capture_validation_failed\n"
            "backend_command_executed\n",
            encoding="utf-8",
        )
        attempt_dir = (
            root / "artifacts" / "nonce-producer-capture-attempt" / "latest"
        )
        attempt_dir.mkdir(parents=True, exist_ok=True)
        (attempt_dir / "manifest.json").write_text(
            "{\n"
            "  \"schema\": \"lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1\",\n"
            "  \"attempt_status\": \"capture_promoted\",\n"
            "  \"request_path\": \"handoff/request/request.json\",\n"
            "  \"readiness_schema\": \"lattice-aggregation:p1-nonce-producer-backend-readiness:v1\",\n"
            "  \"backend_command_executed\": true,\n"
            "  \"admissible_for_p1_nonce_handoff\": true,\n"
            "  \"detected_blockers\": [],\n"
            "  \"handoff_source_profile\": \"repo_reference_cli_capture\",\n"
            "  \"handoff_quarantine\": {\"quarantined\": true, \"allowed_use\": \"reference CLI handoff replay ; requires actual backend evidence; requires Criterion 2 closure evidence\"}\n"
            "}\n",
            encoding="utf-8",
        )
        (
            root / "scripts" / "verify_actual_nonce_producer_capture.py"
        ).write_text(
            "GATE_SCHEMA = \"lattice-aggregation:p1-actual-external-nonce-producer-gate:v1\"\n"
            "EXPECTED_SOURCE_PROFILE = \"admissible_external_backend_capture\"\n"
            "STATUS_READY = \"actual_external_capture_ready\"\n"
            "STATUS_MISSING = \"actual_external_capture_missing\"\n"
            "def source_profile_blockers(label, source_profile, quarantine): pass\n"
            "def build_report(root, attempt_path): pass\n"
            "def write_artifacts(report, out_dir): pass\n"
            "--strict\n"
            "repo_reference_cli_capture\n",
            encoding="utf-8",
        )
        (
            root / "script_tests" / "test_verify_actual_nonce_producer_capture.py"
        ).write_text(
            "def test_reference_cli_promoted_capture_is_blocked_from_actual_external_slot(): pass\n"
            "def test_non_quarantined_external_capture_satisfies_actual_external_slot(): pass\n"
            "def test_strict_mode_exits_nonzero_when_actual_external_capture_is_missing(): pass\n"
            "repo_reference_cli_capture\n"
            "admissible_external_backend_capture\n"
            "actual_external_capture_missing\n"
            "actual_external_capture_ready\n",
            encoding="utf-8",
        )
        actual_gate_dir = (
            root / "artifacts" / "nonce-producer-actual-external-gate" / "latest"
        )
        actual_gate_dir.mkdir(parents=True, exist_ok=True)
        (actual_gate_dir / "manifest.json").write_text(
            "{\n"
            "  \"schema\": \"lattice-aggregation:p1-actual-external-nonce-producer-gate:v1\",\n"
            "  \"gate_status\": \"actual_external_capture_missing\",\n"
            "  \"actual_external_capture_ready\": false,\n"
            "  \"attempt_source_profile\": \"repo_reference_cli_capture\",\n"
            "  \"expected_source_profile\": \"admissible_external_backend_capture\",\n"
            "  \"blockers\": [\"reference CLI handoff replay ; requires actual backend evidence\"]\n"
            "}\n",
            encoding="utf-8",
        )
        (
            root / "scripts" / "stage_external_nonce_producer_capture.py"
        ).write_text(
            "ATTEMPT_SCHEMA = \"lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1\"\n"
            "HANDOFF_SCHEMA = \"lattice-aggregation:p1-nonce-producer-executable-handoff-replay:v1\"\n"
            "CAPTURE_FILE_ORIGIN_EXTERNAL = \"outside_repo_capture_file\"\n"
            "CAPTURE_FILE_ORIGIN_REPO_LOCAL = \"repo_local_capture_file\"\n"
            "EXTERNAL_CAPTURE_REVIEW_SCHEMA = \"lattice-aggregation:p1-external-nonce-producer-capture-review:v1\"\n"
            "REVIEW_FILE_ORIGIN_EXTERNAL = \"outside_repo_review_manifest\"\n"
            "reviewed_external_capture_ready\n"
            "BACKEND_EXECUTION_MODE = \"preexisting_external_capture_file\"\n"
            "CAPTURE_SOURCE_PROFILE_EXTERNAL = \"admissible_external_backend_capture\"\n"
            "REQUIRED_REVIEW_CHECKS = ()\n"
            "def require_outside_repo_capture_file(root, capture_file): pass\n"
            "def require_outside_repo_review_manifest(root, review_manifest): pass\n"
            "def validate_readiness(readiness_path, request, request_sha256): pass\n"
            "def validate_external_review_manifest(root, review_manifest, request, request_sha256, readiness, readiness_path, capture, capture_json, capture_file): pass\n"
            "def validate_capture_matches_request(capture, request): pass\n"
            "def build_intake(): pass\n"
            "def write_artifacts(): pass\n"
            "requires Criterion 2 proof review\n",
            encoding="utf-8",
        )
        (
            root / "script_tests" / "test_stage_external_nonce_producer_capture.py"
        ).write_text(
            "def test_outside_repo_capture_file_stages_non_quarantined_attempt_for_actual_gate(): pass\n"
            "def test_repo_local_capture_file_is_rejected_before_promotion(): pass\n"
            "def test_blocked_or_stale_readiness_is_rejected_before_promotion(): pass\n"
            "def test_stale_capture_request_digest_is_rejected_before_promotion(): pass\n"
            "def test_missing_review_manifest_is_rejected_before_promotion(): pass\n"
            "def test_mismatched_review_manifest_is_rejected_before_promotion(): pass\n"
            "actual_external_capture_ready\n"
            "outside_repo_capture_file\n"
            "external review manifest\n"
            "external review check failed\n"
            "repo-local capture file\n"
            "request digest mismatch\n",
            encoding="utf-8",
        )

    def write_p1_real_threshold_backend_actual_capture_runner_gate(self, root):
        self.write_p1_real_threshold_backend_output_gate(root)
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "script_tests").mkdir(parents=True, exist_ok=True)
        rejection_equivalence_path = (
            root / "src" / "production" / "rejection_equivalence.rs"
        )
        rejection_equivalence_path.write_text(
            rejection_equivalence_path.read_text(encoding="utf-8")
            + "pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_ACTUAL_CAPTURE_RUNNER_GATE: &str = "
            + "\"p1_real_threshold_backend_actual_capture_runner_gate\";\n"
            + "pub fn derive_p1_verified_real_threshold_backend_emission_capture() {}\n"
            + "impl P1RealThresholdBackendEmissionCapture {\n"
            + "pub fn to_canonical_json(&self) {}\n"
            + "}\n"
            + "pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_EXTERNAL_EVIDENCE: &str = "
            + "\"real_threshold_mldsa_external_capture\";\n"
            + "fn runner_gate_tokens(assessment: P1RealThresholdBackendEmissionArtifactAssessment) {\n"
            + "assessment.is_artifact_ready();\n"
            + "P1RealThresholdBackendEmissionCaptureBytes::hex;\n"
            + "package.backend_evidence;\n"
            + "derive_p1_real_threshold_backend_source_package_digest();\n"
            + "derive_p1_real_threshold_backend_implementation_digest();\n"
            + "derive_p1_real_threshold_backend_transcript_digest();\n"
            + "}\n",
            encoding="utf-8",
        )
        test_path = root / "tests" / "production_rejection_equivalence.rs"
        test_path.write_text(
            test_path.read_text(encoding="utf-8")
            + "#[test]\n"
            + "fn real_threshold_backend_capture_runner_emits_canonical_importable_capture() {}\n"
            + "#[test]\n"
            + "fn real_threshold_backend_capture_runner_rejects_unready_package_before_external_capture() {}\n",
            encoding="utf-8",
        )
        (root / "scripts" / "run_backend_emission_capture.py").write_text(
            "CAPTURE_SCHEMA = \"lattice-aggregation:p1-real-threshold-backend-emission-capture:v1\"\n"
            "REQUEST_SCHEMA = \"lattice-aggregation:p1-real-threshold-backend-emission-request:v1\"\n"
            "EXTERNAL_BACKEND_EVIDENCE = \"real_threshold_mldsa_external_capture\"\n"
            "SELECTED_PROFILE = \"ML-DSA-65 coordinator-assisted Shamir nonce DKG P1\"\n"
            "RUNNER_STATUS = \"evidence_present_unclosed\"\n"
            "FORBIDDEN_BACKEND_COMMAND_TOKENS = ('localnet', 'validator_localnet', 'run_simulation_benchmarks')\n"
            "request_sha256 = '12' * 32\n"
            "def validate_backend_command(command):\n"
            "    raise ValueError('forbidden backend command')\n"
            "def load_request(path): pass\n"
            "def validate_request_binding(binding): pass\n"
            "def validate_capture_matches_request(capture, request):\n"
            "    raise ValueError('request digest mismatch')\n"
            "def validate_no_unknown_fields(value, allowed_fields, label): pass\n"
            "def validate_digest_object(value, required_fields, label):\n"
            "    raise ValueError('missing {label} digest')\n"
            "def validate_hex_field(value, expected_bytes, field):\n"
            "    raise ValueError('public_key_hex')\n"
            "def validate_capture_bytes(value, field): pass\n"
            "def parse_capture_json(stdout):\n"
            "    raise ValueError('canonical capture JSON actual external real-threshold evidence')\n"
            "def build_report(): pass\n"
            "def write_artifacts(): pass\n",
            encoding="utf-8",
        )
        (root / "script_tests" / "test_run_backend_emission_capture.py").write_text(
            "def test_build_report_invokes_backend_capture_runner_and_writes_importable_capture_json(): pass\n"
            "def test_build_report_rejects_capture_that_omits_or_stales_request_binding(): pass\n"
            "def test_build_report_rejects_deterministic_simulation_or_localnet_capture_source(): pass\n"
            "def test_build_report_rejects_forged_external_json_from_localnet_or_simulation_command(): pass\n"
            "def test_build_report_rejects_non_importable_capture_shape_before_artifact_write(): pass\n"
            "request_sha256\n"
            "request digest mismatch\n"
            "requires request binding\n"
            "validator_localnet\n"
            "run_simulation_benchmarks\n"
            "real_threshold_mldsa_capture_schema_fixture\n",
            encoding="utf-8",
        )

    def write_p1_real_threshold_backend_emission_request_gate(self, root):
        self.write_p1_real_threshold_backend_actual_capture_runner_gate(root)
        (root / "scripts" / "build_backend_emission_request.py").write_text(
            "REQUEST_SCHEMA = \"lattice-aggregation:p1-real-threshold-backend-emission-request:v1\"\n"
            "CAPTURE_SCHEMA = \"lattice-aggregation:p1-real-threshold-backend-emission-capture:v1\"\n"
            "EXTERNAL_BACKEND_EVIDENCE = \"real_threshold_mldsa_external_capture\"\n"
            "REQUEST_STATUS = \"evidence_present_unclosed\"\n"
            "SELECTED_PROFILE = \"ML-DSA-65 coordinator-assisted Shamir nonce DKG P1\"\n"
            "FORBIDDEN_REQUEST_NAME_TOKENS = ('localnet', 'simulation', 'fixture')\n"
            "def build_request(): pass\n"
            "def write_artifacts(): pass\n"
            "def validate_digest(value, field): pass\n"
            "def validate_message_hex(value): pass\n"
            "validator_count = 10000\n"
            "threshold = 6667\n"
            "aggregate_signature_len = 3309\n"
            "required_capture\n"
            "forbidden_capture_sources\n",
            encoding="utf-8",
        )
        (root / "script_tests" / "test_build_backend_emission_request.py").write_text(
            "def test_build_request_manifest_writes_external_backend_challenge_contract(): pass\n"
            "def test_build_request_manifest_rejects_simulation_names_bad_digests_and_bad_message_hex(): pass\n"
            "lattice-aggregation:p1-real-threshold-backend-emission-request:v1\n"
            "real_threshold_mldsa_external_capture\n"
            "evidence_present_unclosed\n",
            encoding="utf-8",
        )
        artifact_dir = root / "artifacts" / "backend-emission-request" / "latest"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "manifest.json").write_text(
            "{\n"
            "  \"capture_schema\": \"lattice-aggregation:p1-real-threshold-backend-emission-capture:v1\",\n"
            "  \"claim_boundary\": \"conformance/proof-review evidence\",\n"
            "  \"request_schema\": \"lattice-aggregation:p1-real-threshold-backend-emission-request:v1\",\n"
            "  \"request_sha256\": \"1111111111111111111111111111111111111111111111111111111111111111\",\n"
            "  \"request_status\": \"evidence_present_unclosed\",\n"
            "  \"schema_version\": 1\n"
            "}\n",
            encoding="utf-8",
        )
        (artifact_dir / "request.json").write_text(
            "{\n"
            "  \"aggregate_signature_len\": 3309,\n"
            "  \"claim_boundary\": \"conformance/proof-review evidence\",\n"
            "  \"message\": {\"encoding\": \"hex\", \"value\": \"74657374\"},\n"
            "  \"name\": \"p1-real-threshold-backend-emission-request-001\",\n"
            "  \"predecessors\": {\n"
            "    \"selected_profile_binding_digest_hex\": \"2222222222222222222222222222222222222222222222222222222222222222\",\n"
            "    \"standard_verifier_compatibility_artifact_digest_hex\": \"3333333333333333333333333333333333333333333333333333333333333333\",\n"
            "    \"threshold_output_certificate_digest_hex\": \"4444444444444444444444444444444444444444444444444444444444444444\"\n"
            "  },\n"
            "  \"request_status\": \"evidence_present_unclosed\",\n"
            "  \"required_capture\": {\n"
            "    \"backend_evidence\": \"real_threshold_mldsa_external_capture\",\n"
            "    \"mutated_message_rejected\": true,\n"
            "    \"mutated_public_key_rejected\": true,\n"
            "    \"mutated_signature_rejected\": true,\n"
            "    \"schema\": \"lattice-aggregation:p1-real-threshold-backend-emission-capture:v1\"\n"
            "  },\n"
            "  \"schema\": \"lattice-aggregation:p1-real-threshold-backend-emission-request:v1\",\n"
            "  \"selected_profile\": \"ML-DSA-65 coordinator-assisted Shamir nonce DKG P1\",\n"
            "  \"threshold\": 6667,\n"
            "  \"validator_count\": 10000\n"
            "}\n",
            encoding="utf-8",
        )

    def write_p1_real_threshold_backend_capture_file_intake_gate(self, root):
        self.write_p1_real_threshold_backend_emission_request_gate(root)
        (root / "scripts" / "stage_external_backend_emission_capture.py").write_text(
            "CAPTURE_FILE_ORIGIN_EXTERNAL = \"outside_repo_capture_file\"\n"
            "REVIEW_FILE_ORIGIN_EXTERNAL = \"outside_repo_review_manifest\"\n"
            "BACKEND_EXECUTION_MODE = \"preexisting_external_capture_file\"\n"
            "EXTERNAL_CAPTURE_REVIEW_SCHEMA = \"lattice-aggregation:p1-external-backend-emission-capture-review:v1\"\n"
            "EXTERNAL_CAPTURE_REVIEW_STATUS = \"reviewed_external_backend_emission_capture_ready\"\n"
            "def validate_external_review_manifest(): pass\n"
            "def validate_capture_matches_request(): pass\n"
            "def write_artifacts(): pass\n"
            "standard_verifier_acceptance_reviewed\n"
            "no_single_key_standard_provider_output\n"
            "repo-local capture file\n"
            "requires Criterion 2 proof review\n",
            encoding="utf-8",
        )
        (
            root / "script_tests" / "test_stage_external_backend_emission_capture.py"
        ).write_text(
            "def test_outside_repo_capture_file_writes_batch8_consumable_backend_capture(): pass\n"
            "def test_repo_local_capture_file_is_rejected_before_artifact_write(): pass\n"
            "def test_missing_or_failed_review_manifest_is_rejected_before_artifact_write(): pass\n"
            "def test_stale_capture_request_digest_is_rejected_before_artifact_write(): pass\n"
            "lattice-aggregation:p1-external-backend-emission-capture-review:v1\n"
            "reviewed_external_backend_emission_capture_ready\n"
            "preexisting_external_capture_file\n"
            "outside_repo_capture_file\n"
            "outside_repo_review_manifest\n"
            "close_candidate\n",
            encoding="utf-8",
        )

    def write_hazmat_threshold_backend_capture_adapter_gate(self, root):
        self.write_p1_real_threshold_backend_emission_request_gate(root)
        (root / "scripts" / "run_hazmat_threshold_backend_capture.py").write_text(
            "RUST_EMITTER_SOURCE = '''\n"
            "backend_external_pure_verifier_accepts\n"
            "repo_pr69_hazmat_provider_accepts\n"
            "derive_mldsa65_session_rejection_predicate_transcript_once_quorum_met\n"
            "attempt_count\n"
            "retry_count\n"
            "per-attempt-bound-predicates\n"
            "rejection_predicate_fields_available\n"
            "attempts\n"
            "mask_seed_digest_hex\n"
            "challenge_digest_hex\n"
            "z_bound_result\n"
            "r0_bound_result\n"
            "ct0_bound_result\n"
            "hint_bound_result\n"
            "accepted_or_rejected\n"
            "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1\n"
            "real_threshold_mldsa_external_capture\n"
            "dytallix-pq-threshold raw-real-mldsa\n"
            "10_000\n"
            "6_667\n"
            "mutated_message_rejected\n"
            "mutated_public_key_rejected\n"
            "mutated_signature_rejected\n"
            "''' \n"
            "def write_emitter_project(): pass\n"
            "def run_capture(): pass\n"
            "def validate_crate_path(): pass\n"
            "LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE\n"
            "--backend-crate\n",
            encoding="utf-8",
        )
        (root / "script_tests" / "test_run_hazmat_threshold_backend_capture.py").write_text(
            "def test_build_emitter_project_requires_explicit_backend_crate_and_repo_root(): pass\n"
            "def test_run_capture_invokes_generated_release_emitter_and_returns_stdout(): pass\n"
            "def test_run_capture_rejects_missing_or_invalid_backend_crate(): pass\n"
            "backend_external_pure_verifier_accepts\n"
            "repo_pr69_hazmat_provider_accepts\n"
            "per-attempt-bound-predicates\n"
            "rejection_predicate_fields_available\n"
            "accepted_or_rejected\n"
            "Lattice Aggregation Current\n",
            encoding="utf-8",
        )

    def write_hazmat_rejection_equivalence_batch_gate(self, root):
        self.write_hazmat_threshold_backend_capture_adapter_gate(root)
        (root / "scripts" / "run_hazmat_rejection_equivalence_batch.py").write_text(
            "RUST_EMITTER_SOURCE = '''\n"
            "derive_mldsa65_centralized_rejection_predicate_transcript_from_expanded_secret_key\n"
            "derive_mldsa65_session_rejection_predicate_transcript_once_quorum_met\n"
            "lattice-aggregation:p1-rejection-equivalence-batch:v1\n"
            "mldsa65-centralized-vs-threshold-rejection-batch\n"
            "derive_mldsa65_centralized_domain_masking_contribution_from_share\n"
            "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key\n"
            "derive_mldsa65_distributed_nonce_prf_masking_contribution_from_share\n"
            "split_mldsa65_distributed_nonce_prf_output\n"
            "centralized-rho-double-prime-kappa\n"
            "distributed-nonce-prf-output-shares\n"
            "aligned_mask_domain\n"
            "distributed_nonce_prf_domain\n"
            "mask_domain\n"
            "threshold_attempts\n"
            "centralized_attempts\n"
            "predicate_mismatches\n"
            "challenge_digest_matches\n"
            "accepted_or_rejected_matches\n"
            "close_candidate\n"
            "claims_rejection_distribution_preservation\n"
            "claims_theorem_closure\n"
            "''' \n"
            "def write_emitter_project(): pass\n"
            "def run_batch(): pass\n"
            "def validate_crate_path(): pass\n"
            "LATTICE_HAZMAT_THRESHOLD_BACKEND_CRATE\n"
            "--backend-crate\n",
            encoding="utf-8",
        )
        (root / "script_tests" / "test_run_hazmat_rejection_equivalence_batch.py").write_text(
            "def test_build_emitter_project_pins_centralized_threshold_comparator_surface(): pass\n"
            "def test_run_batch_invokes_generated_release_emitter_and_returns_stdout(): pass\n"
            "derive_mldsa65_centralized_rejection_predicate_transcript_from_expanded_secret_key\n"
            "mldsa65-centralized-vs-threshold-rejection-batch\n"
            "centralized-rho-double-prime-kappa\n"
            "distributed-nonce-prf-output-shares\n"
            "aligned_mask_domain\n"
            "distributed_nonce_prf_domain\n"
            "threshold_attempts\n"
            "centralized_attempts\n"
            "predicate_mismatches\n"
            "close_candidate\n"
            "claims_rejection_distribution_preservation\n",
            encoding="utf-8",
        )

    def write_p1_external_backend_closure_candidate_gate(self, root):
        self.write_p1_distributed_nonce_producer_capture_runner_gate(root)
        self.write_hazmat_rejection_equivalence_batch_gate(root)
        (
            root
            / "scripts"
            / "build_p1_external_backend_cryptographic_closure_candidate.py"
        ).write_text(
            "SCHEMA = \"lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1\"\n"
            "NAME = \"p1-external-backend-cryptographic-closure-candidate-v1\"\n"
            "NONCE_GATE_SCHEMA = \"lattice-aggregation:p1-actual-external-nonce-producer-gate:v1\"\n"
            "BACKEND_CAPTURE_SCHEMA = \"lattice-aggregation:p1-real-threshold-backend-emission-capture:v1\"\n"
            "BACKEND_EVIDENCE = \"real_threshold_mldsa_external_capture\"\n"
            "REJECTION_BATCH_SCHEMA = \"lattice-aggregation:p1-rejection-equivalence-batch:v1\"\n"
            "REJECTION_BATCH_NONCE_PRODUCER = \"distributed-nonce-prf-output-shares\"\n"
            "STATUS = \"evidence_present_unclosed\"\n"
            "EXPECTED_NONCE_SOURCE_PROFILE = \"admissible_external_backend_capture\"\n"
            "def build_report(): pass\n"
            "def write_artifacts(): pass\n"
            "actual_external_capture_ready\n"
            "predicate_mismatch_count\n"
            "challenge_digest_matches\n"
            "accepted_or_rejected_matches\n"
            "standard_verifier_accepts_threshold_signature\n"
            "repo_provider_accepts_threshold_signature\n"
            "close_candidate\n"
            "claims_theorem_closure\n"
            "claims_rejection_distribution_preservation\n"
            "pending theorem-closure review\n",
            encoding="utf-8",
        )
        (
            root
            / "script_tests"
            / "test_build_p1_external_backend_cryptographic_closure_candidate.py"
        ).write_text(
            "def test_missing_inputs_build_blocked_nonclosure_candidate(): pass\n"
            "def test_complete_evidence_bundle_computes_close_candidate_without_claiming_closure(): pass\n"
            "def test_distribution_comparison_must_also_be_close_candidate(): pass\n"
            "actual external nonce capture readiness required\n"
            "rejection-distribution comparison requires close-candidate evidence\n"
            "claims_theorem_closure\n"
            "claims_rejection_distribution_preservation\n",
            encoding="utf-8",
        )
        artifact_dir = (
            root
            / "artifacts"
            / "p1-external-backend-cryptographic-closure-candidate"
            / "latest"
        )
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "manifest.json").write_text(
            "{\n"
            "  \"schema\": \"lattice-aggregation:p1-external-backend-cryptographic-closure-candidate:v1\",\n"
            "  \"name\": \"p1-external-backend-cryptographic-closure-candidate-v1\",\n"
            "  \"status\": \"evidence_present_unclosed\",\n"
            "  \"close_candidate\": false,\n"
            "  \"claims_theorem_closure\": false,\n"
            "  \"claims_rejection_distribution_preservation\": false,\n"
            "  \"claims_selected_backend_proof_closure\": false,\n"
            "  \"blockers\": [\n"
            "    \"actual external nonce capture readiness required\",\n"
            "    \"real threshold backend emission capture is missing\"\n"
            "  ]\n"
            "}\n",
            encoding="utf-8",
        )

    def write_p1_external_backend_evidence_attempt_gate(self, root):
        self.write_p1_external_backend_closure_candidate_gate(root)
        (
            root / "scripts" / "run_p1_external_backend_evidence_attempt.py"
        ).write_text(
            "SCHEMA = \"lattice-aggregation:p1-external-backend-evidence-attempt:v1\"\n"
            "NAME = \"p1-external-backend-evidence-attempt-v1\"\n"
            "STATUS_READY = \"external_evidence_close_candidate_ready\"\n"
            "STATUS_BLOCKED = \"blocked_external_evidence_missing\"\n"
            "REVIEW_PACKAGE_SCHEMA = \"lattice-aggregation:p1-external-backend-evidence-package-review:v1\"\n"
            "REVIEW_STATUS_READY = \"reviewed_external_backend_evidence_ready\"\n"
            "REVIEW_SOURCE_ORIGIN = \"outside_repo_review_manifest\"\n"
            "FORBIDDEN_SOURCE_MARKERS = (\"hazmat\", \"simulation\", \"localnet\", \"fixture\")\n"
            "def source_marker_blockers(): pass\n"
            "def review_package_checks(): pass\n"
            "def review_package_expected_input_sha256s(): pass\n"
            "def build_report(): pass\n"
            "def write_artifacts(): pass\n"
            "strict_external_nonce_capture_ready\n"
            "real_threshold_emission_present\n"
            "standard_verifier_acceptance_present\n"
            "mutation_rejection_complete\n"
            "rejection_distribution_comparison_present\n"
            "comparison_close_candidate\n"
            "source_exclusion_passed\n"
            "review_package_present\n"
            "review_package_binds_inputs\n"
            "review_package_claim_boundary_passed\n"
            "review_package_source_exclusions_passed\n"
            "review_package_review_digests_present\n"
            "--review-package\n"
            "claims_theorem_closure\n"
            "claims_rejection_distribution_preservation\n"
            "claims_selected_backend_proof_closure\n"
            "pending theorem-closure review\n",
            encoding="utf-8",
        )
        (
            root / "script_tests" / "test_run_p1_external_backend_evidence_attempt.py"
        ).write_text(
            "def test_missing_external_inputs_write_blocked_attempt_and_candidate(): pass\n"
            "def test_complete_external_bundle_writes_ready_candidate_without_closure_claims(): pass\n"
            "def test_complete_external_bundle_without_review_package_remains_blocked(): pass\n"
            "def test_review_package_digest_drift_blocks_close_candidate(): pass\n"
            "def test_rejects_hazmat_or_simulation_source_markers_before_candidate_ready(): pass\n"
            "def test_strict_main_returns_two_until_close_candidate_ready(): pass\n"
            "blocked_external_evidence_missing\n"
            "external_evidence_close_candidate_ready\n"
            "source_exclusion_passed\n"
            "review_package_binds_inputs\n"
            "reviewed external evidence package is missing\n"
            "review package input digest mismatch\n"
            "claims_theorem_closure\n"
            "claims_rejection_distribution_preservation\n",
            encoding="utf-8",
        )
        artifact_dir = (
            root
            / "artifacts"
            / "p1-external-backend-evidence-attempt"
            / "latest"
        )
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "manifest.json").write_text(
            "{\n"
            "  \"schema\": \"lattice-aggregation:p1-external-backend-evidence-attempt:v1\",\n"
            "  \"name\": \"p1-external-backend-evidence-attempt-v1\",\n"
            "  \"attempt_status\": \"external_evidence_close_candidate_ready\",\n"
            "  \"close_candidate\": true,\n"
            "  \"review_package_path\": \"artifacts/p1-external-backend-evidence-package-review/latest/manifest.json\",\n"
            "  \"claims_theorem_closure\": false,\n"
            "  \"claims_rejection_distribution_preservation\": false,\n"
            "  \"claims_selected_backend_proof_closure\": false,\n"
            "  \"checks\": {\n"
            "    \"source_exclusion_passed\": true,\n"
            "    \"review_package_present\": true,\n"
            "    \"review_package_binds_inputs\": true,\n"
            "    \"review_package_claim_boundary_passed\": true,\n"
            "    \"review_package_source_exclusions_passed\": true,\n"
            "    \"review_package_review_digests_present\": true\n"
            "  },\n"
            "  \"blockers\": []\n"
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
            "Status: reduction-case manifest with required proof slots.\n"
            "## Closure Package Framework\n"
            "Protocol event grammar.\n"
            "Deterministic UAR classifier.\n"
            "Base ML-DSA theorem citation slot.\n"
            "Hybrid bound table.\n"
            "External review signoff.\n"
            "UAR-C0 base ML-DSA forgery.\n"
            "UAR-C1 UAR-C2 UAR-C3 UAR-C4 UAR-C5 UAR-C6 UAR-C7 UAR-C8.\n"
            "Threshold EUF-CMA security requires the filled proof, citation, "
            "and bound slots in this manifest.\n",
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
            + "pub struct P1SelectedBackendThresholdOutputArtifactPackage;\n"
            + "pub struct P1SelectedBackendThresholdOutputArtifactCertificate;\n"
            + "pub enum P1SelectedBackendThresholdOutputArtifactAssessment { ArtifactReady }\n"
            + "pub struct P1SelectedBackendProofClosureArtifactPackage {\n"
            + "pub full_kat_validation_artifact_digest: [u8; 32],\n"
            + "pub rejection_distribution_review_digest: [u8; 32],\n"
            + "pub standard_verifier_compatibility_artifact_digest: [u8; 32],\n"
            + "pub standard_verifier_compatibility_artifact: P1StandardVerifierCompatibilityArtifactCertificate,\n"
            + "pub theorem_linkage_artifact_digest: [u8; 32],\n"
            + "}\n"
            + "pub struct P1SelectedBackendProofClosureArtifactCertificate;\n"
            + "impl P1SelectedBackendProofClosureArtifactCertificate {\n"
            + "pub fn full_kat_validation_artifact_digest(&self) {}\n"
            + "pub fn rejection_distribution_review_digest(&self) {}\n"
            + "pub fn threshold_output_certificate_artifact_digest(&self) {}\n"
            + "pub fn real_recomputation_evidence_artifact_digest(&self) {}\n"
            + "pub fn standard_verifier_compatibility_artifact_digest(&self) {}\n"
            + "pub fn theorem_linkage_artifact_digest(&self) {}\n"
            + "pub fn claims_selected_backend_proof_closure(&self) {}\n"
            + "pub fn claims_rejection_distribution_preservation(&self) {}\n"
            + "pub fn claims_cavp_acvts_validation(&self) {}\n"
            + "pub fn claims_fips_validation(&self) {}\n"
            + "}\n"
            + "pub enum P1SelectedBackendProofClosureArtifactAssessment { ArtifactReady }\n"
            + "pub enum P1SelectedBackendProofClosureClaimBoundary { ProofReviewOnly, ProductionClaim }\n"
            + "pub struct P1StandardVerifierCompatibilityArtifactPackage {\n"
            + "pub artifact_digest: [u8; 32],\n"
            + "pub threshold_output_certificate_digest: [u8; 32],\n"
            + "pub provider_identity_digest: [u8; 32],\n"
            + "pub public_key_digest: [u8; 32],\n"
            + "pub message_digest: [u8; 32],\n"
            + "pub accepted_signature_digest: [u8; 32],\n"
            + "pub standard_verifier_bridge_evidence_digest: [u8; 32],\n"
            + "pub real_recomputation_evidence_digest: [u8; 32],\n"
            + "pub transcript_binding_digest: [u8; 32],\n"
            + "}\n"
            + "pub struct P1StandardVerifierCompatibilityArtifactCertificate;\n"
            + "impl P1StandardVerifierCompatibilityArtifactCertificate {\n"
            + "pub fn public_key_digest(&self) {}\n"
            + "pub fn message_digest(&self) {}\n"
            + "pub fn accepted_signature_digest(&self) {}\n"
            + "pub fn provider_identity_digest(&self) {}\n"
            + "pub fn verifier_result(&self) {}\n"
            + "pub fn claims_selected_backend_proof_closure(&self) {}\n"
            + "pub fn claims_standard_verifier_compatibility(&self) {}\n"
            + "pub fn claims_rejection_distribution_preservation(&self) {}\n"
            + "pub fn claims_cavp_acvts_validation(&self) {}\n"
            + "pub fn claims_fips_validation(&self) {}\n"
            + "pub fn claims_completed_cryptographic_proof(&self) {}\n"
            + "}\n"
            + "pub enum P1StandardVerifierCompatibilityArtifactAssessment { ArtifactReady }\n"
            + "pub enum P1StandardVerifierCompatibilityClaimBoundary { ProofReviewOnly, ProductionClaim }\n"
            + "pub enum P1StandardVerifierCompatibilityResult { Accept, Reject }\n"
            + "pub fn p1_standard_verifier_compatibility_accept_token() { P1StandardVerifierCompatibilityResult::Accept; }\n"
            + "pub struct P1RejectionProofArtifacts;\n"
            + "impl P1RejectionProofArtifacts { pub fn transcript_binding_evidence_digest(&self) {} }\n"
            + "pub fn assess_p1_selected_backend_aggregate_artifact() {}\n"
            + "pub fn assess_p1_selected_backend_threshold_output_artifact() {}\n"
            + "pub fn assess_p1_selected_backend_proof_closure_artifact() {}\n"
            + "pub fn assess_p1_standard_verifier_compatibility_artifact() {}\n"
            + "pub fn derive_p1_selected_backend_aggregate_artifact_package() {}\n"
            + "pub fn derive_p1_selected_backend_threshold_output_artifact_package() {}\n"
            + "pub fn derive_p1_selected_backend_proof_closure_artifact_package() {}\n"
            + "pub fn derive_p1_standard_verifier_compatibility_artifact_package() {}\n"
            + "pub fn derive_p1_standard_verifier_compatibility_artifact_digest() {}\n"
            + "pub fn derive_p1_selected_backend_threshold_output_source_digest() {}\n"
            + "pub fn derive_p1_selected_backend_threshold_output_source_package_digest() {}\n"
            + "pub fn derive_p1_selected_backend_aggregate_certificate_digest() {}\n"
            + "pub fn derive_p1_selected_backend_threshold_output_certificate_digest() {}\n"
            + "pub fn derive_p1_real_recomputation_evidence_digest() {}\n"
            + "pub fn derive_p1_selected_backend_transcript_binding_digest() {}\n"
            + "pub fn derive_p1_selected_backend_signer_set_digest() {}\n"
            + "pub fn derive_p1_selected_backend_attempt_binding_digest() {}\n"
            + "pub struct P1Criterion2ProofSlotArtifact {\n"
            + "pub source_evidence_digest: [u8; 32],\n"
            + "pub review_evidence_digest: [u8; 32],\n"
            + "pub artifact_digest: [u8; 32],\n"
            + "}\n"
            + "pub struct P1Criterion2ProofSlotArtifacts {\n"
            + "pub threshold_output_certificate_artifact: P1Criterion2ProofSlotArtifact,\n"
            + "pub real_recomputation_evidence_artifact: P1Criterion2ProofSlotArtifact,\n"
            + "}\n"
            + "pub enum P1Criterion2ProofSlotArtifactKind {\n"
            + "FullKatValidation,\n"
            + "RejectionDistributionReview,\n"
            + "NormBound,\n"
            + "HintBound,\n"
            + "ChallengeBound,\n"
            + "TranscriptBinding,\n"
            + "TheoremLinkage,\n"
            + "ExternalReview,\n"
            + "ThresholdOutputCertificate,\n"
            + "RealRecomputationEvidence,\n"
            + "}\n"
            + "pub fn derive_p1_criterion2_proof_slot_artifact() {}\n"
            + "pub fn derive_p1_criterion2_proof_slot_artifacts() {}\n"
            + "pub fn derive_p1_criterion2_proof_slot_artifact_digest() {}\n"
            + "pub fn validate_p1_criterion2_proof_slot_artifact() {}\n",
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
            + "fn p1_selected_backend_threshold_output_artifact_accepts_bound_source_and_aggregate_certificate() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_threshold_output_artifact_accepts_arbitrary_source_package_bytes() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_threshold_output_artifact_accepts_real_mldsa_package() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_threshold_output_artifact_rejects_stale_source_digest() {}\n"
            + "#[test]\n"
            + "fn p1_standard_verifier_compatibility_artifact_accepts_bound_verifier_payload() {}\n"
            + "#[test]\n"
            + "fn p1_standard_verifier_compatibility_artifact_rejects_failed_standard_verifier() {}\n"
            + "#[test]\n"
            + "fn p1_standard_verifier_compatibility_artifact_rejects_threshold_certificate_mismatch() {}\n"
            + "#[test]\n"
            + "fn p1_standard_verifier_compatibility_artifact_rejects_bridge_digest_as_artifact_digest() {}\n"
            + "#[test]\n"
            + "fn p1_standard_verifier_compatibility_artifact_rejects_recomputation_digest_drift() {}\n"
            + "#[test]\n"
            + "fn p1_standard_verifier_compatibility_artifact_rejects_bridge_digest_drift() {}\n"
            + "#[test]\n"
            + "fn p1_standard_verifier_compatibility_artifact_rejects_production_claim_boundary() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_accepts_reviewed_threshold_output_and_proof_artifacts() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_stale_threshold_certificate_digest() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_stale_proof_transcript_binding() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_missing_validation_artifact() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_missing_distribution_review_artifact() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_missing_standard_verifier_compatibility_artifact() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_stale_standard_verifier_compatibility_artifact_digest() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_missing_theorem_linkage_artifact() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_threshold_slot_source_tamper() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_threshold_slot_review_tamper() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_recomputation_slot_source_tamper() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_recomputation_slot_review_tamper() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_proof_closure_artifact_rejects_production_claim_boundary() {}\n"
            + "#[test]\n"
            + "fn p1_selected_backend_aggregate_artifact_rejects_unreviewed_package() {}\n",
            encoding="utf-8",
        )

    def write_thesis_operating_parameters_formalization(self, root):
        (root / "docs" / "cryptography" / "thesis-operating-parameters.md").write_text(
            "# Thesis and Operating Parameters\n\n"
            "## Thesis Statement\n\n"
            "Thesis id: native-threshold-mldsa65-aggregation-p1.\n"
            "Status: partially_proven with all criteria partially_met.\n"
            "Boundary: research scaffold evidence; requires selected-backend proof closure evidence; "
            "requires production threshold ml-dsa security evidence; requires cavp/acvts validation evidence; "
            "requires fips validation evidence.\n\n"
            "## Operating Parameters\n\n"
            "Profile: ML-DSA-65 coordinator-assisted Shamir nonce DKG P1.\n"
            "Output shape: one standard-sized ML-DSA-65 signature if proven.\n"
            "Feature gate: production-mldsa65-coordinator.\n\n"
            "## Promotion Criteria\n\n"
            "Each of the five criteria stays partially_met until reviewed proof, "
            "backend, validation, and audit artifacts are present.\n\n"
            "## Failure Criteria\n\n"
            "Failure criteria can disprove the native path or force a fallback "
            "architecture evaluation.\n\n"
            "## Fallback Trigger\n\n"
            "Falcon/LaBRADOR-style proof aggregation is evaluate only.\n",
            encoding="utf-8",
        )
        manifest = {
            "schema": "lattice-aggregation.thesis-operating-parameters.v1",
            "thesis_id": "native-threshold-mldsa65-aggregation-p1",
            "status": "research_scaffold_partially_proven",
            "claim_boundary": {
                "scope": "research scaffold evidence",
                "claims_production_threshold_mldsa_security": False,
                "claims_selected_backend_proof_closure": False,
                "claims_standard_verifier_compatibility_complete": False,
                "claims_rejection_distribution_preservation": False,
                "claims_cavp_acvts_validation": False,
                "claims_fips_validation": False,
            },
            "selected_profile": {
                "name": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
                "parameter_set": "ML-DSA-65",
                "feature_gate": "production-mldsa65-coordinator",
                "coordinator_assumption": "TEE/HSM",
                "standard_verifier_compatibility": "target",
                "signature_bytes": 3309,
                "public_key_bytes": 1952,
                "aggregate_output_shape": "one standard-sized ML-DSA-65 signature if proven",
            },
            "operating_parameters": {
                "security_parameter": "lambda",
                "validator_count": "n",
                "threshold": "t",
                "validator_set": "V",
                "threshold_range": "1 <= t <= n",
                "static_corruption_bound": "at most t - 1 validators",
                "retry_domain": "session_id + attempt_id + retry_counter",
                "rejection_sampling_domain": "centralized ML-DSA-65 acceptance distribution",
                "batch4_dependency": "selected-backend proof-closure artifact package gate",
                "boundary": "conformance/proof-review evidence",
            },
            "criterion_promotion": [
                {
                    "id": "aggregate_mask_distribution",
                    "current_status": "partially_met",
                    "promotion_requires": [
                        "selected-backend mask-generation proof artifact",
                        "reviewed Renyi divergence bound for epsilon_mask",
                        "distribution comparison evidence linked from the closure package",
                    ],
                    "failure_criteria": [
                        "aggregate mask distribution is distinguishable beyond the reviewed bound",
                        "selected profile cannot sample masks in the required ML-DSA-65 domain",
                    ],
                },
                {
                    "id": "aggregate_rejection_equivalence",
                    "current_status": "partially_met",
                    "promotion_requires": [
                        "real threshold aggregate recomputation artifacts",
                        "standard-verifier compatibility artifact digest and reviewer sign-off",
                        "accepted-output rejection-distribution review linked to provider evidence",
                    ],
                    "failure_criteria": [
                        "accepted threshold outputs fail standard ML-DSA-65 verification",
                        "aggregate rejection accepts outputs outside centralized ML-DSA-65 predicates",
                    ],
                },
                {
                    "id": "abort_retry_bias",
                    "current_status": "partially_met",
                    "promotion_requires": [
                        "retry transcript domain separation proof",
                        "selective-abort leakage model and bias bound",
                        "accepted-signature distribution analysis across retries",
                    ],
                    "failure_criteria": [
                        "retry timing can bias accepted signatures beyond the reviewed bound",
                        "attempt identifiers or retry counters are not transcript-bound",
                    ],
                },
                {
                    "id": "partial_contribution_soundness",
                    "current_status": "partially_met",
                    "promotion_requires": [
                        "production LocalAccept proof-backed verifier evidence",
                        "VSS/DKG binding and hiding proof artifacts",
                        "context-binding and leakage review for accepted partials",
                    ],
                    "failure_criteria": [
                        "stale or cross-context partial contributions can be accepted",
                        "accepted partial evidence leaks outside the stated model",
                    ],
                },
                {
                    "id": "unauthorized_aggregate_reduction",
                    "current_status": "partially_met",
                    "promotion_requires": [
                        "threshold unforgeability reduction proof",
                        "base ML-DSA theorem dependency and concrete assumption mapping",
                        "simulator and hybrid-bound artifacts with external review",
                    ],
                    "failure_criteria": [
                        "an unauthorized accepting aggregate does not reduce to a named assumption",
                        "the reduction loses the selected profile or validator-set binding",
                    ],
                },
            ],
            "fallback": {
                "architecture": "Falcon/LaBRADOR-style proof aggregation",
                "status": "evaluate_only",
                "claims_selected_backend": False,
                "pivot_requires": [
                    "scheme selection",
                    "benchmarks",
                    "audit review",
                    "consensus-latency analysis",
                    "claim-boundary docs",
                ],
            },
        }
        (root / "docs" / "cryptography" / "thesis-operating-parameters.json").write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )

    def write_criterion3_proof_substance_formalization(self, root):
        for filename in [
            "criterion-3-proof-substance.md",
            "criterion-3-proof-substance.json",
        ]:
            (root / "docs" / "cryptography" / filename).write_text(
                (ROOT / "docs" / "cryptography" / filename).read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )

    def write_criterion2_proof_substance_formalization(self, root):
        (root / "docs" / "cryptography" / "criterion-2-proof-substance.md").write_text(
            "# Criterion 2 Proof Substance\n\n"
            "## Scope and Claim Boundary\n\n"
            "Criterion id: aggregate_rejection_equivalence.\n"
            "Status: formalized_open_proof_payload; report status "
            "criterion2_proof_payload_formalized.\n"
            "Boundary: requires selected-backend proof closure evidence; requires "
            "production threshold ML-DSA security evidence; requires cavp/acvts "
            "validation evidence; requires fips validation evidence; requires "
            "rejection-distribution preservation proof; "
            "requires a completed standard-verifier compatibility proof.\n\n"
            "## Proof Payload Statement\n\n"
            "Accepted selected-backend threshold output must bind the same public "
            "key, message, signer set, attempt, transcript, and accepted "
            "signature through standard verifier and rejection-equivalence "
            "evidence.\n\n"
            "MLDSA65.Verify(pk, m, sigma) = accept.\n"
            "AggregateAccept(...) = true only when standard ML-DSA verification "
            "or checks proven equivalent to it accept the aggregate output.\n\n"
            "## Required Artifact Slots\n\n"
            "standard_verifier_compatibility_artifact_digest, "
            "real_threshold_backend_emission_artifact_digest, "
            "external_backend_cryptographic_closure_candidate, "
            "p1_external_backend_cryptographic_closure_candidate_gate, "
            "p1_external_backend_cryptographic_closure_candidate_package, "
            "P1ExternalBackendCryptographicClosureCandidatePackage, "
            "scripts/build_p1_external_backend_cryptographic_closure_candidate.py, "
            "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json, "
            "close_candidate = true, "
            "actual external nonce capture, "
            "external_backend_evidence_attempt, "
            "p1_external_backend_evidence_attempt_gate, "
            "p1_external_backend_evidence_attempt_artifact, "
            "scripts/run_p1_external_backend_evidence_attempt.py, "
            "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json, "
            "external_evidence_close_candidate_ready, "
            "source_exclusion_passed, "
            "scripts/build_theorem_closure_review_manifest.py, "
            "theorem_closure_review_incomplete, "
            "distributed_nonce_producer_artifact_digest, "
            "p1_criterion2_distributed_nonce_producer_artifact_gate, "
            "hazmat PRF-output oracle, "
            "P1 nonce producer selection, "
            "derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key, "
            "evidence_present_unclosed from "
            "p1_standard_verifier_compatibility_artifact_gate, "
            "p1_real_threshold_backend_output_gate, "
            "evidence_present_unclosed only, "
            "typed Criterion 2 proof-slot artifact packages, "
            "p1_criterion2_proof_slot_artifact_package, "
            "p1_real_threshold_backend_emission_artifact_package, "
            "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json, "
            "tests/fixtures/p1_real_recomputation_artifact_fixture.json, "
            "tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json, "
            "tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json, "
            "tests/fixtures/p1_standard_provider_single_key_emission_artifact_fixture.json, "
            "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json, "
            "tests/fixtures/p1_theorem_linkage_artifact_fixture.json, "
            "artifacts/nonce-producer-handoff/latest/manifest.json, "
            "artifacts/nonce-producer-handoff/latest/capture/capture.json, "
            "artifacts/nonce-producer-backend-readiness/latest/manifest.json, "
            "artifacts/nonce-producer-capture-attempt/latest/manifest.json, "
            "artifacts/nonce-producer-actual-external-gate/latest/manifest.json, "
            "docs/cryptography/p1-nonce-producer-backend-cli-contract.md, "
            "scripts/run_nonce_producer_handoff_replay.py, "
            "scripts/emit_reviewed_nonce_producer_capture.py, "
            "scripts/check_nonce_producer_backend_readiness.py, "
            "scripts/run_admissible_nonce_producer_capture_attempt.py, "
            "scripts/verify_actual_nonce_producer_capture.py, "
            "scripts/stage_external_nonce_producer_capture.py, "
            "backend_candidate_admissible_pending_capture, "
            "capture_promoted, "
            "actual_external_capture_ready, "
            "outside_repo_capture_file, "
            "preexisting_external_capture_file, "
            "outside_repo_review_manifest, "
            "reviewed_external_capture_ready, "
            "capture-attempt runner, "
            "distributed nonce-PRF interfaces, "
            "no detected blockers, "
            "repo_reference_cli_capture, "
            "admissible_external_backend_capture, "
            "reference CLI, "
            "requires actual backend evidence, "
            "checked_nonce_producer_handoff_replay_capture_json_feeds_rust_importer, "
            "checked threshold-output certificate fixture, "
            "checked recomputation fixture, "
            "checked standard-verifier compatibility fixture, "
            "checked real-threshold backend emission ingestion fixture harness, "
            "actual single-key ML-DSA-65 negative-control emission fixture, "
            "reference CLI handoff replay only, "
            "StandardProviderSingleKey, "
            "checked rejection-distribution review fixture, "
            "checked theorem-linkage fixture, "
            "artifacts/p1-theorem-linkage-review/latest/manifest.json, "
            "lattice-aggregation:p1-theorem-linkage-review:v1, "
            "reviewed_theorem_linkage_ready, "
            "requires real threshold backend implementation evidence, "
            "p1_criterion2_threshold_output_certificate_artifact_gate, "
            "p1_criterion2_real_recomputation_evidence_artifact_gate, "
            "theorem_closure_blocker_requests, "
            "p1_theorem_closure_blocker_request_gate, "
            "rejection_distribution_review_digest, "
            "p1_criterion2_rejection_distribution_review_artifact_gate, "
            "theorem_linkage_artifact_digest, "
            "p1_criterion2_theorem_linkage_artifact_gate, "
            "p1_criterion2_full_kat_validation_artifact_gate, "
            "p1_criterion2_norm_bound_artifact_gate, "
            "p1_criterion2_hint_bound_artifact_gate, "
            "p1_criterion2_challenge_bound_artifact_gate, "
            "p1_criterion2_transcript_binding_artifact_gate, "
            "p1_criterion2_external_review_artifact_gate, "
            "conformance/proof-review evidence, "
            "threshold_output_certificate_digest, "
            "real_recomputation_evidence_digest. "
            "ReviewedP1ShamirNonceDkgTee, "
            "fail-closed hazmat PRF-output oracle, centralized expanded-secret-key helper, "
            "fixture harness, and single-key standard-provider producer classes. "
            "Backend-generated reviewed producer artifact still required for "
            "FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG P1.\n\n"
            "## Theorem Links\n\n"
            "Correctness Lemma 7; Correctness Lemma 8; Noise Lemma D; "
            "Noise Lemma F; Noise Lemma H; FST-L5; FST-L7.\n\n"
            "## Promotion Requirements\n\n"
            "Criterion 2 remains partially_met until reviewed proof payloads, "
            "full KAT/validation artifacts, rejection-distribution review, "
            "standard-verifier compatibility review, and theorem-linkage review "
            "are complete.\n\n"
            "## Failure Conditions\n\n"
            "Failure occurs if accepted threshold outputs fail standard ML-DSA-65 "
            "verification or aggregate rejection accepts outputs outside "
            "centralized ML-DSA-65 predicates.\n\n"
            "## Assessment Boundary\n\n"
            "The overall verdict remains partially_proven.\n",
            encoding="utf-8",
        )
        evidence_sources = {
            "threshold_output_certificate_digest": (
                "p1_criterion2_threshold_output_certificate_artifact_gate"
            ),
            "real_recomputation_evidence_digest": (
                "p1_criterion2_real_recomputation_evidence_artifact_gate"
            ),
            "distributed_nonce_producer_artifact_digest": (
                "p1_criterion2_distributed_nonce_producer_artifact_gate"
            ),
            "standard_verifier_compatibility_artifact_digest": (
                "p1_standard_verifier_compatibility_artifact_gate"
            ),
            "real_threshold_backend_emission_artifact_digest": (
                "p1_real_threshold_backend_output_gate"
            ),
            "external_backend_cryptographic_closure_candidate": (
                "p1_external_backend_cryptographic_closure_candidate_gate"
            ),
            "external_backend_evidence_attempt": (
                "p1_external_backend_evidence_attempt_gate"
            ),
            "theorem_closure_blocker_requests": (
                "p1_theorem_closure_blocker_request_gate"
            ),
            "rejection_distribution_review_digest": (
                "p1_criterion2_rejection_distribution_review_artifact_gate"
            ),
            "theorem_linkage_artifact_digest": (
                "p1_criterion2_theorem_linkage_artifact_gate"
            ),
            "full_kat_validation_artifact_digest": (
                "p1_criterion2_full_kat_validation_artifact_gate"
            ),
            "norm_bound_artifact_digest": (
                "p1_criterion2_norm_bound_artifact_gate"
            ),
            "hint_bound_artifact_digest": (
                "p1_criterion2_hint_bound_artifact_gate"
            ),
            "challenge_bound_artifact_digest": (
                "p1_criterion2_challenge_bound_artifact_gate"
            ),
            "transcript_binding_evidence_digest": (
                "p1_criterion2_transcript_binding_artifact_gate"
            ),
            "external_review_digest": (
                "p1_criterion2_external_review_artifact_gate"
            ),
        }
        artifact_packages = {
            "standard_verifier_compatibility_artifact_digest": (
                "p1_standard_verifier_compatibility_artifact_package"
            ),
            "real_threshold_backend_emission_artifact_digest": (
                "p1_real_threshold_backend_emission_artifact_package"
            ),
            "external_backend_cryptographic_closure_candidate": (
                "p1_external_backend_cryptographic_closure_candidate_package"
            ),
            "external_backend_evidence_attempt": (
                "p1_external_backend_evidence_attempt_artifact"
            ),
            "theorem_closure_blocker_requests": (
                "p1_theorem_closure_blocker_request_artifact"
            ),
            **{
                slot: "p1_criterion2_proof_slot_artifact_package"
                for slot in evidence_sources
                if slot
                not in {
                        "standard_verifier_compatibility_artifact_digest",
                        "real_threshold_backend_emission_artifact_digest",
                        "external_backend_cryptographic_closure_candidate",
                        "external_backend_evidence_attempt",
                        "theorem_closure_blocker_requests",
                    }
            },
        }
        certificate_accessors = {
            "threshold_output_certificate_digest": (
                "threshold_output_certificate_artifact_digest"
            ),
            "real_recomputation_evidence_digest": (
                "real_recomputation_evidence_artifact_digest"
            ),
            "distributed_nonce_producer_artifact_digest": (
                "distributed_nonce_producer_artifact_digest"
            ),
            "external_backend_cryptographic_closure_candidate": (
                "candidate_artifact_digest"
            ),
        }
        certificate_surfaces = {
            "threshold_output_certificate_digest": (
                "p1_selected_backend_proof_closure_artifact_certificate"
            ),
            "real_recomputation_evidence_digest": (
                "p1_selected_backend_proof_closure_artifact_certificate"
            ),
            "distributed_nonce_producer_artifact_digest": (
                "p1_selected_backend_proof_closure_artifact_certificate"
            ),
            "external_backend_cryptographic_closure_candidate": (
                "p1_external_backend_cryptographic_closure_candidate_certificate"
            ),
        }
        certificate_evidence_surfaces = {
            "threshold_output_certificate_digest": (
                "P1SelectedBackendProofClosureArtifactCertificate"
            ),
            "real_recomputation_evidence_digest": (
                "P1SelectedBackendProofClosureArtifactCertificate"
            ),
            "distributed_nonce_producer_artifact_digest": (
                "P1SelectedBackendProofClosureArtifactCertificate"
            ),
            "external_backend_cryptographic_closure_candidate": (
                "P1ExternalBackendCryptographicClosureCandidateCertificate"
            ),
        }

        def criterion2_slot(slot):
            if slot not in evidence_sources:
                return {"id": slot, "current_status": "required_unclosed"}
            if slot == "theorem_closure_blocker_requests":
                return {
                    "id": slot,
                    "current_status": "blocker_inputs_required",
                    "evidence_source": evidence_sources[slot],
                    "artifact_package": artifact_packages[slot],
                    "fixture_path": (
                        "artifacts/theorem-closure-blocker-requests/latest/"
                        "manifest.json"
                    ),
                    "schema": (
                        "lattice-aggregation:theorem-closure-blocker-requests:v1"
                    ),
                    "claim_boundary": (
                        "readiness preflight only; pending external proof "
                        "and validation"
                    ),
                }
            return {
                "id": slot,
                "current_status": "evidence_present_unclosed",
                "evidence_source": evidence_sources[slot],
                "artifact_package": artifact_packages[slot],
                "claim_boundary": "conformance/proof-review evidence",
                **(
                    {
                        "backend_capture_schema": (
                            "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
                        ),
                        "backend_capture_importer": (
                            "derive_p1_verified_real_threshold_backend_emission_artifact_package_from_capture"
                        ),
                        "backend_capture_fixture_path": (
                            "tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json"
                        ),
                    }
                    if slot == "real_threshold_backend_emission_artifact_digest"
                    else {}
                ),
                **(
                    {
                        "artifact_schema": (
                            "lattice-aggregation:p1-external-backend-"
                            "cryptographic-closure-candidate:v1"
                        ),
                        "artifact_path": (
                            "artifacts/p1-external-backend-cryptographic-"
                            "closure-candidate/latest/manifest.json"
                        ),
                        "builder": (
                            "scripts/build_p1_external_backend_cryptographic_"
                            "closure_candidate.py"
                        ),
                        "close_candidate": False,
                        "claims_theorem_closure": False,
                        "claims_rejection_distribution_preservation": False,
                        "claims_selected_backend_proof_closure": False,
                    }
                    if slot == "external_backend_cryptographic_closure_candidate"
                    else {}
                ),
                **(
                    {
                        "certificate_surface": (
                            certificate_surfaces[slot]
                        ),
                        "certificate_accessor": certificate_accessors[slot],
                    }
                    if slot in certificate_accessors
                    else {}
                ),
            }

        manifest = {
            "schema": "lattice-aggregation.criterion-2-proof-substance.v1",
            "criterion_id": "aggregate_rejection_equivalence",
            "status": "formalized_open_proof_payload",
            "claim_boundary": {
                "scope": "criterion-2 proof payload only",
                "claims_theorem_closure": False,
                "claims_criterion_met": False,
                "claims_selected_backend_proof_closure": False,
                "claims_standard_verifier_compatibility_complete": False,
                "claims_rejection_distribution_preservation": False,
                "claims_cavp_acvts_validation": False,
                "claims_fips_validation": False,
                "claims_production_threshold_mldsa_security": False,
            },
            "selected_profile": {
                "name": "ML-DSA-65 coordinator-assisted Shamir nonce DKG P1",
                "feature_gate": "production-mldsa65-coordinator",
                "output_target": "one standard-sized ML-DSA-65 signature if proven",
            },
            "proof_payload": {
                "statement": (
                    "accepted selected-backend threshold output binds same "
                    "public key, message, signer set, attempt, transcript, and "
                    "accepted signature through standard verifier and "
                    "rejection-equivalence evidence"
                ),
                "central_verifier_target": "MLDSA65.Verify(pk, m, sigma) = accept",
                "aggregate_accept_target": (
                    "AggregateAccept(...) = true only when standard ML-DSA "
                    "verification, or checks proven equivalent to it, accepts "
                    "the aggregate output"
                ),
                "distribution_target": (
                    "accepted threshold signatures are indistinguishable from "
                    "ordinary ML-DSA-65 signatures under the reviewed "
                    "rejection-distribution argument"
                ),
                "theorem_links": [
                    "Correctness Lemma 7",
                    "Correctness Lemma 8",
                    "Noise Lemma D",
                    "Noise Lemma F",
                    "Noise Lemma H",
                    "FST-L5",
                    "FST-L7",
                ],
                "required_artifact_slots": [
                    criterion2_slot(slot)
                    for slot in [
                        "threshold_output_certificate_digest",
                        "real_recomputation_evidence_digest",
                        "distributed_nonce_producer_artifact_digest",
                        "standard_verifier_compatibility_artifact_digest",
                        "real_threshold_backend_emission_artifact_digest",
                        "external_backend_cryptographic_closure_candidate",
                        "external_backend_evidence_attempt",
                        "theorem_closure_blocker_requests",
                        "rejection_distribution_review_digest",
                        "theorem_linkage_artifact_digest",
                        "full_kat_validation_artifact_digest",
                        "norm_bound_artifact_digest",
                        "hint_bound_artifact_digest",
                        "challenge_bound_artifact_digest",
                        "transcript_binding_evidence_digest",
                        "external_review_digest",
                    ]
                ],
                "durable_certificate_evidence": [
                    {
                        "slot_id": slot,
                        "certificate_surface": (
                            certificate_evidence_surfaces[slot]
                        ),
                        "certificate_accessor": certificate_accessors[slot],
                        "current_status": "evidence_present_unclosed",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    }
                    for slot in certificate_accessors
                ],
                "artifact_fixture_refs": [
                    {
                        "slot_id": "threshold_output_certificate_digest",
                        "fixture_path": (
                            "tests/fixtures/p1_threshold_output_certificate_artifact_fixture.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-threshold-output-certificate-artifact:v1"
                        ),
                        "current_status": "evidence_present_unclosed",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "real_recomputation_evidence_digest",
                        "fixture_path": (
                            "tests/fixtures/p1_real_recomputation_artifact_fixture.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-real-recomputation-artifact:v1"
                        ),
                        "current_status": "evidence_present_unclosed",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": (
                            "standard_verifier_compatibility_artifact_digest"
                        ),
                        "fixture_path": (
                            "tests/fixtures/p1_standard_verifier_compatibility_artifact_fixture.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-standard-verifier-compatibility-artifact:v1"
                        ),
                        "current_status": "evidence_present_unclosed",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": (
                            "real_threshold_backend_emission_artifact_digest"
                        ),
                        "fixture_path": (
                            "tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-real-threshold-backend-emission-artifact:v1"
                        ),
                        "current_status": "evidence_present_unclosed",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": (
                            "real_threshold_backend_emission_artifact_digest"
                        ),
                        "fixture_path": (
                            "tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-real-threshold-backend-emission-capture:v1"
                        ),
                        "current_status": (
                            "checked_capture_schema_fixture_blocked_until_actual_backend_evidence"
                        ),
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "distributed_nonce_producer_artifact_digest",
                        "fixture_path": (
                            "artifacts/nonce-producer-handoff/latest/capture/capture.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-distributed-nonce-producer-capture:v1"
                        ),
                        "current_status": (
                            "checked_handoff_replay_importable_until_actual_backend_evidence"
                        ),
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "distributed_nonce_producer_artifact_digest",
                        "fixture_path": (
                            "artifacts/nonce-producer-backend-readiness/latest/manifest.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-nonce-producer-backend-readiness:v1"
                        ),
                        "current_status": "backend_candidate_admissible_pending_capture",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "distributed_nonce_producer_artifact_digest",
                        "fixture_path": (
                            "artifacts/nonce-producer-capture-attempt/latest/manifest.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-admissible-nonce-producer-capture-attempt:v1"
                        ),
                        "current_status": "capture_promoted",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "distributed_nonce_producer_artifact_digest",
                        "fixture_path": (
                            "artifacts/nonce-producer-actual-external-gate/latest/manifest.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-actual-external-nonce-producer-gate:v1"
                        ),
                        "current_status": "actual_external_capture_ready",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "external_backend_cryptographic_closure_candidate",
                        "fixture_path": (
                            "artifacts/p1-external-backend-cryptographic-"
                            "closure-candidate/latest/manifest.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-external-backend-"
                            "cryptographic-closure-candidate:v1"
                        ),
                        "current_status": "evidence_present_unclosed",
                        "close_candidate": True,
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "external_backend_evidence_attempt",
                        "fixture_path": (
                            "artifacts/p1-external-backend-evidence-attempt/"
                            "latest/manifest.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-external-backend-evidence-"
                            "attempt:v1"
                        ),
                        "current_status": "external_evidence_close_candidate_ready",
                        "close_candidate": True,
                        "source_exclusion_passed": True,
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "theorem_closure_blocker_requests",
                        "fixture_path": (
                            "artifacts/theorem-closure-blocker-requests/latest/"
                            "manifest.json"
                        ),
                        "schema": (
                            "lattice-aggregation:theorem-closure-blocker-"
                            "requests:v1"
                        ),
                        "current_status": "blocker_inputs_required",
                        "claim_boundary": (
                            "readiness preflight only; pending external proof "
                            "and validation"
                        ),
                    },
                    {
                        "slot_id": "theorem_closure_review",
                        "fixture_path": (
                            "artifacts/theorem-closure-review/latest/manifest.json"
                        ),
                        "schema": (
                            "lattice-aggregation:theorem-closure-review:v1"
                        ),
                        "current_status": "theorem_closure_review_incomplete",
                        "proof_payload_reviewed": True,
                        "standard_verifier_compatibility_reviewed": True,
                        "rejection_distribution_preservation_reviewed": False,
                        "full_kat_validation_reviewed": False,
                        "theorem_linkage_reviewed": True,
                        "claim_boundary": (
                            "readiness preflight only; pending theorem-closure review"
                        ),
                    },
                    {
                        "slot_id": "theorem_linkage_artifact_digest",
                        "fixture_path": (
                            "artifacts/p1-theorem-linkage-review/latest/manifest.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-theorem-linkage-review:v1"
                        ),
                        "current_status": "reviewed_theorem_linkage_ready",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "rejection_distribution_review_digest",
                        "fixture_path": (
                            "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-rejection-distribution-review-artifact:v1"
                        ),
                        "current_status": "evidence_present_unclosed",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    },
                    {
                        "slot_id": "theorem_linkage_artifact_digest",
                        "fixture_path": (
                            "tests/fixtures/p1_theorem_linkage_artifact_fixture.json"
                        ),
                        "schema": (
                            "lattice-aggregation:p1-theorem-linkage-artifact:v1"
                        ),
                        "current_status": "evidence_present_unclosed",
                        "claim_boundary": (
                            "conformance/proof-review evidence"
                        ),
                    }
                ],
            },
            "promotion_requires": [
                "reviewed proof payload tying threshold-output, recomputation, bounds, rejection behavior, and standard verification",
                "full KAT/validation artifact package",
                "reviewed rejection-distribution preservation argument",
                "reviewed standard-verifier compatibility argument",
                "reviewed Batch 7 external-backend closure-candidate bundle populated from actual external nonce and real-threshold backend captures",
                "reviewed Batch 8 grouped external-evidence attempt with source_exclusion_passed true and close_candidate true",
                "theorem-linkage review",
            ],
            "failure_conditions": [
                "accepted threshold outputs fail standard ML-DSA-65 verification",
                "aggregate rejection accepts outputs outside centralized ML-DSA-65 predicates",
            ],
            "evidence_refs": [
                "docs/cryptography/rejection-equivalence-evidence.md",
                "docs/cryptography/proof-obligations.md",
                "src/production/rejection_equivalence.rs",
                "tests/production_rejection_equivalence.rs",
                "tests/fixtures/p1_real_recomputation_artifact_fixture.json",
                "tests/fixtures/p1_real_threshold_backend_emission_artifact_fixture.json",
                "tests/fixtures/p1_real_threshold_backend_emission_capture_schema_fixture.json",
                "tests/fixtures/p1_rejection_distribution_review_artifact_fixture.json",
                "tests/fixtures/p1_theorem_linkage_artifact_fixture.json",
                "scripts/build_p1_external_backend_cryptographic_closure_candidate.py",
                "script_tests/test_build_p1_external_backend_cryptographic_closure_candidate.py",
                "artifacts/p1-external-backend-cryptographic-closure-candidate/latest/manifest.json",
                "scripts/run_p1_external_backend_evidence_attempt.py",
                "script_tests/test_run_p1_external_backend_evidence_attempt.py",
                "artifacts/p1-external-backend-evidence-attempt/latest/manifest.json",
            ],
            "assessment": {
                "criterion_status": "partially_met",
                "overall_verdict": "partially_proven",
                "does_not_change_overall_verdict": True,
                "report_status": "criterion2_proof_payload_formalized",
            },
        }
        (root / "docs" / "cryptography" / "criterion-2-proof-substance.json").write_text(
            json.dumps(manifest, indent=2) + "\n",
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
        self.assertTrue(scan["p1_selected_backend_threshold_output_artifact_gate"])
        self.assertTrue(scan["p1_selected_backend_proof_closure_artifact_gate"])
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])
        aggregate_blockers = "\n".join(aggregate["blockers"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertEqual(report["overall_verdict"], "partially_proven")
        self.assertIn("Selected-backend aggregate-output artifact gate", aggregate_evidence)
        self.assertIn("Real standard-provider selected-backend aggregate-output package", aggregate_evidence)
        self.assertIn("stronger than fixture-only bridge confidence", aggregate_evidence)
        self.assertIn("Selected-backend threshold-output artifact gate", aggregate_evidence)
        self.assertIn(
            "stronger than real standard-provider aggregate-output package evidence",
            aggregate_evidence,
        )
        self.assertIn("reviewed source package digest", aggregate_evidence)
        self.assertIn("Selected-backend proof-closure artifact package gate", aggregate_evidence)
        self.assertIn("threshold-output, recomputation, bounds, rejection behavior, and standard verification evidence", aggregate_evidence)
        self.assertIn("full KAT/validation artifact slots", aggregate_evidence)
        self.assertIn("conformance/proof-review", aggregate_evidence)
        self.assertIn("requires selected-backend proof closure evidence", aggregate_evidence)
        self.assertIn("Selected-backend proof-closure artifact package gating", aggregate_blockers)
        self.assertIn("real standard-provider aggregate-output package", aggregate_blockers)
        self.assertIn("selected-backend proof closure", aggregate_blockers)
        self.assertIn("rejection-distribution preservation", aggregate_blockers)
        self.assertIn("standard-verifier compatibility", aggregate_blockers)
        self.assertIn("selected-backend aggregate-output artifact gate", markdown)
        self.assertIn("p1_selected_backend_proof_closure_artifact_gate", str(scan))
        self.assertIn("p1_selected_backend_threshold_output_artifact_gate", str(scan))
        self.assertNotIn("completely_proven", markdown)

    def test_p1_distributed_nonce_producer_capture_runner_updates_report_without_closing_proofs(
        self,
    ):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_p1_distributed_nonce_producer_capture_runner_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_distributed_nonce_producer_artifact_gate"])
        self.assertTrue(scan["p1_distributed_nonce_producer_request_gate"])
        self.assertTrue(scan["p1_distributed_nonce_producer_capture_runner_gate"])
        self.assertTrue(scan["p1_nonce_producer_backend_readiness_gate"])
        self.assertTrue(scan["p1_nonce_producer_capture_attempt_gate"])
        self.assertTrue(scan["p1_actual_external_nonce_producer_gate"])
        self.assertTrue(scan["p1_nonce_producer_external_origin_guard"])
        self.assertTrue(scan["p1_external_nonce_producer_capture_file_intake"])
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])
        aggregate_blockers = "\n".join(aggregate["blockers"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn("repo-generated distributed nonce-producer request", aggregate_evidence)
        self.assertIn("external Shamir nonce-DKG/TEE producer", aggregate_evidence)
        self.assertIn("required capture schema", aggregate_evidence)
        self.assertIn("p1_shamir_nonce_dkg_tee_external_capture", aggregate_evidence)
        self.assertIn("distributed nonce-producer capture runner", aggregate_evidence)
        self.assertIn("exact request schema/name/SHA-256 binding", aggregate_evidence)
        self.assertIn("rejects stale request digests", aggregate_evidence)
        self.assertIn("non-importable capture shapes", aggregate_evidence)
        self.assertIn("quarantined_local_schema_replay", aggregate_evidence)
        self.assertIn("admissible_external_backend_capture", aggregate_evidence)
        self.assertIn("backend readiness gate", aggregate_evidence)
        self.assertIn("backend_candidate_admissible_pending_capture", aggregate_evidence)
        self.assertIn("no detected blockers", aggregate_evidence)
        self.assertIn("readiness quarantine", aggregate_evidence)
        self.assertIn("capture-attempt runner", aggregate_evidence)
        self.assertIn("capture_promoted", aggregate_evidence)
        self.assertIn("repo_reference_cli_capture", aggregate_evidence)
        self.assertIn("reference CLI", aggregate_evidence)
        self.assertIn("actual external nonce-producer capture gate", aggregate_evidence)
        self.assertIn("actual_external_capture_ready", aggregate_evidence)
        self.assertIn("external command-origin guard", aggregate_evidence)
        self.assertIn("repo-local backend command", aggregate_evidence)
        self.assertIn("outside_repo_executable_or_script", aggregate_evidence)
        self.assertIn("external nonce-producer capture-file intake", aggregate_evidence)
        self.assertIn("outside_repo_capture_file", aggregate_evidence)
        self.assertIn("outside_repo_review_manifest", aggregate_evidence)
        self.assertIn("reviewed_external_capture_ready", aggregate_evidence)
        self.assertIn("preexisting_external_capture_file", aggregate_evidence)
        self.assertIn("backend command", aggregate_evidence)
        self.assertIn("distributed nonce-PRF", aggregate_evidence)
        self.assertIn("evidence_present_unclosed", aggregate_evidence)
        self.assertIn("theorem closure", aggregate_evidence)
        self.assertIn("production threshold ML-DSA security", aggregate_evidence)
        self.assertIn("reviewed external Shamir nonce-DKG/TEE producer", aggregate_blockers)
        self.assertIn("backend readiness gate is now admissible", aggregate_blockers)
        self.assertIn("reference CLI capture", aggregate_blockers)
        self.assertIn("external review dossier", aggregate_blockers)
        self.assertIn("requires actual backend evidence", aggregate_blockers)
        self.assertIn("actual external nonce-producer gate", aggregate_blockers)
        self.assertIn("admissible_external_backend_capture", aggregate_blockers)
        self.assertIn("independently installed backend command", aggregate_blockers)
        self.assertIn("outside the repo", aggregate_blockers)
        self.assertIn("external capture-file intake", aggregate_blockers)
        self.assertIn("real threshold backend and proof review evidence", aggregate_blockers)
        self.assertIn("hazmat PRF-output oracle", aggregate_blockers)
        self.assertNotIn("completely_proven", markdown)

    def test_validator_10000_gate_updates_report_without_claiming_equivalence(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_validator_10000_standard_verifier_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["validator_10000_standard_verifier_fail_closed_gate"])
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])
        aggregate_blockers = "\n".join(aggregate["blockers"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn("10,000-validator standard-verifier fail-closed gate", aggregate_evidence)
        self.assertIn("BackendUnavailable", aggregate_evidence)
        self.assertIn("not standard-verifier equivalence", aggregate_evidence)
        self.assertIn(
            "real threshold ML-DSA backend emits a verifier-accepted aggregate signature",
            aggregate_blockers,
        )
        self.assertIn("10,000-validator standard-verifier fail-closed gate", markdown)
        self.assertNotIn("completely_proven", markdown)

    def test_validator_10000_gate_rejects_missing_fail_closed_boundary(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_validator_10000_standard_verifier_gate(root)
            gate_doc = (
                root
                / "docs"
                / "cryptography"
                / "validator-10000-standard-verifier-gate.md"
            )
            gate_doc.write_text(
                gate_doc.read_text(encoding="utf-8").replace(
                    "not standard-verifier equivalence",
                    "standard-verifier equivalence evidence",
                ),
                encoding="utf-8",
            )

            scan = module.scan_documents(root)

        self.assertFalse(scan["validator_10000_standard_verifier_fail_closed_gate"])

    def test_p1_real_threshold_backend_output_gate_updates_report_without_promoting_claim(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_p1_real_threshold_backend_output_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_real_threshold_backend_output_gate"])
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])
        aggregate_blockers = "\n".join(aggregate["blockers"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn(
            "real-threshold backend emission ingestion artifact", aggregate_evidence
        )
        self.assertIn("canonical backend-emission capture", aggregate_evidence)
        self.assertIn("predecessor certificate digests", aggregate_evidence)
        self.assertIn("expected package digest binding", aggregate_evidence)
        self.assertIn("backend source, implementation, and transcript digests", aggregate_evidence)
        self.assertIn("provider-verified backend-output ingestion", aggregate_evidence)
        self.assertIn("rejects deterministic simulation", aggregate_evidence)
        self.assertIn("ordinary single-key standard-provider output", aggregate_evidence)
        self.assertIn("checked capture schema fixture", aggregate_evidence)
        self.assertIn("blocked as FixtureHarness", aggregate_evidence)
        self.assertIn("negative-control emission fixture", aggregate_evidence)
        self.assertIn("rejected as StandardProviderSingleKey", aggregate_evidence)
        self.assertIn("requires production threshold ml-dsa security evidence", aggregate_evidence)
        self.assertIn("strict external backend capture is now admissible", aggregate_blockers)
        self.assertIn("reviewed cryptographic proof", aggregate_blockers)
        self.assertIn("real-threshold backend emission ingestion artifact", markdown)
        self.assertNotIn("completely_proven", markdown)

    def test_p1_real_threshold_backend_actual_capture_runner_updates_report_without_closing_proofs(
        self,
    ):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_p1_real_threshold_backend_actual_capture_runner_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_real_threshold_backend_output_gate"])
        self.assertTrue(scan["p1_real_threshold_backend_actual_capture_runner_gate"])
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])
        aggregate_blockers = "\n".join(aggregate["blockers"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn("Actual real-threshold backend capture runner", aggregate_evidence)
        self.assertIn("RealThresholdMldsa capture material", aggregate_evidence)
        self.assertIn("artifact-ready package", aggregate_evidence)
        self.assertIn("canonical provider-verified importer", aggregate_evidence)
        self.assertIn("deterministic simulation command sources", aggregate_evidence)
        self.assertIn("non-importable capture shapes", aggregate_evidence)
        self.assertIn("evidence_present_unclosed", aggregate_evidence)
        self.assertIn("does not change aggregate_rejection_equivalence", aggregate_evidence)
        self.assertIn("partially_met", aggregate_evidence)
        self.assertIn("partially_proven", aggregate_evidence)
        self.assertIn("rejection-distribution preservation", aggregate_evidence)
        self.assertIn("production threshold ML-DSA security", aggregate_evidence)
        self.assertIn("reviewed cryptographic proof", aggregate_blockers)
        self.assertNotIn("completely_proven", markdown)

    def test_p1_real_threshold_backend_emission_request_updates_report_without_closing_proofs(
        self,
    ):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_p1_real_threshold_backend_emission_request_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_real_threshold_backend_output_gate"])
        self.assertTrue(scan["p1_real_threshold_backend_actual_capture_runner_gate"])
        self.assertTrue(scan["p1_real_threshold_backend_emission_request_gate"])
        self.assertTrue(scan["p1_real_threshold_backend_request_capture_binding_gate"])
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn("repo-generated real-threshold backend emission request", aggregate_evidence)
        self.assertIn("artifacts/backend-emission-request/latest/request.json", aggregate_evidence)
        self.assertIn("request SHA-256", aggregate_evidence)
        self.assertIn("P1 challenge contract", aggregate_evidence)
        self.assertIn("required capture schema", aggregate_evidence)
        self.assertIn("exact repo-generated request digest", aggregate_evidence)
        self.assertIn("rejects stale or missing request bindings", aggregate_evidence)
        self.assertIn("evidence_present_unclosed", aggregate_evidence)
        self.assertIn("does not change aggregate_rejection_equivalence", aggregate_evidence)
        self.assertNotIn("completely_proven", markdown)

    def test_p1_real_threshold_backend_capture_file_intake_updates_report_without_closing_proofs(
        self,
    ):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_p1_real_threshold_backend_capture_file_intake_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_real_threshold_backend_request_capture_binding_gate"])
        self.assertTrue(scan["p1_real_threshold_backend_capture_file_intake_gate"])
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn("backend-emission capture-file intake", aggregate_evidence)
        self.assertIn("scripts/stage_external_backend_emission_capture.py", aggregate_evidence)
        self.assertIn("outside_repo_capture_file", aggregate_evidence)
        self.assertIn("outside_repo_review_manifest", aggregate_evidence)
        self.assertIn("reviewed_external_backend_emission_capture_ready", aggregate_evidence)
        self.assertIn("preexisting_external_capture_file", aggregate_evidence)
        self.assertIn("single-key standard-provider sources", aggregate_evidence)
        self.assertIn("does not close Criterion 2", aggregate_evidence)
        self.assertNotIn("completely_proven", markdown)

    def test_hazmat_threshold_backend_capture_adapter_updates_report_without_closing_proofs(
        self,
    ):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_hazmat_threshold_backend_capture_adapter_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_real_threshold_backend_request_capture_binding_gate"])
        self.assertTrue(scan["p1_hazmat_threshold_backend_capture_adapter_gate"])
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn(
            "repo-owned hazmat threshold backend capture adapter", aggregate_evidence
        )
        self.assertIn("explicit backend crate path", aggregate_evidence)
        self.assertIn("10,000 validators", aggregate_evidence)
        self.assertIn("standard external-message verifier", aggregate_evidence)
        self.assertIn("mutation rejection", aggregate_evidence)
        self.assertIn("evidence_present_unclosed", aggregate_evidence)
        self.assertIn("does not change aggregate_rejection_equivalence", aggregate_evidence)
        self.assertNotIn("completely_proven", markdown)

    def test_hazmat_rejection_predicate_transcript_updates_report_without_closing_proofs(
        self,
    ):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_hazmat_threshold_backend_capture_adapter_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_hazmat_threshold_backend_capture_adapter_gate"])
        self.assertTrue(
            scan["p1_hazmat_rejection_predicate_transcript_gate"]
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn("per-attempt bound-predicate transcript", aggregate_evidence)
        self.assertIn("attempts[]", aggregate_evidence)
        self.assertIn("retry count", aggregate_evidence)
        self.assertIn("per-attempt ML-DSA rejection predicates", aggregate_evidence)
        self.assertIn("z/r0/ct0/hint", aggregate_evidence)
        self.assertIn("batch comparison", aggregate_evidence)
        self.assertIn(
            "does not by itself prove rejection-distribution preservation",
            aggregate_evidence,
        )
        self.assertNotIn("completely_proven", markdown)

    def test_hazmat_rejection_equivalence_batch_updates_report_without_closing_proofs(
        self,
    ):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_hazmat_rejection_equivalence_batch_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_hazmat_rejection_equivalence_batch_gate"])
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn("centralized-vs-threshold", aggregate_evidence)
        self.assertIn("predicate_mismatches", aggregate_evidence)
        self.assertIn("close_candidate", aggregate_evidence)
        self.assertIn("aligned centralized mask domain", aggregate_evidence)
        self.assertIn("zero predicate mismatches", aggregate_evidence)
        self.assertIn("records remaining theorem review requirements", aggregate_evidence)
        self.assertNotIn("completely_proven", markdown)

    def test_external_backend_closure_candidate_updates_report_without_closing_theorem(
        self,
    ):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_p1_external_backend_closure_candidate_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(
            scan["p1_external_backend_cryptographic_closure_candidate_gate"]
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn("Batch 7 external-backend", aggregate_evidence)
        self.assertIn("computed close_candidate manifest", aggregate_evidence)
        self.assertIn("claims_theorem_closure", aggregate_evidence)
        self.assertIn("records remaining theorem review requirements", aggregate_evidence)
        self.assertNotIn("completely_proven", markdown)

    def test_external_backend_evidence_attempt_updates_report_without_closing_theorem(
        self,
    ):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_p1_external_backend_evidence_attempt_gate(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["p1_external_backend_evidence_attempt_gate"])
        self.assertTrue(scan.get("p1_external_backend_evidence_package_review_gate"))
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        aggregate = criteria_by_id["aggregate_rejection_equivalence"]
        aggregate_evidence = "\n".join(aggregate["observed_evidence"])

        self.assertEqual(aggregate["status"], "partially_met")
        self.assertIn("Batch 8 external-backend evidence attempt", aggregate_evidence)
        self.assertIn("Batch 9 reviewed external evidence package", aggregate_evidence)
        self.assertIn("review_package_binds_inputs", aggregate_evidence)
        self.assertIn("source_exclusion_passed", aggregate_evidence)
        self.assertIn("external_evidence_close_candidate_ready", aggregate_evidence)
        self.assertIn("remaining blockers are theorem-review requirements", aggregate_evidence)
        self.assertNotIn("completely_proven", markdown)

    def test_p1_real_threshold_backend_output_gate_rejects_missing_single_key_boundary(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_p1_real_threshold_backend_output_gate(root)
            rejection_equivalence_path = (
                root / "src" / "production" / "rejection_equivalence.rs"
            )
            rejection_equivalence_path.write_text(
                rejection_equivalence_path.read_text(encoding="utf-8").replace(
                    "StandardProviderSingleKey",
                    "StandardProviderEvidence",
                ),
                encoding="utf-8",
            )

            scan = module.scan_documents(root)

        self.assertFalse(scan["p1_real_threshold_backend_output_gate"])

    def test_p1_real_threshold_backend_output_gate_requires_emission_ingestion_artifact(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_p1_real_threshold_backend_output_gate(root)
            rejection_equivalence_path = (
                root / "src" / "production" / "rejection_equivalence.rs"
            )
            rejection_equivalence_path.write_text(
                rejection_equivalence_path.read_text(encoding="utf-8").replace(
                    "P1RealThresholdBackendEmissionArtifactPackage",
                    "P1RealThresholdBackendEmissionPackage",
                ),
                encoding="utf-8",
            )

            scan = module.scan_documents(root)

        self.assertFalse(scan["p1_real_threshold_backend_output_gate"])

    def test_selected_backend_proof_closure_gate_requires_artifact_slot_tokens(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            rejection_equivalence_path = (
                root / "src" / "production" / "rejection_equivalence.rs"
            )
            rejection_equivalence_path.write_text(
                rejection_equivalence_path.read_text(encoding="utf-8").replace(
                    "standard_verifier_compatibility_artifact_digest",
                    "standard_verifier_compatibility_placeholder",
                ),
                encoding="utf-8",
            )

            scan = module.scan_documents(root)

        self.assertTrue(scan["p1_selected_backend_threshold_output_artifact_gate"])
        self.assertFalse(scan["p1_selected_backend_proof_closure_artifact_gate"])

        for token in [
            "threshold_output_certificate_artifact_digest",
            "real_recomputation_evidence_artifact_digest",
        ]:
            with self.subTest(token=token):
                with tempfile.TemporaryDirectory() as tmp:
                    root = pathlib.Path(tmp)
                    self.write_minimal_repo_docs(root)
                    self.write_acceptance_predicate_scaffold(root)
                    self.write_hazmat_standard_verifier_bridge(root)
                    self.write_blocker_evidence_gates(root)
                    self.write_selected_backend_docs(root)
                    self.write_selected_backend_aggregate_artifact_gate(root)
                    rejection_equivalence_path = (
                        root / "src" / "production" / "rejection_equivalence.rs"
                    )
                    rejection_equivalence_path.write_text(
                        rejection_equivalence_path.read_text(
                            encoding="utf-8"
                        ).replace(token, "durable_accessor_placeholder"),
                        encoding="utf-8",
                    )

                    scan = module.scan_documents(root)

                self.assertTrue(
                    scan["p1_selected_backend_threshold_output_artifact_gate"]
                )
                self.assertFalse(
                    scan["p1_selected_backend_proof_closure_artifact_gate"]
                )

    def test_standard_verifier_compatibility_artifact_gate_requires_bound_payload_tokens(self):
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
            self.assertTrue(scan["p1_standard_verifier_compatibility_artifact_gate"])

            rejection_equivalence_path = (
                root / "src" / "production" / "rejection_equivalence.rs"
            )
            rejection_equivalence_path.write_text(
                rejection_equivalence_path.read_text(encoding="utf-8").replace(
                    "public_key_digest",
                    "public_key_placeholder",
                ),
                encoding="utf-8",
            )

            scan = module.scan_documents(root)

        self.assertTrue(scan["p1_selected_backend_proof_closure_artifact_gate"])
        self.assertFalse(scan["p1_standard_verifier_compatibility_artifact_gate"])

    def test_thesis_operating_parameters_update_report_without_closing_proofs(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_thesis_operating_parameters_formalization(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["thesis_operating_parameters_formalized"])
        self.assertEqual(
            report["thesis_operating_parameters"]["status"],
            "formalized_research_boundary",
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")
        self.assertIn("native-threshold-mldsa65-aggregation-p1", markdown)
        self.assertIn("research scaffold evidence", markdown)
        self.assertIn("one standard-sized ML-DSA-65 signature if proven", markdown)
        self.assertIn("Falcon/LaBRADOR-style proof aggregation", markdown)
        self.assertNotIn("completely_proven", markdown)

    def test_thesis_operating_parameters_rejects_selected_fallback_or_claim_drift(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_thesis_operating_parameters_formalization(root)
            manifest_path = (
                root
                / "docs"
                / "cryptography"
                / "thesis-operating-parameters.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["claim_boundary"][
                "claims_selected_backend_proof_closure"
            ] = True
            manifest["fallback"]["status"] = "selected_backend"
            manifest["fallback"]["claims_selected_backend"] = True
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)

        self.assertFalse(scan["thesis_operating_parameters_formalized"])
        self.assertEqual(
            report["thesis_operating_parameters"]["status"],
            "missing_or_incomplete",
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")

    def test_thesis_operating_parameters_rejects_operating_parameter_or_anchor_drift(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_thesis_operating_parameters_formalization(root)
            manifest_path = (
                root
                / "docs"
                / "cryptography"
                / "thesis-operating-parameters.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["operating_parameters"]["retry_domain"] = "retry_counter"
            manifest["criterion_promotion"][0]["promotion_requires"] = [
                "a",
                "b",
                "c",
            ]
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )

            scan = module.scan_documents(root)
            thesis = scan["thesis_operating_parameters"]

        self.assertFalse(scan["thesis_operating_parameters_formalized"])
        self.assertIn("operating_parameters", thesis["missing_evidence"])
        self.assertIn(
            "criterion promotion/failure anchors",
            thesis["missing_evidence"],
        )

    def test_criterion2_proof_substance_updates_report_without_closing_proofs(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_criterion2_proof_substance_formalization(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["criterion2_proof_substance_formalized"])
        self.assertTrue(scan["p1_standard_verifier_compatibility_artifact_gate"])
        self.assertEqual(
            report["criterion2_proof_substance"]["status"],
            "criterion2_proof_payload_formalized",
        )
        self.assertEqual(
            report["criterion2_proof_substance"]["artifact_slot_statuses"][
                "standard_verifier_compatibility_artifact_digest"
            ],
            "evidence_present_unclosed",
        )
        self.assertEqual(
            report["criterion2_proof_substance"]["artifact_slot_statuses"][
                "threshold_output_certificate_digest"
            ],
            "evidence_present_unclosed",
        )
        self.assertEqual(
            report["criterion2_proof_substance"]["artifact_slot_statuses"][
                "real_recomputation_evidence_digest"
            ],
            "evidence_present_unclosed",
        )
        self.assertEqual(
            report["criterion2_proof_substance"]["artifact_slot_statuses"][
                "real_threshold_backend_emission_artifact_digest"
            ],
            "evidence_present_unclosed",
        )
        self.assertEqual(
            report["criterion2_proof_substance"]["artifact_slot_sources"][
                "real_threshold_backend_emission_artifact_digest"
            ],
            "p1_real_threshold_backend_output_gate",
        )
        self.assertEqual(
            report["criterion2_proof_substance"]["artifact_slot_packages"][
                "real_threshold_backend_emission_artifact_digest"
            ],
            "p1_real_threshold_backend_emission_artifact_package",
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        self.assertEqual(
            criteria_by_id["aggregate_rejection_equivalence"]["status"],
            "partially_met",
        )
        self.assertIn("Criterion 2 Proof Substance", markdown)
        self.assertIn("standard_verifier_compatibility_artifact_digest", markdown)
        self.assertIn("threshold_output_certificate_digest", markdown)
        self.assertIn("real_recomputation_evidence_digest", markdown)
        self.assertIn("real_threshold_backend_emission_artifact_digest", markdown)
        self.assertIn("p1_real_threshold_backend_output_gate", markdown)
        self.assertIn("p1_real_threshold_backend_emission_artifact_package", markdown)
        self.assertIn("evidence_present_unclosed", markdown)
        self.assertIn("p1_standard_verifier_compatibility_artifact_gate", markdown)
        self.assertIn(
            "p1_criterion2_threshold_output_certificate_artifact_gate",
            markdown,
        )
        self.assertIn(
            "p1_criterion2_real_recomputation_evidence_artifact_gate",
            markdown,
        )
        self.assertIn("Durable certificate accessors", markdown)
        self.assertIn("Durable certificate evidence", markdown)
        self.assertIn(
            "P1SelectedBackendProofClosureArtifactCertificate::threshold_output_certificate_artifact_digest",
            markdown,
        )
        self.assertIn(
            "P1SelectedBackendProofClosureArtifactCertificate::real_recomputation_evidence_artifact_digest",
            markdown,
        )
        self.assertIn(
            "threshold_output_certificate_artifact_digest",
            markdown,
        )
        self.assertIn(
            "real_recomputation_evidence_artifact_digest",
            markdown,
        )
        self.assertIn("rejection_distribution_review_digest", markdown)
        self.assertIn("theorem_linkage_artifact_digest", markdown)
        self.assertIn("formalized_open_proof_payload", markdown)
        self.assertNotIn("completely_proven", markdown)

    def test_criterion2_proof_substance_rejects_claim_drift_or_missing_slots(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_criterion2_proof_substance_formalization(root)
            manifest_path = (
                root
                / "docs"
                / "cryptography"
                / "criterion-2-proof-substance.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["claim_boundary"]["claims_criterion_met"] = True
            manifest["proof_payload"]["required_artifact_slots"] = [
                slot
                for slot in manifest["proof_payload"]["required_artifact_slots"]
                if slot["id"] != "theorem_linkage_artifact_digest"
            ]
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)

        self.assertFalse(scan["criterion2_proof_substance_formalized"])
        self.assertEqual(
            report["criterion2_proof_substance"]["status"],
            "missing_or_incomplete",
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")

    def test_criterion3_proof_substance_updates_report_without_closing_proofs(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_acceptance_predicate_scaffold(root)
            self.write_hazmat_standard_verifier_bridge(root)
            self.write_blocker_evidence_gates(root)
            self.write_selected_backend_docs(root)
            self.write_selected_backend_aggregate_artifact_gate(root)
            self.write_criterion3_proof_substance_formalization(root)

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)
            markdown = module.render_markdown(report)

        self.assertTrue(scan["criterion3_proof_substance_formalized"])
        self.assertEqual(
            report["criterion3_proof_substance"]["status"],
            "criterion3_proof_payload_formalized",
        )
        self.assertEqual(
            report["criterion3_proof_substance"]["artifact_slot_statuses"][
                "retry_domain_separation_proof_digest"
            ],
            "required_unclosed",
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")
        criteria_by_id = {criterion["id"]: criterion for criterion in report["criteria"]}
        self.assertEqual(
            criteria_by_id["abort_retry_bias"]["status"],
            "partially_met",
        )
        self.assertIn("Criterion 3 Proof Substance", markdown)
        self.assertIn("abort_retry_bias", markdown)
        self.assertIn("retry_domain_separation_proof_digest", markdown)
        self.assertIn(
            "p1_criterion3_retry_domain_separation_artifact_gate",
            markdown,
        )
        self.assertIn("Noise Lemma G", markdown)
        self.assertIn("formalized_open_proof_payload", markdown)
        self.assertNotIn("completely_proven", markdown)

    def test_criterion3_proof_substance_rejects_claim_drift_or_missing_slots(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_minimal_repo_docs(root)
            self.write_criterion3_proof_substance_formalization(root)
            manifest_path = (
                root
                / "docs"
                / "cryptography"
                / "criterion-3-proof-substance.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["claim_boundary"]["claims_criterion_met"] = True
            manifest["proof_payload"]["required_artifact_slots"] = [
                slot
                for slot in manifest["proof_payload"]["required_artifact_slots"]
                if slot["id"] != "timeout_retry_policy_digest"
            ]
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )

            scan = module.scan_documents(root)
            report = module.build_report(root, run_commands=False)

        self.assertFalse(scan["criterion3_proof_substance_formalized"])
        self.assertEqual(
            report["criterion3_proof_substance"]["status"],
            "missing_or_incomplete",
        )
        self.assertEqual(report["overall_verdict"], "partially_proven")

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
                "requires proof artifacts",
                "\n".join(criterion["blockers"]),
            )
        self.assertIn("## Selected Backend Direction", markdown)
        self.assertIn("ML-DSA-65 coordinator-assisted Shamir nonce DKG P1", markdown)
        self.assertIn("closure-run implementation", markdown)
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

    def test_selected_backend_report_omits_old_nonclosure_blocker_language(self):
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

        combined = json.dumps(report, sort_keys=True).lower() + "\n" + markdown.lower()
        old_nonclosure_phrases = [
            "not proof " + "closure",
            "not production " + "approval",
            "theorem " + "closure",
            "research scaffold " + "only",
        ]
        for phrase in old_nonclosure_phrases:
            self.assertNotIn(phrase, combined)

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
            dashboard = json.loads(
                (out_dir / "closure-dashboard.json").read_text(encoding="utf-8")
            )
            dashboard_markdown = (out_dir / "closure-dashboard.md").read_text(
                encoding="utf-8"
            )

        self.assertIn("testing_statement", report)
        self.assertEqual(report["overall_verdict"], "partially_proven")
        self.assertEqual(report["claim_boundary"], "closure-run implementation track")
        self.assertEqual(report["commands"], [])
        self.assertEqual(saved["overall_verdict"], "partially_proven")
        self.assertEqual(
            dashboard["schema"],
            "lattice-aggregation.current-closure-dashboard.v1",
        )
        self.assertEqual(dashboard["overall_verdict"], "partially_proven")
        self.assertEqual(dashboard["claim_boundary"], "closure-run implementation track")
        self.assertIn("criteria", dashboard)
        self.assertIn("proof_artifact_slots", dashboard)
        self.assertIn("external_capture_provenance_requirements", dashboard)
        self.assertIn("pending theorem-closure review", dashboard["non_closure_guards"])
        self.assertIn("# Lattice Aggregation Hypothesis Assessment", markdown)
        self.assertIn("partially_proven", markdown)
        self.assertIn("# Current Closure Dashboard", dashboard_markdown)
        self.assertIn("partially_proven", dashboard_markdown)

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
