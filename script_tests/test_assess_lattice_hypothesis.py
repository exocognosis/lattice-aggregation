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
                "claim_boundary": "conformance/proof-review evidence only",
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
                "claim_boundary": "conformance/proof-review evidence only",
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
                "claim_boundary": "conformance/proof-review evidence only",
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
                "claim_boundary": "conformance/proof-review evidence only",
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
                "claim_boundary": "conformance/proof-review evidence only",
            },
            status["artifact_fixture_refs"],
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
            + "pub const P1_REAL_THRESHOLD_BACKEND_EMISSION_CAPTURE_EXTERNAL_EVIDENCE: &str = "
            + "\"real_threshold_mldsa_external_capture\";\n"
            + "pub struct P1RealThresholdBackendEmissionCapture;\n"
            + "pub struct P1OwnedRealThresholdBackendEmissionOutput;\n"
            + "impl P1RealThresholdBackendEmissionCapture {\n"
            + "pub fn decode_json(&self) {}\n"
            + "pub fn to_backend_output_material(&self) {}\n"
            + "fn validate_predecessors(&self) {}\n"
            + "fn validate_expected_digests(&self) {}\n"
            + "}\n"
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
            "framework/conformance evidence only\n"
            "does not claim production threshold ML-DSA security\n"
            "blocked until a real threshold ML-DSA backend emits a verifier-accepted aggregate signature\n",
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
            "EXTERNAL_BACKEND_EVIDENCE = \"real_threshold_mldsa_external_capture\"\n"
            "SELECTED_PROFILE = \"ML-DSA-65 coordinator-assisted Shamir nonce DKG P1\"\n"
            "RUNNER_STATUS = \"evidence_present_unclosed\"\n"
            "FORBIDDEN_BACKEND_COMMAND_TOKENS = ('localnet', 'validator_localnet', 'run_simulation_benchmarks')\n"
            "def validate_backend_command(command):\n"
            "    raise ValueError('forbidden backend command')\n"
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
            "def test_build_report_rejects_deterministic_simulation_or_localnet_capture_source(): pass\n"
            "def test_build_report_rejects_forged_external_json_from_localnet_or_simulation_command(): pass\n"
            "def test_build_report_rejects_non_importable_capture_shape_before_artifact_write(): pass\n"
            "validator_localnet\n"
            "run_simulation_benchmarks\n"
            "real_threshold_mldsa_capture_schema_fixture\n",
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
            "Boundary: research scaffold only; not selected-backend proof closure; "
            "not production threshold ML-DSA security; not CAVP/ACVTS validation; "
            "not FIPS validation.\n\n"
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
                "scope": "research scaffold only",
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
                "boundary": "conformance/proof-review evidence only",
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
            "Boundary: not selected-backend proof closure; not production "
            "threshold ML-DSA security; not CAVP/ACVTS validation; not FIPS "
            "validation; not rejection-distribution preservation; "
            "not a completed standard-verifier compatibility proof.\n\n"
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
            "checked threshold-output certificate fixture, "
            "checked recomputation fixture, "
            "checked standard-verifier compatibility fixture, "
            "checked real-threshold backend emission ingestion fixture harness, "
            "actual single-key ML-DSA-65 negative-control emission fixture, "
            "blocked from artifact readiness, "
            "StandardProviderSingleKey, "
            "checked rejection-distribution review fixture, "
            "checked theorem-linkage fixture, "
            "not a real threshold backend implementation, "
            "p1_criterion2_threshold_output_certificate_artifact_gate, "
            "p1_criterion2_real_recomputation_evidence_artifact_gate, "
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
            "conformance/proof-review evidence only, "
            "threshold_output_certificate_digest, "
            "real_recomputation_evidence_digest.\n\n"
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
            "standard_verifier_compatibility_artifact_digest": (
                "p1_standard_verifier_compatibility_artifact_gate"
            ),
            "real_threshold_backend_emission_artifact_digest": (
                "p1_real_threshold_backend_output_gate"
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
            **{
                slot: "p1_criterion2_proof_slot_artifact_package"
                for slot in evidence_sources
                if slot
                not in {
                    "standard_verifier_compatibility_artifact_digest",
                    "real_threshold_backend_emission_artifact_digest",
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
        }
        manifest = {
            "schema": "lattice-aggregation.criterion-2-proof-substance.v1",
            "criterion_id": "aggregate_rejection_equivalence",
            "status": "formalized_open_proof_payload",
            "claim_boundary": {
                "scope": "criterion-2 proof payload only",
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
                    (
                        {
                            "id": slot,
                            "current_status": "evidence_present_unclosed",
                            "evidence_source": evidence_sources[slot],
                            "artifact_package": artifact_packages[slot],
                            "claim_boundary": (
                                "conformance/proof-review evidence only"
                            ),
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
                                if slot
                                == "real_threshold_backend_emission_artifact_digest"
                                else {}
                            ),
                            **(
                                {
                                    "certificate_surface": (
                                        "p1_selected_backend_proof_closure_artifact_certificate"
                                    ),
                                    "certificate_accessor": (
                                        certificate_accessors[slot]
                                    ),
                                }
                                if slot in certificate_accessors
                                else {}
                            ),
                        }
                        if slot in evidence_sources
                        else {"id": slot, "current_status": "required_unclosed"}
                    )
                    for slot in [
                        "threshold_output_certificate_digest",
                        "real_recomputation_evidence_digest",
                        "standard_verifier_compatibility_artifact_digest",
                        "real_threshold_backend_emission_artifact_digest",
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
                            "P1SelectedBackendProofClosureArtifactCertificate"
                        ),
                        "certificate_accessor": certificate_accessors[slot],
                        "current_status": "evidence_present_unclosed",
                        "claim_boundary": (
                            "conformance/proof-review evidence only"
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
                            "conformance/proof-review evidence only"
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
                            "conformance/proof-review evidence only"
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
                            "conformance/proof-review evidence only"
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
                            "conformance/proof-review evidence only"
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
                            "conformance/proof-review evidence only"
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
                            "conformance/proof-review evidence only"
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
                            "conformance/proof-review evidence only"
                        ),
                    }
                ],
            },
            "promotion_requires": [
                "reviewed proof payload tying threshold-output, recomputation, bounds, rejection behavior, and standard verification",
                "full KAT/validation artifact package",
                "reviewed rejection-distribution preservation argument",
                "reviewed standard-verifier compatibility argument",
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
        self.assertIn("not selected-backend proof closure", aggregate_evidence)
        self.assertIn("Selected-backend proof-closure artifact package gating", aggregate_blockers)
        self.assertIn("real standard-provider aggregate-output package", aggregate_blockers)
        self.assertIn("selected-backend proof closure", aggregate_blockers)
        self.assertIn("rejection-distribution preservation", aggregate_blockers)
        self.assertIn("standard-verifier compatibility", aggregate_blockers)
        self.assertIn("selected-backend aggregate-output artifact gate", markdown)
        self.assertIn("p1_selected_backend_proof_closure_artifact_gate", str(scan))
        self.assertIn("p1_selected_backend_threshold_output_artifact_gate", str(scan))
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
        self.assertIn("not production threshold ML-DSA security", aggregate_evidence)
        self.assertIn("real threshold backend emissions", aggregate_blockers)
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
        self.assertIn("research scaffold only", markdown)
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
