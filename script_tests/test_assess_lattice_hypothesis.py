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
        (root / "docs" / "benchmarks" / "release-readiness-checklist.md").write_text(
            "Add standard-verifier bridge tests for accepted aggregate "
            "signatures.\n",
            encoding="utf-8",
        )

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
