import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_internal_theorem_closure_criterion_inputs.py"
BUNDLE_SCRIPT = ROOT / "scripts" / "build_internal_theorem_closure_bundle.py"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InternalTheoremClosureCriterionInputTests(unittest.TestCase):
    def test_current_repository_builds_fail_closed_inputs_for_all_criteria(self):
        module = load_module(
            SCRIPT, "build_internal_theorem_closure_criterion_inputs"
        )

        report = module.build_report(ROOT, generated_at="2026-07-18T00:00:00Z")
        manifest = report["manifest"]

        self.assertEqual(manifest["schema"], module.SCHEMA)
        self.assertEqual(
            manifest["input_status"], "fail_closed_requirements_generated"
        )
        self.assertFalse(any(manifest["claim_flags"].values()))
        self.assertEqual(
            sorted(report["criteria"]),
            sorted(criterion_id for criterion_id, _ in module.BUNDLE.CRITERIA),
        )
        for criterion_id, document in report["criteria"].items():
            self.assertEqual(
                document["schema"], module.BUNDLE.CRITERION_EVIDENCE_SCHEMA
            )
            self.assertEqual(document["criterion_id"], criterion_id)
            self.assertEqual(document["evidence_status"], "required_unclosed")
            self.assertEqual(document["assessment_status"], "unproven")
            self.assertFalse(document["claim_flags"]["claims_criterion_met"])
            self.assertFalse(
                document["claim_flags"]["claims_substantive_proof_complete"]
            )
            self.assertTrue(document["blockers"])
            self.assertTrue(
                all(value is False for value in document["substantive_checks"].values())
            )
            for group in module.BUNDLE.REQUIRED_ARTIFACT_GROUPS:
                self.assertTrue(document[group])
                self.assertTrue(
                    all(
                        (ROOT / record["path"]).is_file()
                        and record["sha256"] == module.BUNDLE.sha256_path(ROOT / record["path"])
                        for record in document[group]
                    )
                )

    def test_generated_inputs_are_consumed_by_bundle_as_unproven_not_missing(self):
        inputs = load_module(
            SCRIPT, "build_internal_theorem_closure_criterion_inputs_for_bundle"
        )
        bundle = load_module(BUNDLE_SCRIPT, "build_internal_theorem_closure_bundle")

        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "evidence"
            inputs.write_artifacts(
                inputs.build_report(ROOT, generated_at="2026-07-18T00:00:00Z"),
                out,
            )
            report = bundle.build_report(
                ROOT,
                evidence_dir=out,
                generated_at="2026-07-18T00:00:00Z",
            )

        manifest = report["manifest"]
        self.assertEqual(manifest["bundle_status"], bundle.BLOCKED_STATUS)
        self.assertFalse(manifest["internal_closure_candidate"])
        for criterion in manifest["criteria"]:
            self.assertTrue(criterion["evidence_input"]["present"])
            self.assertNotIn("criterion evidence manifest is missing", criterion["blockers"])
            self.assertIn(
                "criterion evidence declares unresolved blockers",
                criterion["blockers"],
            )
            self.assertIn(
                "criterion-specific substantive checks are incomplete",
                criterion["blockers"],
            )

    def test_cli_writes_inputs_manifest_summary_and_checksums(self):
        module = load_module(
            SCRIPT, "build_internal_theorem_closure_criterion_inputs_cli"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "inputs"
            code = module.main(["--root", str(ROOT), "--out", str(out)])

            self.assertEqual(code, 0)
            self.assertTrue((out / "manifest.json").is_file())
            self.assertTrue((out / "summary.md").is_file())
            self.assertTrue((out / "SHA256SUMS").is_file())
            for criterion_id, _ in module.BUNDLE.CRITERIA:
                path = out / f"{criterion_id}.json"
                self.assertTrue(path.is_file())
                document = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(document["criterion_id"], criterion_id)


if __name__ == "__main__":
    unittest.main()
