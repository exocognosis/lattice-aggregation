import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_internal_theorem_closure_bundle.py"
CAPTURE_TEST_SCRIPT = (
    ROOT / "script_tests" / "test_validate_internal_aggregation_campaign_capture.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location(
        "build_internal_theorem_closure_bundle", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_capture_fixtures():
    spec = importlib.util.spec_from_file_location(
        "internal_campaign_capture_fixtures_for_bundle", CAPTURE_TEST_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class InternalTheoremClosureBundleTests(unittest.TestCase):
    def test_current_repository_builds_blocked_five_criterion_bundle(self):
        module = load_module()

        report = module.build_report(ROOT, generated_at="2026-07-18T00:00:00Z")
        manifest = report["manifest"]

        self.assertEqual(manifest["schema"], module.BUNDLE_SCHEMA)
        self.assertEqual(manifest["bundle_status"], module.BLOCKED_STATUS)
        self.assertFalse(manifest["internal_closure_candidate"])
        self.assertEqual(manifest["claim_boundary"], module.CLAIM_BOUNDARY)
        self.assertFalse(any(manifest["claim_flags"].values()))
        self.assertEqual(
            [item["criterion_id"] for item in manifest["criteria"]],
            [item[0] for item in module.CRITERIA],
        )
        self.assertTrue(
            all(
                item["bundle_evidence_status"] == module.CRITERION_BLOCKED_STATUS
                and not item["internal_closure_ready"]
                for item in manifest["criteria"]
            )
        )
        self.assertFalse(manifest["campaign"]["ready"])
        self.assertEqual(
            manifest["independent_review"]["status"],
            "pending_independent_cryptographic_review",
        )
        self.assertFalse(manifest["independent_review"]["completed"])

    def test_criterion_can_pass_only_with_verified_substantive_evidence(self):
        module = load_module()
        digest = "ab" * 32
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            artifact_groups = {}
            for group in module.REQUIRED_ARTIFACT_GROUPS:
                path = root / "evidence" / f"{group}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(group, encoding="utf-8")
                artifact_groups[group] = [
                    {"path": path.relative_to(root).as_posix(), "sha256": module.sha256_path(path)}
                ]

            evidence_digests = {}
            for group, records in artifact_groups.items():
                observed = [
                    module.verify_declared_artifact(item, root) for item in records
                ]
                evidence_digests[module.ARTIFACT_GROUP_DIGEST_KEYS[group]] = (
                    module.sha256_text(
                        module.canonical_json(
                            [
                                {"path": item["path"], "sha256": item["observed_sha256"]}
                                for item in observed
                            ]
                        )
                    )
                )

            criterion_id = module.CRITERIA[0][0]
            evidence = {
                "schema": module.CRITERION_EVIDENCE_SCHEMA,
                "schema_version": 1,
                "criterion_id": criterion_id,
                "evidence_class": "substantive_proof_and_execution_evidence",
                "evidence_status": module.CRITERION_READY_STATUS,
                "assessment_status": "met",
                "readiness_only": False,
                "claim_boundary": module.CLAIM_BOUNDARY,
                "protocol_profile": module.PROTOCOL_PROFILE,
                "substantive_checks": {
                    key: True for key in module.CRITERION_SUBSTANTIVE_CHECKS[criterion_id]
                },
                "evidence_digests": evidence_digests,
                **artifact_groups,
                "reproducibility": {
                    "commands": [
                        {
                            "command": ["cargo", "test"],
                            "exit_code": 0,
                            "passed": True,
                            "output_sha256": digest,
                        }
                    ]
                },
                "provenance": {
                    "source_class": "production_real_distributed_threshold",
                    "source_path": "src",
                    "real_distributed_threshold_core_verified": True,
                    "simulation": False,
                    "hazmat": False,
                    "quarantined": False,
                    "git_commit": "1" * 40,
                    "worktree_clean": True,
                    "source_tree_sha256": digest,
                },
                "internal_review": {
                    "completed": True,
                    "reviewed_at": "2026-07-18T00:00:00Z",
                    "reviewer_identity_sha256": digest,
                    "review_digest_sha256": digest,
                    "independent_review_completed": False,
                },
                "independent_review": {
                    "required": True,
                    "completed": False,
                    "status": "pending_independent_cryptographic_review",
                },
                "claim_flags": {
                    "claims_criterion_met": True,
                    "claims_substantive_proof_complete": True,
                    "claims_independent_review_complete": False,
                    "claims_external_validation_complete": False,
                },
                "blockers": [],
            }
            evidence_path = root / "criterion.json"
            write_json(evidence_path, evidence)
            record = module.build_criterion_record(
                root=root,
                criterion_id=criterion_id,
                statement=module.CRITERIA[0][1],
                assessment={"criteria": [{"id": criterion_id, "status": "partially_met"}]},
                evidence_path=evidence_path,
                source_tree_sha256=digest,
                provenance={"commit": "1" * 40, "worktree_clean": True},
            )

        self.assertTrue(record["internal_closure_ready"])
        self.assertEqual(record["bundle_evidence_status"], module.CRITERION_READY_STATUS)
        self.assertEqual(record["legacy_assessment_status"], "partially_met")
        self.assertEqual(record["blockers"], [])
        self.assertFalse(any(record["claim_flags"].values()))

    def test_campaign_binding_requires_digest_bound_strong_profile(self):
        module = load_module()
        fixtures = load_capture_fixtures()
        validator = fixtures.load_module(
            fixtures.VALIDATE_SCRIPT, "campaign_validator_for_bundle_test"
        )
        request_builder = fixtures.build_module()
        verifier = fixtures.ReviewedAuthorizationVerifier()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            request = request_builder.build_request(
                "theorem-closure-internal-001",
                authorization_verifier_profile=fixtures.verifier_profile(verifier),
            )["request"]
            records = fixtures.evidence_bundle(root, validator.REQUIRED_EVIDENCE_ROLES)
            capture = fixtures.capture_for(request, records)
            fixtures.install_valid_authorization(
                root, request, records, capture, validator
            )
            validation = validator.validate_campaign(
                request, capture, root, authorization_verifier=verifier
            )
            request_path = root / "request.json"
            capture_path = root / "capture.json"
            validation_path = root / "manifest.json"
            write_json(request_path, request)
            write_json(capture_path, capture)
            write_json(validation_path, validation)

            campaign = module.validate_campaign_binding(
                request_path,
                capture_path,
                validation_path,
                root,
                authorization_verifier=verifier,
            )
            validation["capture_sha256"] = "ef" * 32
            write_json(validation_path, validation)
            tampered = module.validate_campaign_binding(
                request_path,
                capture_path,
                validation_path,
                root,
                authorization_verifier=verifier,
            )

        self.assertTrue(campaign["ready"])
        self.assertFalse(tampered["ready"])
        self.assertFalse(tampered["checks"]["capture_digest_bound"])
        self.assertFalse(tampered["checks"]["deterministic_validator_revalidation"])

    def test_strict_cli_exits_two_for_current_incomplete_repository(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--root",
                    str(ROOT),
                    "--out",
                    str(pathlib.Path(temp_dir) / "bundle"),
                    "--require-internal-closure",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("internal theorem closure remains blocked", result.stderr)


if __name__ == "__main__":
    unittest.main()
