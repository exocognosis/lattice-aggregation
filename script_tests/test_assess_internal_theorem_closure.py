"""Closure-assessor regressions discovered by the script_tests CI target."""

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "tests/test_assess_internal_theorem_closure.py"
SPEC = importlib.util.spec_from_file_location(
    "closure_assessor_regressions_discovered_by_script_tests", SOURCE
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# unittest discovery recognizes imported TestCase classes in module globals.
InternalTheoremClosureTests = MODULE.InternalTheoremClosureTests


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeterministicClosurePipelineTests(unittest.TestCase):
    def test_reviewed_callback_and_real_builders_reach_internal_candidate(self):
        repo = Path(__file__).resolve().parents[1]
        assessor = MODULE.ASSESSOR
        bundle_builder = load_script(
            "bundle_builder_for_end_to_end_assessor_test",
            repo / "scripts/build_internal_theorem_closure_bundle.py",
        )
        campaign_builder = load_script(
            "campaign_builder_for_end_to_end_assessor_test",
            repo / "scripts/build_internal_aggregation_campaign_request.py",
        )
        campaign_validator = load_script(
            "campaign_validator_for_end_to_end_assessor_test",
            repo / "scripts/validate_internal_aggregation_campaign_capture.py",
        )
        fixtures = load_script(
            "campaign_fixtures_for_end_to_end_assessor_test",
            repo / "script_tests/test_validate_internal_aggregation_campaign_capture.py",
        )
        verifier = fixtures.ReviewedAuthorizationVerifier()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gitignore").write_text("artifacts/\n", encoding="utf-8")
            source = root / "src/protocol.txt"
            source.parent.mkdir(parents=True)
            source.write_text("deterministic threshold protocol source\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "closure-test@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Closure Test"], cwd=root, check=True
            )
            subprocess.run(["git", "add", ".gitignore", "src/protocol.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)

            campaign_dir = root / "artifacts/internal-aggregation-campaign/latest"
            campaign_dir.mkdir(parents=True)
            request = campaign_builder.build_request(
                "theorem-closure-internal-001",
                authorization_verifier_profile=fixtures.verifier_profile(verifier),
            )["request"]
            records = fixtures.evidence_bundle(
                campaign_dir, campaign_validator.REQUIRED_EVIDENCE_ROLES
            )
            capture = fixtures.capture_for(request, records)
            fixtures.install_valid_authorization(
                campaign_dir, request, records, capture, campaign_validator
            )
            validation = campaign_validator.validate_campaign(
                request,
                capture,
                campaign_dir,
                authorization_verifier=verifier,
            )
            request_path = campaign_dir / "request.json"
            capture_path = campaign_dir / "capture.json"
            validation_path = campaign_dir / "manifest.json"
            for path, value in (
                (request_path, request),
                (capture_path, capture),
                (validation_path, validation),
            ):
                path.write_text(
                    bundle_builder.canonical_json(value), encoding="utf-8"
                )

            source_inventory = bundle_builder.build_inventory([source], root)
            commit = bundle_builder.run_git(root, ["rev-parse", "HEAD"])
            criterion_dir = root / "artifacts/internal-theorem-closure-evidence/latest"
            criterion_dir.mkdir(parents=True)
            criterion_paths = {}
            for criterion_id, _statement in bundle_builder.CRITERIA:
                groups = {}
                evidence_digests = {}
                for group in bundle_builder.REQUIRED_ARTIFACT_GROUPS:
                    artifact = criterion_dir / f"{criterion_id}-{group}.txt"
                    artifact.write_text(f"{criterion_id}:{group}\n", encoding="utf-8")
                    record = {
                        "path": artifact.relative_to(root).as_posix(),
                        "sha256": bundle_builder.sha256_path(artifact),
                    }
                    groups[group] = [record]
                    verified = bundle_builder.verify_declared_artifact(record, root)
                    evidence_digests[
                        bundle_builder.ARTIFACT_GROUP_DIGEST_KEYS[group]
                    ] = bundle_builder.sha256_text(
                        bundle_builder.canonical_json(
                            [
                                {
                                    "path": verified["path"],
                                    "sha256": verified["observed_sha256"],
                                }
                            ]
                        )
                    )
                evidence = {
                    "schema": bundle_builder.CRITERION_EVIDENCE_SCHEMA,
                    "schema_version": 1,
                    "criterion_id": criterion_id,
                    "evidence_class": "substantive_proof_and_execution_evidence",
                    "evidence_status": bundle_builder.CRITERION_READY_STATUS,
                    "assessment_status": "met",
                    "readiness_only": False,
                    "claim_boundary": bundle_builder.CLAIM_BOUNDARY,
                    "protocol_profile": copy.deepcopy(bundle_builder.PROTOCOL_PROFILE),
                    "substantive_checks": {
                        key: True
                        for key in bundle_builder.CRITERION_SUBSTANTIVE_CHECKS[
                            criterion_id
                        ]
                    },
                    "evidence_digests": evidence_digests,
                    **groups,
                    "reproducibility": {
                        "commands": [
                            {
                                "command": ["deterministic-fixture-check"],
                                "exit_code": 0,
                                "passed": True,
                                "output_sha256": bundle_builder.sha256_text("passed"),
                            }
                        ]
                    },
                    "provenance": {
                        "source_class": "production_real_distributed_threshold",
                        "source_path": "src/protocol.txt",
                        "real_distributed_threshold_core_verified": True,
                        "simulation": False,
                        "hazmat": False,
                        "quarantined": False,
                        "git_commit": commit,
                        "worktree_clean": True,
                        "source_tree_sha256": source_inventory["tree_sha256"],
                    },
                    "internal_review": {
                        "completed": True,
                        "reviewed_at": "2026-07-18T00:00:00Z",
                        "reviewer_identity_sha256": bundle_builder.sha256_text("reviewer"),
                        "review_digest_sha256": bundle_builder.sha256_text("review"),
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
                path = criterion_dir / f"{criterion_id}.json"
                path.write_text(bundle_builder.canonical_json(evidence), encoding="utf-8")
                criterion_paths[criterion_id] = path

            legacy = root / "artifacts/legacy.json"
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text("{}\n", encoding="utf-8")
            anchor = root / "artifacts/evidence-anchor.txt"
            anchor.write_text("bound evidence\n", encoding="utf-8")
            bundle_report = bundle_builder.build_report(
                root,
                assessment_path=legacy,
                readiness_path=legacy,
                theorem_review_path=legacy,
                campaign_request_path=request_path,
                campaign_capture_path=capture_path,
                campaign_validation_path=validation_path,
                evidence_dir=criterion_dir,
                source_paths=[source],
                artifact_paths=[anchor],
                provenance_record=bundle_builder.collect_provenance(root),
                toolchain_record={"all_identified": True, "commands": [], "lockfiles": []},
                authorization_verifier=verifier,
                generated_at="2026-07-18T00:00:00Z",
            )
            self.assertTrue(bundle_report["manifest"]["internal_closure_candidate"])
            bundle_path = root / "artifacts/internal-theorem-closure-bundle/latest/manifest.json"
            bundle_path.parent.mkdir(parents=True)
            bundle_path.write_text(
                bundle_builder.canonical_json(bundle_report["manifest"]), encoding="utf-8"
            )

            result = assessor.build_report(
                root,
                criterion_paths=criterion_paths,
                campaign_request_path=request_path,
                campaign_capture_path=capture_path,
                campaign_validation_path=validation_path,
                bundle_path=bundle_path,
                authorization_verifier=verifier,
            )["manifest"]

        self.assertTrue(result["internally_closed_pending_independent_review"])
        self.assertEqual(result["blockers"], [])
