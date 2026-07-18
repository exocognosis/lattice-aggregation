#!/usr/bin/env python3
"""Focused fail-closed tests for assess_internal_theorem_closure.py."""

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts/assess_internal_theorem_closure.py"
SPEC = importlib.util.spec_from_file_location("internal_closure", SCRIPT)
ASSESSOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSESSOR)
DIGEST = "a" * 64
COMMIT = "b" * 40


def pending_review():
    return {
        "required": True,
        "completed": False,
        "status": ASSESSOR.PENDING_REVIEW_STATUS,
    }


def claim_flags(required_claim):
    return {
        required_claim: True,
        "claims_independent_review_complete": False,
        "claims_external_validation_complete": False,
    }


def criterion_manifest(criterion_id):
    flags = claim_flags("claims_criterion_met")
    flags["claims_substantive_proof_complete"] = True
    return {
        "schema": ASSESSOR.CRITERION_SCHEMA,
        "schema_version": 1,
        "criterion_id": criterion_id,
        "claim_boundary": ASSESSOR.BUNDLE_CLAIM_BOUNDARY,
        "evidence_status": ASSESSOR.CRITERION_READY_STATUS,
        "evidence_class": ASSESSOR.EVIDENCE_CLASS,
        "assessment_status": "met",
        "readiness_only": False,
        "protocol_profile": copy.deepcopy(ASSESSOR.PROTOCOL_PROFILE),
        "blockers": [],
        "substantive_checks": {
            check: True for check in ASSESSOR.CRITERIA[criterion_id]
        },
        "evidence_digests": {
            digest: DIGEST for digest in ASSESSOR.CRITERION_DIGESTS
        },
        "claim_flags": flags,
        "provenance": {
            "source_class": ASSESSOR.SAFE_SOURCE_CLASS,
            "source_path": "artifacts/production-threshold-run/capture.json",
            "real_distributed_threshold_core_verified": True,
            "simulation": False,
            "hazmat": False,
            "quarantined": False,
            "worktree_clean": True,
            "git_commit": COMMIT,
        },
        "reproducibility": {
            "commands": [
                {
                    "command": ["cargo", "test", "--all-features"],
                    "exit_code": 0,
                    "passed": True,
                    "output_sha256": DIGEST,
                }
            ]
        },
        "internal_review": {
            "completed": True,
            "reviewed_at": "2026-07-18T00:00:00Z",
            "reviewer_identity_sha256": DIGEST,
            "review_digest_sha256": DIGEST,
            "independent_review_completed": False,
        },
        "independent_review": pending_review(),
    }


def campaign_validation_manifest():
    return {
        "schema": ASSESSOR.CAMPAIGN_VALIDATION_SCHEMA,
        "campaign_id": "internal-closure-campaign-001",
        "campaign_status": ASSESSOR.CAMPAIGN_READY_STATUS,
        "internal_campaign_evidence_ready": True,
        "theorem_status": "unclosed_pending_proof_and_independent_review",
        "claims_theorem_closure": False,
        "claims_fips_validation": False,
        "request_sha256": DIGEST,
        "capture_sha256": DIGEST,
        "evidence_bundle_binding_sha256": DIGEST,
        "evidence_bindings": {"transcript_bundle": DIGEST},
        "preregistered_case_count": 24,
        "validated_execution_count": 24,
        "blockers": [],
    }


def bundle_manifest(criterion_paths, campaign_path, campaign):
    criterion_records = []
    for criterion_id, path in criterion_paths.items():
        criterion_records.append(
            {
                "criterion_id": criterion_id,
                "assessment_status": "met",
                "declared_evidence_status": ASSESSOR.CRITERION_READY_STATUS,
                "bundle_evidence_status": ASSESSOR.CRITERION_READY_STATUS,
                "internal_closure_ready": True,
                "claim_flags": {
                    key: False for key in ASSESSOR.BUNDLE_PUBLIC_CLAIMS
                },
                "checks": {"verified": True},
                "internal_review": {
                    "valid": True,
                    "record": {
                        "completed": True,
                        "independent_review_completed": False,
                    },
                },
                "evidence_input": {
                    "present": True,
                    "sha256": ASSESSOR.sha256_path(path),
                },
                "blockers": [],
            }
        )
    return {
        "schema": ASSESSOR.BUNDLE_SCHEMA,
        "schema_version": 1,
        "bundle_status": ASSESSOR.STATUS_CLOSED,
        "internal_closure_candidate": True,
        "claim_boundary": ASSESSOR.BUNDLE_CLAIM_BOUNDARY,
        "protocol_profile": copy.deepcopy(ASSESSOR.PROTOCOL_PROFILE),
        "claim_flags": {key: False for key in ASSESSOR.BUNDLE_PUBLIC_CLAIMS},
        "internal_review": {
            "required": True,
            "completed": True,
            "status": "complete",
        },
        "independent_review": pending_review(),
        "criteria": criterion_records,
        "checks": {key: True for key in ASSESSOR.BUNDLE_CHECKS},
        "global_blockers": [],
        "source_inventory": {"file_count": 1, "tree_sha256": DIGEST},
        "artifact_inventory": {"file_count": 1, "tree_sha256": DIGEST},
        "provenance": {
            "repository_available": True,
            "worktree_clean": True,
            "commit": COMMIT,
            "changed_paths": [],
        },
        "campaign": {
            "ready": True,
            "blockers": [],
            "request_sha256": campaign["request_sha256"],
            "capture_sha256": campaign["capture_sha256"],
            "evidence_bundle_binding_sha256": campaign[
                "evidence_bundle_binding_sha256"
            ],
        },
        "inputs": {
            "campaign_validation": {
                "present": True,
                "sha256": ASSESSOR.sha256_path(campaign_path),
            }
        },
        "bundle_digest_sha256": DIGEST,
    }


class AssessmentFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.criteria = {
            criterion_id: criterion_manifest(criterion_id)
            for criterion_id in ASSESSOR.CRITERIA
        }
        self.campaign_validation = campaign_validation_manifest()

    def write(self):
        paths = {}
        for criterion_id, document in self.criteria.items():
            path = self.root / f"{criterion_id}.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            paths[criterion_id] = path
        campaign = self.root / "campaign-validation.json"
        campaign.write_text(json.dumps(self.campaign_validation), encoding="utf-8")
        bundle = self.root / "bundle.json"
        bundle.write_text(
            json.dumps(bundle_manifest(paths, campaign, self.campaign_validation)),
            encoding="utf-8",
        )
        return paths, campaign, bundle

    def assess(self):
        paths, campaign, bundle = self.write()
        return ASSESSOR.build_report(
            self.root,
            criterion_paths=paths,
            campaign_validation_path=campaign,
            bundle_path=bundle,
        )["manifest"]


class InternalTheoremClosureTests(unittest.TestCase):
    def test_hand_authored_ready_manifests_cannot_promote(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = AssessmentFixture(directory).assess()

        self.assertFalse(manifest["internally_closed_pending_independent_review"])
        self.assertEqual(manifest["assessment_status"], ASSESSOR.STATUS_BLOCKED)
        self.assertFalse(manifest["claim_flags"]["claims_internal_theorem_closure"])
        self.assertFalse(manifest["claim_flags"]["claims_independent_review_complete"])
        self.assertTrue(
            any(
                "deterministic" in blocker or "campaign request" in blocker
                for blocker in manifest["blocker_groups"]["campaign_validation"]
            )
        )
        self.assertTrue(
            any(
                "digest" in blocker
                for blocker in manifest["blocker_groups"]["closure_bundle"]
            )
        )

    def test_readiness_only_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AssessmentFixture(directory)
            manifest = fixture.criteria["aggregate_mask_distribution"]
            manifest["schema"] = "lattice-aggregation:theorem-closure-review:v1"
            manifest["evidence_class"] = "readiness_preflight"
            manifest["readiness_only"] = True
            result = fixture.assess()

        self.assertFalse(result["internally_closed_pending_independent_review"])
        blockers = result["blocker_groups"]["aggregate_mask_distribution"]
        self.assertTrue(any("readiness-only" in blocker for blocker in blockers))

    def test_false_substantive_claim_flag_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AssessmentFixture(directory)
            fixture.criteria["abort_retry_bias"]["claim_flags"][
                "claims_substantive_proof_complete"
            ] = False
            result = fixture.assess()

        blockers = result["blocker_groups"]["abort_retry_bias"]
        self.assertTrue(any("not true" in blocker for blocker in blockers))
        self.assertTrue(any("false claim flag" in blocker for blocker in blockers))

    def test_dirty_provenance_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AssessmentFixture(directory)
            fixture.criteria["abort_retry_bias"]["provenance"][
                "worktree_clean"
            ] = False
            result = fixture.assess()

        blockers = result["blocker_groups"]["abort_retry_bias"]
        self.assertTrue(any("provenance" in blocker for blocker in blockers))

    def test_unsafe_source_classes_are_rejected(self):
        for unsafe in ("hazmat-capture", "simulated-flow", "quarantined-input"):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as directory:
                fixture = AssessmentFixture(directory)
                fixture.criteria["partial_contribution_soundness"]["provenance"][
                    "source_path"
                ] = f"artifacts/{unsafe}/capture.json"
                result = fixture.assess()

                blockers = result["blocker_groups"]["partial_contribution_soundness"]
                self.assertTrue(any("non-hazmat" in blocker for blocker in blockers))

    def test_missing_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AssessmentFixture(directory)
            del fixture.criteria["unauthorized_aggregate_reduction"][
                "evidence_digests"
            ]["proof_digest"]
            result = fixture.assess()

        self.assertIn(
            "missing or invalid SHA-256 digest: proof_digest",
            result["blocker_groups"]["unauthorized_aggregate_reduction"],
        )

    def test_independent_review_semantics_must_be_explicitly_pending(self):
        mutations = (
            lambda document: document.pop("independent_review"),
            lambda document: document["independent_review"].update({"required": False}),
            lambda document: document["independent_review"].update({"completed": True}),
            lambda document: document["independent_review"].update({"status": "complete"}),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                fixture = AssessmentFixture(directory)
                mutate(fixture.criteria["aggregate_rejection_equivalence"])
                result = fixture.assess()
                blockers = result["blocker_groups"]["aggregate_rejection_equivalence"]
                self.assertTrue(any("independent review" in blocker for blocker in blockers))

    def test_absent_or_incomplete_real_campaign_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AssessmentFixture(directory)
            fixture.campaign_validation["validated_execution_count"] = 23
            fixture.campaign_validation["internal_campaign_evidence_ready"] = False
            result = fixture.assess()

        blockers = result["blocker_groups"]["campaign_validation"]
        self.assertTrue(any("exactly all 24" in blocker for blocker in blockers))
        self.assertTrue(any("not ready" in blocker for blocker in blockers))

    def test_bundle_public_claim_or_dirty_provenance_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AssessmentFixture(directory)
            paths, campaign, bundle = fixture.write()
            document = json.loads(bundle.read_text(encoding="utf-8"))
            document["claim_flags"]["claims_theorem_closure"] = True
            document["provenance"]["worktree_clean"] = False
            bundle.write_text(json.dumps(document), encoding="utf-8")
            result = ASSESSOR.build_report(
                directory,
                criterion_paths=paths,
                campaign_validation_path=campaign,
                bundle_path=bundle,
            )["manifest"]

        blockers = result["blocker_groups"]["closure_bundle"]
        self.assertTrue(any("public/security" in blocker for blocker in blockers))
        self.assertTrue(any("dirty" in blocker for blocker in blockers))

    def test_bundle_must_bind_exact_criterion_manifest_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AssessmentFixture(directory)
            paths, campaign, bundle = fixture.write()
            criterion = paths["aggregate_mask_distribution"]
            criterion.write_text(
                criterion.read_text(encoding="utf-8") + "\n", encoding="utf-8"
            )
            result = ASSESSOR.build_report(
                directory,
                criterion_paths=paths,
                campaign_validation_path=campaign,
                bundle_path=bundle,
            )["manifest"]

        blockers = result["blocker_groups"]["closure_bundle"]
        self.assertTrue(any("content-addressed" in blocker for blocker in blockers))

    def test_current_repository_defaults_remain_blocked(self):
        result = ASSESSOR.build_report(REPO_ROOT)["manifest"]

        self.assertEqual(result["assessment_status"], ASSESSOR.STATUS_BLOCKED)
        self.assertFalse(result["internally_closed_pending_independent_review"])
        self.assertGreaterEqual(len(result["blockers"]), 7)

    def test_strict_cli_exits_two_for_current_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--root",
                    str(REPO_ROOT),
                    "--out",
                    str(Path(directory) / "assessment"),
                    "--strict",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
