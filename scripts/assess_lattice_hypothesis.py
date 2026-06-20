#!/usr/bin/env python3
"""Assess lattice aggregation hypothesis evidence for the current checkout."""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


REQUIRED_DOCUMENTS = [
    "README.md",
    "docs/cryptography/proof-obligations.md",
    "docs/cryptography/noise-rejection-proof-plan.md",
    "docs/cryptography/formal-security-theorem.md",
    "docs/cryptography/ideal-functionality.md",
    "docs/benchmarks/release-readiness-checklist.md",
]

TESTING_STATEMENT = (
    "If a threshold ML-DSA-65 lattice aggregation protocol emits an accepted "
    "aggregate output, then the output should behave like a centralized "
    "ML-DSA-65 signature under the same public key and message, while "
    "preserving threshold soundness, rejection-sampling distribution, "
    "contribution validity, leakage boundaries, and unforgeability reduction "
    "claims."
)


def default_criteria():
    """Return the five canonical hypothesis success criteria."""
    return [
        {
            "id": "aggregate_mask_distribution",
            "statement": (
                "Aggregate masks match or closely approximate centralized "
                "ML-DSA masks."
            ),
            "required_evidence": [
                "selected threshold ML-DSA construction",
                "Renyi divergence bound for epsilon_mask",
                "mask distribution comparison evidence",
            ],
            "proof_anchors": ["Noise Lemma B", "Noise Lemma H"],
        },
        {
            "id": "aggregate_rejection_equivalence",
            "statement": (
                "Aggregate rejection checks match centralized ML-DSA rejection "
                "checks."
            ),
            "required_evidence": [
                "real aggregate recomputation",
                "standard verifier bridge tests",
                "ML-DSA-65 norm, hint, and challenge bound checks",
            ],
            "proof_anchors": [
                "Noise Lemma D",
                "Noise Lemma F",
                "Correctness Lemma 7",
                "Correctness Lemma 8",
            ],
        },
        {
            "id": "abort_retry_bias",
            "statement": (
                "Selective aborts and retries do not bias accepted signatures."
            ),
            "required_evidence": [
                "abort leakage model",
                "retry transcript domain separation",
                "accepted-signature distribution proof",
            ],
            "proof_anchors": ["Noise Lemma G", "Noise Lemma H", "FST-L7"],
        },
        {
            "id": "partial_contribution_soundness",
            "statement": (
                "Every accepted partial contribution is sound, context-bound, "
                "and hiding enough for the chosen leakage model."
            ),
            "required_evidence": [
                "local partial acceptance predicate",
                "partial-share verification evidence",
                "VSS/DKG hiding and binding proof",
            ],
            "proof_anchors": ["FST-L4", "Noise Lemma E", "VSS hiding"],
        },
        {
            "id": "unauthorized_aggregate_reduction",
            "statement": (
                "Every unauthorized accepting aggregate output reduces to a "
                "base ML-DSA forgery or a named threshold-side assumption "
                "violation."
            ),
            "required_evidence": [
                "threshold unforgeability reduction",
                "base ML-DSA theorem dependency",
                "named threshold-side assumptions",
            ],
            "proof_anchors": ["FST-L6", "FST-T1", "IF-R6"],
        },
    ]


def overall_verdict(criteria):
    """Roll criterion statuses into the requested four-way verdict."""
    statuses = [criterion["status"] for criterion in criteria]
    if statuses and all(status == "met" for status in statuses):
        return "completely_proven"
    if statuses and all(status == "failed" for status in statuses):
        return "completely_disproven"
    if any(status == "failed" for status in statuses):
        return "partially_disproven"
    if any(status in {"met", "partially_met", "blocked"} for status in statuses):
        return "partially_proven"
    return "partially_proven"


def scan_documents(root):
    """Scan source documents for current claim boundaries and proof blockers."""
    root = Path(root)
    texts = {}
    missing = []
    for relative in REQUIRED_DOCUMENTS:
        path = root / relative
        try:
            texts[relative] = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            texts[relative] = ""
            missing.append(relative)

    combined = "\n".join(texts.values()).lower()
    readme = texts["README.md"].lower()

    return {
        "documents": texts,
        "missing_documents": missing,
        "readme_research_boundary": (
            "research status" in readme
            and "deterministic simulation" in readme
            and "if the hypothesis is proven" in readme
        ),
        "standard_verifier_blocked": (
            "standard-verifier bridge tests" in combined
            or "standard mldsa verification" in combined
            or "standard ml-dsa verification" in combined
            or "does not perform real ml-dsa aggregate rejection checks" in combined
        ),
        "renyi_evidence_blocked": (
            "renyi divergence" in combined and "epsilon_mask" in combined
        ),
        "abort_bias_blocked": (
            "noise lemma g" in combined
            or "abort distribution" in combined
            or "abort compatibility" in combined
        ),
        "partial_soundness_scaffold": (
            "simulatedaggregator checks threshold and validator-universe matching"
            in combined
            or "context-bound" in combined
            or "transcript binding" in combined
            or "canonical collection" in combined
        ),
        "partial_soundness_blocked": (
            "fst-l4 partial-share validity" in combined
            or "localaccept" in combined
            or "real local acceptance" in combined
            or "vss hiding" in combined
        ),
        "unforgeability_reduction_blocked": (
            "fst-l6 no subthreshold signing" in combined
            or "proof status: not proved" in combined
            or "unauthorized aggregate output would imply a forgery" in combined
        ),
    }


def classify_criteria(criteria, scan):
    """Attach observed evidence, blockers, and status to each criterion."""
    classified = []
    missing = scan.get("missing_documents", [])
    missing_blocker = (
        "Missing required assessment documents: " + ", ".join(missing)
        if missing
        else None
    )
    readme_blocker = (
        "README keeps the hypothesis conditional on theorem closure, a reviewed "
        "threshold backend, and standard ML-DSA verification."
    )

    for criterion in criteria:
        item = dict(criterion)
        observed = []
        blockers = []
        status = "blocked"

        if missing_blocker:
            blockers.append(missing_blocker)
        elif criterion["id"] == "aggregate_mask_distribution":
            if scan["readme_research_boundary"]:
                blockers.append(readme_blocker)
            if scan["renyi_evidence_blocked"]:
                blockers.append(
                    "Renyi-divergence evidence for epsilon_mask is still a "
                    "release-readiness blocker."
                )
        elif criterion["id"] == "aggregate_rejection_equivalence":
            if scan["standard_verifier_blocked"]:
                blockers.append(
                    "Standard ML-DSA verifier bridge and real aggregate "
                    "rejection checks are not present."
                )
        elif criterion["id"] == "abort_retry_bias":
            if scan["abort_bias_blocked"]:
                blockers.append(
                    "Abort leakage and retry-bias distribution analysis remain "
                    "open proof obligations."
                )
        elif criterion["id"] == "partial_contribution_soundness":
            if scan["partial_soundness_scaffold"]:
                observed.append(
                    "Scaffold evidence supports transcript binding, validator "
                    "universe checks, or context-bound contribution shape."
                )
            if scan["partial_soundness_blocked"]:
                blockers.append(
                    "Production local acceptance, partial verification, and "
                    "hiding proof evidence are not complete."
                )
            status = "partially_met" if observed and blockers else "blocked"
        elif criterion["id"] == "unauthorized_aggregate_reduction":
            if scan["unforgeability_reduction_blocked"]:
                blockers.append(
                    "Threshold unforgeability reduction is stated as a target, "
                    "not a completed proof."
                )

        if criterion["id"] != "partial_contribution_soundness":
            status = "blocked" if blockers else "met"

        item["observed_evidence"] = observed
        item["blockers"] = blockers
        item["status"] = status
        item["verdict_contribution"] = (
            "supports_scaffold_only" if status == "partially_met" else "not_proven"
        )
        classified.append(item)

    return classified


def default_commands():
    """Return default scaffold commands for the current-checkout assessment."""
    return [
        ["cargo", "test", "--test", "simulated_flow"],
        ["cargo", "test", "--test", "simulation"],
        ["cargo", "test", "--test", "proof_documentation_manifest"],
        [
            "cargo",
            "test",
            "--features",
            "coordinator-assisted",
            "--test",
            "production_epsilon",
            "--test",
            "production_prefilter",
            "--test",
            "production_hints",
            "--test",
            "production_wire",
            "--test",
            "production_transcript",
            "--test",
            "production_coordinator",
        ],
        ["cargo", "run"],
    ]


def run_command(command, root, env=None):
    """Run one command and capture bounded metadata for the report."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=root,
        env=merged_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "command": command,
        "exit_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def git_value(root, args, fallback="unknown"):
    """Return a git metadata value without failing report generation."""
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return fallback
    if completed.returncode != 0:
        return fallback
    value = completed.stdout.strip()
    return value if value else fallback


def command_environment(offline=False, target_dir=None):
    """Build environment overrides for Cargo command execution."""
    env = {}
    if offline:
        env["CARGO_NET_OFFLINE"] = "true"
    if target_dir:
        env["CARGO_TARGET_DIR"] = str(target_dir)
    return env


def summarize_commands(command_results):
    """Summarize command outcomes and extract lightweight execution evidence."""
    if not command_results:
        return {"all_passed": None, "passed": 0, "failed": 0}
    passed = sum(1 for result in command_results if result["exit_code"] == 0)
    failed = len(command_results) - passed
    return {"all_passed": failed == 0, "passed": passed, "failed": failed}


def execution_evidence(command_results):
    """Extract high-signal evidence from command output."""
    evidence = []
    if command_results and all(result["exit_code"] == 0 for result in command_results):
        evidence.append("Cargo scaffold checks completed")
    joined = "\n".join(result.get("stdout", "") for result in command_results)
    if "session_id,duration_ms,aborts,bandwidth_bytes" in joined:
        evidence.append("Simulation harness emitted duration, abort, and bandwidth telemetry.")
    if "test result: ok" in joined:
        evidence.append("Rust test output reported passing test suites.")
    return evidence


def build_report(
    root,
    run_commands=True,
    command_runner=run_command,
    commands=None,
    offline=False,
    target_dir=None,
):
    """Build the full assessment report dictionary."""
    root = Path(root)
    scan = scan_documents(root)
    criteria = classify_criteria(default_criteria(), scan)
    env = command_environment(offline=offline, target_dir=target_dir)
    selected_commands = commands if commands is not None else default_commands()
    command_results = []
    if run_commands:
        for command in selected_commands:
            command_results.append(command_runner(command, root, env))

    summary = summarize_commands(command_results)
    evidence = execution_evidence(command_results)
    if summary["failed"]:
        criteria = mark_command_failures(criteria, command_results)

    return {
        "testing_statement": TESTING_STATEMENT,
        "commit": git_value(root, ["rev-parse", "HEAD"]),
        "branch": git_value(root, ["branch", "--show-current"]),
        "claim_boundary": "research scaffold only",
        "readme_comparison": readme_comparison(scan),
        "criteria": criteria,
        "commands": command_results,
        "command_summary": summary,
        "execution_evidence": evidence,
        "overall_verdict": overall_verdict(criteria),
    }


def mark_command_failures(criteria, command_results):
    """Attach command failures without turning proof blockers into proof failures."""
    failed_commands = [
        " ".join(result["command"])
        for result in command_results
        if result["exit_code"] != 0
    ]
    if not failed_commands:
        return criteria
    marked = []
    for criterion in criteria:
        item = dict(criterion)
        item["blockers"] = list(item.get("blockers", []))
        item["blockers"].append(
            "Executable scaffold command failed: " + "; ".join(failed_commands)
        )
        if item["status"] == "met":
            item["status"] = "blocked"
        marked.append(item)
    return marked


def readme_comparison(scan):
    """Return claim-boundary comparison points against the top-level README."""
    if scan.get("readme_research_boundary"):
        return [
            "README states the repository is deterministic research scaffolding.",
            "README makes the hypothesis conditional on theorem closure, a reviewed threshold backend, and standard ML-DSA verification.",
            "Missing production proof artifacts are blockers, not contradictions.",
        ]
    return [
        "README research boundary was not detected; claim-drift review is required.",
    ]


def write_reports(report, out_dir):
    """Write JSON and Markdown assessment reports."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "assessment.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "assessment.md").write_text(render_markdown(report), encoding="utf-8")


def render_markdown(report):
    """Render a compact human-readable assessment."""
    lines = [
        "# Lattice Aggregation Hypothesis Assessment",
        "",
        f"Overall verdict: `{report['overall_verdict']}`",
        f"Claim boundary: `{report['claim_boundary']}`",
        f"Branch: `{report['branch']}`",
        f"Commit: `{report['commit']}`",
        "",
        "## Testing Statement",
        "",
        report["testing_statement"],
        "",
        "## README Comparison",
        "",
    ]
    for item in report["readme_comparison"]:
        lines.append(f"- {item}")

    lines.extend(["", "## Criteria", ""])
    for criterion in report["criteria"]:
        lines.append(f"### {criterion['statement']}")
        lines.append("")
        lines.append(f"- Status: `{criterion['status']}`")
        if criterion.get("observed_evidence"):
            for evidence in criterion["observed_evidence"]:
                lines.append(f"- Evidence: {evidence}")
        if criterion.get("blockers"):
            for blocker in criterion["blockers"]:
                lines.append(f"- Blocker: {blocker}")
        lines.append("")

    lines.extend(["## Command Summary", ""])
    summary = report["command_summary"]
    if summary["all_passed"] is None:
        lines.append("Commands were skipped.")
    else:
        lines.append(
            f"Passed: {summary['passed']}; failed: {summary['failed']}; "
            f"all passed: `{summary['all_passed']}`."
        )
    for evidence in report["execution_evidence"]:
        lines.append(f"- {evidence}")
    lines.append("")
    return "\n".join(lines)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Assess lattice aggregation hypothesis evidence."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root to assess.",
    )
    parser.add_argument(
        "--out",
        default="artifacts/hypothesis/latest",
        help="Output directory for assessment.json and assessment.md.",
    )
    parser.add_argument(
        "--skip-commands",
        action="store_true",
        help="Build the report without running Cargo commands.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Set CARGO_NET_OFFLINE=true for Cargo commands.",
    )
    parser.add_argument(
        "--target-dir",
        help="Set CARGO_TARGET_DIR for Cargo commands.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return 2 unless the verdict is completely_proven.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = Path(args.root).resolve()
    report = build_report(
        root,
        run_commands=not args.skip_commands,
        offline=args.offline,
        target_dir=args.target_dir,
    )
    write_reports(report, Path(args.out))
    if args.strict and report["overall_verdict"] != "completely_proven":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
