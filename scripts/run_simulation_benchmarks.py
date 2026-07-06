#!/usr/bin/env python3
"""Run deterministic simulation benchmark profiles and write review artifacts."""

import argparse
import csv
import hashlib
import io
import json
import platform
import subprocess
import sys
import time
from pathlib import Path


CLAIM_BOUNDARY = "deterministic research telemetry; requires security evidence review"


def sha256_text(text):
    """Return the SHA-256 digest for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def benchmark_command(profile):
    """Return the Cargo command used to produce structured benchmark CSV."""
    return [
        "cargo",
        "run",
        "--quiet",
        "--",
        "--profile",
        profile,
        "--format",
        "csv",
        "--no-wall-sleep",
    ]


def run_command(command, root, env):
    """Run a benchmark command and capture stdout, stderr, status, and duration."""
    merged_env = None
    if env:
        import os

        merged_env = os.environ.copy()
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


def capture_value(command, root, fallback="unknown"):
    """Capture a small metadata command without failing benchmark generation."""
    try:
        completed = subprocess.run(
            command,
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


def collect_metadata(root):
    """Collect benchmark provenance metadata for the current checkout."""
    return {
        "commit": capture_value(["git", "rev-parse", "HEAD"], root),
        "branch": capture_value(["git", "branch", "--show-current"], root),
        "cargo_version": capture_value(["cargo", "--version"], root),
        "rustc_version": capture_value(["rustc", "--version"], root),
        "os": platform.platform(),
        "python_version": platform.python_version(),
    }


def metadata_from_provider(provider, root):
    """Call metadata providers from tests or production code."""
    try:
        return provider(root)
    except TypeError:
        return provider()


def parse_trials_csv(text):
    """Parse structured harness CSV into typed row dictionaries."""
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for row in reader:
        rows.append(
            {
                "profile": row["profile"],
                "experiment": row["experiment"],
                "trial": int(row["trial"]),
                "validators": int(row["validators"]),
                "threshold": int(row["threshold"]),
                "malicious_validator": row["malicious_validator"],
                "wall_duration_ms": float(row["wall_duration_ms"]),
                "logical_latency_ms": int(row["logical_latency_ms"]),
                "aborts": int(row["aborts"]),
                "bandwidth_bytes": int(row["bandwidth_bytes"]),
                "mldsa65_public_key_bytes": int(row["mldsa65_public_key_bytes"]),
                "mldsa65_signature_bytes": int(row["mldsa65_signature_bytes"]),
                "commitment_bytes": int(row["commitment_bytes"]),
                "no_wall_sleep": row["no_wall_sleep"] == "true",
            }
        )
    if not rows:
        raise ValueError("benchmark CSV contained no trial rows")
    return rows


def mean(values):
    """Return the arithmetic mean for numeric values."""
    values = list(values)
    return sum(values) / len(values)


def summarize_trials(trials):
    """Summarize benchmark trials by experiment label."""
    groups = {}
    for trial in trials:
        groups.setdefault(trial["experiment"], []).append(trial)

    summary = []
    for experiment, rows in groups.items():
        first = rows[0]
        summary.append(
            {
                "experiment": experiment,
                "validators": first["validators"],
                "threshold": first["threshold"],
                "trials": len(rows),
                "malicious_validator": first["malicious_validator"],
                "mean_wall_duration_ms": round(
                    mean(row["wall_duration_ms"] for row in rows), 4
                ),
                "mean_logical_latency_ms": round(
                    mean(row["logical_latency_ms"] for row in rows), 1
                ),
                "mean_aborts": round(mean(row["aborts"] for row in rows), 1),
                "mean_bandwidth_bytes": round(
                    mean(row["bandwidth_bytes"] for row in rows)
                ),
            }
        )
    return summary


def render_summary(report):
    """Render a checked-in Markdown summary for benchmark review."""
    manifest = report["manifest"]
    lines = [
        "# Large-Scale Simulation Benchmark Summary",
        "",
        "This file is generated from deterministic simulation harness output. "
        "It is deterministic research telemetry, requires security evidence review, not "
        "real-world validator performance, and requires production-readiness evidence.",
        "",
        f"- Generated at: `{manifest['generated_at']}`",
        f"- Commit: `{manifest['metadata']['commit']}`",
        f"- Branch: `{manifest['metadata']['branch']}`",
        f"- Profile: `{manifest['profile']}`",
        f"- Trial rows: `{manifest['trial_count']}`",
        f"- Claim boundary: `{manifest['claim_boundary']}`",
        f"- CSV SHA-256: `{manifest['artifacts']['trials_csv_sha256']}`",
        "",
        "## Scenario Summary",
        "",
        "| Experiment | Validators | Threshold | Trials | Malicious validator | Mean wall ms | Mean logical latency ms | Mean aborts | Mean bandwidth bytes |",
        "| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in report["summary_rows"]:
        lines.append(
            "| {experiment} | {validators} | {threshold} | {trials} | "
            "{malicious_validator} | {mean_wall_duration_ms:.4f} | "
            "{mean_logical_latency_ms:.1f} | {mean_aborts:.1f} | "
            "{mean_bandwidth_bytes} |".format(**row)
        )
    lines.extend(
        [
            "",
            "## Regeneration",
            "",
            "```sh",
            "python3 scripts/run_simulation_benchmarks.py --out docs/benchmarks/generated/latest-simulation",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def build_report(
    root,
    profile="large",
    command_runner=run_command,
    metadata_provider=collect_metadata,
    generated_at=None,
    target_dir=None,
):
    """Run the harness and build in-memory artifact content."""
    root = Path(root)
    command = benchmark_command(profile)
    env = {}
    if target_dir:
        env["CARGO_TARGET_DIR"] = str(target_dir)
    result = command_runner(command, root, env)
    if result["exit_code"] != 0:
        raise RuntimeError(
            "benchmark command failed: "
            + " ".join(command)
            + "\n"
            + result.get("stderr", "")
        )

    trials_csv = result["stdout"]
    trials = parse_trials_csv(trials_csv)
    metadata = metadata_from_provider(metadata_provider, root)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    manifest = {
        "generated_at": generated_at,
        "profile": profile,
        "claim_boundary": CLAIM_BOUNDARY,
        "metadata": metadata,
        "command": command,
        "command_duration_seconds": result["duration_seconds"],
        "trial_count": len(trials),
        "artifacts": {
            "trials_csv": "trials.csv",
            "summary_md": "summary.md",
            "trials_csv_sha256": sha256_text(trials_csv),
        },
    }
    report = {
        "manifest": manifest,
        "trials": trials,
        "summary_rows": summarize_trials(trials),
        "trials_csv": trials_csv,
    }
    summary_markdown = render_summary(report)
    manifest["artifacts"]["summary_md_sha256"] = sha256_text(summary_markdown)
    report["summary_markdown"] = summary_markdown
    return report


def write_artifacts(report, out_dir):
    """Write manifest, trial CSV, and Markdown summary to an artifact directory."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "trials.csv").write_text(report["trials_csv"], encoding="utf-8")
    (out_dir / "summary.md").write_text(
        report["summary_markdown"], encoding="utf-8"
    )
    (out_dir / "manifest.json").write_text(
        json.dumps(report["manifest"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Run deterministic lattice aggregation simulation benchmarks."
    )
    parser.add_argument("--root", default=".", help="Repository root.")
    parser.add_argument(
        "--out",
        default="docs/benchmarks/generated/latest-simulation",
        help="Output directory for manifest.json, trials.csv, and summary.md.",
    )
    parser.add_argument(
        "--profile",
        default="large",
        choices=["smoke", "large"],
        help="Harness profile to run.",
    )
    parser.add_argument(
        "--target-dir",
        help="Optional Cargo target directory for isolated benchmark builds.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    root = Path(args.root)
    report = build_report(root, profile=args.profile, target_dir=args.target_dir)
    write_artifacts(report, Path(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
