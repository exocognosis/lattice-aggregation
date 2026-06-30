#!/usr/bin/env python3
"""Run the local validator-network smoke runner and write telemetry artifacts."""

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


CLAIM_BOUNDARY = (
    "local validator-network engineering telemetry; not security evidence; "
    "not real-world validator performance; not production-readiness evidence; "
    "not production network liveness, authenticated transport, or consensus safety; "
    "not side-channel resistance; not CAVP/ACVTS validation; not FIPS validation; "
    "not production threshold ML-DSA security"
)


def sha256_text(text):
    """Return the SHA-256 digest for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path):
    """Return the SHA-256 digest for a file, or unknown if absent."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "unknown"


def canonical_json(data):
    """Render stable pretty JSON with a trailing newline."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def localnet_command():
    """Return the Cargo command used to run the localnet smoke example."""
    return ["cargo", "run", "--quiet", "--example", "validator_localnet"]


def run_command(command, root, env):
    """Run a command and capture stdout, stderr, status, and duration."""
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
    """Capture a small metadata command without failing packet generation."""
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
    """Collect localnet packet provenance metadata."""
    root = Path(root)
    return {
        "commit": capture_value(["git", "rev-parse", "HEAD"], root),
        "branch": capture_value(["git", "branch", "--show-current"], root),
        "dirty": bool(capture_value(["git", "status", "--short"], root, fallback="")),
        "cargo_version": capture_value(["cargo", "--version"], root),
        "rustc_version": capture_value(["rustc", "--version"], root),
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "cargo_lock_sha256": sha256_file(root / "Cargo.lock"),
    }


def metadata_from_provider(provider, root):
    """Call metadata providers from tests or production code."""
    try:
        return provider(root)
    except TypeError:
        return provider()


def parse_key_value_output(text):
    """Parse key=value localnet example output."""
    values = {}
    for line in text.splitlines():
        if not line.strip() or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    required = [
        "claim_boundary",
        "validators",
        "threshold",
        "finalized",
        "evidence_count",
        "broadcast_count",
        "direct_send_count",
        "network_bytes",
    ]
    missing = [key for key in required if key not in values]
    if missing:
        raise ValueError(f"localnet output missing fields: {', '.join(missing)}")
    if values["claim_boundary"] != CLAIM_BOUNDARY:
        raise ValueError("localnet output claim boundary drifted")

    return {
        "claim_boundary": values["claim_boundary"],
        "validators": int(values["validators"]),
        "threshold": int(values["threshold"]),
        "finalized": int(values["finalized"]),
        "evidence_count": int(values["evidence_count"]),
        "broadcast_count": int(values["broadcast_count"]),
        "direct_send_count": int(values["direct_send_count"]),
        "network_bytes": int(values["network_bytes"]),
    }


def render_metrics_csv(metrics):
    """Render one-row localnet metrics CSV."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "profile",
            "validators",
            "threshold",
            "finalized",
            "evidence_count",
            "broadcast_count",
            "direct_send_count",
            "network_bytes",
            "claim_boundary",
        ],
    )
    writer.writeheader()
    writer.writerow({"profile": "localnet-smoke", **metrics})
    return output.getvalue()


def render_topology_json(metrics):
    """Render local-only topology metadata."""
    return canonical_json(
        {
            "profile": "localnet-smoke",
            "validator_count": metrics["validators"],
            "threshold": metrics["threshold"],
            "transport_mode": "in-memory tokio mpsc",
            "network_scope": "single-process local runner",
            "authentication_policy": "none; local engineering telemetry only",
            "replay_policy": "session-id scoped actor state only",
            "timeout_policy": "actor round timeout",
            "retry_policy": "none in first localnet smoke runner",
            "session_cleanup_policy": "drop local in-memory channels after run",
        }
    )


def render_events_jsonl(metrics):
    """Render structured localnet event summary."""
    events = [
        {
            "event_type": "localnet_summary",
            "profile": "localnet-smoke",
            "validators": metrics["validators"],
            "threshold": metrics["threshold"],
            "finalized": metrics["finalized"],
            "evidence_count": metrics["evidence_count"],
            "broadcast_count": metrics["broadcast_count"],
            "direct_send_count": metrics["direct_send_count"],
            "network_bytes": metrics["network_bytes"],
        },
        {
            "event_type": "claim_boundary",
            "claim_boundary": metrics["claim_boundary"],
        },
    ]
    return "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)


def render_summary(generated_at, metadata, metrics):
    """Render human-readable localnet summary."""
    return "\n".join(
        [
            "# Local Validator-Network Telemetry Summary",
            "",
            "This file is generated from a local in-memory validator-network runner. "
            + CLAIM_BOUNDARY
            + ".",
            "",
            f"- Generated at: `{generated_at}`",
            f"- Commit: `{metadata['commit']}`",
            f"- Branch: `{metadata['branch']}`",
            "- Profile: `localnet-smoke`",
            f"- Validators: `{metrics['validators']}`",
            f"- Threshold: `{metrics['threshold']}`",
            f"- Finalized callbacks: `{metrics['finalized']}`",
            f"- Evidence records: `{metrics['evidence_count']}`",
            f"- Broadcast calls: `{metrics['broadcast_count']}`",
            f"- Direct-send calls: `{metrics['direct_send_count']}`",
            f"- Network bytes: `{metrics['network_bytes']}`",
            f"- Claim boundary: `{metrics['claim_boundary']}`",
            "",
            "## Regeneration",
            "",
            "```sh",
            "python3 scripts/run_localnet_runner.py --out artifacts/localnet/latest",
            "```",
            "",
        ]
    )


def render_node_log_readme():
    """Render the first-run node log directory contract."""
    return "\n".join(
        [
            "# Localnet Node Logs",
            "",
            "The first localnet smoke runner executes validators in one process and "
            "does not yet emit per-validator log streams. This placeholder keeps "
            "the packet layout stable for later multi-process or per-node "
            "telemetry runs.",
            "",
        ]
    )


def build_report(
    root,
    command_runner=run_command,
    metadata_provider=collect_metadata,
    generated_at=None,
    target_dir=None,
):
    """Run the localnet example and build in-memory artifact content."""
    root = Path(root)
    command = localnet_command()
    env = {}
    if target_dir:
        env["CARGO_TARGET_DIR"] = str(target_dir)
    result = command_runner(command, root, env)
    if result["exit_code"] != 0:
        raise RuntimeError(
            "localnet command failed: "
            + " ".join(command)
            + "\n"
            + result.get("stderr", "")
        )

    metrics = parse_key_value_output(result["stdout"])
    metadata = metadata_from_provider(metadata_provider, root)
    generated_at = generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    topology_json = render_topology_json(metrics)
    metrics_csv = render_metrics_csv(metrics)
    events_jsonl = render_events_jsonl(metrics)
    summary_md = render_summary(generated_at, metadata, metrics)

    manifest = {
        "schema_version": 1,
        "generated_at": generated_at,
        "claim_boundary": CLAIM_BOUNDARY,
        "metadata": metadata,
        "command": command,
        "command_duration_seconds": result["duration_seconds"],
        "exit_code": result["exit_code"],
        "feature_set": "default",
        "backend": "deterministic simulated backend",
        "topology": {
            "profile": "localnet-smoke",
            "validator_count": metrics["validators"],
            "threshold": metrics["threshold"],
            "transport_mode": "in-memory tokio mpsc",
        },
    }

    report = {
        "manifest": manifest,
        "metrics": metrics,
        "topology_json": topology_json,
        "metrics_csv": metrics_csv,
        "events_jsonl": events_jsonl,
        "summary_md": summary_md,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
    }
    return report


def artifact_contents(report):
    """Build final artifact file contents."""
    contents = {
        "topology.json": report["topology_json"],
        "metrics.csv": report["metrics_csv"],
        "events.jsonl": report["events_jsonl"],
        "command.stdout.log": report["stdout"],
        "command.stderr.log": report["stderr"],
        "node-logs/README.md": render_node_log_readme(),
        "summary.md": report["summary_md"],
    }
    artifacts = {
        name: {
            "path": name,
            "sha256": sha256_text(text),
            "bytes": len(text.encode("utf-8")),
        }
        for name, text in sorted(contents.items())
    }
    manifest = dict(report["manifest"])
    manifest["artifacts"] = artifacts
    contents["manifest.json"] = canonical_json(manifest)
    checksum_lines = [
        f"{sha256_text(text)}  {name}" for name, text in sorted(contents.items())
    ]
    contents["SHA256SUMS"] = "\n".join(checksum_lines) + "\n"
    return contents


def write_artifacts(report, out_dir):
    """Write localnet packet artifacts."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in artifact_contents(report).items():
        target = out_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="output artifact directory")
    parser.add_argument("--target-dir", help="Cargo target directory for the run")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parents[1]
    report = build_report(root, target_dir=args.target_dir)
    write_artifacts(report, Path(args.out))
    print(Path(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
