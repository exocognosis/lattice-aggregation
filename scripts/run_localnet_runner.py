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


def localnet_command(profile="honest"):
    """Return the Cargo command used to run the localnet smoke example."""
    command = ["cargo", "run", "--quiet", "--example", "validator_localnet"]
    if profile == "honest":
        return command
    if profile == "withheld-partial":
        return command + [
            "--",
            "--profile",
            "withheld-partial",
            "--validators",
            "4",
            "--threshold",
            "4",
            "--withheld-validator",
            "4",
        ]
    if profile == "quorum-participation":
        return command + [
            "--",
            "--profile",
            "honest",
            "--validators",
            "4",
            "--threshold",
            "3",
            "--triggered-validators",
            "3",
        ]
    if profile == "authenticated-transport":
        return command + ["--", "--transport", "authenticated-envelope"]
    if profile == "authenticated-envelope-tamper":
        return command + [
            "--",
            "--transport",
            "authenticated-envelope",
            "--profile",
            "authenticated-envelope-tamper",
            "--validators",
            "4",
            "--threshold",
            "3",
            "--tamper-validator",
            "4",
        ]
    raise ValueError(f"unsupported localnet profile: {profile}")


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
        "fault_profile",
        "validators",
        "triggered_validator_count",
        "threshold",
        "transport_mode",
        "authentication_policy",
        "finalized",
        "all_validators_finalized",
        "evidence_count",
        "broadcast_count",
        "direct_send_count",
        "dropped_message_count",
        "authenticated_envelope_count",
        "rejected_envelope_count",
        "network_bytes",
    ]
    missing = [key for key in required if key not in values]
    if missing:
        raise ValueError(f"localnet output missing fields: {', '.join(missing)}")
    if values["claim_boundary"] != CLAIM_BOUNDARY:
        raise ValueError("localnet output claim boundary drifted")

    return {
        "claim_boundary": values["claim_boundary"],
        "fault_profile": values["fault_profile"],
        "validators": int(values["validators"]),
        "triggered_validator_count": int(values["triggered_validator_count"]),
        "threshold": int(values["threshold"]),
        "transport_mode": values["transport_mode"],
        "authentication_policy": values["authentication_policy"],
        "finalized": int(values["finalized"]),
        "all_validators_finalized": values["all_validators_finalized"] == "true",
        "evidence_count": int(values["evidence_count"]),
        "broadcast_count": int(values["broadcast_count"]),
        "direct_send_count": int(values["direct_send_count"]),
        "dropped_message_count": int(values["dropped_message_count"]),
        "authenticated_envelope_count": int(values["authenticated_envelope_count"]),
        "rejected_envelope_count": int(values["rejected_envelope_count"]),
        "network_bytes": int(values["network_bytes"]),
    }


def render_metrics_csv(metrics):
    """Render one-row localnet metrics CSV."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "profile",
            "fault_profile",
            "validators",
            "triggered_validator_count",
            "threshold",
            "transport_mode",
            "authentication_policy",
            "finalized",
            "all_validators_finalized",
            "evidence_count",
            "broadcast_count",
            "direct_send_count",
            "dropped_message_count",
            "authenticated_envelope_count",
            "rejected_envelope_count",
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
            "fault_profile": metrics["fault_profile"],
            "validator_count": metrics["validators"],
            "triggered_validator_count": metrics["triggered_validator_count"],
            "threshold": metrics["threshold"],
            "transport_mode": metrics["transport_mode"],
            "network_scope": "single-process local runner",
            "authentication_policy": metrics["authentication_policy"],
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
            "fault_profile": metrics["fault_profile"],
            "validators": metrics["validators"],
            "triggered_validator_count": metrics["triggered_validator_count"],
            "threshold": metrics["threshold"],
            "transport_mode": metrics["transport_mode"],
            "authentication_policy": metrics["authentication_policy"],
            "finalized": metrics["finalized"],
            "all_validators_finalized": metrics["all_validators_finalized"],
            "evidence_count": metrics["evidence_count"],
            "broadcast_count": metrics["broadcast_count"],
            "direct_send_count": metrics["direct_send_count"],
            "dropped_message_count": metrics["dropped_message_count"],
            "authenticated_envelope_count": metrics["authenticated_envelope_count"],
            "rejected_envelope_count": metrics["rejected_envelope_count"],
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
    fault_note = "No local fault injection was enabled for this packet."
    regeneration_command = "python3 scripts/run_localnet_runner.py --out artifacts/localnet/latest"
    participation_note = "All configured validators actively triggered signing."
    transport_note = "No authenticated local transport envelope was enabled for this packet."
    if metrics["fault_profile"] != "honest":
        fault_note = (
            "This packet is fault-injection telemetry for local validator "
            "orchestration only; it is not production network liveness or "
            "consensus-safety evidence."
        )
        regeneration_command = (
            "python3 scripts/run_localnet_runner.py --profile "
            + metrics["fault_profile"]
            + " --out artifacts/localnet/"
            + metrics["fault_profile"]
        )
    elif metrics["triggered_validator_count"] < metrics["validators"]:
        participation_note = (
            "This packet records a passive validator quorum-participation "
            "profile; the passive validator did not trigger signing, is not "
            "counted as finalized, and this is not slashing evidence."
        )
        regeneration_command = (
            "python3 scripts/run_localnet_runner.py --profile "
            "quorum-participation --out artifacts/localnet/quorum-participation"
        )
    if metrics["transport_mode"] == "authenticated local envelope over tokio mpsc":
        transport_note = (
            "This packet exercises an authenticated local envelope with a "
            "deterministic validator identity digest; it is not production "
            "authenticated transport, peer discovery, replay-resistance, or "
            "network-liveness evidence."
        )
        regeneration_command = (
            "python3 scripts/run_localnet_runner.py --profile "
            "authenticated-transport --out artifacts/localnet/authenticated-transport"
        )
    if metrics["fault_profile"] == "authenticated-envelope-tamper":
        fault_note = (
            "The authenticated-envelope-tamper packet is local "
            "tamper-rejection telemetry only: it records tampered authenticated "
            "local envelopes through rejected_envelope_count without treating "
            "the local transport rejection as slashing evidence; this is not "
            "slashing evidence."
        )
        transport_note = (
            "This packet exercises tampered authenticated local envelopes with "
            "a deterministic validator identity digest; it is not production "
            "authenticated transport, peer discovery, replay-resistance, "
            "network-liveness, consensus-safety, Byzantine-fault-tolerance, "
            "slashing-soundness, or cryptographic security evidence."
        )
        regeneration_command = (
            "python3 scripts/run_localnet_runner.py --profile "
            "authenticated-envelope-tamper --out "
            "artifacts/localnet/authenticated-envelope-tamper"
        )

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
            f"- Fault profile: `{metrics['fault_profile']}`",
            f"- Validators: `{metrics['validators']}`",
            f"- Triggered validators: `{metrics['triggered_validator_count']}`",
            f"- Threshold: `{metrics['threshold']}`",
            f"- Transport mode: `{metrics['transport_mode']}`",
            f"- Authentication policy: `{metrics['authentication_policy']}`",
            f"- Finalized callbacks: `{metrics['finalized']}`",
            f"- All validators finalized: `{metrics['all_validators_finalized']}`",
            f"- Evidence records: `{metrics['evidence_count']}`",
            f"- Broadcast calls: `{metrics['broadcast_count']}`",
            f"- Direct-send calls: `{metrics['direct_send_count']}`",
            f"- Dropped message deliveries: `{metrics['dropped_message_count']}`",
            f"- Authenticated envelopes: `{metrics['authenticated_envelope_count']}`",
            f"- Rejected envelopes: `{metrics['rejected_envelope_count']}`",
            f"- Network bytes: `{metrics['network_bytes']}`",
            f"- Claim boundary: `{metrics['claim_boundary']}`",
            f"- Fault boundary: {fault_note}",
            f"- Participation boundary: {participation_note}",
            f"- Transport boundary: {transport_note}",
            "",
            "## Regeneration",
            "",
            "```sh",
            regeneration_command,
            "```",
            "",
        ]
    )


def render_node_log(metrics, validator_index):
    """Render deterministic per-validator local node telemetry."""
    lines = [
        f"validator={validator_index}",
        f"fault_profile={metrics['fault_profile']}",
        f"threshold={metrics['threshold']}",
        f"validator_count={metrics['validators']}",
        f"triggered_validator_count={metrics['triggered_validator_count']}",
        f"transport_mode={metrics['transport_mode']}",
        f"authentication_policy={metrics['authentication_policy']}",
        f"all_validators_finalized={metrics['all_validators_finalized']}",
        f"evidence_count={metrics['evidence_count']}",
        f"dropped_message_count={metrics['dropped_message_count']}",
        f"authenticated_envelope_count={metrics['authenticated_envelope_count']}",
        f"rejected_envelope_count={metrics['rejected_envelope_count']}",
        "claim_boundary=" + metrics["claim_boundary"],
        "",
    ]
    return "\n".join(lines)


def render_node_log_readme():
    """Render the first-run node log directory contract."""
    return "\n".join(
        [
            "# Localnet Node Logs",
            "",
            "The localnet runner executes validators in one process and emits "
            "per-validator local telemetry summaries only. These are not raw "
            "production validator logs and must not be used as production "
            "network evidence.",
            "",
        ]
    )


def build_report(
    root,
    profile="honest",
    command_runner=run_command,
    metadata_provider=collect_metadata,
    generated_at=None,
    target_dir=None,
):
    """Run the localnet example and build in-memory artifact content."""
    root = Path(root)
    command = localnet_command(profile)
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
        "fault_profile": metrics["fault_profile"],
        "triggered_validator_count": metrics["triggered_validator_count"],
        "transport_mode": metrics["transport_mode"],
        "authentication_policy": metrics["authentication_policy"],
        "all_validators_finalized": metrics["all_validators_finalized"],
        "dropped_message_count": metrics["dropped_message_count"],
        "authenticated_envelope_count": metrics["authenticated_envelope_count"],
        "rejected_envelope_count": metrics["rejected_envelope_count"],
        "metadata": metadata,
        "command": command,
        "command_duration_seconds": result["duration_seconds"],
        "exit_code": result["exit_code"],
        "feature_set": "default",
        "backend": "deterministic simulated backend",
        "topology": {
            "profile": "localnet-smoke",
            "fault_profile": metrics["fault_profile"],
            "validator_count": metrics["validators"],
            "triggered_validator_count": metrics["triggered_validator_count"],
            "threshold": metrics["threshold"],
            "transport_mode": metrics["transport_mode"],
            "authentication_policy": metrics["authentication_policy"],
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
    for validator_index in range(1, report["metrics"]["validators"] + 1):
        contents[f"node-logs/validator-{validator_index}.log"] = render_node_log(
            report["metrics"], validator_index
        )
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
    parser.add_argument(
        "--profile",
        choices=[
            "honest",
            "withheld-partial",
            "quorum-participation",
            "authenticated-transport",
            "authenticated-envelope-tamper",
        ],
        default="honest",
        help="localnet profile to execute",
    )
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parents[1]
    report = build_report(root, profile=args.profile, target_dir=args.target_dir)
    write_artifacts(report, Path(args.out))
    print(Path(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
