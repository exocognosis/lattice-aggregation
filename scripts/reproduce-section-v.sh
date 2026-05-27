#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/dytallix-pq-threshold-target}"
OUTPUT_FILE="${SECTION_V_OUTPUT:-/tmp/dytallix-section-v-sample-output.txt}"
ARTIFACT_DIR="$ROOT_DIR/docs/benchmarks/artifacts"
SAMPLE_FILE="$ARTIFACT_DIR/section-v-sample-output.txt"
CHECKSUM_FILE="$ARTIFACT_DIR/SHA256SUMS"

export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

cd "$ROOT_DIR"

echo "== Section V reproduction =="
echo "root: $ROOT_DIR"
echo "target: $CARGO_TARGET_DIR"
echo "output: $OUTPUT_FILE"

echo "== Generate Section V artifacts =="
cargo run -j1 --features hazmat-real-mldsa,experimental-vss > "$OUTPUT_FILE"

echo "== Check regenerated artifact headings and headers =="
for required in \
  "===== ML-DSA-65 Single-Signer Baseline Comparison CSV =====" \
  "===== Small-Scale Consensus: LaTeX =====" \
  "===== Mid-Scale Distributed Fabric: Transcript JSONL =====" \
  "===== Adversarial WAN Cluster: Transcript CSV =====" \
  "===== Mid-Scale Distributed Fabric: Experimental VSS Complaint JSONL =====" \
  "profile,validators,threshold,trial,baseline_sign_ns,baseline_verify_ns,threshold_duration_ns,threshold_bytes,signature_bytes,latency_overhead_x" \
  "session_id,duration_ms,aborts,bandwidth_bytes" \
  "experiment,trial,attempt,direction,round,validator_index,block_height,session_id,encoded_len,frame_digest,production_statement_digest" \
  "experiment,trial,validator_index,evidence_kind,session_id,evidence_len,evidence_digest,production_vss_relation_statement_digest,evidence_hex"
do
  grep -Fq "$required" "$OUTPUT_FILE"
done

echo "== Verify checked-in sample checksum =="
(
  cd "$ARTIFACT_DIR"
  shasum -a 256 -c "$(basename "$CHECKSUM_FILE")"
)

echo "== Verify regenerated artifact schema =="
cargo test -j1 --features hazmat-real-mldsa,experimental-vss \
  --test section_v_sample_bundle \
  --test reproducibility_manifest \
  --test hazmat_mldsa65_simulation_grid

echo "== Regenerated output digest =="
shasum -a 256 "$OUTPUT_FILE"

if [[ "${REFRESH_SECTION_V_SAMPLE:-0}" == "1" ]]; then
  echo "== Refresh checked-in sample bundle =="
  cp "$OUTPUT_FILE" "$SAMPLE_FILE"
  (
    cd "$ARTIFACT_DIR"
    shasum -a 256 "$(basename "$SAMPLE_FILE")" > "$(basename "$CHECKSUM_FILE")"
    shasum -a 256 -c "$(basename "$CHECKSUM_FILE")"
  )
fi

echo "Section V reproduction checks passed."
