#!/usr/bin/env python3
"""Executable feasibility model for the distributed-mask MPC route.

This script turns the ratified epsilon-mask fork decision into a reproducible
engineering estimate. It models the small-committee MPC route that can make a
joint ML-DSA-65 mask exactly ExpandMask-distributed while preserving the
standard verifier. It does not implement MPC, prove security, or claim theorem
closure.
"""

import argparse
import json
import math


SCHEMA = "lattice-aggregation:distributed-mask-mpc-feasibility-model:v1"
STATUS = "feasibility_model_only"
CLAIM_BOUNDARY = "research feasibility model; not a protocol proof"
SELECTED_ROUTE = "exit_1_heavy_mpc_distributed_expandmask"
SELECTED_PROFILE = "ML-DSA-65 small-committee MPC mask route"

CLAIM_FLAG_KEYS = (
    "claims_theorem_closure",
    "claims_criterion_met",
    "claims_selected_backend_proof_closure",
    "claims_epsilon_mask_closed",
    "claims_rejection_distribution_preservation",
    "claims_standard_verifier_compatibility_complete",
    "claims_production_threshold_mldsa_security",
    "claims_cavp_acvts_validation",
    "claims_fips_validation",
)

# ML-DSA-65 structure.
N = 256
K = 6
L = 5
Q = 8_380_417
GAMMA1 = 1 << 19
GAMMA2 = (Q - 1) // 32
TAU = 49
ETA = 4
BETA = TAU * ETA
Z_BOUND = GAMMA1 - BETA
R0_BOUND = GAMMA2 - BETA
OMEGA = 55
EXPECTED_REPETITIONS = 4.25

# Same order-of-magnitude model as FST-L12, kept local so the feasibility
# artifact has a stable JSON-producing command.
COEFFS_W = K * N
COEFFS_Z = L * N
CE_DECOMPOSE = COEFFS_W
CE_Z_NORM = COEFFS_Z
CE_R0_NORM = COEFFS_W
CE_HINT = COEFFS_W
CE_PER_ATTEMPT = CE_DECOMPOSE + CE_Z_NORM + CE_R0_NORM + CE_HINT
MULTS_PER_COMPARISON_EQUIV = 24
FIELD_BYTES = 8
ROUNDS_PER_ATTEMPT = 18


def false_claim_flags():
    return {key: False for key in CLAIM_FLAG_KEYS}


def speculative_width():
    """Return parallel attempts so Pr[all reject] < 2^-20."""
    reject_probability = 1 - 1 / EXPECTED_REPETITIONS
    return math.ceil(math.log(2**-20) / math.log(reject_probability))


def bandwidth_per_mult_per_party(k, regime):
    if regime == "king_dn":
        return 2 * FIELD_BYTES
    if regime == "all_to_all":
        return (k - 1) * FIELD_BYTES
    raise ValueError(f"unknown regime: {regime}")


def committee_result(k):
    ce_per_signature = CE_PER_ATTEMPT * EXPECTED_REPETITIONS
    secure_multiplications = ce_per_signature * MULTS_PER_COMPARISON_EQUIV
    king_bytes = secure_multiplications * bandwidth_per_mult_per_party(k, "king_dn")
    all_to_all_bytes = secure_multiplications * bandwidth_per_mult_per_party(
        k, "all_to_all"
    )
    return {
        "committee_size": k,
        "honest_majority_faults_tolerated": (k - 1) // 2,
        "secure_multiplications_per_signature": round(secure_multiplications),
        "king_dn_bandwidth_mb_per_party_per_signature": round(king_bytes / 1_000_000, 1),
        "all_to_all_bandwidth_mb_per_party_per_signature": round(
            all_to_all_bytes / 1_000_000, 1
        ),
    }


def latency_summary():
    width = speculative_width()
    sequential_rounds = ROUNDS_PER_ATTEMPT * EXPECTED_REPETITIONS
    speculative_rounds = ROUNDS_PER_ATTEMPT
    return {
        "rounds_per_attempt": ROUNDS_PER_ATTEMPT,
        "expected_repetitions": EXPECTED_REPETITIONS,
        "speculative_width_for_2^-20_all_reject": width,
        "sequential": {
            "rounds": round(sequential_rounds, 2),
            "regional_50ms_seconds": round(sequential_rounds * 0.050, 2),
            "global_200ms_seconds": round(sequential_rounds * 0.200, 2),
            "bandwidth_multiplier": 1,
        },
        "speculative": {
            "rounds": speculative_rounds,
            "regional_50ms_seconds": round(speculative_rounds * 0.050, 2),
            "global_200ms_seconds": round(speculative_rounds * 0.200, 2),
            "bandwidth_multiplier": width,
        },
    }


def go_no_go(latency):
    best_case = latency["speculative"]["regional_50ms_seconds"]
    worst_case = latency["sequential"]["global_200ms_seconds"]
    targets = [
        ("solana_0_4s_block", 0.4),
        ("cosmos_tendermint_6s_block", 6.0),
        ("ethereum_12s_slot", 12.0),
        ("epoch_certificate_6_4min", 384.0),
        ("hourly_checkpoint", 3600.0),
    ]
    results = []
    for target, budget in targets:
        if worst_case <= budget:
            verdict = "go_even_worst_case"
        elif best_case <= budget:
            verdict = "go_requires_speculative_regional"
        else:
            verdict = "no_go"
        results.append(
            {
                "target": target,
                "budget_seconds": budget,
                "best_case_seconds": best_case,
                "worst_case_seconds": worst_case,
                "verdict": verdict,
            }
        )
    return results


def build_model():
    latency = latency_summary()
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "status": STATUS,
        "evidence_status": "evidence_present_unclosed",
        "overall_verdict_preserved": "partially_proven",
        "criterion_status_preserved": {
            "aggregate_mask_distribution": "partially_met",
            "aggregate_rejection_equivalence": "partially_met",
            "abort_retry_bias": "partially_met",
            "partial_contribution_soundness": "partially_met",
            "unauthorized_aggregate_reduction": "partially_met",
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "claim_flags": false_claim_flags(),
        "selected_route": SELECTED_ROUTE,
        "selected_profile": SELECTED_PROFILE,
        "ml_dsa_65_parameters": {
            "n": N,
            "k": K,
            "l": L,
            "q": Q,
            "gamma1": GAMMA1,
            "gamma2": GAMMA2,
            "tau": TAU,
            "eta": ETA,
            "beta": BETA,
            "z_bound": Z_BOUND,
            "r0_bound": R0_BOUND,
            "omega": OMEGA,
        },
        "mpc_scope": {
            "inside_mpc": [
                "joint ExpandMask-uniform y sampling",
                "secret-shared z = y + c*s1",
                "Decompose(w) / HighBits(w)",
                "z infinity-norm predicate",
                "r0 infinity-norm predicate",
                "MakeHint and omega predicate",
            ],
            "outside_mpc_public_or_linear": [
                "A*y and A*z linear share operations",
                "commit-reveal of w1",
                "Fiat-Shamir challenge over public transcript",
                "final FIPS 204 signature packing",
                "unmodified ML-DSA-65 verification",
            ],
        },
        "operation_model": {
            "comparison_equivalents_per_attempt": CE_PER_ATTEMPT,
            "comparison_equivalents_per_signature": round(
                CE_PER_ATTEMPT * EXPECTED_REPETITIONS, 2
            ),
            "secure_multiplications_per_signature": round(
                CE_PER_ATTEMPT
                * EXPECTED_REPETITIONS
                * MULTS_PER_COMPARISON_EQUIV
            ),
            "comparison_equivalent_components": {
                "decompose_w": CE_DECOMPOSE,
                "z_norm": CE_Z_NORM,
                "r0_norm": CE_R0_NORM,
                "hint_and_omega": CE_HINT,
            },
            "model_assumption": (
                "order-of-magnitude comparison-equivalent model; replace with "
                "exact circuit counts before proof review"
            ),
        },
        "committee_results": [committee_result(k) for k in (8, 16, 32, 64, 128)],
        "latency": latency,
        "go_no_go": go_no_go(latency),
        "recommended_prototype": {
            "committee_size": 64,
            "cadence": "epoch_certificate",
            "schedule": "sequential",
            "multiplication_protocol": "king_dn",
            "explicit_non_goal": "per_block_high_frequency_consensus_signing",
        },
        "non_closure_guards": [
            "does not implement distributed MPC",
            "does not close epsilon_mask",
            "does not prove rejection-distribution preservation",
            "does not claim production threshold ML-DSA security",
            "does not claim CAVP/ACVTS or FIPS validation",
        ],
    }


def render_text(model):
    lines = [
        "distributed-mask MPC feasibility model",
        f"status: {model['status']}",
        f"route: {model['selected_route']}",
        f"claim_boundary: {model['claim_boundary']}",
        "claim_flags_all_false: "
        + str(not any(model["claim_flags"].values())).lower(),
        "",
        "go/no-go:",
    ]
    for result in model["go_no_go"]:
        lines.append(
            f"- {result['target']}: {result['verdict']} "
            f"(best={result['best_case_seconds']}s, "
            f"worst={result['worst_case_seconds']}s)"
        )
    return "\n".join(lines) + "\n"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Model distributed-mask MPC feasibility for ML-DSA-65."
    )
    parser.add_argument("--json", action="store_true", help="emit canonical JSON")
    return parser.parse_args()


def main():
    args = parse_args()
    model = build_model()
    if args.json:
        print(json.dumps(model, indent=2, sort_keys=True))
    else:
        print(render_text(model), end="")


if __name__ == "__main__":
    main()
