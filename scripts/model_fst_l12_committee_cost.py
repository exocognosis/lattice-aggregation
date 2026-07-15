"""
FST-L12: committee-MPC cost model for exit-1 threshold ML-DSA-65.

Converts the FST-T4 existence result into an engineering budget: for a small
committee of k parties running the NONLINEAR core of ML-DSA-65 signing inside
honest-majority MPC, estimate (i) secure-operation count, (ii) bandwidth per
party per signature, (iii) wall-clock latency per signature, and test each
against real block-time / checkpoint-cadence targets.

Every constant is a labeled MODEL assumption (L12-M*). Push on any of them.
This is an order-of-magnitude engineering estimate, not a protocol proof.
"""
import math

# ============================================================================
# ML-DSA-65 structural facts (FIPS 204) -- not assumptions
# ============================================================================
N   = 256
K   = 6                      # rows of A ; w, r0 live in R_q^K
L   = 5                      # z lives in R_q^L
Q   = 8380417                # 23-bit prime
LOG2Q = math.log2(Q)         # ~22.99
OMEGA = 55                   # max hint weight (ML-DSA-65)
E_REP = 4.25                 # expected signing repetitions (FIPS 204 ML-DSA-65)

COEFFS_W  = K * N            # 1536  (decompose, r0-check, hint)
COEFFS_Z  = L * N            # 1280  (z-norm check)

# ============================================================================
# L12-M1: nonlinear core -> "comparison-equivalent" (CE) secure ops per ATTEMPT
#   Only the nonlinear parts need MPC. A*y and z=y+c*s1 are LOCAL on shares;
#   the challenge hash runs on w1 which is public in the signature (commit-
#   reveal, ~2 rounds, no hash-in-MPC). What remains:
# ============================================================================
CE_decompose = COEFFS_W          # Decompose(w) -> (w1, r0): ~1 CE / coeff
CE_znorm     = COEFFS_Z          # ||z||_inf < gamma1-beta : ~1 CE / coeff
CE_r0norm    = COEFFS_W          # ||r0||_inf < gamma2-beta: ~1 CE / coeff
CE_hint      = COEFFS_W          # MakeHint + weight<=omega: ~1 CE / coeff
CE_per_attempt = CE_decompose + CE_znorm + CE_r0norm + CE_hint   # ~5888
CE_per_sig     = CE_per_attempt * E_REP                          # ~25024

# L12-M2: one comparison-equivalent = M_CMP secure multiplications.
#   Bit-decomposition comparison over a 23-bit prime ~ log2(q) mults.
M_CMP = 24
MULT_per_sig = CE_per_sig * M_CMP

# ============================================================================
# L12-M3: bandwidth per secure multiplication, two honest-majority regimes.
#   Work in a ~64-bit ring for comparison gadgets (statistical slack): F=8 B.
# ============================================================================
F_BYTES = 8
def bw_per_mult_per_party(k, regime):
    if regime == "all2all":   # naive reshare: send 1 elt to each other party
        return (k - 1) * F_BYTES
    if regime == "king_dn":   # Damgard-Nielsen king-based: O(1) per party
        return 2 * F_BYTES
    raise ValueError

# ============================================================================
# L12-M4: circuit DEPTH (rounds) per attempt. Comparisons in a layer batch,
#   so rounds track depth, NOT operation count.
# ============================================================================
R_decompose = 6
R_challenge = 2      # commit-reveal of w1
R_norm      = 6      # batched range checks (z and r0 in parallel)
R_hint      = 4
ROUNDS_per_attempt = R_decompose + R_challenge + R_norm + R_hint   # 18

# L12-M5: WAN round-trip per synchronization round.
LAT = {"regional_50ms": 0.050, "global_200ms": 0.200}

# L12-M6: scheduling. Sequential = discover reject then retry (E_REP attempts
#   in series). Speculative = run S attempts in parallel, keep first accept
#   (latency of 1 attempt, bandwidth x S). S chosen so P(all reject) < 2^-20.
def spec_width():
    p_reject = 1 - 1 / E_REP           # per-attempt reject prob
    return math.ceil(math.log(2**-20) / math.log(p_reject))

S = spec_width()

# ============================================================================
# Report
# ============================================================================
print("=" * 74)
print("FST-L12 committee-MPC cost model for exit-1 threshold ML-DSA-65")
print("=" * 74)
print(f"nonlinear core: {CE_per_attempt:.0f} comparison-equiv/attempt x {E_REP} attempts")
print(f"            =  {CE_per_sig:.0f} CE/sig  x {M_CMP} mult/CE  =  {MULT_per_sig:,.0f} secure mults/sig")
print(f"circuit depth:  {ROUNDS_per_attempt} rounds/attempt")
print(f"speculative width S (P[all reject]<2^-20): {S} parallel attempts\n")

print(f"{'k':>4} | {'BW/party/sig (king-DN)':>22} | {'BW/party/sig (all-to-all)':>25}")
print("-" * 74)
for k in [8, 16, 32, 64, 128]:
    bw_king = MULT_per_sig * bw_per_mult_per_party(k, "king_dn")
    bw_a2a  = MULT_per_sig * bw_per_mult_per_party(k, "all2all")
    print(f"{k:>4} | {bw_king/1e6:>18.1f} MB | {bw_a2a/1e6:>21.1f} MB")

print("\nWall-clock latency per signature (independent of k; depth-bound):")
print(f"{'schedule':>16} | {'rounds':>7} | {'regional 50ms':>14} | {'global 200ms':>13} | {'BW multiplier':>13}")
print("-" * 74)
seq_rounds  = ROUNDS_per_attempt * E_REP
spec_rounds = ROUNDS_per_attempt
for name, rounds, mult in [("sequential", seq_rounds, 1), ("speculative", spec_rounds, S)]:
    reg = rounds * LAT["regional_50ms"]
    glo = rounds * LAT["global_200ms"]
    print(f"{name:>16} | {rounds:>7.0f} | {reg:>12.2f} s | {glo:>11.2f} s | x{mult:>11}")

print("\n" + "=" * 74)
print("GO / NO-GO against real cadences")
print("=" * 74)
targets = [
    ("Solana ~0.4s block",        0.4),
    ("Ethereum 12s slot",         12.0),
    ("Cosmos/Tendermint ~6s",     6.0),
    ("epoch cert ~6.4min (Eth)",  384.0),
    ("hourly checkpoint",         3600.0),
]
best_reg  = spec_rounds * LAT["regional_50ms"]     # best case: speculative + regional
worst_glo = seq_rounds  * LAT["global_200ms"]      # worst case: sequential + global
print(f"best-case latency  (speculative, regional): {best_reg:.2f} s")
print(f"worst-case latency (sequential, global):    {worst_glo:.2f} s\n")
for label, budget in targets:
    verdict = "GO (even worst-case)" if worst_glo <= budget else (
              "GO (needs speculative/regional)" if best_reg <= budget else "NO-GO")
    print(f"  {label:<28} budget {budget:>7.1f}s  ->  {verdict}")

print("\nBW sanity (king-DN, k=64, speculative x{}):".format(S))
bw = MULT_per_sig * bw_per_mult_per_party(64, "king_dn") * S / 1e6
print(f"  {bw:.0f} MB/party/sig. For an EPOCH certificate (not per block) this")
print(f"  is a once-per-epoch cost, not a per-transaction cost.")
