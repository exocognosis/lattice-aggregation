"""
Numbers for FST-T5 (flooding-family infeasibility at standard ML-DSA-65 params).

Two branches of the additive-response family F:
  (a) statistical flooding, no per-party rejection:
      required sigma_min = ||Delta||_2 * sqrt(Q_s * lambda_R)   (Renyi-style, optimistic)
      vs available budget gamma1 - beta.
  (b) per-party rejection sampling (each z_i box-uniform, individually hiding):
      aggregate norm grows ~ sqrt(t); expected total attempts
      E(t) = min over local gamma1_loc of 1 / (alpha_loc^t * P_agg).

All Gaussian/independence approximations are MODEL assumptions (FST-M1..M3 in doc).
Only the z-bound is enforced; the gamma2 low-bits/hint checks would only tighten.
"""
import math

# --- ML-DSA-65 (FIPS 204) ---
Q       = 8380417
GAMMA1  = 1 << 19          # 524288
TAU     = 49
ETA     = 4
BETA    = TAU * ETA        # 196
ELL     = 5
DIM     = ELL * 256        # 1280 coefficients in z
B       = GAMMA1 - BETA    # 524092 verifier bound

def Qfun(x):  # Gaussian upper tail
    return 0.5 * math.erfc(x / math.sqrt(2.0))

# ||c*s1_i||_2 estimate: per-coeff of c*s1 is sum of TAU terms, each +-Unif{-eta..eta}
# E[s^2] for s uniform on {-4..4} = 60/9
Es2 = (2 * (16 + 9 + 4 + 1)) / 9.0
per_coeff_var = TAU * Es2
DELTA2 = math.sqrt(per_coeff_var * DIM)   # l2 norm of the hidden shift across z
print(f"ML-DSA-65: gamma1={GAMMA1}, beta={BETA}, B=gamma1-beta={B}, dim(z)={DIM}")
print(f"||c*s1||_2 (model estimate) = {DELTA2:.0f}\n")

# ---------- Branch (a): pure flooding ----------
print("Branch (a): statistical flooding (no per-party rejection)")
print(f"{'Q_s (queries)':>14} | {'sigma_min = ||D||2*sqrt(Qs)':>26} | {'sigma_min/B':>11} | verdict")
print("-" * 72)
for logQs in [64, 45, 30, 20, 10]:
    sigma_min = DELTA2 * math.sqrt(2.0 ** logQs)      # lambda_R = 1: MOST optimistic
    ratio = sigma_min / B
    verdict = "dead (any t)" if ratio > 1 else f"t_max ~ {int((B/(sigma_min*3.27))**2)}"
    print(f"{'2^'+str(logQs):>14} | {sigma_min:>26.3e} | {ratio:>11.1f} | {verdict}")
print("  (lambda_R = 1 is maximally generous to the protocol; any real Renyi proof")
print("   multiplies sigma_min upward. Raccoon grew q to ~2^49 to buy this room.)\n")

# ---------- Branch (b): per-party rejection ----------
print("Branch (b): per-party rejection sampling, aggregate z = sum z_i")
print("  alpha_loc = exp(-DIM*beta/g)  (per-party z-check acceptance, local bound g)")
print("  sigma_t   = (g - beta) * sqrt(t/3);  P_agg = (1 - 2Q(B/sigma_t))^DIM")
print(f"{'t':>6} | {'best g (gamma1_loc)':>19} | {'alpha_loc^t':>11} | {'P_agg':>9} | {'E[attempts]':>12}")
print("-" * 72)
results = {}
for t in [2, 3, 4, 5, 6, 8, 10, 16, 100, 10000]:
    best = None
    # search local bound g over a wide grid
    for gexp in range(200, 2000):
        g = int(GAMMA1 * gexp / 1000.0)
        if g <= BETA + 1:
            continue
        alpha_loc = math.exp(-DIM * BETA / g)
        sigma_t = (g - BETA) * math.sqrt(t / 3.0)
        pc = 2 * Qfun(B / sigma_t)
        if pc >= 1.0:
            continue
        p_agg = (1 - pc) ** DIM
        denom = (alpha_loc ** t) * p_agg
        if denom <= 0:
            continue
        E = 1.0 / denom
        if best is None or E < best[0]:
            best = (E, g, alpha_loc ** t, p_agg)
    if best:
        E, g, at, pa = best
        results[t] = E
        Estr = f"{E:.2e}" if E > 1e4 else f"{E:.1f}"
        print(f"{t:>6} | {g:>19} | {at:>11.2e} | {pa:>9.3f} | {Estr:>12}")
    else:
        print(f"{t:>6} | {'-':>19} | {'-':>11} | {'-':>9} | {'infeasible':>12}")

print()
for t in [4, 6, 8]:
    if t in results:
        print(f"  t={t}: expected ~{results[t]:.2e} full interactive attempts per signature")
print("  -> exp(Theta(t)) wall. Consistent with published exact-ML-DSA threshold")
print("     schemes topping out around 6 parties (NIST PQC 2025).")
