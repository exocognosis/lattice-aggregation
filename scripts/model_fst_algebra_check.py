"""
Sanity-check the two claims that decide whether 'threshold ML-DSA-65 -> one
standard-size signature under the UNMODIFIED verifier' is even coherent.

Toy ring R_q = Z_q[X]/(X^n + 1). We use the REAL ML-DSA-65 modulus q and a small
ring degree n so the arithmetic is honest but printable.

  (A) Is ML-DSA verification linear enough that an aggregate z, t "just works"?
  (B) What happens to coefficient sizes when you Shamir-reconstruct a SHORT secret
      across parties? (the 'Lagrange widens coefficients' obligation the repo lists
      as open)
"""

Q = 8380417              # ML-DSA / Dilithium modulus
N = 16                  # toy ring degree (real ML-DSA uses 256)
GAMMA1 = 1 << 19        # ML-DSA-65 masking bound (2^19)
BETA = 196              # ML-DSA-65 beta = tau*eta = 49*4
BOUND = GAMMA1 - BETA   # the exact bound the standard verifier enforces: ||z||_inf < BOUND

def cmod(x):
    """centered representative in (-q/2, q/2]"""
    x %= Q
    return x - Q if x > Q // 2 else x

def poly_add(a, b): return [(a[i] + b[i]) % Q for i in range(N)]
def poly_sub(a, b): return [(a[i] - b[i]) % Q for i in range(N)]

def poly_mul(a, b):
    """multiply in Z_q[X]/(X^N + 1)"""
    r = [0] * (2 * N)
    for i in range(N):
        if a[i] == 0: continue
        for j in range(N):
            r[i + j] += a[i] * b[j]
    out = [0] * N
    for i in range(N):
        out[i] = (r[i] - r[i + N]) % Q      # X^N = -1
    return out

def scal_mul(s, a): return [(s * a[i]) % Q for i in range(N)]
def inf_norm(a): return max(abs(cmod(x)) for x in a)

# deterministic pseudo-randomness (no Math.random needed, reproducible)
_st = 0x243F6A88
def rnd():
    global _st
    _st = (1103515245 * _st + 12345) & 0x7FFFFFFF
    return _st
def short_poly(bound):  # coeffs in [-bound, bound]
    return [rnd() % (2 * bound + 1) - bound for _ in range(N)]
def rand_poly():        # uniform coeffs in Z_q
    return [rnd() % Q for _ in range(N)]

print("=" * 70)
print("q =", Q, " ring degree N =", N)
print("standard ML-DSA-65 verifier requires ||z||_inf <", BOUND, "(= gamma1 - beta)")
print("=" * 70)

# ---------------------------------------------------------------------------
# (A) Verification-identity linearity.
#   Single signer: t = A*s1 + s2, w = A*y, z = y + c*s1.
#   Verifier recomputes  A*z - c*t  and expects it to equal  w - c*s2.
#   If this identity survives replacing (s1,s2,y) by AGGREGATES, aggregation is
#   at least algebraically coherent.
# ---------------------------------------------------------------------------
K, L = 2, 2
A  = [[rand_poly() for _ in range(L)] for _ in range(K)]
s1 = [short_poly(2) for _ in range(L)]
s2 = [short_poly(2) for _ in range(K)]
y  = [short_poly(3) for _ in range(L)]
c  = short_poly(1)                      # challenge: tiny coeffs (real c is tau=+-1s)

def matvec(M, v):
    return [ [0]*N if False else
             __import__('functools').reduce(poly_add, (poly_mul(M[r][j], v[j]) for j in range(len(v))))
             for r in range(len(M)) ]

t   = [poly_add(matvec(A, s1)[r], s2[r]) for r in range(K)]     # public key
w   = matvec(A, y)
z   = [poly_add(y[j], poly_mul(c, s1[j])) for j in range(L)]

lhs = [poly_sub(matvec(A, z)[r], poly_mul(c, t[r])) for r in range(K)]  # A*z - c*t
rhs = [poly_sub(w[r], poly_mul(c, s2[r])) for r in range(K)]            # w - c*s2
identity_ok = all(lhs[r] == rhs[r] for r in range(K))
print("\n(A) verification identity  A*z - c*t == w - c*s2 :", identity_ok)
print("    -> the map is LINEAR in (s1,s2,y); aggregation is algebraically coherent.")

# ---------------------------------------------------------------------------
# (B) The catch: shortness is NOT linear-friendly.
#   Shamir-share a SHORT secret s1 across n=5 parties, threshold t=3.
#   Reconstruction  sum_i lambda_i * share_i = s1  is EXACT (Lemma 3, true).
#   But look at the sizes of the shares and of a Lagrange-weighted mask sum.
# ---------------------------------------------------------------------------
def lagrange_at_0(active):
    lam = {}
    for i in active:
        num = den = 1
        for j in active:
            if j == i: continue
            num = (num * (-j)) % Q
            den = (den * (i - j)) % Q
        lam[i] = (num * pow(den, Q - 2, Q)) % Q
    return lam

def build_sharing(indices, secret, T):
    coeffs = [secret] + [rand_poly() for _ in range(T - 1)]   # P(Y), P(0)=secret
    def P(x):
        acc, xp = [0]*N, 1
        for a in coeffs:
            acc = poly_add(acc, scal_mul(xp % Q, a)); xp = (xp * x) % Q
        return acc
    return {i: P(i) for i in indices}

def reconstruct(active, shares):
    lam = lagrange_at_0(active)
    recon = [0]*N
    for i in active:
        recon = poly_add(recon, scal_mul(lam[i], shares[i]))
    return recon, lam

secret = short_poly(2)                       # ||secret||_inf <= 2  (a real ML-DSA s1 coeff)
T = 3
def centered(p): return [cmod(x) for x in p]

print("\n(B) Shamir over R_q is EXACT but does not preserve shortness.")
print("    ||secret||_inf =", inf_norm(secret), "(short, as required for an ML-DSA key)")

# --- regime 1: tiny consecutive validator indices {1,2,3} ---
sh1 = build_sharing(range(1, 6), secret, T)
r1, lam1 = reconstruct([1, 2, 3], sh1)
print("\n  regime 1  active set = {1,2,3} (tiny consecutive ids)")
print("    reconstruction exact:", centered(r1) == centered(secret))
print("    Lagrange coeffs |lambda_i| =", sorted(abs(cmod(v)) for v in lam1.values()), "  <- small integers!")
y1 = {i: short_poly(3) for i in [1, 2, 3]}
m1 = [0]*N
for i in [1, 2, 3]: m1 = poly_add(m1, scal_mul(lam1[i], y1[i]))
print("    ||sum lambda_i * y_i||_inf =", inf_norm(m1), " (stays tiny -- masks survive)")

# --- regime 2: spread-out large validator ids (realistic for a 10,000-set) ---
ids = [1_000_003, 4_500_271, 7_777_777]      # arbitrary distinct large field elements
sh2 = build_sharing(ids, secret, T)
r2, lam2 = reconstruct(ids, sh2)
print("\n  regime 2  active set = large spread ids", ids)
print("    reconstruction exact:", centered(r2) == centered(secret))
print("    Lagrange coeffs |lambda_i| =", sorted(abs(cmod(v)) for v in lam2.values()), "  <- full-size ~q/2!")
y2 = {i: short_poly(3) for i in ids}
m2 = [0]*N
for i in ids: m2 = poly_add(m2, scal_mul(lam2[i], y2[i]))
print("    each ||y_i||_inf =", max(inf_norm(y2[i]) for i in ids), " but ||sum lambda_i*y_i||_inf =", inf_norm(m2))
print("    standard verifier bound (gamma1 - beta) =", BOUND)
print("    -> Lagrange-weighted mask exceeds the bound by ~%.1fx  => z REJECTED." % (inf_norm(m2)/BOUND))
print("\n    Takeaway: whether naive t-of-n aggregation even fits the standard bound")
print("    depends on the active-set indices. Real threshold lattice schemes must")
print("    engineer the mask combination so the aggregate stays short REGARDLESS of A")
print("    -- exactly the 'epsilon_mask / rejection-equivalence' obligation left open.")
print("=" * 70)
