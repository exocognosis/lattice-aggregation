# Exact Distributed ExpandMask MPC

## Target

The production target is one standard 3,309-byte ML-DSA-65 signature produced
from a 6,667-signer subset of a 10,000-validator epoch, verified by an
unmodified FIPS 204 verifier. The 10,000/6,667 Ed25519 authorization layer is
not a substitute for 6,667 ML-DSA secret-share contributions.

## Selected construction

The selected exact-mask path uses MP-SPDZ with malicious dishonest-majority
security and multiple MACs (MAMA, built on MASCOT/SPDZ). The circuit in
`mpc/Programs/Source/mldsa65_expandmask.mpc` computes, without opening any
secret intermediate:

1. `rhopp = SHAKE256(K || rnd || mu, 64)` from XOR-shared `K` and `rnd`;
2. the five FIPS 204 `ExpandMask` SHAKE256 streams for ML-DSA-65;
3. every 20-bit packed coefficient and `gamma1 - encoded` conversion; and
4. one additive arithmetic mask share per signer modulo `q = 8380417`.

The program reveals only a random additive share to each signer. The joint
`K`, `rnd`, `rhopp`, packed mask bytes, and mask polynomial remain secret. A
coalition missing any one output share cannot reconstruct the mask.

This is preferred over the repository's existing summed-uniform nonce path:
that path follows an Irwin-Hall distribution and does not satisfy exact FIPS
`ExpandMask`. It is also preferred over a small honest-majority MPC service,
which would weaken the 6,667-of-10,000 corruption threshold.

## Fail-closed integration boundary

Compilation alone does not set `exact_distributed_expand_mask` or
`exact_expand_mask_mpc` true. Promotion requires all of the following:

- a pinned, clean MP-SPDZ source commit;
- malicious MAMA execution with 6,667 distinct signer processes;
- authenticated private inputs and private per-signer output files;
- DKG-bound shares of `K` rather than synthetic XOR-share fixtures;
- transcript, preprocessing, binary, environment, and output-share digests;
- exact byte-equivalence checks against FIPS 204 vectors without opening the
  production joint mask;
- adversarial abort, malformed-share, replay, and output-substitution checks;
- independent cryptographic review of the circuit and share-custody boundary.

The candidate builder is:

```sh
python3 scripts/build_exact_expandmask_mpc_candidate.py \
  --mp-spdz-root /absolute/path/to/MP-SPDZ \
  --compile-signers 2
```

The two-signer compile is a compiler-contract check only. It is not a
production execution or theorem-closure artifact.

## External runtime boundary

MP-SPDZ is intentionally not vendored into this repository. Operators provide
a separately reviewed checkout through `MP_SPDZ_ROOT`; the candidate manifest
records its commit. MP-SPDZ itself states that its framework has not undergone
the security review required for critical production code, so independent
review remains mandatory even after a successful distributed run.
