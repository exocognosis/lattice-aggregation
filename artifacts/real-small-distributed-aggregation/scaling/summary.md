# Distributed ML-DSA-65 aggregation - real scaling curve (N=4..8)

Machine: 8 CPU / 16 GiB (macOS (Darwin 25.5.0)); MP-SPDZ commit `6a2256e327b507918859f605735543bb32a39d9d`; runtime `mama-party.x` (malicious, dishonest-majority); security_parameter = 40.

`\*` N=3 is a prior reference run, shown for context only (RSS was not sampled for it).

| N | status | wall_s | mpc_s | global_MB | per_party_MB | peak_RSS_sum_MB | accepted | signature_sha256 |
|---|--------|--------|-------|-----------|--------------|-----------------|----------|------------------|
| 3\* | ref | 86.02 | 79.37 | 12067.1 | 4022.4 | (not sampled) | true | 6490a294... |
| 4 | ok | 253.73 | 157.28 | 28353.0 | 7088.26 | 3455.2 | true | e1476ef9... |
| 5 | ok | 308.88 | 238.84 | 54710.2 | 10942.02 | 5696.4 | true | e1476ef9... |
| 6 | failed | 159.66 | 118.73 | None | None | 5533.4 | false | - |

Columns: `wall_s` = full orchestrator wall time (emit + compile + MPC + sign); `mpc_s` = pure MP-SPDZ time from the party-0 log; `global_MB`/`per_party_MB` = real 'Global/Data sent' from the party logs; `peak_RSS_sum_MB` = max summed resident memory of the N `mama-party.x` processes from `ps` sampling; `accepted` = real `standard_verifier_accepted` from that N's manifest.

Note on identical signatures: N=4 and N=5 emit the SAME signature sha256 because both selected the same kappa=0-accepting seed (5) for the same message, and the threshold signature is deterministic in (seed, rnd, message, key). The MPC over N parties computes additive shares of the SAME ExpandMask mask, which reconstructs identically regardless of how many parties share it -- so adding parties changes the COST (28.4 GB -> 54.7 GB global traffic) but not the OUTPUT. Each row's acceptance is nonetheless an independent, real `verify_standard` call on that run's produced signature. (The N=3 reference differs because it used a different message/seed.)

## Where the box saturates

The 16 GiB / 8-CPU box saturates at N=6: the run failed with `MPC run not clean at N=6: all-pairs OT traffic exhausted OS network buffers (ENOBUFS 'No buffer space available' -> OT-thread fatal buffer desync) under memory pressure (swap peaked 10.7 GB); exit codes [-13,1,1,1,1,1], no outputs, no completion. Real saturation, not a clean abort.` (peak summed party RSS 5533.4 MB, swap used rose to 10705.9 MB). Every N below it (4, 5) completed with a real accepted signature; the sweep was stopped early at the first hard failure rather than continuing to hammer the machine. This is a real, quantified wall: a dishonest-majority MPC whose all-pairs preprocessing memory and traffic grow super-linearly cannot host many signers on a single commodity box.

## Extrapolation to the 6,667-party target (LABELLED EXTRAPOLATION)

EXTRAPOLATION (power-law log-log fit over the measured OK points, NOT a measurement): global traffic ~ N^2.946 (2 points), which projects to ~8.78e+07 TB of global data for a single 6667-party MPC run. Peak resident memory ~ N^2.241 projects to ~5.58e+07 GiB of summed party RSS -- vastly beyond the 16 GiB of this box. This confirms that a single 6667-signer MPC is infeasible on one commodity machine and must be sharded across a fleet / committee structure; the numbers are a fitted projection, not observed.

