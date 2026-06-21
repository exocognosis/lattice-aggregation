# Large-Scale Simulation Benchmark Summary

This file is generated from deterministic simulation harness output. It is deterministic research telemetry, not security evidence, not real-world validator performance, and not production-readiness evidence.

- Generated at: `2026-06-21T14:19:32Z`
- Commit: `7eff8011a16d042d9233c8b13a62dbe214c4f2fa`
- Branch: `codex/epsilon-prefilter-guardrails`
- Profile: `large`
- Trial rows: `28`
- Claim boundary: `deterministic research telemetry; not security evidence`
- CSV SHA-256: `d81947bc708546abb0d7a6a9a3e85acf1df3076549e08da5ca9658ced5e7127a`

## Scenario Summary

| Experiment | Validators | Threshold | Trials | Malicious validator | Mean wall ms | Mean logical latency ms | Mean aborts | Mean bandwidth bytes |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| Large Baseline 3 | 3 | 2 | 10 | none | 2.2337 | 0.0 | 0.0 | 332 |
| Large Regional 64 | 64 | 43 | 10 | 44 | 2.5804 | 157.5 | 3.5 | 9277 |
| Large Continental 512 | 512 | 342 | 5 | 377 | 11.9019 | 4343.4 | 6.4 | 74421 |
| Large Validator Set 10000 | 10000 | 6667 | 3 | 9999 | 486.6441 | 144983.0 | 9.0 | 1453309 |

## Regeneration

```sh
python3 scripts/run_simulation_benchmarks.py --out docs/benchmarks/generated/latest-simulation
```
