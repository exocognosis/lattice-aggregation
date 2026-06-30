# Large-Scale Simulation Benchmark Summary

This file is generated from deterministic simulation harness output. It is deterministic research telemetry, not security evidence, not real-world validator performance, and not production-readiness evidence.

- Generated at: `2026-06-30T16:57:43Z`
- Commit: `ed725a124b343c37d8336858dec4954a3b6a30e2`
- Branch: `codex/simulated-validator-baseline`
- Profile: `large`
- Trial rows: `28`
- Claim boundary: `deterministic research telemetry; not security evidence`
- CSV SHA-256: `ab4a39af69854efed309db926b3ec7aa6c6fa1520dd4687badb0b792ac82cf9f`

## Scenario Summary

| Experiment | Validators | Threshold | Trials | Malicious validator | Mean wall ms | Mean logical latency ms | Mean aborts | Mean bandwidth bytes |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| Large Baseline 3 | 3 | 2 | 10 | none | 2.9219 | 0.0 | 0.0 | 332 |
| Large Regional 64 | 64 | 43 | 10 | 44 | 2.9183 | 157.5 | 3.5 | 9277 |
| Large Continental 512 | 512 | 342 | 5 | 377 | 10.4558 | 4343.4 | 6.4 | 74421 |
| Large Validator Set 10000 | 10000 | 6667 | 3 | 9999 | 370.8444 | 144983.0 | 9.0 | 1453309 |

## Regeneration

```sh
python3 scripts/run_simulation_benchmarks.py --out docs/benchmarks/generated/latest-simulation
```
