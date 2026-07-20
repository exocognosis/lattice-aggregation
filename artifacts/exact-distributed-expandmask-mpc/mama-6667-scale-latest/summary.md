# Malicious-MAMA 6,667-party scale run

- Status: `blocked_fail_closed`
- Classification: `local_simulation_or_preflight_only`
- Real cryptographic parties completed: `false`
- Theorem closure claimed: `false`
- Bounded local probe passed: `false`

## Measured basis

- Measured parties: `2`
- Security parameter: `40`
- Measured global data: `3268.97 MB`
- Measured maximum per-party data: `1634.5 MB`
- Measured protocol rounds: `18785`
- Measured benchmark time: `14.4249 seconds`

## Scale planning bounds

- Optimistic total traffic floor: `10897211.5 MB`
- Pairwise total traffic extrapolation: `72640811859.0 MB`
- All-to-all peer pairs: `22221111`
- Local process hard limit: `4000`
- Required party processes: `6667`

## Blockers

- signed 6,667-party inventory is absent
- local hard process limit 4000 is below 6667 parties
- preflight detected one local host; local interfaces, ports, or processes cannot represent 6,667 distinct custodial signer hosts
- distributed CPU, memory, bandwidth, and round-latency capacity has not been reserved and measured
- 6,667 production custody roots and signer endpoints are not available in this environment

These results are preflight and bounded-probe evidence only. A local collection
of labels, ports, or subprocesses is not 6,667 distinct custodial signers.
