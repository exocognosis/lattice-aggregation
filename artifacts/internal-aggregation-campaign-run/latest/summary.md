# Internal Aggregation Campaign Runner

- Runner status: `blocked_capture_validation_failed`
- Official capture written: `false`
- Official validation written: `false`
- Command origin: `outside_repo_executable_or_script`
- Capture SHA-256: `ab155c33b025e381b3c2eeb88f8da31d3ca76b0d80818983ed0cdf0b2d5a5ea0`
- Validation status: `blocked_fail_closed`
- Validated executions: `24`

## Blockers

- capture evidence class mismatch: expected 'actual_distributed_threshold_mldsa_campaign'
- capture execution mode mismatch: expected 'actual_distributed_threshold_backend'
- case k08-abort-001 abort_recorded mismatch: expected True
- case k08-abort-001 protocol outcome mismatch: expected 'aborted'
- case k08-accepted-001 aggregate emission mismatch: expected True
- case k08-accepted-001 aggregate signature digest invalid
- case k08-accepted-001 protocol outcome mismatch: expected 'accepted'
- case k08-accepted-001 signature length mismatch: expected 3309
- case k08-accepted-001 standard verifier invocation mismatch: expected True
- case k08-accepted-001 standard verifier result mismatch: expected True
- case k08-accepted-001 verifier mutation rejection must be true: message
- case k08-accepted-001 verifier mutation rejection must be true: public_key
- case k08-accepted-001 verifier mutation rejection must be true: signature
- case k08-malicious-share-001 malicious_share_rejected mismatch: expected True
- case k08-malicious-share-001 protocol outcome mismatch: expected 'rejected'
- case k08-rejected-001 protocol outcome mismatch: expected 'rejected'
- case k08-rejected-001 rejection_predicate_recorded mismatch: expected True
- case k08-retry-001 aggregate emission mismatch: expected True
- case k08-retry-001 aggregate signature digest invalid
- case k08-retry-001 protocol outcome mismatch: expected 'accepted'
- ... 129 additional blockers recorded in run-manifest.json

This runner can promote only internal campaign evidence. It does not
claim theorem closure, production threshold security, FIPS validation,
or independent cryptographic review completion.
