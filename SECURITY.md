# Security Policy

## Research Status

Lattice Aggregation is not production-ready cryptography. The default backend is a deterministic simulation backend intended for protocol and integration tests. It does not produce or verify real ML-DSA signatures.

Do not use this repository to protect funds, production validator keys, consensus safety, or confidential material without an independent cryptographic implementation review and security audit.

## Reporting Issues

Please report security issues privately through GitHub's private vulnerability reporting for `exocognosis/lattice-aggregation` if it is enabled. If private reporting is unavailable, open a minimal public issue that says a vulnerability report is needed without disclosing exploit details.

Useful reports include:

- transcript-binding flaws
- validator attribution or duplicate-detection bypasses
- malformed wire-message handling
- denial-of-service paths in actor/session management
- unsafe production-readiness claims
- accidental secret exposure in logs, debug output, fixtures, or docs

## Scope

In scope:

- Rust library and binary code in `src/`
- tests and fixtures
- audit and cryptography documentation
- GitHub Actions configuration

Out of scope:

- claims that the simulation backend is not production cryptography
- vulnerabilities requiring production deployment of the simulation backend despite the documented warnings

## Disclosure

Please allow time for triage before public disclosure. This project is research-oriented, so some findings may result in documentation changes, explicit non-goal statements, or removal of unsafe claims rather than immediate production patches.
