# Contributing

Thanks for helping improve Lattice Aggregation.

This repository is a research scaffold for threshold post-quantum signature aggregation. Contributions are welcome, but cryptographic claims need to stay exact and test-backed.

## Development

Run the full test suite before opening a pull request:

```sh
cargo test
```

Format code with:

```sh
cargo fmt
```

Check lints when available:

```sh
cargo clippy --all-targets --all-features -- -D warnings
```

## Pull Request Expectations

- Keep changes focused and explain the protocol or integration behavior being changed.
- Add or update tests for validation rules, transcript changes, state transitions, and wire-format behavior.
- Update docs when a change affects threat model, audit surface, feature gates, or production-readiness claims.
- Do not describe simulated signatures as real ML-DSA signatures.
- Avoid adding dependencies to cryptographic or consensus-critical paths without explaining the trust and maintenance tradeoffs.

## Cryptography Review Bar

Changes touching cryptographic boundaries should identify:

- which assumptions changed
- which transcript fields are bound
- which inputs are attacker-controlled
- which outputs are deterministic test artifacts versus production cryptographic outputs
- which tests or review notes cover the change
