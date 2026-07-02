# P1 Nonce Producer Selection

Status: `p1_nonce_producer_route_selected`, not theorem closure.

Date: 2026-07-02

## Scope and Claim Boundary

This document selects the next concrete producer route for replacing the
current hazmat PRF-output oracle used by the distributed-nonce comparator.
The selected route is:

```text
FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG P1
```

The selected profile is `P1 TEE/HSM coordinator`. It is the closest match to
this repository's current Profile P1 direction because it targets standard-size
ML-DSA-65 signatures accepted by unmodified FIPS 204 verifiers while using a
coordinator-assisted TEE/HSM trust assumption.

This is a route-selection artifact only. It is not theorem closure, not selected-backend proof closure, not production threshold ML-DSA security, not rejection-distribution preservation, not completed standard-verifier
compatibility, not CAVP/ACVTS validation, and not FIPS validation.

The machine-readable companion is
[`p1-nonce-producer-selection.json`](p1-nonce-producer-selection.json).

## Replacement Target

The current distributed-nonce-prf-output-shares comparator mode still derives
its nonce PRF output from:

```text
derive_mldsa65_centralized_nonce_prf_output_from_expanded_secret_key
```

That function is treated here as the hazmat PRF-output oracle. The replacement
target is a reviewed P1 Shamir nonce-DKG producer whose artifact fills:

```text
distributed_nonce_producer_artifact_digest
```

Current slot status: `required_unclosed`.

## Required Backend Artifacts

The reviewed producer artifact must bind at least these fields before the
distributed-nonce comparator output can be treated as reviewed producer
evidence:

- `source_reference_digest`
- `selected_profile_binding_digest`
- `coordinator_attestation_digest`
- `shamir_nonce_dkg_transcript_digest`
- `active_set_digest`
- `pairwise_mask_seed_commitment_digest`
- `nonce_share_commitment_digest`
- `attempt_binding_digest`
- `abort_accountability_digest`
- `standard_verifier_bridge_digest`
- `external_review_digest`

The artifact must also preserve the existing claim boundary:
`conformance/proof-review evidence only`.

## Source-Backed Ranking

1. `FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG` is the selected
   P1 route. The current arXiv record identifies the v6 title, Shamir nonce
   DKG technique, arbitrary-threshold aim, P1 TEE/HSM coordinator profile, and
   unmodified-verifier target:
   https://arxiv.org/abs/2601.20917
2. `Quorus: Efficient, Scalable Threshold ML-DSA Signatures from MPC` is a
   later P2/MPC candidate because it is standard-verifier compatible and
   scalable, but it is not the shortest P1 coordinator-assisted oracle
   replacement:
   https://www.usenix.org/conference/usenixsecurity26/presentation/bienstock
3. `Efficient Threshold ML-DSA` / Mithril-style short-sharing work is a
   small-committee fallback because it is ML-DSA compatible but the primary
   public description targets up to six parties:
   https://www.usenix.org/conference/usenixsecurity26/presentation/celi
4. NIST's Multi-Party Threshold Cryptography page is the process context for
   submitted threshold material and future package writeups:
   https://csrc.nist.gov/Projects/threshold-cryptography/tcall-1

## Next Implementation Gate

The next implementation gate is not another deterministic simulation. It is a
producer artifact gate that rejects any distributed-nonce comparator result
whose producer is `hazmat-prf-output-oracle`, a centralized expanded-secret
helper, a fixture harness, or ordinary single-key standard-provider output.

The first acceptable producer evidence class is a reviewed P1 Shamir nonce-DKG
artifact with `distributed_nonce_producer_artifact_digest`, source reference,
backend implementation digest, active-set binding, attempt binding,
coordinator attestation, nonce-DKG transcript, pairwise mask commitments,
abort-accountability evidence, and standard-verifier bridge digest.
