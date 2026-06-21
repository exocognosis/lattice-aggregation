# Partial Contribution Soundness Evidence

Date: 2026-06-20

## Scope

This note records the current evidence boundary for blocker 4:

```text
Every accepted partial contribution is sound, context-bound, and hiding enough
for the chosen leakage model.
```

The current implementation is a typed conformance scaffold in
`src/production/partial_soundness.rs`, tested by
`tests/production_partial_soundness.rs`. It does not complete the cryptographic
proof for local partial soundness, rejection-sampling distribution preservation,
or zero-knowledge hiding.

## Evidence Classes

`EvidenceClass::ScaffoldDigestOnly` means the accepted partial is checked
against public digest evidence already carried by
`AcceptedPartialContribution`. This class is useful for wiring, regression
tests, and avoiding accidental context drift. It is not a proof-backed local
verifier result.

`EvidenceClass::ProofBacked` means the evidence carries a reviewed local proof
verifier label, verifier-key digest, soundness-theorem digest, proof digest, and
verifier-transcript digest. The typed check binds those digests to the accepted
partial token and transcript context, but the repository still needs an audited
proof verifier to make this class production-meaningful.

Callers that require real proof-backed evidence use
`PartialEvidenceRequirement::ProofBackedOnly`; digest-only scaffold evidence is
then rejected with a policy error instead of being silently promoted.

## Checks Added

Partial verifier binding checks that the accepted partial signer, commitment
digest, challenge digest, partial-share digest, and local bounds proof digest
match the verifier statement digest supplied for that partial. A stale or
mismatched accepted partial fails before any aggregate claim can be made.

Transcript and context binding records the session ID, epoch, key ID, validator
set digest, DKG transcript digest, active signer set, threshold, public key
digest, application message digest, message binding, attempt ID, coordinator
attestation digest, retry counter, and challenge digest. Evidence minted for a
different retry or transcript context is rejected as `TranscriptMismatch`.

Local proof soundness labeling distinguishes digest-only evidence from
proof-backed evidence. The digest-only label is intentionally non-promotable to
a proof-backed requirement.

Leakage and hiding budget checks compare the observed `EpsilonLedger`
components against caller-selected `LeakageLimits` under a named
`LeakageModel`. Any component that exceeds its ceiling is rejected with
`partial leakage budget exceeded`.

## Current Boundary

This is concrete progress from `partially_met` because accepted partial
evidence now has typed checks for:

- accepted partial token binding;
- transcript and retry context binding;
- local proof class and soundness label;
- leakage budget accounting.

It remains conformance-only until the module is wired into the public
production profile, the proof-backed constructor is fed by a real reviewed proof
verifier, and the formal proof documents establish that the selected leakage
model is sufficient for the adversary model.

## Remaining Work

To fully close blocker 4, later work should:

- export and integrate `partial_soundness` through the production module once
  ownership allows touching `src/production.rs`;
- feed `ProofBackedLocalVerifier` from an audited local proof verifier instead
  of test fixtures;
- connect accepted partial soundness evidence to aggregate acceptance so every
  aggregate path requires the selected evidence level;
- update the claims matrix and proof manifest in the owning documentation batch;
- prove the leakage model, simulator, and local verifier soundness obligations
  referenced by `docs/cryptography/noise-rejection-proof-plan.md`.
