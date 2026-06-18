# Batch H Proof Dependency Graph
<a id="batch-h-proof-dependency-graph"></a>

Stable anchor: batch-h-proof-dependency-graph

Status: Batch H theorem dependency graph and residual map, not a production proof.

This document is the reviewer-facing dependency graph for the threshold ML-DSA
lattice aggregation proof route. It names the root theorem, lists the proof
and implementation dependencies that feed it, and records each residual term
that remains visible until the corresponding theorem, backend discharge, or
audit item is closed.

This map is deliberately conservative. It does not claim that any residual is
zero, negligible, or numerically bounded unless the referenced theorem later
states that fact. Implementation evidence is not cryptographic proof.

## H-DAG-1. Root Theorem Dependency Graph
<a id="h-dag-1"></a>

The root theorem is the final threshold ML-DSA unforgeability statement for an
active adversary under the repository's transcript, setup, contribution,
aggregation, rejection, and classifier semantics.

```text
root theorem
  depends on backend discharge
  depends on VSS/DKG proof
  depends on contribution proof relation
  depends on standard ML-DSA verification
  depends on unauthorized-output classifier
  depends on residual epsilon ledger
  depends on implementation and side-channel evidence
```

The current graph is conditional, not closed. The immediate theorem route may
use idealized functionality boundaries to isolate signing-side reasoning, but a
production theorem must replace those boundaries with concrete realization
theorems and an auditable implementation story.

| Node | Depends on | Current status | Residual or proof term | Closure requirement |
| --- | --- | --- | --- | --- |
| root theorem | Every node below | Proof draft | `Adv_threshold_mldsa` plus the residual epsilon ledger | Assemble the final hybrid sequence and import only discharged backend theorems. |
| backend discharge | VSS/DKG proof, contribution proof relation, implementation evidence | Open blocker | `eps_backend` | Select concrete production backends, prove their realization theorems, and bind them to audited code. |
| VSS/DKG proof | Setup functionality, complaint handling, public-key derivation, anti-framing, key-bias bounds | Conditional assumption | `eps_vss` | Replace `F_VSS_DKG` with a concrete malicious-secure VSS/DKG theorem or keep the production claim blocked. |
| contribution proof relation | Contribution statement grammar, witness relation, extraction or simulation route, hiding requirements | Proof draft | `eps_contrib` | Replace ideal `F_CONTRIB` use with a selected contribution backend theorem or explicit ideal-realization proof. |
| standard ML-DSA verification | Byte layout, high-bit reconstruction, hint semantics, challenge binding, rejection predicate equivalence | Proof draft plus code evidence | `eps_verify` | Prove accepted threshold outputs verify under unmodified ML-DSA verification, or account for the residual in the rejection route. |
| unauthorized-output classifier | Authorization cases, totality, disjointness, per-case reductions, unmapped-zero theorem | Proof draft | `eps_classify` | Prove every accepting unauthorized output maps to a base ML-DSA forgery or a named threshold-side bad event. |
| residual epsilon ledger | All residual definitions and bound composition | Proof draft | `eps_backend`, `eps_vss`, `eps_contrib`, `eps_verify`, `eps_classify`, `eps_side_channel` | Keep every unclosed loss visible in the final theorem statement. |
| implementation and side-channel evidence | Rust tests, crosswalks, feature gates, deterministic vectors, audit packet | Code evidence | `eps_side_channel`, implementation residual, audit residual | Complete review and auditing; do not treat test coverage as a cryptographic proof. |

## H-DAG-2. Dependency Status Ledger
<a id="h-dag-2"></a>

Status key:

- Code evidence: implementation, test, vector, policy-gate, or crosswalk
  evidence that supports traceability but does not prove cryptographic
  security.
- Proof draft: theorem shape, simulator route, reduction skeleton, lemma
  closure, or residual decomposition that still needs final proof text.
- Conditional assumption: an ideal functionality, external assumption, or
  bounded term that can be used only while the assumption remains explicit.
- Open blocker: an item that must be closed before production wording is safe.

| Dependency | Status class | Evidence route | Residual map | Production disposition |
| --- | --- | --- | --- | --- |
| VSS/DKG proof | Conditional assumption and open blocker | `vss-dkg-backend-dependency-graph.md`, `vss-dkg-production-obligation-split.md`, `eps-vss-production-route.md` | `eps_vss` | Production remains blocked until a concrete backend is selected, proved, and audited. |
| Contribution proof relation | Proof draft and open blocker | `f-contrib-realization-simulator.md`, `f-contrib-ideal-functionality.md`, `contribution-soundness-relation.md` | `eps_contrib` | Immediate theorem work may isolate through `F_CONTRIB`; production needs a real backend theorem. |
| Standard ML-DSA verification | Code evidence plus proof draft | `eps-verify-to-rej-absorption-theorem.md`, `eps-verify-rejection-absorption-closure.md`, hazmat verifier tests | `eps_verify` | Verifier compatibility must be proved or carried as an explicit residual. |
| Unauthorized-output classifier | Proof draft | `eps-classify-unmapped-zero-theorem.md`, `eps-classify-totality-disjointness-closure.md`, `unauthorized-output-classifier-elimination.md` | `eps_classify` | Final unforgeability cannot remove the classifier residual until totality, disjointness, and unmapped-zero are closed. |
| Backend discharge | Open blocker | Backend selection records, production policy gates, proof-implementation crosswalks | `eps_backend` | A selected backend ID, parameter set, proof route, implementation binding, and audit trail are required. |
| Side-channel and implementation boundary | Code evidence and open blocker | `side-channel-boundary.md`, `proof-implementation-crosswalk.md`, production policy tests | `eps_side_channel` | Constant-time, randomness, compiler, transport, and integration review remain outside the cryptographic proof unless explicitly modeled. |
| Residual epsilon ledger | Proof draft | `epsilon-residual-ledger-final-form.md`, `proof-closure-ledger.md`, `proof-gap-priority-map.md` | All listed residuals | The ledger is a map; it does not discharge any residual by itself. |
| Base ML-DSA assumption | Conditional assumption | ML-DSA verification and unforgeability assumption imported by the theorem route | `q_out * eps_mldsa` | The final theorem may cite the standard ML-DSA assumption only through the declared reduction interface. |

## H-DAG-3. Residual Epsilon Ledger
<a id="h-dag-3"></a>

The Batch H residual epsilon ledger keeps the top-level residuals visible in
the dependency graph:

```text
Adv_root(A,Z)
 <= eps_backend(A,Z)
  + eps_vss(A,Z)
  + eps_contrib(A,Z)
  + eps_verify(A,Z)
  + eps_classify(A,Z)
  + eps_side_channel(A,Z)
  + existing signing-side residuals
  + q_out * eps_mldsa(B_mldsa)
  + negl(lambda).
```

| Residual | Source dependency | Current class | Discharge path |
| --- | --- | --- | --- |
| `eps_backend` | Backend discharge | Open blocker | Select, prove, implement, and audit the production backend stack. |
| `eps_vss` | VSS/DKG proof | Conditional assumption until realized | Replace ideal setup with concrete malicious-secure VSS/DKG and public-key derivation proofs. |
| `eps_contrib` | Contribution proof relation | Proof draft | Prove contribution relation soundness, extraction or simulation, hiding, and transcript binding. |
| `eps_verify` | Standard ML-DSA verification | Proof draft plus code evidence | Prove byte-level verifier compatibility or absorb the term into a proved rejection predicate route. |
| `eps_classify` | Unauthorized-output classifier | Proof draft | Close classifier totality, disjointness, per-case reductions, and unmapped-zero. |
| `eps_side_channel` | Implementation and side-channel boundary | Code evidence and open blocker | Complete side-channel, randomness, compiler, integration, and external audit work. |

The residual epsilon ledger is a theorem accounting device. It must remain
visible anywhere the root theorem is discussed until every row has a completed
proof or a deliberately retained assumption.

## H-DAG-4. Backend Discharge Criteria
<a id="h-dag-4"></a>

Backend discharge means more than passing tests. A dependency can move from
open blocker to closed only when all of the following are true:

1. The backend is named by stable ID, version, parameter set, feature boundary,
   and transcript grammar.
2. The proof relation states exact witnesses, public inputs, accepted outputs,
   malformed-object behavior, leakage, and failure records.
3. The reduction or simulator proves the required binding, hiding,
   extractability, simulation, or unforgeability claim under declared
   assumptions.
4. The implementation evidence binds the proof statement to canonical code,
   negative tests, vectors, fail-closed gates, and audit artifacts.
5. The residual epsilon ledger is updated so the backend term is either
   discharged, renamed to a precise retained assumption, or left as an open
   blocker.

Until these criteria are met, implementation evidence is not cryptographic
proof and the repository remains not a production proof.

## H-DAG-5. Non-Claims
<a id="h-dag-5"></a>

This Batch H document does not prove threshold ML-DSA unforgeability. It does
not select a production VSS/DKG backend, does not select a production
contribution backend, does not prove standard-verifier compatibility, does not
eliminate the unauthorized-output classifier residual, and does not close
side-channel or audit residuals.

The safe reading is: this file is a theorem dependency graph and residual map.
It is not a production proof.

## H-DAG-6. Manifest Anchors
<a id="h-dag-6"></a>

Stable strings:

- `batch-h-proof-dependency-graph`
- `H-DAG-1`
- `H-DAG-2`
- `H-DAG-3`
- `root theorem`
- `backend discharge`
- `VSS/DKG proof`
- `contribution proof relation`
- `standard ML-DSA verification`
- `unauthorized-output classifier`
- `residual epsilon ledger`
- `eps_backend`
- `eps_vss`
- `eps_contrib`
- `eps_verify`
- `eps_classify`
- `eps_side_channel`
- `implementation evidence is not cryptographic proof`
- `not a production proof`
