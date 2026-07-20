//! Signer-local custody handles, end-to-end transcript linkage, and the
//! single-use mask-consumption ledger for threshold ML-DSA-65 signing.
//!
//! # What this module establishes
//!
//! * [`NonExportableModuleShare`] / [`NonExportablePolyArrayShare`] hold one
//!   signer's private `s1_i` / `s2_i` share. The inner value is reachable only
//!   through a borrowing callback ([`NonExportableModuleShare::with`]); it is
//!   never returned, cloned, or serialized, and it is best-effort zeroized on
//!   drop. Signer-local partial generation therefore consumes custody-held
//!   shares without exporting them, and the coordinator never assembles a
//!   plaintext vector of every signer's secret share.
//! * [`end_to_end_linkage_digest`] binds the DKG transcript, public key,
//!   message, `mu`, ordered signing set, exact-ExpandMask attempt, `kappa`,
//!   MPC transcript, public commitment, partial-response bundle, rejection
//!   outcome, and the final aggregate signature into one digest.
//! * [`MaskConsumptionLedger`] enforces single-use consumption of each exact
//!   mask attempt and accounts for retries and aborts, with a serializable
//!   state so a deployment can persist it across process restarts.
//!
//! # What this module does NOT establish (fail-closed)
//!
//! A handle whose [`ShareProvenance`] is [`ShareProvenance::LocalSeedDerivedForTest`]
//! traces back to a locally generated secret, so consuming it never proves
//! no-single-secret signing. [`ShareProvenance::ExternalAttestedVault`] is a
//! caller assertion that an independently attested custody vault produced the
//! share; this crate ships no such provider, so that provenance is an
//! independently reviewable claim, not a self-certification. Likewise the
//! linkage digest *binds* the listed fields but does not by itself prove that
//! the referenced DKG or MPC transcripts came from a real distributed
//! execution — that authenticity remains gated by their own (currently
//! unmet) production evidence. Every production/theorem gate stays false.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::backend::module_partial::{ModuleVecL, L};
use crate::low_level::poly::{Poly, N};
use crate::types::ValidatorId;

/// ML-DSA-65 module rank `K` (public-vector / `s2` dimension).
const K: usize = 6;

/// Provenance of the secret shares behind a custody handle.
///
/// Fail-closed by construction: the only variant that could support a
/// no-single-secret claim is [`ShareProvenance::ExternalAttestedVault`], and
/// even that is a caller-supplied, independently reviewable assertion rather
/// than something this crate certifies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ShareProvenance {
    /// Shares dealt from a locally generated secret, for tests and development.
    /// Consuming these never establishes no-single-secret signing.
    LocalSeedDerivedForTest,
    /// Shares delivered by an external, independently attested custody vault.
    /// This crate contains no such provider; the variant records a claim that
    /// an external reviewer must corroborate against real attestation evidence.
    ExternalAttestedVault,
}

impl ShareProvenance {
    /// Whether this provenance, on its own, could ever back a no-single-secret
    /// production claim. Always requires external corroboration; the local
    /// test provenance can never qualify.
    pub fn is_external_attested(self) -> bool {
        matches!(self, ShareProvenance::ExternalAttestedVault)
    }
}

/// A single signer's private `s1_i` share, reachable only via a callback.
///
/// The type is deliberately neither `Clone`, `Copy`, nor serializable, and it
/// exposes no accessor that returns the inner value. The inner coefficients are
/// overwritten on drop (best effort: `Poly` is `Copy`, so perfect erasure is
/// not guaranteed for compiler-made copies).
pub struct NonExportableModuleShare {
    inner: ModuleVecL,
}

impl NonExportableModuleShare {
    /// Seal a share into a non-exportable handle.
    pub fn seal(share: ModuleVecL) -> Self {
        Self { inner: share }
    }

    /// Borrow the share for one signer-local operation. The closure result must
    /// not smuggle the secret out; callers return only public partial data.
    pub fn with<R>(&self, operation: impl FnOnce(&ModuleVecL) -> R) -> R {
        operation(&self.inner)
    }
}

impl Drop for NonExportableModuleShare {
    fn drop(&mut self) {
        self.inner = ModuleVecL::zero();
    }
}

impl core::fmt::Debug for NonExportableModuleShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NonExportableModuleShare")
            .field("inner", &"<sealed>")
            .finish()
    }
}

/// A single signer's private `s2_i` share (`[Poly; M]`), reachable only via a
/// callback. Same non-export discipline as [`NonExportableModuleShare`].
pub struct NonExportablePolyArrayShare<const M: usize> {
    inner: [Poly; M],
}

impl<const M: usize> NonExportablePolyArrayShare<M> {
    /// Seal a poly-array share into a non-exportable handle.
    pub fn seal(share: [Poly; M]) -> Self {
        Self { inner: share }
    }

    /// Borrow the share for one signer-local operation.
    pub fn with<R>(&self, operation: impl FnOnce(&[Poly; M]) -> R) -> R {
        operation(&self.inner)
    }
}

impl<const M: usize> Drop for NonExportablePolyArrayShare<M> {
    fn drop(&mut self) {
        self.inner = [Poly::zero(); M];
    }
}

impl<const M: usize> core::fmt::Debug for NonExportablePolyArrayShare<M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NonExportablePolyArrayShare")
            .field("inner", &"<sealed>")
            .finish()
    }
}

/// One signer's fixed (deal-once) custody handles for its `s1_i` / `s2_i`
/// shares, bound to its validator identity and evaluation point.
#[derive(Debug)]
pub struct SignerCustodyHandle65 {
    /// Signer identity.
    pub validator: ValidatorId,
    /// Shamir evaluation point (`x`, nonzero).
    pub x: u16,
    /// Provenance of the sealed shares.
    pub provenance: ShareProvenance,
    /// Non-exportable `s1_i` share (`R_q^L`).
    pub s1_handle: NonExportableModuleShare,
    /// Non-exportable `s2_i` share (`R_q^K`).
    pub s2_handle: NonExportablePolyArrayShare<K>,
}

impl SignerCustodyHandle65 {
    /// Whether every handle in a set claims external attested custody. Used only
    /// to *surface* the claim; it never flips a production gate on its own.
    pub fn all_external_attested(handles: &[SignerCustodyHandle65]) -> bool {
        !handles.is_empty()
            && handles
                .iter()
                .all(|handle| handle.provenance.is_external_attested())
    }
}

/// Digest binding the ordered signing set (validator, x) pairs. Kept separate
/// from the Lagrange-weighted binding so linkage evidence can reference the set
/// identity independently of the per-attempt weighting.
pub fn signing_set_identity_digest(members: &[(ValidatorId, u16)]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/custody/signing-set-identity/v1");
    hasher.update(&(members.len() as u64).to_be_bytes());
    for (validator, x) in members {
        hasher.update(&validator.0.to_be_bytes());
        hasher.update(&x.to_be_bytes());
    }
    let mut digest = [0u8; 32];
    hasher.finalize_xof().read(&mut digest);
    digest
}

/// The transcript elements linked into a single end-to-end signing digest.
///
/// Every field is a *binding input*: mutating any of them changes the linkage
/// digest. The digest proves the fields were bound together, not that each one
/// is authentic — authenticity of the DKG/MPC transcripts stays gated by their
/// own production evidence.
#[derive(Clone, Copy, Debug)]
pub struct EndToEndLinkageInputs<'a> {
    /// Digest of the no-dealer DKG transcript that produced the key shares.
    pub dkg_transcript_digest: &'a [u8; 32],
    /// Encoded joint public key bytes.
    pub public_key: &'a [u8],
    /// Message being signed.
    pub message: &'a [u8],
    /// FIPS 204 `mu = H(tr || ctx || M)`.
    pub mu: &'a [u8; 64],
    /// Identity digest of the ordered signing set.
    pub signing_set_digest: &'a [u8; 32],
    /// Binding digest of the accepted exact-ExpandMask attempt (`rhopp`,
    /// `kappa`, ordered signing set and its Lagrange weights).
    pub mask_input_binding_digest: &'a [u8; 32],
    /// The accepted retry counter `kappa_base`.
    pub kappa_base: u16,
    /// Digest of the exact-MPC transcript that produced the additive masks.
    pub mpc_transcript_digest: &'a [u8; 32],
    /// Digest of the aggregate public commitment `w`.
    pub commitment_digest: &'a [u8; 32],
    /// Digest of the emitted partial-response bundle.
    pub partial_bundle_digest: &'a [u8; 32],
    /// Digest of the accepted rejection-predicate state.
    pub rejection_predicate_digest: &'a [u8; 32],
    /// Number of rejected attempts before acceptance.
    pub rejected_attempts: u32,
    /// Final standard-size aggregate signature bytes.
    pub aggregate_signature: &'a [u8],
}

/// Bind every listed transcript element into one linkage digest.
pub fn end_to_end_linkage_digest(inputs: &EndToEndLinkageInputs<'_>) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"lattice-aggregation/custody/end-to-end-linkage/v1");
    for field in [
        inputs.dkg_transcript_digest.as_slice(),
        inputs.public_key,
        inputs.message,
        inputs.mu.as_slice(),
        inputs.signing_set_digest.as_slice(),
        inputs.mask_input_binding_digest.as_slice(),
        inputs.mpc_transcript_digest.as_slice(),
        inputs.commitment_digest.as_slice(),
        inputs.partial_bundle_digest.as_slice(),
        inputs.rejection_predicate_digest.as_slice(),
        inputs.aggregate_signature,
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.update(&inputs.kappa_base.to_le_bytes());
    hasher.update(&inputs.rejected_attempts.to_le_bytes());
    let mut digest = [0u8; 32];
    hasher.finalize_xof().read(&mut digest);
    digest
}

/// A recorded selective abort during retry accounting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortRecord {
    /// Signing-transcript digest the abort occurred under (hex).
    pub transcript_digest_hex: String,
    /// Retry counter at abort time.
    pub kappa_base: u16,
    /// Short reason label.
    pub reason: String,
}

/// Serializable snapshot of a [`MaskConsumptionLedger`], for durable storage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskLedgerState {
    /// Consumption keys already spent (hex), one per (transcript, kappa,
    /// attempt-binding) tuple.
    pub consumed_keys_hex: Vec<String>,
    /// Retry counts keyed by signing-transcript digest (hex).
    pub retries: BTreeMap<String, u32>,
    /// Recorded selective aborts.
    pub aborts: Vec<AbortRecord>,
}

/// Errors from the mask-consumption ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// The exact mask attempt was already consumed (single-use violation).
    MaskAlreadyConsumed {
        /// Consumption key (hex).
        key_hex: String,
    },
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LedgerError::MaskAlreadyConsumed { key_hex } => write!(
                f,
                "exact mask attempt already consumed (single-use violation): {key_hex}"
            ),
        }
    }
}

impl std::error::Error for LedgerError {}

/// Enforces single-use consumption of exact mask attempts and accounts for
/// retries and selective aborts.
///
/// The in-memory set is authoritative for one process; [`MaskConsumptionLedger::to_state`]
/// and [`MaskConsumptionLedger::from_state`] let a deployment persist and reload
/// the spent set so single-use survives restarts. This crate provides the
/// accounting structure; durable storage (and the fsync discipline that makes
/// it crash-safe) is the deployment's responsibility, so the persistent-replay
/// production gate stays the caller's to satisfy.
#[derive(Clone, Debug, Default)]
pub struct MaskConsumptionLedger {
    consumed: BTreeSet<[u8; 32]>,
    retries: BTreeMap<[u8; 32], u32>,
    aborts: Vec<AbortRecord>,
}

impl MaskConsumptionLedger {
    /// A fresh, empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Deterministic consumption key for one exact mask attempt.
    pub fn consumption_key(
        transcript_digest: &[u8; 32],
        kappa_base: u16,
        input_binding_digest: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(b"lattice-aggregation/custody/mask-consumption-key/v1");
        hasher.update(transcript_digest);
        hasher.update(&kappa_base.to_le_bytes());
        hasher.update(input_binding_digest);
        let mut key = [0u8; 32];
        hasher.finalize_xof().read(&mut key);
        key
    }

    /// Spend one exact mask attempt. Errors if it was already spent.
    pub fn consume(
        &mut self,
        transcript_digest: &[u8; 32],
        kappa_base: u16,
        input_binding_digest: &[u8; 32],
    ) -> Result<(), LedgerError> {
        let key = Self::consumption_key(transcript_digest, kappa_base, input_binding_digest);
        if !self.consumed.insert(key) {
            return Err(LedgerError::MaskAlreadyConsumed {
                key_hex: encode_hex(&key),
            });
        }
        Ok(())
    }

    /// Whether an attempt has already been consumed (no state change).
    pub fn is_consumed(
        &self,
        transcript_digest: &[u8; 32],
        kappa_base: u16,
        input_binding_digest: &[u8; 32],
    ) -> bool {
        let key = Self::consumption_key(transcript_digest, kappa_base, input_binding_digest);
        self.consumed.contains(&key)
    }

    /// Record one rejection-loop retry for a signing transcript.
    pub fn record_retry(&mut self, transcript_digest: &[u8; 32]) {
        *self.retries.entry(*transcript_digest).or_insert(0) += 1;
    }

    /// Retry count observed for a signing transcript.
    pub fn retries(&self, transcript_digest: &[u8; 32]) -> u32 {
        self.retries.get(transcript_digest).copied().unwrap_or(0)
    }

    /// Record a selective abort.
    pub fn record_abort(&mut self, transcript_digest: &[u8; 32], kappa_base: u16, reason: &str) {
        self.aborts.push(AbortRecord {
            transcript_digest_hex: encode_hex(transcript_digest),
            kappa_base,
            reason: reason.to_owned(),
        });
    }

    /// Total number of spent mask attempts.
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    /// Recorded aborts.
    pub fn aborts(&self) -> &[AbortRecord] {
        &self.aborts
    }

    /// Export a serializable snapshot for durable storage.
    pub fn to_state(&self) -> MaskLedgerState {
        MaskLedgerState {
            consumed_keys_hex: self.consumed.iter().map(|key| encode_hex(key)).collect(),
            retries: self
                .retries
                .iter()
                .map(|(digest, count)| (encode_hex(digest), *count))
                .collect(),
            aborts: self.aborts.clone(),
        }
    }

    /// Reload a ledger from a serialized snapshot. Unparseable hex entries are
    /// rejected so a corrupted persistence file cannot silently drop spent keys.
    pub fn from_state(state: &MaskLedgerState) -> Result<Self, LedgerError> {
        let mut consumed = BTreeSet::new();
        for key_hex in &state.consumed_keys_hex {
            consumed.insert(decode_digest(key_hex)?);
        }
        let mut retries = BTreeMap::new();
        for (digest_hex, count) in &state.retries {
            retries.insert(decode_digest(digest_hex)?, *count);
        }
        Ok(Self {
            consumed,
            retries,
            aborts: state.aborts.clone(),
        })
    }

    /// Digest binding the full accounting state, for evidence linkage.
    pub fn accounting_digest(&self) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(b"lattice-aggregation/custody/mask-ledger-accounting/v1");
        hasher.update(&(self.consumed.len() as u64).to_be_bytes());
        for key in &self.consumed {
            hasher.update(key);
        }
        hasher.update(&(self.retries.len() as u64).to_be_bytes());
        for (digest, count) in &self.retries {
            hasher.update(digest);
            hasher.update(&count.to_be_bytes());
        }
        hasher.update(&(self.aborts.len() as u64).to_be_bytes());
        for abort in &self.aborts {
            hasher.update(&(abort.transcript_digest_hex.len() as u64).to_be_bytes());
            hasher.update(abort.transcript_digest_hex.as_bytes());
            hasher.update(&abort.kappa_base.to_le_bytes());
            hasher.update(&(abort.reason.len() as u64).to_be_bytes());
            hasher.update(abort.reason.as_bytes());
        }
        let mut digest = [0u8; 32];
        hasher.finalize_xof().read(&mut digest);
        digest
    }
}

fn decode_digest(hex: &str) -> Result<[u8; 32], LedgerError> {
    if hex.len() != 64 {
        return Err(LedgerError::MaskAlreadyConsumed {
            key_hex: hex.to_owned(),
        });
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&hex[start..start + 2], 16).map_err(|_| {
            LedgerError::MaskAlreadyConsumed {
                key_hex: hex.to_owned(),
            }
        })?;
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Compile-time assurance that the module dimensions match the signer's.
const _: () = {
    assert!(L == 5);
    assert!(K == 6);
    assert!(N == 256);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    #[test]
    fn non_exportable_share_zeroizes_on_drop_and_hides_debug() {
        let mut vec = ModuleVecL::zero();
        vec.components[0].coeffs[0] = 1234;
        let handle = NonExportableModuleShare::seal(vec);
        let observed = handle.with(|share| share.components[0].coeffs[0]);
        assert_eq!(observed, 1234);
        // Debug never prints the secret.
        assert!(format!("{handle:?}").contains("<sealed>"));
    }

    #[test]
    fn ledger_enforces_single_use_and_survives_roundtrip() {
        let transcript = digest(0x11);
        let binding = digest(0x22);
        let mut ledger = MaskConsumptionLedger::new();
        assert!(!ledger.is_consumed(&transcript, 0, &binding));
        ledger
            .consume(&transcript, 0, &binding)
            .expect("first spend");
        assert!(ledger.is_consumed(&transcript, 0, &binding));
        let err = ledger
            .consume(&transcript, 0, &binding)
            .expect_err("double spend rejected");
        assert!(matches!(err, LedgerError::MaskAlreadyConsumed { .. }));

        // A different kappa is a different attempt and is spendable.
        ledger
            .consume(&transcript, 5, &binding)
            .expect("distinct kappa");

        ledger.record_retry(&transcript);
        ledger.record_retry(&transcript);
        ledger.record_abort(&transcript, 5, "test-selective-abort");
        assert_eq!(ledger.retries(&transcript), 2);
        assert_eq!(ledger.consumed_count(), 2);
        assert_eq!(ledger.aborts().len(), 1);

        // Persist and reload; the spent set and accounting digest are stable.
        let state = ledger.to_state();
        let reloaded = MaskConsumptionLedger::from_state(&state).expect("reload");
        assert!(reloaded.is_consumed(&transcript, 0, &binding));
        assert!(reloaded.is_consumed(&transcript, 5, &binding));
        assert_eq!(
            reloaded.accounting_digest(),
            ledger.accounting_digest(),
            "accounting digest is stable across persistence roundtrip"
        );
    }

    #[test]
    fn linkage_digest_changes_when_any_field_changes() {
        let dkg = digest(0x01);
        let pk = vec![0x02u8; 1952];
        let message = b"linkage-message".to_vec();
        let mu = [0x03u8; 64];
        let set = digest(0x04);
        let binding = digest(0x05);
        let mpc = digest(0x06);
        let commitment = digest(0x07);
        let bundle = digest(0x08);
        let rejection = digest(0x09);
        let sig = vec![0x0au8; 3309];

        let base = EndToEndLinkageInputs {
            dkg_transcript_digest: &dkg,
            public_key: &pk,
            message: &message,
            mu: &mu,
            signing_set_digest: &set,
            mask_input_binding_digest: &binding,
            kappa_base: 0,
            mpc_transcript_digest: &mpc,
            commitment_digest: &commitment,
            partial_bundle_digest: &bundle,
            rejection_predicate_digest: &rejection,
            rejected_attempts: 0,
            aggregate_signature: &sig,
        };
        let base_digest = end_to_end_linkage_digest(&base);

        let mut changed_kappa = base;
        changed_kappa.kappa_base = 5;
        assert_ne!(base_digest, end_to_end_linkage_digest(&changed_kappa));

        let mut changed_retries = base;
        changed_retries.rejected_attempts = 3;
        assert_ne!(base_digest, end_to_end_linkage_digest(&changed_retries));

        let other_dkg = digest(0xff);
        let mut changed_dkg = base;
        changed_dkg.dkg_transcript_digest = &other_dkg;
        assert_ne!(base_digest, end_to_end_linkage_digest(&changed_dkg));
    }

    #[test]
    fn provenance_is_fail_closed_for_local_shares() {
        assert!(!ShareProvenance::LocalSeedDerivedForTest.is_external_attested());
        assert!(ShareProvenance::ExternalAttestedVault.is_external_attested());
    }
}
