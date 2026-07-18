//! Authenticated encryption **interface** for per-receiver VSS share transport.
//!
//! Increment 2b of the real threshold key material build-out
//! (`docs/superpowers/plans/2026-07-10-real-threshold-key-material-vss.md`;
//! design: `docs/superpowers/specs/2026-07-12-increment-2b-closure-design.md`).
//! Today [`crate::crypto::vss_bdlop`] deals shares in the clear, so any party
//! that assembles all shares (the DKG `finalize` caller, any `DkgOutput` holder)
//! can reconstruct the secret; secrecy is scoped only to sub-threshold
//! *validator* coalitions. This module provides the transport seam that would let
//! a dealer hand each receiver a share only that receiver can open.
//!
//! ## What this IS
//!
//! A [`ShareTransport`] trait plus a SHAKE256-based reference implementation
//! ([`Shake256Transport`]) built entirely on the existing `sha3` dependency. It
//! is an **encrypt-then-MAC symmetric authenticated-encryption interface**: given
//! a per-receiver [`ReceiverKey`] and a unique nonce, [`ShareTransport::seal`]
//! produces a [`SealedShare`] that [`ShareTransport::open`] recovers only under
//! the same key, nonce (carried in the sealed object), and associated data.
//!
//! ## What this is NOT (security boundary — read before use)
//!
//! - **Not a KEM and not key exchange.** It assumes a **pre-shared per-receiver
//!   symmetric key channel**: [`ReceiverKey`] must already be shared between
//!   dealer and receiver (established out of band, or by a future ML-KEM
//!   handshake that this trait abstracts). It does **not** distribute keys.
//! - **Not post-quantum key transport.** A real PQ-secure transport needs
//!   **ML-KEM (FIPS 203)**, which is a new crate / justified dependency exception
//!   the repository does not yet take (see the design spec, Section 4.2). This
//!   interim primitive gives no public-key functionality and no forward secrecy.
//! - **Nonce-reuse is fatal.** Confidentiality holds under the SHAKE256-as-PRF
//!   assumption **only for unique `(key, nonce)` pairs**. Reusing a `(key,
//!   nonce)` pair leaks the XOR of plaintexts (stream-cipher caveat). The caller
//!   owns nonce uniqueness.
//! - **Not constant-time end-to-end.** The tag comparison is a best-effort
//!   constant-time check; the rest of the code (and the underlying `Poly`
//!   arithmetic a caller would serialize) is not audited for timing leakage.
//! - **Not wired into VSS/DKG.** This is an additive, self-contained interface;
//!   no existing VSS/DKG security property is changed by adding it. Integration
//!   (sealing `HidingShare`s, binding ciphertexts into the DKG commit digest) is
//!   specified in the design doc but deliberately not implemented here.
//!
//! It closes no hypothesis criterion and makes no production threshold ML-DSA
//! security claim.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of a [`ReceiverKey`].
pub const KEY_BYTES: usize = 32;
/// Length in bytes of a [`SealedShare`] authentication tag.
pub const TAG_BYTES: usize = 32;

const ENC_SUBKEY_LABEL: &[u8] = b"lattice-aggregation/share-transport/subkey/enc/v1";
const MAC_SUBKEY_LABEL: &[u8] = b"lattice-aggregation/share-transport/subkey/mac/v1";
const KEYSTREAM_LABEL: &[u8] = b"lattice-aggregation/share-transport/keystream/v1";
const MAC_LABEL: &[u8] = b"lattice-aggregation/share-transport/mac/v1";

/// A pre-shared per-receiver symmetric key.
///
/// This is the **assumed** input of the transport, not something it produces:
/// see the module security boundary. The key material is zeroized on drop; it is
/// deliberately not `Debug`-printable (a redacting `Debug` is provided). It is
/// explicitly `Clone` for dealer/receiver provisioning; every clone is
/// zeroized on drop, and callers should still minimize live copies.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ReceiverKey([u8; KEY_BYTES]);

impl ReceiverKey {
    /// Wrap raw key bytes already agreed on the pre-shared channel.
    ///
    /// Does **not** derive or exchange a key — the caller must supply a key that
    /// was established securely elsewhere.
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Derive a receiver key from a **pre-shared channel secret** and a receiver
    /// index via domain-separated SHAKE256.
    ///
    /// This is a key-derivation convenience for a channel secret both parties
    /// already hold; it is **not** a key-exchange and provides no secrecy against
    /// a party that knows `channel_secret`. Distinct indices yield independent
    /// keys.
    pub fn from_channel_secret(channel_secret: &[u8], receiver_index: u16) -> Self {
        let mut hasher = Shake256::default();
        absorb(
            &mut hasher,
            b"lattice-aggregation/share-transport/receiver-key/v1",
        );
        absorb(&mut hasher, channel_secret);
        hasher.update(&receiver_index.to_be_bytes());
        let mut bytes = [0u8; KEY_BYTES];
        hasher.finalize_xof().read(&mut bytes);
        Self(bytes)
    }

    /// Derive the `(encryption, authentication)` subkeys by domain-separated
    /// SHAKE256, so the keystream and MAC never share PRF output.
    fn subkeys(&self) -> ([u8; KEY_BYTES], [u8; KEY_BYTES]) {
        (
            derive_subkey(&self.0, ENC_SUBKEY_LABEL),
            derive_subkey(&self.0, MAC_SUBKEY_LABEL),
        )
    }
}

impl core::fmt::Debug for ReceiverKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ReceiverKey(REDACTED)")
    }
}

/// A sealed (encrypted + authenticated) share, safe to place on a public wire.
///
/// Reveals only the plaintext length (via `ciphertext` length) and the caller's
/// nonce; the plaintext is hidden and any modification is rejected by
/// [`ShareTransport::open`]. It is **not** bound to a receiver or session by
/// itself — the caller passes that context as associated data to
/// [`ShareTransport::seal`]/[`ShareTransport::open`].
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SealedShare {
    /// Caller-supplied nonce; MUST be unique per [`ReceiverKey`] (see boundary).
    pub nonce: Vec<u8>,
    /// XOR-stream ciphertext of the plaintext share (same length as plaintext).
    pub ciphertext: Vec<u8>,
    /// Encrypt-then-MAC authentication tag over nonce, associated data, and
    /// ciphertext.
    pub tag: [u8; TAG_BYTES],
}

/// Authenticated-encryption transport for per-receiver shares.
///
/// Implementations provide confidentiality and integrity of a share **under an
/// already-established per-receiver key**. They do **not** establish that key —
/// the trait is the seam where a real ML-KEM-backed hybrid transport would later
/// drop in (see the module boundary).
pub trait ShareTransport {
    /// Seal `plaintext` under `key` with a unique `nonce`, binding
    /// `associated_data` (e.g. session id, dealer id, receiver index) so a
    /// ciphertext cannot be replayed into a different context.
    ///
    /// The caller MUST NOT reuse a `(key, nonce)` pair (see the module boundary).
    fn seal(
        &self,
        key: &ReceiverKey,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> SealedShare;

    /// Open a [`SealedShare`], returning the plaintext only when the key, the
    /// nonce carried in `sealed`, and `associated_data` all match and the
    /// ciphertext is unmodified.
    ///
    /// Returns `None` on any authentication failure — a tampered nonce,
    /// ciphertext, or tag, mismatched associated data, or a wrong key — so a
    /// caller learns nothing beyond accept/reject. It never returns a
    /// silently-wrong plaintext.
    fn open(
        &self,
        key: &ReceiverKey,
        associated_data: &[u8],
        sealed: &SealedShare,
    ) -> Option<Vec<u8>>;
}

/// SHAKE256-based encrypt-then-MAC reference implementation of
/// [`ShareTransport`].
///
/// A zero-sized selector for the reference construction described in the module
/// docs. It is a **reference interface implementation, not a production KEM**:
/// re-read the module security boundary before relying on it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Shake256Transport;

impl ShareTransport for Shake256Transport {
    fn seal(
        &self,
        key: &ReceiverKey,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> SealedShare {
        let (k_enc, k_mac) = key.subkeys();
        let ciphertext = xor_keystream(&k_enc, nonce, plaintext);
        let tag = mac_tag(&k_mac, nonce, associated_data, &ciphertext);
        SealedShare {
            nonce: nonce.to_vec(),
            ciphertext,
            tag,
        }
    }

    fn open(
        &self,
        key: &ReceiverKey,
        associated_data: &[u8],
        sealed: &SealedShare,
    ) -> Option<Vec<u8>> {
        let (k_enc, k_mac) = key.subkeys();
        let expected = mac_tag(&k_mac, &sealed.nonce, associated_data, &sealed.ciphertext);
        // Encrypt-then-MAC: verify the tag before touching the ciphertext.
        if !constant_time_eq(&expected, &sealed.tag) {
            return None;
        }
        Some(xor_keystream(&k_enc, &sealed.nonce, &sealed.ciphertext))
    }
}

/// Derive a 32-byte subkey from key material and a domain label.
fn derive_subkey(key: &[u8; KEY_BYTES], label: &[u8]) -> [u8; KEY_BYTES] {
    let mut hasher = Shake256::default();
    absorb(&mut hasher, label);
    absorb(&mut hasher, key);
    let mut out = [0u8; KEY_BYTES];
    hasher.finalize_xof().read(&mut out);
    out
}

/// Produce `data.len()` keystream bytes from `SHAKE256(k_enc || nonce)` and XOR
/// them onto `data` (encryption and decryption are the same operation).
fn xor_keystream(k_enc: &[u8; KEY_BYTES], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    absorb(&mut hasher, KEYSTREAM_LABEL);
    absorb(&mut hasher, k_enc);
    absorb(&mut hasher, nonce);
    let mut reader = hasher.finalize_xof();

    let mut out = vec![0u8; data.len()];
    reader.read(&mut out);
    for (byte, &plain) in out.iter_mut().zip(data.iter()) {
        *byte ^= plain;
    }
    out
}

/// Compute the encrypt-then-MAC tag over the nonce, associated data, and
/// ciphertext under `k_mac`. Length-prefixed absorption keeps the byte stream
/// unambiguous, so no two distinct inputs collide.
fn mac_tag(
    k_mac: &[u8; KEY_BYTES],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> [u8; TAG_BYTES] {
    let mut hasher = Shake256::default();
    absorb(&mut hasher, MAC_LABEL);
    absorb(&mut hasher, k_mac);
    absorb(&mut hasher, nonce);
    absorb(&mut hasher, associated_data);
    absorb(&mut hasher, ciphertext);
    let mut tag = [0u8; TAG_BYTES];
    hasher.finalize_xof().read(&mut tag);
    tag
}

/// Length-prefixed SHAKE256 absorption for unambiguous domain separation.
fn absorb(hasher: &mut Shake256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Best-effort constant-time equality over equal-length byte slices.
///
/// Folds every byte difference into an accumulator so the running time does not
/// depend on the position of the first mismatch. This is a best-effort guard,
/// not a formally verified constant-time primitive (see the module boundary).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod share_transport_tests {
    use super::*;

    const NONCE: &[u8] = b"nonce-0000000001";
    const AD: &[u8] = b"session=7|dealer=3|receiver=5";

    fn key() -> ReceiverKey {
        ReceiverKey::from_bytes([0x24; KEY_BYTES])
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let transport = Shake256Transport;
        let plaintext = b"share value + aggregated randomness bytes";
        let sealed = transport.seal(&key(), NONCE, AD, plaintext);
        // The ciphertext is not the plaintext (it is actually encrypted).
        assert_ne!(sealed.ciphertext.as_slice(), plaintext.as_slice());
        assert_eq!(sealed.ciphertext.len(), plaintext.len());

        let opened = transport
            .open(&key(), AD, &sealed)
            .expect("open must succeed");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn round_trip_handles_empty_plaintext() {
        let transport = Shake256Transport;
        let sealed = transport.seal(&key(), NONCE, AD, b"");
        assert!(sealed.ciphertext.is_empty());
        assert_eq!(transport.open(&key(), AD, &sealed), Some(Vec::new()));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let transport = Shake256Transport;
        let mut sealed = transport.seal(&key(), NONCE, AD, b"secret share");
        sealed.ciphertext[0] ^= 0x01;
        assert!(
            transport.open(&key(), AD, &sealed).is_none(),
            "a flipped ciphertext bit must fail authentication"
        );
    }

    #[test]
    fn tampered_tag_is_rejected() {
        let transport = Shake256Transport;
        let mut sealed = transport.seal(&key(), NONCE, AD, b"secret share");
        sealed.tag[0] ^= 0x01;
        assert!(transport.open(&key(), AD, &sealed).is_none());
    }

    #[test]
    fn tampered_nonce_is_rejected() {
        let transport = Shake256Transport;
        let mut sealed = transport.seal(&key(), NONCE, AD, b"secret share");
        sealed.nonce[0] ^= 0x01;
        assert!(
            transport.open(&key(), AD, &sealed).is_none(),
            "the nonce is authenticated by the tag"
        );
    }

    #[test]
    fn mismatched_associated_data_is_rejected() {
        let transport = Shake256Transport;
        let sealed = transport.seal(&key(), NONCE, AD, b"secret share");
        assert!(
            transport
                .open(&key(), b"session=7|dealer=3|receiver=6", &sealed)
                .is_none(),
            "associated data (receiver index) must be bound"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let transport = Shake256Transport;
        let sealed = transport.seal(&key(), NONCE, AD, b"secret share");
        let wrong = ReceiverKey::from_bytes([0x25; KEY_BYTES]);
        assert!(
            transport.open(&wrong, AD, &sealed).is_none(),
            "a different receiver key must not open the share"
        );
    }

    #[test]
    fn distinct_receiver_keys_are_independent() {
        // Keys derived for different receivers from the same channel secret do
        // not open each other's sealed shares.
        let transport = Shake256Transport;
        let k5 = ReceiverKey::from_channel_secret(b"channel", 5);
        let k6 = ReceiverKey::from_channel_secret(b"channel", 6);
        let sealed = transport.seal(&k5, NONCE, AD, b"receiver 5 share");
        assert_eq!(
            transport.open(&k5, AD, &sealed).as_deref(),
            Some(b"receiver 5 share".as_slice())
        );
        assert!(transport.open(&k6, AD, &sealed).is_none());
    }

    #[test]
    fn seal_is_deterministic_for_fixed_inputs() {
        // Determinism (fixed key, nonce, AD, plaintext) makes the transport
        // testable and reproducible; it is also why the caller — not the
        // transport — owns nonce uniqueness.
        let transport = Shake256Transport;
        let a = transport.seal(&key(), NONCE, AD, b"same");
        let b = transport.seal(&key(), NONCE, AD, b"same");
        assert_eq!(a, b);
    }
}
