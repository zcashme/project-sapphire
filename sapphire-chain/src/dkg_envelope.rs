//! Sealed-box envelopes for DKG round-2 packages.
//!
//! Round-2 of FROST DKG produces, for each ordered (sender, recipient) pair,
//! a `round2::Package` that contains a *secret share contribution* the
//! recipient must combine into their final key share. These cannot be
//! broadcast in plaintext: any party that sees all of them can reconstruct
//! the group's signing key.
//!
//! Sapphire ships round-2 packages through the coordination chain (so every
//! validator sees the same transcript and the protocol is replayable), but
//! seals each package to the intended recipient's X25519 public key. Only
//! the holder of the matching secret key can open the envelope.
//!
//! Sender identity is asserted by the chain (the validator submits the tx
//! under their consensus identity); we don't bind it in the envelope.

use crypto_box::{
    aead::{Aead, AeadCore, OsRng as CboxOsRng},
    ChaChaBox, PublicKey, SecretKey,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// X25519 public key serialized as raw 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncPublicKey(pub [u8; 32]);

impl From<PublicKey> for EncPublicKey {
    fn from(pk: PublicKey) -> Self {
        EncPublicKey(pk.to_bytes())
    }
}

impl From<EncPublicKey> for PublicKey {
    fn from(value: EncPublicKey) -> Self {
        PublicKey::from(value.0)
    }
}

/// Sealed envelope: ephemeral-pubkey || nonce || ciphertext (anonymous-sender
/// authenticated encryption to a recipient's static X25519 pubkey).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed(pub Vec<u8>);

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("ciphertext too short")]
    TooShort,
    #[error("decryption failed")]
    Decrypt,
}

/// Seal `plaintext` to `recipient`. Each call produces a fresh ephemeral
/// X25519 keypair, performs DH against `recipient`, and encrypts under
/// XChaCha20-Poly1305. Output layout: `eph_pub(32) || nonce(24) || ct||tag`.
pub fn seal<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient: &EncPublicKey,
    plaintext: &[u8],
) -> Sealed {
    let ephemeral_secret = SecretKey::generate(rng);
    let ephemeral_public = ephemeral_secret.public_key();
    let recipient_pk: PublicKey = (*recipient).into();
    let cbox = ChaChaBox::new(&recipient_pk, &ephemeral_secret);
    // Nonce gen uses its own OsRng draw — fine; this is symmetric AEAD nonce,
    // unrelated to the caller's RNG seam.
    let nonce = ChaChaBox::generate_nonce(&mut CboxOsRng);
    let ct = cbox
        .encrypt(&nonce, plaintext)
        .expect("XChaCha20-Poly1305 encrypt is infallible on valid keys");

    let mut out = Vec::with_capacity(32 + 24 + ct.len());
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Sealed(out)
}

/// Open a [`Sealed`] envelope with the recipient's secret key.
pub fn open(secret: &SecretKey, sealed: &Sealed) -> Result<Vec<u8>, EnvelopeError> {
    if sealed.0.len() < 32 + 24 {
        return Err(EnvelopeError::TooShort);
    }
    let (eph_pub_bytes, rest) = sealed.0.split_at(32);
    let (nonce_bytes, ct) = rest.split_at(24);

    let eph_pub_arr: [u8; 32] = eph_pub_bytes
        .try_into()
        .expect("split_at guarantees length 32");
    let eph_pub = PublicKey::from(eph_pub_arr);
    let cbox = ChaChaBox::new(&eph_pub, secret);
    let nonce = chacha20poly1305_nonce_from_slice(nonce_bytes);
    cbox.decrypt(&nonce, ct)
        .map_err(|_| EnvelopeError::Decrypt)
}

fn chacha20poly1305_nonce_from_slice(
    bytes: &[u8],
) -> crypto_box::aead::generic_array::GenericArray<u8, crypto_box::aead::consts::U24> {
    let arr: [u8; 24] = bytes.try_into().expect("nonce slice length");
    arr.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn round_trip() {
        let mut rng = OsRng;
        let recipient_sk = SecretKey::generate(&mut rng);
        let recipient_pk: EncPublicKey = recipient_sk.public_key().into();

        let pt = b"shamir share contribution from participant 3 to participant 5";
        let sealed = seal(&mut rng, &recipient_pk, pt);
        let opened = open(&recipient_sk, &sealed).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn wrong_recipient_fails() {
        let mut rng = OsRng;
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_sk = SecretKey::generate(&mut rng);
        let bob_pk: EncPublicKey = bob_sk.public_key().into();

        let sealed = seal(&mut rng, &bob_pk, b"for bob's eyes only");
        assert!(open(&alice_sk, &sealed).is_err());
    }
}
