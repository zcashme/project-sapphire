//! On-the-wire protocol types.
//!
//! These are the request/response envelopes that flow between client →
//! coordinator → signers. Generic over the FROST `Ciphersuite` so the same
//! protocol works for Ed25519 (default), RedPallas (Zcash Orchard), or any
//! other supported scheme.

use frost_core::{
    keys::PublicKeyPackage,
    round1::SigningCommitments,
    round2::SignatureShare,
    Ciphersuite, Identifier, Signature,
};
use serde::{Deserialize, Serialize};

/// A request for the network to produce a signature over `message`.
///
/// In V0 this is unauthenticated. V0.2+ adds a `auth_zkp` field carrying a
/// proof that the caller is authorized to request a signature under this
/// derivation path / policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct SigningRequest<C: Ciphersuite> {
    /// Unique request ID. Used to dedupe and route response.
    pub request_id: uuid_lite::Uuid,
    /// Message bytes to be signed.
    #[serde(with = "hex::serde")]
    pub message: Vec<u8>,
    /// Public key package identifying the group key.
    pub group_pubkey: PublicKeyPackage<C>,
    /// Identifiers of the signers the coordinator selected to participate.
    pub participants: Vec<Identifier<C>>,
}

/// A completed signature produced by the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct SigningResponse<C: Ciphersuite> {
    pub request_id: uuid_lite::Uuid,
    pub signature: Signature<C>,
}

/// Round-1 message: per-signer commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct Round1Message<C: Ciphersuite> {
    pub participant: Identifier<C>,
    pub commitments: SigningCommitments<C>,
}

/// Round-2 message: per-signer signature share.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct Round2Message<C: Ciphersuite> {
    pub participant: Identifier<C>,
    pub share: SignatureShare<C>,
}

/// Re-exports so downstream crates don't have to depend on frost-core directly.
pub mod frost_types {
    pub use frost_core::{
        keys::{KeyPackage, PublicKeyPackage, SecretShare},
        round1::{SigningCommitments, SigningNonces},
        round2::SignatureShare,
        Identifier, Signature, SigningPackage, VerifyingKey,
    };
    pub use frost_core::Ciphersuite;
}

/// Minimal UUID-lite shim so we don't pull in the full `uuid` crate just for IDs.
///
/// V0 uses random 16-byte IDs encoded as hex. We can swap in the real `uuid`
/// crate if/when it earns its weight.
pub mod uuid_lite {
    use rand::RngCore;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct Uuid(pub [u8; 16]);

    impl Uuid {
        pub fn new<R: RngCore>(rng: &mut R) -> Self {
            let mut bytes = [0u8; 16];
            rng.fill_bytes(&mut bytes);
            Self(bytes)
        }

        pub fn to_hex(&self) -> String {
            hex::encode(self.0)
        }
    }

    impl std::fmt::Display for Uuid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.to_hex())
        }
    }

    impl Serialize for Uuid {
        fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
            ser.serialize_str(&self.to_hex())
        }
    }

    impl<'de> Deserialize<'de> for Uuid {
        fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
            let s = String::deserialize(de)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 16 {
                return Err(serde::de::Error::custom("Uuid must be 16 bytes"));
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            Ok(Uuid(arr))
        }
    }
}

/// Holds a signer's secret key share alongside the group's public key package.
/// Persisted to disk by the signer node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct KeyShareBundle<C: Ciphersuite> {
    pub key_package: frost_core::keys::KeyPackage<C>,
    pub public_key_package: PublicKeyPackage<C>,
}

/// In-flight signing nonces. The signer holds onto these between rounds.
/// They MUST NOT be reused across signing sessions.
#[derive(Debug)]
pub struct PendingNonces<C: Ciphersuite> {
    pub nonces: frost_core::round1::SigningNonces<C>,
}
