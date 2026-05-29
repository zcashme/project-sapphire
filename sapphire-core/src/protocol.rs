//! Shared protocol types.
//!
//! Generic over the FROST `Ciphersuite` so the same types serve Ed25519
//! (tests) or RedPallas (Zcash Orchard spend-auth).

use frost_core::{keys::PublicKeyPackage, Ciphersuite};
use serde::{Deserialize, Serialize};

/// Minimal UUID-lite shim so we don't pull in the full `uuid` crate just for
/// IDs: a random 16-byte value encoded as hex.
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
/// Persisted to disk by the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct KeyShareBundle<C: Ciphersuite> {
    pub key_package: frost_core::keys::KeyPackage<C>,
    pub public_key_package: PublicKeyPackage<C>,
}
