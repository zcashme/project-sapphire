//! Trusted-dealer keygen.
//!
//! A single trusted party generates the group key and distributes shares.
//! **The dealer briefly sees the full secret key** — acceptable for prototyping
//! and demos, replaced by DKG in V0.2.

use std::collections::BTreeMap;

use frost_core::{
    keys::{self, IdentifierList, KeyPackage, PublicKeyPackage},
    Ciphersuite, Identifier,
};
use rand_core::{CryptoRng, RngCore};

use sapphire_core::{Error, MpcParams, Result};

/// Generate a `threshold`-of-`total` group via trusted-dealer keygen.
///
/// Returns one [`KeyPackage`] per participant plus the shared [`PublicKeyPackage`].
/// The dealer's transient state is dropped on return.
pub fn generate_with_trusted_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(
    params: MpcParams,
    rng: &mut R,
) -> Result<(
    BTreeMap<Identifier<C>, KeyPackage<C>>,
    PublicKeyPackage<C>,
)> {
    let (secret_shares, public_key_package) = keys::generate_with_dealer::<C, _>(
        params.total,
        params.threshold,
        IdentifierList::Default,
        rng,
    )
    .map_err(Error::from)?;

    let mut key_packages = BTreeMap::new();
    for (identifier, secret_share) in secret_shares {
        let key_package = KeyPackage::try_from(secret_share).map_err(Error::from)?;
        key_packages.insert(identifier, key_package);
    }

    Ok((key_packages, public_key_package))
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_ed25519::Ed25519Sha512;

    #[test]
    fn trusted_dealer_produces_consistent_packages() {
        let mut rng = rand::thread_rng();
        let params = MpcParams::new(2, 3).unwrap();
        let (key_packages, pkp) =
            generate_with_trusted_dealer::<Ed25519Sha512, _>(params, &mut rng).unwrap();
        assert_eq!(key_packages.len(), 3);
        // Each key package's verifying share should appear in the public key package.
        for (id, kp) in &key_packages {
            let vs = pkp.verifying_shares().get(id).unwrap();
            assert_eq!(vs, kp.verifying_share());
        }
    }
}
