//! Distributed Key Generation.
//!
//! Implements FROST's three-round DKG (`part1` → `part2` → `part3`) simulated
//! in-process: each "participant" is a local computation, with messages
//! exchanged through `BTreeMap`s rather than the network.
//!
//! This is the same protocol a fully distributed Sapphire DKG ceremony would
//! run; the only thing changed is the transport. The output — a [`KeyPackage`]
//! per participant plus a shared [`PublicKeyPackage`] — is indistinguishable
//! from trusted-dealer output to downstream signing code.
//!
//! **Security property:** No participant ever sees another participant's
//! secret polynomial coefficients. The reconstructable secret is never
//! materialized in any one place.

use std::collections::BTreeMap;

use frost_core::{
    keys::{
        dkg::{self, round1, round2},
        KeyPackage, PublicKeyPackage,
    },
    Ciphersuite, Identifier,
};
use rand_core::{CryptoRng, RngCore};

use sapphire_core::{Error, MpcParams, Result};

/// Run the FROST DKG protocol in-process for `params.total` participants.
///
/// Returns the same shape as [`crate::trusted_dealer::generate_with_trusted_dealer`]:
/// one [`KeyPackage`] per participant + the shared [`PublicKeyPackage`].
///
/// Each participant uses an identifier from `1..=total` (FROST's default).
pub fn generate_with_dkg<C: Ciphersuite, R: RngCore + CryptoRng>(
    params: MpcParams,
    rng: &mut R,
) -> Result<(
    BTreeMap<Identifier<C>, KeyPackage<C>>,
    PublicKeyPackage<C>,
)> {
    let total = params.total;
    let threshold = params.threshold;

    // -------- Round 1 --------
    // Each participant computes (secret_package_r1, public_package_r1).
    let mut secrets_r1: BTreeMap<Identifier<C>, round1::SecretPackage<C>> = BTreeMap::new();
    let mut publics_r1: BTreeMap<Identifier<C>, round1::Package<C>> = BTreeMap::new();
    for i in 1..=total {
        let id: Identifier<C> = i.try_into().map_err(Error::from)?;
        let (secret_pkg, public_pkg) =
            dkg::part1::<C, _>(id, total, threshold, &mut *rng).map_err(Error::from)?;
        secrets_r1.insert(id, secret_pkg);
        publics_r1.insert(id, public_pkg);
    }

    // -------- Round 2 --------
    // Each participant receives all *other* participants' r1 public packages
    // and runs part2, producing one secret_r2 and a map of r2 packages keyed
    // by recipient identifier.
    let mut secrets_r2: BTreeMap<Identifier<C>, round2::SecretPackage<C>> = BTreeMap::new();
    // For each recipient, collect the r2 messages sent *to* them.
    let mut inbox_r2: BTreeMap<Identifier<C>, BTreeMap<Identifier<C>, round2::Package<C>>> =
        BTreeMap::new();
    for id in publics_r1.keys() {
        inbox_r2.insert(*id, BTreeMap::new());
    }

    for (id, secret_r1) in secrets_r1 {
        // Public packages from everyone except `id`.
        let others_r1: BTreeMap<_, _> = publics_r1
            .iter()
            .filter(|(other, _)| **other != id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        let (secret_r2, sent_r2) = dkg::part2::<C>(secret_r1, &others_r1).map_err(Error::from)?;
        secrets_r2.insert(id, secret_r2);

        // Distribute each r2 package to its recipient's inbox.
        for (recipient, pkg) in sent_r2 {
            inbox_r2
                .get_mut(&recipient)
                .expect("recipient inbox preallocated")
                .insert(id, pkg);
        }
    }

    // -------- Round 3 --------
    // Each participant verifies received r2 packages and computes its KeyPackage.
    let mut key_packages = BTreeMap::new();
    let mut group_pkp: Option<PublicKeyPackage<C>> = None;

    for (id, secret_r2) in secrets_r2 {
        let received_r2 = inbox_r2.remove(&id).expect("inbox present");
        let others_r1: BTreeMap<_, _> = publics_r1
            .iter()
            .filter(|(other, _)| **other != id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        let (key_pkg, pkp) =
            dkg::part3::<C>(&secret_r2, &others_r1, &received_r2).map_err(Error::from)?;
        key_packages.insert(id, key_pkg);

        // All participants compute the same PKP; check that for safety.
        match &group_pkp {
            None => group_pkp = Some(pkp),
            Some(existing) => {
                if existing.verifying_key() != pkp.verifying_key() {
                    return Err(Error::Frost(
                        "DKG inconsistency: participants disagree on group verifying key".into(),
                    ));
                }
            }
        }
    }

    Ok((key_packages, group_pkp.expect("at least one participant")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_ed25519::Ed25519Sha512;

    #[test]
    fn dkg_produces_signable_group() {
        let mut rng = rand::thread_rng();
        let params = MpcParams::new(2, 3).unwrap();
        let (key_packages, pkp) =
            generate_with_dkg::<Ed25519Sha512, _>(params, &mut rng).unwrap();
        assert_eq!(key_packages.len(), 3);
        for (id, kp) in &key_packages {
            let vs = pkp.verifying_shares().get(id).unwrap();
            assert_eq!(vs, kp.verifying_share());
        }
    }
}
