//! Sapphire signer.
//!
//! A signer holds one key share of a Sapphire MPC group and produces FROST
//! protocol messages. In the chain-driven Sapphire architecture, each
//! validator owns one [`Signer`] and reacts to chain state by submitting
//! commitments / shares back as on-chain transactions; the library itself
//! does no networking.

use std::collections::HashMap;
use std::sync::Mutex;

use frost_core::{
    keys::KeyPackage,
    round1::{self, SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Ciphersuite, Identifier, SigningPackage,
};
use frost_rerandomized::{RandomizedCiphersuite, Randomizer};
use rand_core::{CryptoRng, RngCore};

use sapphire_core::{
    protocol::{uuid_lite::Uuid, KeyShareBundle},
    Error, Result,
};

/// A Sapphire signer node.
///
/// Stateless from the protocol's perspective — nonces are held only between
/// round 1 and round 2 for a given session ID.
pub struct Signer<C: Ciphersuite> {
    bundle: KeyShareBundle<C>,
    /// Pending nonces, keyed by the coordinator-assigned session ID.
    /// Wrapped in a Mutex so the signer can be shared across tasks.
    pending: Mutex<HashMap<Uuid, SigningNonces<C>>>,
}

impl<C: Ciphersuite> Signer<C> {
    pub fn new(bundle: KeyShareBundle<C>) -> Self {
        Self {
            bundle,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn identifier(&self) -> Identifier<C> {
        *self.bundle.key_package.identifier()
    }

    pub fn key_package(&self) -> &KeyPackage<C> {
        &self.bundle.key_package
    }

    /// Round 1: produce a fresh commitment for `session_id`.
    /// The signer remembers the nonces internally until [`Signer::sign_share`].
    pub fn commit<R: RngCore + CryptoRng>(
        &self,
        session_id: Uuid,
        rng: &mut R,
    ) -> Result<SigningCommitments<C>> {
        let (nonces, commitments) =
            round1::commit::<C, _>(self.bundle.key_package.signing_share(), rng);
        let mut pending = self.pending.lock().expect("pending lock poisoned");
        if pending.contains_key(&session_id) {
            return Err(Error::SessionInUse);
        }
        pending.insert(session_id, nonces);
        Ok(commitments)
    }

    /// Round 2: produce a signature share given the coordinator-assembled
    /// [`SigningPackage`]. Consumes the per-session nonces.
    pub fn sign_share(
        &self,
        session_id: &Uuid,
        signing_package: &SigningPackage<C>,
    ) -> Result<SignatureShare<C>> {
        let nonces = {
            let mut pending = self.pending.lock().expect("pending lock poisoned");
            pending.remove(session_id).ok_or(Error::SessionNotFound)?
        };
        let share = round2::sign::<C>(signing_package, &nonces, &self.bundle.key_package)
            .map_err(Error::from)?;
        Ok(share)
    }

    /// Abort a session before round 2. Drops the nonces.
    pub fn abort(&self, session_id: &Uuid) {
        let mut pending = self.pending.lock().expect("pending lock poisoned");
        pending.remove(session_id);
    }
}

impl<C: RandomizedCiphersuite> Signer<C> {
    /// Round 2 for rerandomized FROST: produce a share against the
    /// rerandomized key derived from `randomizer`. Consumes the per-session
    /// nonces just like [`Signer::sign_share`].
    pub fn sign_share_rerandomized(
        &self,
        session_id: &Uuid,
        signing_package: &SigningPackage<C>,
        randomizer: Randomizer<C>,
    ) -> Result<SignatureShare<C>> {
        let nonces = {
            let mut pending = self.pending.lock().expect("pending lock poisoned");
            pending.remove(session_id).ok_or(Error::SessionNotFound)?
        };
        #[allow(deprecated)]
        let share = frost_rerandomized::sign::<C>(
            signing_package,
            &nonces,
            &self.bundle.key_package,
            randomizer,
        )
        .map_err(Error::from)?;
        Ok(share)
    }
}
