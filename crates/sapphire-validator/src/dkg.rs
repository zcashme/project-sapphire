//! Chain-driven DKG participant.
//!
//! Wraps the FROST DKG protocol so that each round's message exchange flows
//! through the Sapphire coordination chain. The participant reacts to
//! [`State`] just like [`crate::Validator`] does for signing:
//!
//!   * sees a `ceremony` it belongs to → submits its round-1 package.
//!   * sees round-1 complete → runs `dkg::part2`, seals each round-2 package
//!     to its recipient's X25519 key, submits them.
//!   * sees round-2 complete → opens the envelopes addressed to it, runs
//!     `dkg::part3`, submits the resulting [`PublicKeyPackage`] for cross-
//!     check, and stashes its derived [`KeyPackage`] for later promotion.
//!
//! Once `state.group` is `Some` (the chain promoted the agreed PKP into a
//! [`GroupConfig`]), the caller can call [`DkgParticipant::into_validator`]
//! to drop into the normal signing flow.

use std::collections::BTreeMap;

use crypto_box::SecretKey as EncSecretKey;
use frost_core::{
    keys::{
        dkg::{self, round1, round2},
        KeyPackage, PublicKeyPackage,
    },
    Ciphersuite, Identifier,
};
use rand_core::{CryptoRng, RngCore};
use sapphire_chain::{
    dkg_envelope::{open as open_envelope, seal as seal_envelope, EncPublicKey, EnvelopeError},
    state::State,
    tx::Tx,
};
use sapphire_core::protocol::KeyShareBundle;

use crate::Validator;

/// One participant in a chain-driven DKG ceremony.
pub struct DkgParticipant<C: Ciphersuite> {
    pub identifier: Identifier<C>,
    pub enc_secret: EncSecretKey,
    pub enc_public: EncPublicKey,

    /// Holds `part1` output until `part2` consumes it.
    secret_r1: Option<round1::SecretPackage<C>>,
    /// Holds `part2` output until `part3` consumes it.
    secret_r2: Option<round2::SecretPackage<C>>,

    /// Have we already broadcast our round-1 package?
    submitted_r1: bool,
    /// Have we already submitted all our round-2 envelopes?
    submitted_r2: bool,
    /// Have we already submitted our finalize tx?
    submitted_finalize: bool,

    /// Populated after `part3` runs successfully.
    pub key_package: Option<KeyPackage<C>>,
    pub public_key_package: Option<PublicKeyPackage<C>>,
}

#[derive(Debug, thiserror::Error)]
pub enum DkgError {
    #[error("frost dkg: {0}")]
    Frost(String),
    #[error("envelope decryption: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("ceremony state inconsistency: {0}")]
    Inconsistent(&'static str),
}

impl<C: Ciphersuite> From<frost_core::Error<C>> for DkgError {
    fn from(e: frost_core::Error<C>) -> Self {
        DkgError::Frost(e.to_string())
    }
}

impl<C: Ciphersuite> DkgParticipant<C> {
    /// Generate a fresh participant. Picks a new X25519 keypair for round-2
    /// envelope routing.
    pub fn new<R: RngCore + CryptoRng>(identifier: Identifier<C>, rng: &mut R) -> Self {
        let enc_secret = EncSecretKey::generate(rng);
        let enc_public: EncPublicKey = enc_secret.public_key().into();
        Self {
            identifier,
            enc_secret,
            enc_public,
            secret_r1: None,
            secret_r2: None,
            submitted_r1: false,
            submitted_r2: false,
            submitted_finalize: false,
            key_package: None,
            public_key_package: None,
        }
    }

    /// Drive the ceremony one step. Returns the txs this participant wants
    /// committed in the next block.
    pub fn react<R: RngCore + CryptoRng>(
        &mut self,
        state: &State<C>,
        rng: &mut R,
    ) -> Result<Vec<Tx<C>>, DkgError> {
        let mut out = Vec::new();

        // If the chain has already promoted the ceremony into a GroupConfig,
        // there's nothing more for the DKG layer to do — the caller should
        // call `into_validator` and switch to the signing flow.
        if state.group.is_some() {
            return Ok(out);
        }

        let ceremony = match &state.ceremony {
            Some(c) => c,
            None => return Ok(out),
        };
        if !ceremony.validators.contains_key(&self.identifier) {
            return Ok(out);
        }

        let total = ceremony.params.total;
        let threshold = ceremony.params.threshold;

        // ---- Round 1 ----
        if !self.submitted_r1 {
            if ceremony.round1.contains_key(&self.identifier) {
                // Someone (us) already posted r1; just remember that.
                self.submitted_r1 = true;
            } else {
                let (secret_r1, package_r1) =
                    dkg::part1::<C, _>(self.identifier, total, threshold, rng)?;
                self.secret_r1 = Some(secret_r1);
                self.submitted_r1 = true;
                out.push(Tx::DkgRound1 {
                    from: self.identifier,
                    package: package_r1,
                });
                return Ok(out);
            }
        }

        // ---- Round 2 ----
        // Only runnable once all r1 packages are on-chain.
        if !ceremony.r1_complete() {
            return Ok(out);
        }

        if !self.submitted_r2 {
            // Build "others' r1 packages" map (everyone except us).
            let others_r1: BTreeMap<_, _> = ceremony
                .round1
                .iter()
                .filter(|(id, _)| **id != self.identifier)
                .map(|(id, pkg)| (*id, pkg.clone()))
                .collect();

            let secret_r1 = self
                .secret_r1
                .take()
                .ok_or(DkgError::Inconsistent("missing r1 secret for r2"))?;
            let (secret_r2, sent_r2) = dkg::part2::<C>(secret_r1, &others_r1)?;
            self.secret_r2 = Some(secret_r2);

            // Seal each outgoing r2 package to its recipient and queue the txs.
            for (recipient, pkg) in sent_r2 {
                let recipient_pk = ceremony
                    .validators
                    .get(&recipient)
                    .ok_or(DkgError::Inconsistent("recipient has no enc pubkey"))?;
                let plaintext = serde_json::to_vec(&pkg)?;
                let sealed = seal_envelope(rng, recipient_pk, &plaintext);
                out.push(Tx::DkgRound2 {
                    from: self.identifier,
                    to: recipient,
                    sealed,
                });
            }
            self.submitted_r2 = true;
            return Ok(out);
        }

        // ---- Round 3 / Finalize ----
        if !ceremony.r2_complete() {
            return Ok(out);
        }

        if !self.submitted_finalize {
            // If we already submitted (and the tx is still in flight), don't
            // re-derive — the chain will dedupe.
            if ceremony.finalize.contains_key(&self.identifier) {
                self.submitted_finalize = true;
                return Ok(out);
            }

            // Open every envelope addressed to us.
            let mut received_r2: BTreeMap<Identifier<C>, round2::Package<C>> = BTreeMap::new();
            for ((from, to), sealed) in &ceremony.round2 {
                if *to != self.identifier {
                    continue;
                }
                let pt = open_envelope(&self.enc_secret, sealed)?;
                let pkg: round2::Package<C> = serde_json::from_slice(&pt)?;
                received_r2.insert(*from, pkg);
            }

            let others_r1: BTreeMap<_, _> = ceremony
                .round1
                .iter()
                .filter(|(id, _)| **id != self.identifier)
                .map(|(id, pkg)| (*id, pkg.clone()))
                .collect();

            let secret_r2 = self
                .secret_r2
                .take()
                .ok_or(DkgError::Inconsistent("missing r2 secret for finalize"))?;
            let (key_pkg, pkp) = dkg::part3::<C>(&secret_r2, &others_r1, &received_r2)?;

            self.key_package = Some(key_pkg);
            self.public_key_package = Some(pkp.clone());
            self.submitted_finalize = true;

            out.push(Tx::DkgFinalize {
                from: self.identifier,
                pkp,
            });
            return Ok(out);
        }

        Ok(out)
    }

    /// Has this participant successfully completed DKG locally?
    pub fn is_complete(&self) -> bool {
        self.key_package.is_some() && self.public_key_package.is_some()
    }

    /// Consume self and produce a regular signing [`Validator`].
    ///
    /// Errors if DKG hasn't completed (no key package derived locally).
    /// Note: `RandomizedCiphersuite` isn't required to construct a Validator,
    /// only to drive the signing react loop, so this stays on `Ciphersuite`.
    pub fn into_validator(self) -> Result<Validator<C>, DkgError> {
        let key_package = self
            .key_package
            .ok_or(DkgError::Inconsistent("DKG not complete: no key package"))?;
        let pkp = self
            .public_key_package
            .ok_or(DkgError::Inconsistent("DKG not complete: no PKP"))?;
        Ok(Validator::new(KeyShareBundle {
            key_package,
            public_key_package: pkp,
        }))
    }
}
