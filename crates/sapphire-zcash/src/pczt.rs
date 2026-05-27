//! Orchard PCZT signer driven by Sapphire.
//!
//! PCZT (Partially Constructed Zcash Transaction, ZIP-269) splits transaction
//! construction into roles: Creator, Constructor, IO Finalizer, Prover,
//! Signer, Combiner, Spend Finalizer, Transaction Extractor. Sapphire plays
//! the **Signer** role for Orchard spends.
//!
//! For each Orchard action in the bundle the Constructor has already chosen
//! the per-spend randomizer `α` and set `rk = ak + α·G`. The Prover (a
//! separate trusted role for now, see SAPPHIRE.md Phase 2) has set the
//! `zkproof`. All Sapphire needs is `(sighash, α)` per action — it drives the
//! coordination chain to produce a rerandomized signature, then injects it
//! via [`orchard::pczt::Action::apply_signature`], which verifies the
//! signature against `rk` before accepting it.

use ff::PrimeField;
use frost_rerandomized::Randomizer;
use orchard::{pczt::Bundle as PcztBundle, primitives::redpallas};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use sapphire_chain::sim::ChainSim;
use sapphire_validator::Validator;

use crate::{drive_signing_session, Cs, SignError};

#[derive(Debug, Error)]
pub enum PcztSignError {
    #[error("PCZT action {0} has no `alpha`; Constructor must set it before Signer runs")]
    ActionMissingAlpha(usize),

    #[error("sapphire signing failed for action {action}: {source}")]
    Sign {
        action: usize,
        #[source]
        source: SignError,
    },

    #[error("could not convert Sapphire randomizer/signature bytes for action {0}")]
    Conversion(usize),

    #[error("orchard rejected externally-applied signature for action {0}: {1}")]
    ApplyRejected(usize, String),
}

/// Sign every Orchard action in `bundle` via Sapphire.
///
/// `sighash` is the ZIP-244 transaction sighash, computed by the caller from
/// the surrounding transaction (transparent, sapling, orchard) — PCZT itself
/// does not store it because it depends on bundle context outside Orchard.
///
/// Mutates each action's `spend_auth_sig` in place. On return, the PCZT is
/// ready for the Spend Finalizer + Transaction Extractor roles.
pub fn sign_pczt_orchard_bundle<R: RngCore + CryptoRng>(
    bundle: &mut PcztBundle,
    sighash: [u8; 32],
    chain: &mut ChainSim<Cs>,
    validators: &mut [Validator<Cs>],
    rng: &mut R,
) -> Result<(), PcztSignError> {
    for (idx, action) in bundle.actions_mut().iter_mut().enumerate() {
        let alpha_scalar = action
            .spend()
            .alpha()
            .as_ref()
            .ok_or(PcztSignError::ActionMissingAlpha(idx))?;

        // pallas::Scalar ↔ Randomizer<PallasBlake2b512> by byte roundtrip.
        // Both are the Pallas scalar field; the 32-byte little-endian
        // canonical encoding is the same on both sides. This insulates us
        // from any future divergence in newtype lineage.
        let alpha_bytes = alpha_scalar.to_repr();
        let alpha_randomizer = Randomizer::<Cs>::deserialize(alpha_bytes.as_ref())
            .map_err(|_| PcztSignError::Conversion(idx))?;

        let signature = drive_signing_session(chain, validators, sighash, alpha_randomizer, rng)
            .map_err(|source| PcztSignError::Sign {
                action: idx,
                source,
            })?;

        let sig_bytes = signature
            .serialize()
            .map_err(|_| PcztSignError::Conversion(idx))?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PcztSignError::Conversion(idx))?;
        let orchard_sig = redpallas::Signature::<redpallas::SpendAuth>::from(sig_arr);

        action
            .apply_signature(sighash, orchard_sig)
            .map_err(|e| PcztSignError::ApplyRejected(idx, format!("{:?}", e)))?;
    }
    Ok(())
}
