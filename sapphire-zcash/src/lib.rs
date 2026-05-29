//! Sapphire → Zcash interop.
//!
//! Sapphire produces FROST-RedPallas signatures rerandomized per request.
//! This crate is the bridge from those signatures to actual Orchard spend
//! authorization:
//!
//! * [`drive_signing_session`] — given a [`ChainSim`], a slate of
//!   [`Validator`]s, a 32-byte sighash, and an `α` randomizer, run one full
//!   chain lifecycle and return the aggregated [`Signature`]. This is the
//!   primitive you call once per Orchard action.
//!
//! * [`pczt::sign_pczt_orchard_bundle`] (feature `pczt`) — given an
//!   `orchard::pczt::Bundle` whose actions have `α` set, walk every action,
//!   call [`drive_signing_session`] for each, then apply the resulting
//!   signatures via `orchard::pczt::Action::apply_signature`. This is the
//!   thing a Sapphire-using wallet calls right before tx extraction.
//!
//! The signing primitives here are deliberately *not* tied to Orchard's tx
//! types — the chain doesn't know about Zcash. The Orchard-specific glue
//! lives in [`pczt`].

use frost_core::Signature;
use frost_rerandomized::Randomizer;
use rand_core::{CryptoRng, RngCore};
use reddsa::frost::redpallas::PallasBlake2b512;
use thiserror::Error;

use sapphire_chain::{
    sim::ChainSim,
    state::{ApplyError, RequestStatus},
    tx::Tx,
};
use sapphire_core::protocol::uuid_lite::Uuid;
use sapphire_node::Node;

#[cfg(feature = "pczt")]
pub mod pczt;

/// Sapphire is RedPallas-only for the Zcash-facing surface. Other ciphersuites
/// don't produce Orchard-valid signatures, so they're not reachable from here.
pub type Cs = PallasBlake2b512;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("chain rejected SubmitRequest: {0}")]
    SubmitRequestRejected(String),

    #[error("validator react failed: {0}")]
    ValidatorReact(#[from] sapphire_core::Error),

    #[error("request finished in Failed state: {0}")]
    AggregationFailed(String),

    #[error("request never reached Completed state (last status: {0})")]
    StuckBeforeCompletion(&'static str),

    #[error("request entry missing from final chain state")]
    RequestMissing,
}

impl From<ApplyError> for SignError {
    fn from(e: ApplyError) -> Self {
        SignError::SubmitRequestRejected(e.to_string())
    }
}

/// Drive the Sapphire coordination chain through one signing session.
///
/// Submits a `SubmitRequest` carrying `sighash` and `alpha`, then loops the
/// react → commit_block cycle until the request reaches a terminal status.
/// Returns the aggregated [`Signature`] on success.
///
/// The signature verifies against `rk = group_vk + α·G`, which is exactly
/// what Orchard's spend-auth check uses (`spend.rk.verify(sighash, sig)` in
/// `orchard::pczt::Action::apply_signature`).
pub fn drive_signing_session<R: RngCore + CryptoRng>(
    chain: &mut ChainSim<Cs>,
    validators: &mut [Node<Cs>],
    sighash: [u8; 32],
    alpha: Randomizer<Cs>,
    rng: &mut R,
) -> Result<Signature<Cs>, SignError> {
    let request_id = Uuid::new(rng);

    chain.submit(Tx::SubmitRequest {
        request_id,
        message: sighash.to_vec(),
        randomizer: alpha,
    });
    for (_, result) in chain.commit_block() {
        if let Err(e) = result {
            return Err(e.into());
        }
    }

    // Bound iterations defensively — under honest validators the chain reaches
    // Completed in two more blocks (commits then shares). Cap at 8 in case a
    // validator can't produce a share and we'd otherwise loop forever.
    for _ in 0..8 {
        let mut emitted_any = false;
        for v in validators.iter_mut() {
            for tx in v.react(&chain.state, rng)? {
                chain.submit(tx);
                emitted_any = true;
            }
        }
        let _ = chain.commit_block();

        let entry = chain
            .state
            .requests
            .get(&request_id)
            .ok_or(SignError::RequestMissing)?;
        match &entry.status {
            RequestStatus::Completed { signature, .. } => return Ok(*signature),
            RequestStatus::Failed { reason } => {
                return Err(SignError::AggregationFailed(reason.clone()))
            }
            _ if !emitted_any => {
                // Nothing else to do and we're not done — give up.
                return Err(SignError::StuckBeforeCompletion(match entry.status {
                    RequestStatus::AwaitingCommitments { .. } => "AwaitingCommitments",
                    RequestStatus::Signing { .. } => "Signing",
                    _ => "unreachable",
                }));
            }
            _ => continue,
        }
    }
    Err(SignError::StuckBeforeCompletion("loop bound exhausted"))
}
