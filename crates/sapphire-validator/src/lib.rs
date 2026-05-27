//! Sapphire validator-signer.
//!
//! A validator node combines two roles:
//! 1. **Consensus validator** — participates in the coordination chain's BFT.
//! 2. **MPC signer** — holds one FROST key share.
//!
//! These roles share the same identity (`Identifier<C>` in FROST language; a
//! validator address in CometBFT language). The validator watches the chain
//! state after each block and reacts by submitting transactions:
//!
//! * sees a new `SubmitRequest` → submits its round-1 commitment.
//! * sees a `Signing` phase that includes it as a selected participant →
//!   submits its round-2 share.
//!
//! The aggregation itself happens deterministically inside the state machine
//! once the threshold of shares is committed — no one node "is" the
//! coordinator. That's the V1 architectural shift away from the centralized
//! HTTP coordinator in V0.

use std::collections::HashSet;

use frost_core::{Ciphersuite, Identifier};
use frost_rerandomized::RandomizedCiphersuite;
use rand_core::{CryptoRng, RngCore};

use sapphire_chain::{
    state::{RequestStatus, State},
    tx::Tx,
};
use sapphire_core::{
    protocol::{uuid_lite::Uuid, KeyShareBundle},
    Error,
};
use sapphire_signer::Signer;

/// One validator-signer in the coordination chain.
pub struct Validator<C: Ciphersuite> {
    pub identifier: Identifier<C>,
    pub signer: Signer<C>,
    /// Request IDs we've already produced a commitment for (avoid resubmitting).
    pub committed_requests: HashSet<Uuid>,
    /// Request IDs we've already produced a share for.
    pub shared_requests: HashSet<Uuid>,
}

impl<C: Ciphersuite> Validator<C> {
    pub fn new(bundle: KeyShareBundle<C>) -> Self {
        let identifier = *bundle.key_package.identifier();
        Self {
            identifier,
            signer: Signer::new(bundle),
            committed_requests: HashSet::new(),
            shared_requests: HashSet::new(),
        }
    }
}

impl<C: RandomizedCiphersuite> Validator<C> {
    /// Inspect the current chain state and return any txs this validator
    /// should submit. Stateless w.r.t. the chain — the validator's own
    /// memory only tracks "have I already responded to this request?".
    ///
    /// Bounded on [`RandomizedCiphersuite`] because round-2 signing uses
    /// the per-request randomizer stored on-chain.
    pub fn react<R: RngCore + CryptoRng>(
        &mut self,
        state: &State<C>,
        rng: &mut R,
    ) -> Result<Vec<Tx<C>>, Error> {
        let mut out = Vec::new();
        let group = match &state.group {
            Some(g) => g,
            None => return Ok(out),
        };
        if !group.validators.contains(&self.identifier) {
            return Ok(out);
        }

        for (request_id, entry) in &state.requests {
            match &entry.status {
                RequestStatus::AwaitingCommitments { commitments } => {
                    if commitments.contains_key(&self.identifier) {
                        self.committed_requests.insert(*request_id);
                        continue;
                    }
                    if self.committed_requests.contains(request_id) {
                        // Already submitted; tx in flight, don't double-submit.
                        continue;
                    }
                    let commitments = self.signer.commit(*request_id, rng)?;
                    self.committed_requests.insert(*request_id);
                    out.push(Tx::SubmitCommitment {
                        request_id: *request_id,
                        validator: self.identifier,
                        commitments,
                    });
                }
                RequestStatus::Signing {
                    signing_package,
                    participants,
                    shares,
                } => {
                    if !participants.contains(&self.identifier) {
                        continue;
                    }
                    if shares.contains_key(&self.identifier) {
                        self.shared_requests.insert(*request_id);
                        continue;
                    }
                    if self.shared_requests.contains(request_id) {
                        continue;
                    }
                    let share = match self.signer.sign_share_rerandomized(
                        request_id,
                        signing_package,
                        entry.randomizer,
                    ) {
                        Ok(s) => s,
                        Err(Error::SessionNotFound) => {
                            // We committed but our commit wasn't in the
                            // threshold-cut, so we have no nonces for this
                            // request. Round 2 needs them; nothing to do.
                            tracing::debug!(
                                validator = ?self.identifier,
                                request = %request_id,
                                "no nonces for this request, skipping share submission"
                            );
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    self.shared_requests.insert(*request_id);
                    out.push(Tx::SubmitShare {
                        request_id: *request_id,
                        validator: self.identifier,
                        share,
                    });
                }
                RequestStatus::Completed { .. } | RequestStatus::Failed { .. } => {}
            }
        }
        Ok(out)
    }
}
