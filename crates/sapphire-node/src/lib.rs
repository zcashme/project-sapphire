//! Sapphire node.
//!
//! Each Sapphire node holds one FROST key share, runs the FROST round-1 /
//! round-2 math locally, and reacts to chain state by submitting [`Tx<C>`]s.
//! It also drives chain-driven DKG via [`DkgParticipant`] (which produces a
//! `Node` once the ceremony completes).
//!
//! There is no separate "signer" type any more — `Node` *is* the signer.
//! `react()` is the only loop the rest of the system calls into; everything
//! else (nonce management, request bookkeeping, the FROST primitives) is
//! an implementation detail.

pub mod dkg;

pub use dkg::{DkgError, DkgParticipant};

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use frost_core::{
    keys::KeyPackage,
    round1::{self, SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Ciphersuite, Identifier, SigningPackage,
};
use frost_rerandomized::{RandomizedCiphersuite, Randomizer};
use rand_core::{CryptoRng, RngCore};

use sapphire_chain::{
    state::{RequestStatus, State},
    tx::Tx,
};
use sapphire_core::{
    protocol::{uuid_lite::Uuid, KeyShareBundle},
    Error,
};

/// One Sapphire node: a FROST key-share holder that reacts to chain state.
pub struct Node<C: Ciphersuite> {
    pub identifier: Identifier<C>,
    bundle: KeyShareBundle<C>,
    /// Pending FROST round-1 nonces, keyed by request id. Held between
    /// round-1 (we emitted commitments) and round-2 (we consume them for
    /// the signature share).
    pending: Mutex<HashMap<Uuid, SigningNonces<C>>>,
    /// Requests we've already produced a commitment for (avoid double-submit).
    committed_requests: HashSet<Uuid>,
    /// Requests we've already produced a share for.
    shared_requests: HashSet<Uuid>,
}

impl<C: Ciphersuite> Node<C> {
    pub fn new(bundle: KeyShareBundle<C>) -> Self {
        let identifier = *bundle.key_package.identifier();
        Self {
            identifier,
            bundle,
            pending: Mutex::new(HashMap::new()),
            committed_requests: HashSet::new(),
            shared_requests: HashSet::new(),
        }
    }

    pub fn identifier(&self) -> Identifier<C> {
        self.identifier
    }

    pub fn key_package(&self) -> &KeyPackage<C> {
        &self.bundle.key_package
    }

    /// FROST round 1: produce a commitment for `session_id`. Caches the
    /// per-session nonces internally until round 2. Exposed so tests (and
    /// any future direct callers) can drive a single round without going
    /// through [`Node::react`].
    pub fn commit<R: RngCore + CryptoRng>(
        &self,
        session_id: Uuid,
        rng: &mut R,
    ) -> Result<SigningCommitments<C>, Error> {
        let (nonces, commitments) =
            round1::commit::<C, _>(self.bundle.key_package.signing_share(), rng);
        let mut pending = self.pending.lock().expect("pending lock poisoned");
        if pending.contains_key(&session_id) {
            return Err(Error::SessionInUse);
        }
        pending.insert(session_id, nonces);
        Ok(commitments)
    }
}

impl<C: RandomizedCiphersuite> Node<C> {
    /// FROST round 2 (rerandomized): produce a signature share against the
    /// rerandomized verifying key `rk = ak + α·G`. Consumes the per-session
    /// nonces cached by [`Node::commit`].
    fn sign_share_rerandomized(
        &self,
        session_id: &Uuid,
        signing_package: &SigningPackage<C>,
        randomizer: Randomizer<C>,
    ) -> Result<SignatureShare<C>, Error> {
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

    /// Inspect the current chain state and return any txs this node should
    /// submit. Stateless w.r.t. the chain — the node's own memory only
    /// tracks "have I already responded to this request?".
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
                    let commitments = self.commit(*request_id, rng)?;
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
                    let share = match self.sign_share_rerandomized(
                        request_id,
                        signing_package,
                        entry.randomizer,
                    ) {
                        Ok(s) => s,
                        Err(Error::SessionNotFound) => {
                            // We committed but our commit wasn't in the
                            // threshold-cut, so we have no nonces for this
                            // request. Nothing to do.
                            tracing::debug!(
                                node = ?self.identifier,
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
