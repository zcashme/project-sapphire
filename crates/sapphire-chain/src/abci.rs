//! ABCI adapter skeleton.
//!
//! This module is a typed contract showing how Sapphire's state machine maps
//! onto CometBFT's Application BlockChain Interface (ABCI 2.0 / ABCI++). It
//! deliberately does **not** depend on `tower-abci` so the workspace stays
//! lightweight; integrators who want a real CometBFT node link `tower-abci`
//! and dispatch each ABCI method to the corresponding [`AbciApp`] method
//! below.
//!
//! ## Mapping
//!
//! | ABCI++ method        | Maps to                                                          |
//! |----------------------|------------------------------------------------------------------|
//! | `Info`               | Return state version, app hash (= hash of `State`)               |
//! | `InitChain`          | Empty state (`State::default()`); group seeded via first `InitGroup` tx |
//! | `CheckTx`            | `apply_tx(&self.state, &tx)` dry-run — accept if `Ok`            |
//! | `PrepareProposal`    | Sort mempool txs by ID, drop anything that fails `CheckTx`        |
//! | `ProcessProposal`    | Accept; this app is order-independent within `InitGroup` block    |
//! | `FinalizeBlock`      | For each tx: `self.state = apply_tx(&self.state, &tx)?`           |
//! | `Commit`             | Persist state; return app hash                                    |
//! | `Query`              | Look up [`RequestEntry`] by request ID, return its status         |
//!
//! ## Deployment shape
//!
//! In production: each Sapphire validator runs a CometBFT node binary that
//! talks to a `sapphire-node` process implementing [`AbciApp`]. The
//! validator-signer logic (`sapphire-validator`) runs as a sidecar on each
//! node, watching for new requests via the chain's Query API (or a state
//! stream) and submitting commit/share txs through CometBFT's RPC.
//!
//! ## Why CometBFT and not consensus-from-scratch
//!
//! - Mature implementation, ~150 deployments in production.
//! - Honest-majority BFT, deterministic finality (no probabilistic reverts).
//! - Slashing/staking primitives via Cosmos SDK if Sapphire adopts that.
//! - Validator set changes via consensus, not a centralized switch.

use std::collections::BTreeMap;

use frost_core::Ciphersuite;

use sapphire_core::protocol::uuid_lite::Uuid;

use crate::state::{ApplyError, RequestStatus, State};
use crate::tx::Tx;

/// ABCI-shaped wrapper around the deterministic state machine.
///
/// Replace this with a thin `tower-abci::v038::Application` impl to deploy
/// against a real CometBFT node.
pub struct AbciApp<C: Ciphersuite> {
    pub state: State<C>,
    pub app_hash: [u8; 32],
}

impl<C: Ciphersuite> Default for AbciApp<C> {
    fn default() -> Self {
        Self {
            state: State::default(),
            app_hash: [0u8; 32],
        }
    }
}

impl<C: Ciphersuite> AbciApp<C> {
    pub fn new() -> Self {
        Self::default()
    }

    /// ABCI `CheckTx`: dry-run the transaction without committing.
    pub fn check_tx(&self, tx: &Tx<C>) -> Result<(), ApplyError> {
        crate::state::apply_tx(&self.state, tx).map(|_| ())
    }

    /// ABCI `FinalizeBlock`/`DeliverTx`: apply the tx, mutating state.
    pub fn deliver_tx(&mut self, tx: &Tx<C>) -> Result<(), ApplyError> {
        self.state = crate::state::apply_tx(&self.state, tx)?;
        Ok(())
    }

    /// ABCI `Commit`: compute and return the app hash. V0 uses a placeholder.
    ///
    /// Production: serialize `state` canonically and hash with the same hash
    /// the rest of the chain uses (typically sha256 for CometBFT).
    pub fn commit(&mut self) -> [u8; 32] {
        // TODO: replace with a real canonical-encoding hash. This placeholder
        // is intentionally distinguishable from the zero hash.
        let n_requests = self.state.requests.len() as u64;
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&n_requests.to_be_bytes());
        self.app_hash = h;
        h
    }

    /// ABCI `Query`: return a request entry's status by ID.
    pub fn query_request(&self, request_id: &Uuid) -> Option<&RequestStatus<C>> {
        self.state.requests.get(request_id).map(|r| &r.status)
    }

    /// Bulk query: return the status of every known request.
    pub fn query_all_requests(&self) -> BTreeMap<Uuid, &RequestStatus<C>> {
        self.state
            .requests
            .iter()
            .map(|(k, v)| (*k, &v.status))
            .collect()
    }
}
