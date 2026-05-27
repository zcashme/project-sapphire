//! In-process simulator for the Sapphire coordination chain.
//!
//! Holds the current [`State`], collects pending [`Tx`]s into a "mempool"
//! between blocks, then commits a block by applying them in order. Validators
//! observe each new state and can react by submitting further transactions.
//!
//! No CometBFT dependency; same semantics as the real chain, just without
//! cryptographic block production / network gossip. Drop-in replacement for
//! tests and demos; the production runtime swaps in a `tower-abci` adapter
//! that calls [`apply_tx`] from `DeliverTx`.

use std::collections::VecDeque;

use frost_core::Ciphersuite;
use tracing::debug;

use crate::state::{apply_tx, ApplyError, State};
use crate::tx::Tx;

pub struct ChainSim<C: Ciphersuite> {
    pub state: State<C>,
    pub mempool: VecDeque<Tx<C>>,
    pub block_height: u64,
    /// Last block's accepted txs, exposed to validators so they can react.
    pub last_block: Vec<Tx<C>>,
}

impl<C: Ciphersuite> Default for ChainSim<C> {
    fn default() -> Self {
        Self {
            state: State::default(),
            mempool: VecDeque::new(),
            block_height: 0,
            last_block: Vec::new(),
        }
    }
}

impl<C: Ciphersuite> ChainSim<C> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a tx to the mempool. Doesn't apply it until [`commit_block`].
    pub fn submit(&mut self, tx: Tx<C>) {
        self.mempool.push_back(tx);
    }

    /// Process every pending tx in FIFO order, building the next block.
    ///
    /// Failed txs are silently dropped (in a real chain they'd be rejected
    /// at `CheckTx` / `DeliverTx` and excluded from the block). V0 returns
    /// the list of (tx, result) so tests can assert on outcomes.
    pub fn commit_block(&mut self) -> Vec<(Tx<C>, Result<(), ApplyError>)> {
        let mut accepted = Vec::new();
        let mut results = Vec::new();
        let mut state = self.state.clone();
        while let Some(tx) = self.mempool.pop_front() {
            match apply_tx(&state, &tx) {
                Ok(next) => {
                    state = next;
                    accepted.push(tx.clone());
                    results.push((tx, Ok(())));
                }
                Err(e) => {
                    debug!(error = %e, "tx rejected");
                    results.push((tx, Err(e)));
                }
            }
        }
        self.state = state;
        self.last_block = accepted;
        self.block_height += 1;
        results
    }
}
