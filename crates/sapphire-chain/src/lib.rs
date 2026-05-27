//! Sapphire coordination chain.
//!
//! The V1 design replaces the centralized HTTP coordinator with a BFT
//! coordination chain whose validators are also the MPC signers. Every step
//! of a signing session — the request itself, each participant's round-1
//! commitment, each participant's round-2 share — flows as a transaction
//! on the chain. The chain's state machine deterministically aggregates the
//! final FROST signature once enough shares are committed.
//!
//! ## What lives here
//!
//! * [`Tx`] — the chain's transaction types.
//! * [`State`] — the deterministic state machine.
//! * [`apply_tx`] — the pure state-transition function.
//! * `mod sim` — an in-process simulator (no CometBFT dependency) used by
//!   `sapphire-tests` and by demos. The same [`State`] / [`apply_tx`] pair
//!   plugs straight into a `tower-abci` adapter for real CometBFT
//!   deployment — that's the next engineering step, not a redesign.
//!
//! ## Why this works without smart contracts on Zcash
//!
//! Sapphire's coordination chain is a *separate* chain from Zcash. Its only
//! purpose is to sequence sign requests, gather FROST messages between
//! validator-signers, and produce the final signature deterministically.
//! The resulting Zcash transaction is broadcast to Zcash L1 by whichever
//! party wants the signed tx (typically the caller).

pub mod abci;
pub mod sim;
pub mod state;
pub mod tx;

pub use state::{apply_tx, ApplyError, RequestEntry, RequestStatus, State};
pub use tx::Tx;
