//! Sapphire coordination-chain transaction types.
//!
//! Each variant corresponds to one state-changing operation that participants
//! submit to the chain. The deterministic state machine in [`crate::state`]
//! consumes these and updates [`crate::State`].

use frost_core::{
    keys::PublicKeyPackage,
    round1::SigningCommitments,
    round2::SignatureShare,
    Ciphersuite, Identifier,
};
use frost_rerandomized::Randomizer;
use serde::{Deserialize, Serialize};

use sapphire_core::{protocol::uuid_lite::Uuid, MpcParams};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub enum Tx<C: Ciphersuite> {
    /// Bootstrap the chain with the MPC group's threshold parameters,
    /// public key package, and the set of validator-signer identifiers.
    /// Valid exactly once; subsequent attempts fail.
    InitGroup {
        params: MpcParams,
        pkp: PublicKeyPackage<C>,
        validators: Vec<Identifier<C>>,
    },

    /// A caller asks the chain to produce a signature over `message`,
    /// rerandomized with `randomizer`.
    ///
    /// For Orchard spend-auth, the caller derives `randomizer` from the
    /// per-spend `α` in the Orchard bundle they are building. Every validator
    /// reads it from chain state so they all sign against the same
    /// rerandomized key; the on-chain aggregation produces a signature valid
    /// under the rerandomized verifying key `rk = ak + α·G`.
    SubmitRequest {
        request_id: Uuid,
        message: Vec<u8>,
        randomizer: Randomizer<C>,
    },

    /// A validator submits its round-1 FROST commitment for a request.
    SubmitCommitment {
        request_id: Uuid,
        validator: Identifier<C>,
        commitments: SigningCommitments<C>,
    },

    /// A validator submits its round-2 FROST signature share.
    SubmitShare {
        request_id: Uuid,
        validator: Identifier<C>,
        share: SignatureShare<C>,
    },
}
