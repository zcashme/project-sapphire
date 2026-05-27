//! Sapphire coordination-chain transaction types.
//!
//! Each variant corresponds to one state-changing operation that participants
//! submit to the chain. The deterministic state machine in [`crate::state`]
//! consumes these and updates [`crate::State`].

use std::collections::BTreeMap;

use frost_core::{
    keys::{dkg::round1, PublicKeyPackage},
    round1::SigningCommitments,
    round2::SignatureShare,
    Ciphersuite, Identifier,
};
use frost_rerandomized::Randomizer;
use serde::{Deserialize, Serialize};

use sapphire_core::{protocol::uuid_lite::Uuid, MpcParams};

use crate::dkg_envelope::{EncPublicKey, Sealed};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub enum Tx<C: Ciphersuite> {
    /// Bootstrap the chain with the MPC group's threshold parameters,
    /// public key package, and the set of validator-signer identifiers.
    /// Use this when the key material was produced *off* the chain (trusted
    /// dealer, or prior DKG ceremony). For chain-driven DKG, use the
    /// [`Tx::DkgBegin`] family instead.
    InitGroup {
        params: MpcParams,
        pkp: PublicKeyPackage<C>,
        validators: Vec<Identifier<C>>,
    },

    /// Open a distributed key generation ceremony.
    ///
    /// Lists every participant's FROST identifier and their X25519 public key
    /// used to seal round-2 envelopes. All `total` participants then progress
    /// through [`Tx::DkgRound1`] → [`Tx::DkgRound2`] → [`Tx::DkgFinalize`].
    DkgBegin {
        params: MpcParams,
        validators: BTreeMap<Identifier<C>, EncPublicKey>,
    },

    /// A participant broadcasts their FROST DKG round-1 package.
    /// Public — contains polynomial commitments only.
    DkgRound1 {
        from: Identifier<C>,
        package: round1::Package<C>,
    },

    /// A participant sends their FROST DKG round-2 package to `to`,
    /// sealed with `to`'s X25519 public key.
    ///
    /// Round-2 packages carry secret share contributions: they MUST be
    /// confidential to the (sender, recipient) pair. Anyone watching the
    /// chain sees the (from, to) routing but cannot decrypt the payload
    /// without `to`'s X25519 secret key.
    DkgRound2 {
        from: Identifier<C>,
        to: Identifier<C>,
        sealed: Sealed,
    },

    /// A participant submits the [`PublicKeyPackage`] they derived locally
    /// in round 3. The chain accepts the ceremony as complete once all
    /// participants have submitted *matching* PKPs, at which point the
    /// state machine creates a `GroupConfig` from the agreed PKP.
    DkgFinalize {
        from: Identifier<C>,
        pkp: PublicKeyPackage<C>,
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

