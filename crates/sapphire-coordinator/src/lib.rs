//! Sapphire coordinator.
//!
//! Orchestrates a FROST signing round across a set of [`Signer`]s and
//! assembles the final [`Signature`].
//!
//! The coordinator is abstracted over a [`SignerTransport`] so the same logic
//! works against in-process signers (used in tests) and remote HTTP signers
//! (used in production deployments).

use std::collections::BTreeMap;

use async_trait::async_trait;
use frost_core::{
    keys::PublicKeyPackage,
    round1::SigningCommitments,
    round2::{self, SignatureShare},
    Ciphersuite, Identifier, Signature, SigningPackage,
};
use rand_core::{CryptoRng, RngCore};

use sapphire_core::{
    protocol::uuid_lite::Uuid,
    Error, MpcParams, Result,
};

/// Transport for talking to individual signers.
///
/// Implementors: `LocalTransport` (in-process), `HttpTransport` (V0.1).
///
/// `?Send` on the async-trait macro: FROST ciphersuite associated types
/// (field scalars, group elements) don't carry blanket Send + Sync bounds,
/// so requiring `Send` futures forces us into a thicket of where-clauses.
/// V0 runs everything single-threaded; revisit when we add multi-threaded
/// HTTP transport.
#[async_trait(?Send)]
pub trait SignerTransport<C: Ciphersuite> {
    /// Ask signer `id` to produce a round-1 commitment for `session_id`.
    async fn commit(
        &self,
        id: Identifier<C>,
        session_id: Uuid,
    ) -> Result<SigningCommitments<C>>;

    /// Ask signer `id` to produce a round-2 signature share.
    async fn sign_share(
        &self,
        id: Identifier<C>,
        session_id: Uuid,
        signing_package: SigningPackage<C>,
    ) -> Result<SignatureShare<C>>;
}

pub struct Coordinator<C: Ciphersuite> {
    pub params: MpcParams,
    pub public_key_package: PublicKeyPackage<C>,
}

impl<C: Ciphersuite> Coordinator<C> {
    pub fn new(params: MpcParams, public_key_package: PublicKeyPackage<C>) -> Self {
        Self {
            params,
            public_key_package,
        }
    }

    /// Drive a full FROST signing round.
    ///
    /// `participants` must contain at least `threshold` distinct identifiers
    /// known to the [`PublicKeyPackage`].
    pub async fn sign<T, R>(
        &self,
        transport: &T,
        message: &[u8],
        participants: &[Identifier<C>],
        rng: &mut R,
    ) -> Result<Signature<C>>
    where
        T: SignerTransport<C> + ?Sized,
        R: RngCore + CryptoRng,
    {
        if (participants.len() as u16) < self.params.threshold {
            return Err(Error::NotEnoughSigners {
                have: participants.len() as u16,
                need: self.params.threshold,
            });
        }
        let mut sorted = participants.to_vec();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != participants.len() {
            return Err(Error::DuplicateParticipant);
        }
        for id in &sorted {
            if !self.public_key_package.verifying_shares().contains_key(id) {
                return Err(Error::UnknownParticipant);
            }
        }

        let session_id = Uuid::new(rng);
        tracing::debug!(session = %session_id, "starting signing session");

        // Round 1: collect commitments from all selected participants.
        let mut commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>> = BTreeMap::new();
        for id in &sorted {
            let commitments = transport.commit(*id, session_id).await?;
            commitments_map.insert(*id, commitments);
        }

        // Build the SigningPackage and broadcast it.
        let signing_package = SigningPackage::<C>::new(commitments_map, message);

        // Round 2: collect signature shares.
        let mut shares_map: BTreeMap<Identifier<C>, SignatureShare<C>> = BTreeMap::new();
        for id in &sorted {
            let share = transport
                .sign_share(*id, session_id, signing_package.clone())
                .await?;
            shares_map.insert(*id, share);
        }

        // Aggregate.
        let signature = frost_core::aggregate::<C>(
            &signing_package,
            &shares_map,
            &self.public_key_package,
        )
        .map_err(Error::from)?;

        tracing::debug!(session = %session_id, "signature aggregated");
        Ok(signature)
    }
}

/// Verify a signature against the group verifying key.
///
/// Thin re-export for callers that don't want to depend on frost-core directly.
pub fn verify<C: Ciphersuite>(
    public_key_package: &PublicKeyPackage<C>,
    message: &[u8],
    signature: &Signature<C>,
) -> Result<()> {
    public_key_package
        .verifying_key()
        .verify(message, signature)
        .map_err(Error::from)
}

// Re-export round2::Identifier for convenience, plus silence unused import warning.
#[allow(unused_imports)]
use round2 as _round2;
