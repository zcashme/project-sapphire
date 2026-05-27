//! In-process signer transport.
//!
//! Holds direct references to [`Signer`]s and dispatches calls synchronously.
//! Used by tests, by the CLI demo, and as a reference implementation for
//! out-of-process transports.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use frost_core::{
    round1::SigningCommitments, round2::SignatureShare, Ciphersuite, Identifier, SigningPackage,
};
use rand::rngs::OsRng;

use sapphire_coordinator::SignerTransport;
use sapphire_core::{protocol::uuid_lite::Uuid, Error, Result};
use sapphire_signer::Signer;

/// Holds references to all signers; for tests and the CLI demo.
pub struct LocalTransport<C: Ciphersuite> {
    signers: BTreeMap<Identifier<C>, Arc<Signer<C>>>,
}

impl<C: Ciphersuite> LocalTransport<C> {
    pub fn new(signers: BTreeMap<Identifier<C>, Arc<Signer<C>>>) -> Self {
        Self { signers }
    }

    fn lookup(&self, id: Identifier<C>) -> Result<&Arc<Signer<C>>> {
        self.signers.get(&id).ok_or(Error::UnknownParticipant)
    }
}

#[async_trait(?Send)]
impl<C: Ciphersuite> SignerTransport<C> for LocalTransport<C> {
    async fn commit(
        &self,
        id: Identifier<C>,
        session_id: Uuid,
    ) -> Result<SigningCommitments<C>> {
        let signer = self.lookup(id)?;
        let mut rng = OsRng;
        signer.commit(session_id, &mut rng)
    }

    async fn sign_share(
        &self,
        id: Identifier<C>,
        session_id: Uuid,
        signing_package: SigningPackage<C>,
    ) -> Result<SignatureShare<C>> {
        let signer = self.lookup(id)?;
        signer.sign_share(&session_id, &signing_package)
    }
}
