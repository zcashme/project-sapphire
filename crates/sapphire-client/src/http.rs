//! HTTP signer transport.
//!
//! Talks to remote [`sapphire-signer`] HTTP servers. The coordinator holds an
//! `HttpTransport` mapping each [`Identifier`] to a base URL and dispatches
//! round-1 and round-2 calls over JSON.

use std::collections::BTreeMap;

use async_trait::async_trait;
use frost_core::{
    round1::SigningCommitments, round2::SignatureShare, Ciphersuite, Identifier, SigningPackage,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use sapphire_coordinator::SignerTransport;
use sapphire_core::{protocol::uuid_lite::Uuid, Error, Result};

#[derive(Debug, Serialize)]
struct CommitReq {
    session_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
struct CommitResp<C: Ciphersuite> {
    commitments: SigningCommitments<C>,
}

#[derive(Debug, Serialize)]
#[serde(bound = "C: Ciphersuite")]
struct SignShareReq<C: Ciphersuite> {
    session_id: Uuid,
    signing_package: SigningPackage<C>,
}

#[derive(Debug, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
struct SignShareResp<C: Ciphersuite> {
    share: SignatureShare<C>,
}

/// HTTP signer transport.
///
/// Construct with a map of [`Identifier`] → base URL (e.g. `http://127.0.0.1:8801`).
pub struct HttpTransport<C: Ciphersuite> {
    base_urls: BTreeMap<Identifier<C>, String>,
    client: Client,
}

impl<C: Ciphersuite> HttpTransport<C> {
    pub fn new(base_urls: BTreeMap<Identifier<C>, String>) -> Self {
        Self {
            base_urls,
            client: Client::new(),
        }
    }

    fn url(&self, id: Identifier<C>, path: &str) -> Result<String> {
        let base = self.base_urls.get(&id).ok_or(Error::UnknownParticipant)?;
        Ok(format!("{}{}", base.trim_end_matches('/'), path))
    }
}

#[async_trait(?Send)]
impl<C: Ciphersuite> SignerTransport<C> for HttpTransport<C> {
    async fn commit(
        &self,
        id: Identifier<C>,
        session_id: Uuid,
    ) -> Result<SigningCommitments<C>> {
        let url = self.url(id, "/commit")?;
        let resp = self
            .client
            .post(&url)
            .json(&CommitReq { session_id })
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Transport(format!("commit: {}", resp.status())));
        }
        let parsed: CommitResp<C> = resp
            .json()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(parsed.commitments)
    }

    async fn sign_share(
        &self,
        id: Identifier<C>,
        session_id: Uuid,
        signing_package: SigningPackage<C>,
    ) -> Result<SignatureShare<C>> {
        let url = self.url(id, "/sign_share")?;
        let resp = self
            .client
            .post(&url)
            .json(&SignShareReq {
                session_id,
                signing_package,
            })
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Transport(format!("sign_share: {}: {}", status, body)));
        }
        let parsed: SignShareResp<C> = resp
            .json()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(parsed.share)
    }
}
