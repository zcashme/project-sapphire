//! HTTP server wrapping a [`Signer`].
//!
//! Exposes a small JSON API used by the Sapphire coordinator:
//!
//! | Method | Path           | Body                                                | Returns                |
//! |--------|----------------|-----------------------------------------------------|------------------------|
//! | POST   | `/commit`      | `{ "session_id": "<hex>" }`                         | `SigningCommitments`   |
//! | POST   | `/sign_share`  | `{ "session_id": "...", "signing_package": ... }`   | `SignatureShare`       |
//! | POST   | `/abort`       | `{ "session_id": "..." }`                           | `{}`                   |
//! | GET    | `/info`        | —                                                   | `{ "identifier": ... }`|
//!
//! The server is hard-coded to the default Sapphire ciphersuite (Ed25519
//! today, swap [`sapphire_core::ciphersuite::SapphireCiphersuite`] to RedPallas
//! when wiring up Zcash). Mixing ciphersuites within one signer process makes
//! no sense — each signer holds shares for exactly one group key.
//!
//! Endpoints are unauthenticated in V0. V0.2 adds caller authentication
//! (signed requests + per-coordinator ACLs).

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use frost_core::{round1::SigningCommitments, round2::SignatureShare, Identifier, SigningPackage};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use sapphire_core::{ciphersuite::SapphireCiphersuite as Cs, protocol::uuid_lite::Uuid, Error};

use crate::Signer;

struct ApiError(Error);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            Error::SessionNotFound => StatusCode::NOT_FOUND,
            Error::SessionInUse => StatusCode::CONFLICT,
            Error::InvalidParams { .. }
            | Error::DuplicateParticipant
            | Error::UnknownParticipant
            | Error::NotEnoughSigners { .. } => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(serde_json::json!({ "error": self.0.to_string() }));
        (status, body).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct CommitReq {
    session_id: Uuid,
}

#[derive(Debug, Serialize)]
struct CommitResp {
    commitments: SigningCommitments<Cs>,
}

#[derive(Debug, Deserialize)]
struct SignShareReq {
    session_id: Uuid,
    signing_package: SigningPackage<Cs>,
}

#[derive(Debug, Serialize)]
struct SignShareResp {
    share: SignatureShare<Cs>,
}

#[derive(Debug, Deserialize)]
struct AbortReq {
    session_id: Uuid,
}

#[derive(Debug, Serialize)]
struct InfoResp {
    identifier: Identifier<Cs>,
}

async fn commit_handler(
    State(state): State<Arc<Signer<Cs>>>,
    Json(req): Json<CommitReq>,
) -> Result<Json<CommitResp>, ApiError> {
    let mut rng = OsRng;
    let commitments = state.commit(req.session_id, &mut rng)?;
    Ok(Json(CommitResp { commitments }))
}

async fn sign_share_handler(
    State(state): State<Arc<Signer<Cs>>>,
    Json(req): Json<SignShareReq>,
) -> Result<Json<SignShareResp>, ApiError> {
    let share = state.sign_share(&req.session_id, &req.signing_package)?;
    Ok(Json(SignShareResp { share }))
}

async fn abort_handler(
    State(state): State<Arc<Signer<Cs>>>,
    Json(req): Json<AbortReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.abort(&req.session_id);
    Ok(Json(serde_json::json!({})))
}

async fn info_handler(State(state): State<Arc<Signer<Cs>>>) -> Json<InfoResp> {
    Json(InfoResp {
        identifier: state.identifier(),
    })
}

/// Build an axum [`Router`] that wraps `signer`.
pub fn router(signer: Arc<Signer<Cs>>) -> Router {
    Router::new()
        .route("/commit", post(commit_handler))
        .route("/sign_share", post(sign_share_handler))
        .route("/abort", post(abort_handler))
        .route("/info", get(info_handler))
        .with_state(signer)
}

/// Run the signer server on the given socket address. Returns when the
/// listener stops accepting connections.
pub async fn serve(
    signer: Arc<Signer<Cs>>,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = router(signer);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "sapphire signer listening");
    axum::serve(listener, app).await?;
    Ok(())
}
