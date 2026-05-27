use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid threshold parameters: threshold={threshold}, total={total}")]
    InvalidParams { threshold: u16, total: u16 },

    #[error("not enough signers: have {have}, need {need}")]
    NotEnoughSigners { have: u16, need: u16 },

    #[error("unknown participant identifier")]
    UnknownParticipant,

    #[error("duplicate participant in signing set")]
    DuplicateParticipant,

    #[error("session already in use")]
    SessionInUse,

    #[error("session not found")]
    SessionNotFound,

    #[error("invalid commitment from participant")]
    InvalidCommitment,

    #[error("invalid signature share from participant")]
    InvalidSignatureShare,

    #[error("FROST error: {0}")]
    Frost(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("transport error: {0}")]
    Transport(String),
}

impl<C: frost_core::Ciphersuite> From<frost_core::Error<C>> for Error {
    fn from(e: frost_core::Error<C>) -> Self {
        Error::Frost(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
