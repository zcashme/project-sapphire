use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Threshold parameters for an MPC group: `threshold`-of-`total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcParams {
    pub threshold: u16,
    pub total: u16,
}

impl MpcParams {
    pub fn new(threshold: u16, total: u16) -> Result<Self> {
        if threshold == 0 || total == 0 || threshold > total {
            return Err(Error::InvalidParams { threshold, total });
        }
        Ok(Self { threshold, total })
    }
}
