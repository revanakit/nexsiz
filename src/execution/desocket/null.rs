//! Null desocket provider — no protocol reset.
//! Author  : Revana
//! Date    : 08/08/2026

use super::ProtocolReset;
use crate::common::error::Result;
use crate::execution::connector::TcpConnector;

#[derive(Debug, Default)]
pub struct NullDesocket;

impl NullDesocket {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolReset for NullDesocket {
    fn name(&self) -> &str {
        "null"
    }

    fn is_enabled(&self) -> bool {
        false
    }

    fn reset(&self, _conn: &mut TcpConnector) -> Result<bool> {
        Ok(false)
    }
}
