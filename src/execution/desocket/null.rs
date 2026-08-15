//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::desocket::null
//!

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
