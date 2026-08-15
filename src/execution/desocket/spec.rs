//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::desocket::spec
//!
//! SpecDesocket sends the exact byte sequences provided by the operator
//! (via ProtocolModel.desocket or a JSON model).  No heuristics — the
//! operator is the source of truth for protocol-level reset.

use super::ProtocolReset;
use crate::common::error::Result;
use crate::execution::connector::TcpConnector;
use crate::input::model::DesocketSpec;

/// ProtocolReset implementation driven entirely by a DesocketSpec.
pub struct SpecDesocket {
    name: String,
    sequences: Vec<Vec<u8>>,
    goodbye: Option<Vec<u8>>,
    success_on_response: bool,
}

impl SpecDesocket {
    pub fn from_spec(model_name: &str, spec: &DesocketSpec) -> Self {
        Self {
            name: format!("spec:{}", model_name),
            sequences: spec.sequences.clone(),
            goodbye: spec.goodbye.clone(),
            success_on_response: spec.success_on_response,
        }
    }

    fn probe(&self, conn: &mut TcpConnector, data: &[u8]) -> Result<bool> {
        if !conn.is_connected() {
            return Ok(false);
        }
        if data.is_empty() {
            return Ok(true);
        }
        match conn.send(data) {
            Ok(()) => {}
            Err(_) => return Ok(false),
        }
        match conn.recv(512) {
            Ok((resp, timed_out)) => {
                if self.success_on_response {
                    // Accept any non-hard-close outcome (including clean timeout).
                    Ok(true)
                } else {
                    // Stricter: require a non-empty response.
                    Ok(!timed_out && !resp.is_empty())
                }
            }
            Err(crate::common::error::NexsizError::ConnectionClosed) => Ok(false),
            Err(_) => Ok(false),
        }
    }
}

impl ProtocolReset for SpecDesocket {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_enabled(&self) -> bool {
        !self.sequences.is_empty()
    }

    fn reset(&self, conn: &mut TcpConnector) -> Result<bool> {
        if !conn.is_connected() || self.sequences.is_empty() {
            return Ok(false);
        }
        for seq in &self.sequences {
            if self.probe(conn, seq)? {
                return Ok(true);
            }
            if !conn.is_connected() {
                return Ok(false);
            }
        }
        // All sequences tried without a usable session → soft failure.
        Ok(false)
    }

    fn goodbye(&self) -> Option<&[u8]> {
        self.goodbye.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_spec_disabled() {
        let spec = DesocketSpec::default();
        let d = SpecDesocket::from_spec("x", &spec);
        assert!(!d.is_enabled());
        assert_eq!(d.name(), "spec:x");
    }

    #[test]
    fn with_sequences_enabled() {
        let mut spec = DesocketSpec::default();
        spec.sequences.push(vec![0x00, 0x00]);
        let d = SpecDesocket::from_spec("custom", &spec);
        assert!(d.is_enabled());
        assert_eq!(d.goodbye(), None);
    }

    #[test]
    fn goodbye_present() {
        let mut spec = DesocketSpec::default();
        spec.sequences.push(b"RSET\r\n".to_vec());
        spec.goodbye = Some(b"QUIT\r\n".to_vec());
        let d = SpecDesocket::from_spec("smtp-like", &spec);
        assert_eq!(d.goodbye(), Some(&b"QUIT\r\n"[..]));
    }
}
