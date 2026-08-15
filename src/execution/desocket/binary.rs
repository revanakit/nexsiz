//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::desocket::binary
//!
//! Fallback when no operator DesocketSpec is present.  Ordered probes:
//!   1. Zero-length frame
//!   2. Common opcode frames (0x00, 0xFF, 0x01)
//!   3. Final liveness zero-length

use super::ProtocolReset;
use crate::common::error::Result;
use crate::execution::connector::TcpConnector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    Be2,
    Be4,
    Le2,
    Le4,
}

impl Framing {
    fn length_bytes(self, len: u32) -> Vec<u8> {
        match self {
            Framing::Be2 => (len as u16).to_be_bytes().to_vec(),
            Framing::Le2 => (len as u16).to_le_bytes().to_vec(),
            Framing::Be4 => len.to_be_bytes().to_vec(),
            Framing::Le4 => len.to_le_bytes().to_vec(),
        }
    }
}

pub struct BinaryLpDesocket {
    framing: Framing,
    name: &'static str,
}

impl BinaryLpDesocket {
    pub fn be2() -> Self {
        Self {
            framing: Framing::Be2,
            name: "binary-lp",
        }
    }

    pub fn le2() -> Self {
        Self {
            framing: Framing::Le2,
            name: "binary-lp-le",
        }
    }

    pub fn be4() -> Self {
        Self {
            framing: Framing::Be4,
            name: "binary-lp4",
        }
    }

    pub fn le4() -> Self {
        Self {
            framing: Framing::Le4,
            name: "binary-lp4-le",
        }
    }

    fn frame(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = self.framing.length_bytes(payload.len() as u32);
        out.extend_from_slice(payload);
        out
    }

    fn zero_frame(&self) -> Vec<u8> {
        self.framing.length_bytes(0)
    }

    fn opcode_frames(&self) -> [Vec<u8>; 3] {
        [
            self.frame(&[0x00]),
            self.frame(&[0xFF]),
            self.frame(&[0x01]),
        ]
    }

    fn probe(&self, conn: &mut TcpConnector, data: &[u8]) -> Result<bool> {
        if !conn.is_connected() {
            return Ok(false);
        }
        match conn.send(data) {
            Ok(()) => {}
            Err(_) => return Ok(false),
        }
        match conn.recv(512) {
            Ok((_resp, _timed_out)) => Ok(true),
            Err(crate::common::error::NexsizError::ConnectionClosed) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    fn run_heuristics(&self, conn: &mut TcpConnector) -> Result<bool> {
        if self.probe(conn, &self.zero_frame())? {
            return Ok(true);
        }
        if !conn.is_connected() {
            return Ok(false);
        }
        for frame in &self.opcode_frames() {
            if self.probe(conn, frame)? {
                return Ok(true);
            }
            if !conn.is_connected() {
                return Ok(false);
            }
        }
        self.probe(conn, &self.zero_frame())
    }
}

impl ProtocolReset for BinaryLpDesocket {
    fn name(&self) -> &str {
        self.name
    }

    fn is_enabled(&self) -> bool {
        true
    }

    fn reset(&self, conn: &mut TcpConnector) -> Result<bool> {
        if !conn.is_connected() {
            return Ok(false);
        }
        self.run_heuristics(conn)
    }

    fn goodbye(&self) -> Option<&[u8]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_be2() {
        let d = BinaryLpDesocket::be2();
        assert_eq!(d.zero_frame(), vec![0x00, 0x00]);
        assert_eq!(d.frame(&[0xAA]), vec![0x00, 0x01, 0xAA]);
    }

    #[test]
    fn framing_le2() {
        let d = BinaryLpDesocket::le2();
        assert_eq!(d.frame(&[0xAA]), vec![0x01, 0x00, 0xAA]);
    }

    #[test]
    fn framing_be4() {
        let d = BinaryLpDesocket::be4();
        assert_eq!(d.zero_frame(), vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn names_and_enabled() {
        assert_eq!(BinaryLpDesocket::be2().name(), "binary-lp");
        assert!(BinaryLpDesocket::le2().is_enabled());
    }
}
