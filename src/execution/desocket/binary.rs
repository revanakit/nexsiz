//! Heuristic desocket provider for length-prefixed binary protocols.
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! Production-ready generic reset for models such as `binary-lp`,
//! `binary-lp-le`, `lp`, `lp-le` and similar length-prefixed binary
//! framing.  Because there is no universal “RSET” opcode, we use an
//! ordered series of conservative probes:
//!
//!   1. Zero-length frame (length field = 0)
//!   2. Minimal frames carrying common reset / noop opcodes (0x00, 0xFF, 0x01)
//!   3. Liveness probe (any short valid-looking frame)
//!
//! Success = send succeeds and the connection remains usable
//! (response received or clean timeout without peer close).
//! Soft failure (Ok(false)) lets the caller fall back to a full reconnect.

use super::ProtocolReset;
use crate::common::error::Result;
use crate::execution::connector::TcpConnector;

/// Length-field endianness and width.
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
            Framing::Be2 => {
                let v = (len as u16).to_be_bytes();
                v.to_vec()
            }
            Framing::Le2 => {
                let v = (len as u16).to_le_bytes();
                v.to_vec()
            }
            Framing::Be4 => len.to_be_bytes().to_vec(),
            Framing::Le4 => len.to_le_bytes().to_vec(),
        }
    }

    fn header_width(self) -> usize {
        match self {
            Framing::Be2 | Framing::Le2 => 2,
            Framing::Be4 | Framing::Le4 => 4,
        }
    }
}

/// Production heuristic desocket for length-prefixed binary protocols.
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

    /// Build a complete length-prefixed frame.
    fn frame(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = self.framing.length_bytes(payload.len() as u32);
        out.extend_from_slice(payload);
        out
    }

    /// Zero-length frame (most conservative “do nothing” probe).
    fn zero_frame(&self) -> Vec<u8> {
        self.framing.length_bytes(0)
    }

    /// Common single-byte opcode frames used by many binary protocols
    /// for reset / disconnect / noop.
    fn opcode_frames(&self) -> [Vec<u8>; 3] {
        [
            self.frame(&[0x00]),
            self.frame(&[0xFF]),
            self.frame(&[0x01]),
        ]
    }

    /// Attempt one probe.  Returns:
    /// - Ok(true)  – connection still healthy (response or clean timeout)
    /// - Ok(false) – peer closed or hard failure → caller should reconnect
    /// - Err(_)    – I/O error that already invalidated the stream
    fn probe(&self, conn: &mut TcpConnector, data: &[u8]) -> Result<bool> {
        if !conn.is_connected() {
            return Ok(false);
        }
        match conn.send(data) {
            Ok(()) => {}
            Err(_) => return Ok(false),
        }
        // Receive up to a modest buffer; we only care whether the peer
        // stayed alive, not the semantic content.
        match conn.recv(512) {
            Ok((_resp, _timed_out)) => {
                // Any outcome short of ConnectionClosed is acceptable.
                // Empty + timeout still means the TCP session is open.
                Ok(true)
            }
            Err(crate::common::error::NexsizError::ConnectionClosed) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    /// Ordered heuristic sequence.
    fn run_heuristics(&self, conn: &mut TcpConnector) -> Result<bool> {
        // 1. Zero-length frame
        if self.probe(conn, &self.zero_frame())? {
            return Ok(true);
        }
        // Connection may have been closed by the previous probe; bail early.
        if !conn.is_connected() {
            return Ok(false);
        }

        // 2. Common opcode frames
        for frame in &self.opcode_frames() {
            if self.probe(conn, frame)? {
                return Ok(true);
            }
            if !conn.is_connected() {
                return Ok(false);
            }
        }

        // 3. Final liveness: another zero-length (or a 1-byte pad)
        //    After the above we are already conservative; one more attempt.
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
        // Static zero-length is the safest “I’m leaving” signal for LP protocols.
        // We cannot return a dynamically built frame from a static method,
        // so we expose None and let the caller rely on TCP close.
        // (Future: once SocketState owns a small buffer we can improve this.)
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(BinaryLpDesocket::be2().name(), "binary-lp");
        assert_eq!(BinaryLpDesocket::le2().name(), "binary-lp-le");
        assert_eq!(BinaryLpDesocket::be4().name(), "binary-lp4");
        assert_eq!(BinaryLpDesocket::le4().name(), "binary-lp4-le");
    }

    #[test]
    fn framing_be2_zero() {
        let d = BinaryLpDesocket::be2();
        assert_eq!(d.zero_frame(), vec![0x00, 0x00]);
        assert_eq!(d.frame(&[0xAA]), vec![0x00, 0x01, 0xAA]);
    }

    #[test]
    fn framing_le2_zero() {
        let d = BinaryLpDesocket::le2();
        assert_eq!(d.zero_frame(), vec![0x00, 0x00]);
        assert_eq!(d.frame(&[0xAA]), vec![0x01, 0x00, 0xAA]);
    }

    #[test]
    fn framing_be4() {
        let d = BinaryLpDesocket::be4();
        assert_eq!(d.zero_frame(), vec![0x00, 0x00, 0x00, 0x00]);
        assert_eq!(d.frame(&[0x01, 0x02]), vec![0x00, 0x00, 0x00, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn enabled() {
        assert!(BinaryLpDesocket::be2().is_enabled());
    }
}
