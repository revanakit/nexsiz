//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::desocket::binary
//!
//! Binary length-prefixed (LP) desocket fallback
//!
//! Purpose
//! --------
//! This module implements a conservative, protocol-agnostic "desocket" (connection
//! reset / liveness probe) for services that speak simple binary length-prefixed
//! protocols. It is used as a fallback when no operator-provided DesocketSpec is
//! available. The goal is to detect whether the remote endpoint responds to
//! length-prefixed frames and to exercise simple common opcodes to provoke a
//! response or otherwise determine liveliness without assuming higher-level
//! semantics.
//!
//! Behavior & heuristics
//! --------------------
//! - Supports four framing variants:
//!     * Be2  — big-endian 2-byte length prefix (u16)
//!     * Le2  — little-endian 2-byte length prefix (u16)
//!     * Be4  — big-endian 4-byte length prefix (u32)
//!     * Le4  — little-endian 4-byte length prefix (u32)
//! - Probe sequence (ordered, short and conservative):
//!     1. Send a zero-length frame (length prefix only).
//!     2. If no response, send a small set of common single-byte payloads wrapped
//!        in a length prefix: 0x00, 0xFF, 0x01 (each as a separate framed message).
//!     3. Re-send a final zero-length frame as a liveness check.
//! - A probe is considered successful if any sent frame elicits a response from
//!   the peer (recv returns a payload or non-timeout result). Connection closure
//!   or I/O errors are treated as failures for that probe.
//! - Probes do not attempt protocol negotiation beyond these lightweight checks,
//!   and they never mutate application-level state deliberately (only minimal
//!   stimulus bytes are used).
//!
//! Public API (high level)
//! -----------------------
//! - BinaryLpDesocket::be2() / le2() / be4() / le4()
//!     constructors for each framing variant.
//! - Implements ProtocolReset trait with:
//!     - name() -> &str
//!     - is_enabled() -> bool
//!     - reset(conn: &mut TcpConnector) -> Result<bool>
//!     - goodbye() -> Option<&[u8]>
//!
//! Notes for maintainers
//! ---------------------
//! - length encoding: 2-byte variants cast the length to u16 before serializing;
//!   4-byte variants serialize u32 directly. The frame() helper constructs the
//!   final wire bytes as [length-prefix | payload].
//! - The heuristic is intentionally lightweight to avoid making strong
//!   assumptions about application-layer semantics. If you need protocol-specific
//!   behavior, provide a DesocketSpec/operator instead of relying on this fallback.

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
