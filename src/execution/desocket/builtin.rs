//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::desocket::builtin
//!
//! Description:
//! This module implements a small set of built-in, protocol-aware "desocket"
//! (connection-reset / session-recovery) strategies used by the fuzzer to
//! attempt an orderly return of a live TCP session to a known-good state.
//!
//! Responsibilities:
//! - Provide minimal, well-formed protocol-level sequences that request the
//!   server to abandon in-progress operations and return the session to an
//!   idle/ready state (where possible).
//! - Expose a unified ProtocolReset implementation so the caller can attempt
//!   to reuse the existing TcpConnector connection instead of reconnecting.
//!
//! Supported protocols:
//! - FTP   : ABOR, REIN, NOOP fallbacks; checks standard 2xx/220/200 responses.
//! - SMTP  : RSET and response-code validation (250 / 2xx success range).
//! - MQTT  : Sends DISCONNECT (fixed header 0xE0 0x00); server is expected to
//!           close the socket — caller should reconnect (soft-failure).
//! - HTTP  : Minimal OPTIONS probe with Connection: keep-alive; accepts any
//!           response that begins with "HTTP/" as a successful probe.
//!
//! Semantics:
//! - reset(conn) -> Result<bool, NexsizError>
//!     * Ok(true)  => connection appears reusable (no reconnect required).
//!     * Ok(false) => connection should be considered unusable; caller should
//!                   close/reconnect as appropriate.
//!     * Err(_)    => I/O or connector error propagated via NexsizError.
//! - goodbye() -> Option<&[u8]>
//!     * Returns an optional "polite" closing sequence bytes the caller may
//!       send before tearing down the connection (if applicable).
//!
//! Design notes / constraints:
//! - All sequences are best-effort and intentionally conservative — the code
//!   avoids aggressive state mutation and prefers to signal "reconnect" when
//!   ambiguity exists (fail-safe behavior for fuzzing sessions).
//! - The module relies on TcpConnector to perform actual I/O and to indicate
//!   read timeouts; timing and low-level socket errors are surfaced via Result.
//! - This implementation targets TCP-based request/response protocols only.
//! - Keep changes to these sequences protocol-aware and idempotent when possible.
//!
//! Testing & extension:
//! - Unit tests validate naming and goodbye sequences; protocol probes are
//!   intentionally minimal to allow integration tests against real servers.
//! - To add a new protocol, implement a Kind variant, a reset_<proto> method
//!   following the established conventions, and expose a constructor + goodbye.
//!
//! See also: ProtocolReset trait (contract for name(), is_enabled(), reset(),
//! goodbye()) and the TcpConnector implementation for recv/send/timeouts.

use super::ProtocolReset;
use crate::common::error::{NexsizError, Result};
use crate::execution::connector::TcpConnector;

#[derive(Debug, Clone, Copy)]
enum Kind {
    Ftp,
    Smtp,
    Mqtt,
    Http,
}

/// Built-in desocket provider with protocol-specific reset sequences.
pub struct BuiltinDesocket {
    kind: Kind,
    name: &'static str,
}

impl BuiltinDesocket {
    pub fn ftp() -> Self {
        Self {
            kind: Kind::Ftp,
            name: "ftp",
        }
    }

    pub fn smtp() -> Self {
        Self {
            kind: Kind::Smtp,
            name: "smtp",
        }
    }

    pub fn mqtt() -> Self {
        Self {
            kind: Kind::Mqtt,
            name: "mqtt",
        }
    }

    pub fn http() -> Self {
        Self {
            kind: Kind::Http,
            name: "http",
        }
    }

    fn try_send_recv(conn: &mut TcpConnector, data: &[u8], max: usize) -> Result<(Vec<u8>, bool)> {
        conn.send(data)?;
        conn.recv(max)
    }

    fn extract_code(resp: &[u8]) -> i32 {
        let mut code: i32 = 0;
        let mut found = false;
        for &b in resp.iter().take(8) {
            if b.is_ascii_digit() {
                found = true;
                code = code * 10 + (b - b'0') as i32;
            } else if found {
                break;
            } else {
                break;
            }
        }
        if found && code > 0 {
            code
        } else {
            0
        }
    }

    fn reset_ftp(&self, conn: &mut TcpConnector) -> Result<bool> {
        // Best-effort: ABOR (abort transfer) then REIN (reinitialize) if supported,
        // else QUIT and signal caller to reconnect.
        // Many servers do not implement REIN; we try soft path first.
        let _ = Self::try_send_recv(conn, b"ABOR\r\n", 512);
        match Self::try_send_recv(conn, b"REIN\r\n", 512) {
            Ok((resp, timed_out)) => {
                if timed_out {
                    return Ok(false);
                }
                let code = Self::extract_code(&resp);
                // 220 = service ready after REIN on some servers
                // 500/502 = not implemented → fall back
                if code == 220 || code == 200 {
                    return Ok(true);
                }
            }
            Err(_) => return Ok(false),
        }
        // Soft fallback: just send NOOP to probe liveness
        match Self::try_send_recv(conn, b"NOOP\r\n", 512) {
            Ok((resp, timed_out)) => {
                if timed_out {
                    return Ok(false);
                }
                let code = Self::extract_code(&resp);
                Ok((200..300).contains(&code))
            }
            Err(_) => Ok(false),
        }
    }

    fn reset_smtp(&self, conn: &mut TcpConnector) -> Result<bool> {
        // RSET clears mail transaction state without closing the session.
        match Self::try_send_recv(conn, b"RSET\r\n", 512) {
            Ok((resp, timed_out)) => {
                if timed_out {
                    return Ok(false);
                }
                let code = Self::extract_code(&resp);
                // 250 = OK
                Ok(code == 250 || (200..300).contains(&code))
            }
            Err(_) => Ok(false),
        }
    }

    fn reset_mqtt(&self, conn: &mut TcpConnector) -> Result<bool> {
        // MQTT DISCONNECT fixed header 0xE0, remaining length 0.
        // After DISCONNECT the server closes the connection; we signal
        // soft-failure so caller does full reconnect (expected).
        match conn.send(&[0xE0, 0x00]) {
            Ok(()) => {
                // Server should close; drain any residual
                let _ = conn.recv(64);
                Ok(false) // force reconnect after DISCONNECT
            }
            Err(_) => Ok(false),
        }
    }

    fn reset_http(&self, conn: &mut TcpConnector) -> Result<bool> {
        // HTTP/1.1 keep-alive: send a minimal OPTIONS or HEAD to probe.
        // If Connection: close was negotiated we cannot recover → reconnect.
        match Self::try_send_recv(
            conn,
            b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
            1024,
        ) {
            Ok((resp, timed_out)) => {
                if timed_out || resp.is_empty() {
                    return Ok(false);
                }
                // Any HTTP response starting with "HTTP/" is good enough
                Ok(resp.starts_with(b"HTTP/"))
            }
            Err(_) => Ok(false),
        }
    }
}

impl ProtocolReset for BuiltinDesocket {
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
        match self.kind {
            Kind::Ftp => self.reset_ftp(conn),
            Kind::Smtp => self.reset_smtp(conn),
            Kind::Mqtt => self.reset_mqtt(conn),
            Kind::Http => self.reset_http(conn),
        }
    }

    fn goodbye(&self) -> Option<&[u8]> {
        match self.kind {
            Kind::Ftp => Some(b"QUIT\r\n"),
            Kind::Smtp => Some(b"QUIT\r\n"),
            Kind::Mqtt => Some(&[0xE0, 0x00]),
            Kind::Http => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(BuiltinDesocket::ftp().name(), "ftp");
        assert_eq!(BuiltinDesocket::smtp().name(), "smtp");
        assert_eq!(BuiltinDesocket::mqtt().name(), "mqtt");
        assert_eq!(BuiltinDesocket::http().name(), "http");
    }

    #[test]
    fn goodbye_ftp() {
        assert_eq!(BuiltinDesocket::ftp().goodbye(), Some(&b"QUIT\r\n"[..]));
    }
}
