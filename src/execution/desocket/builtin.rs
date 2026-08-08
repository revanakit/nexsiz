//! Built-in protocol-aware desocket / reset sequences.
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! Each variant sends a minimal “return to ready” sequence over the live
//! TCP connection. Success is determined by response codes when available.

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
