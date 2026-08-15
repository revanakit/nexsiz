//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::connector
//!
//! Purpose:
//!   Implements low-level network connectors and execution harnesses used by
//!   the fuzzer to drive stateful protocol interactions over TCP and UDP.
//!   This module provides:
//!     - TcpConnector: a blocking TCP connector with per-operation timeouts,
//!       optional connection reuse, and a two-stage receive strategy to
//!       differentiate slow responders from hangs.
//!     - UdpConnector: a simple UDP send/receive wrapper with configurable
//!       timeouts and ephemeral local binding.
//!     - execute_tcp / execute_udp: higher-level routines that drive a
//!       TestCase (sequence of messages), collect responses, compute a
//!       deterministic state hash, and map observed conditions to OutcomeClass.
//!     - extract_response_code: heuristic helper to extract numeric response
//!       codes from protocol replies (human-readable or binary).
//!
//! Key behaviors and guarantees:
//!   - Connect/bind operations configure per-operation read/write timeouts.
//!   - TcpConnector.recv uses a primary read (configured timeout) and, on
//!     timeout, performs a short probe (timeout/4) to distinguish slow
//!     responses from hang-like behavior. Empty reads are treated as
//!     connection-closed events.
//!   - Error handling maps OS and I/O errors into NexsizError variants so the
//!     execution harness can classify outcomes (Ok, Hang, ConnectionReset,
//!     Error, etc.).
//!   - The connectors are intentionally minimal and blocking; callers must
//!     provide exclusive mutable access (not thread-safe by default).
//!
//! Usage (summary):
//!   - TCP: let mut c = TcpConnector::new(addr, timeout); c.connect()?;
//!          c.send(&data)?; let (resp, timed_out) = c.recv(max_len)?;
//!   - UDP: let mut u = UdpConnector::new(addr, timeout); u.bind()?;
//!          u.send(&data)?; let (resp, timed_out) = u.recv(max_len)?;
//!
//! Testing:
//!   - Unit tests at the bottom of the file exercise basic construction and
//!     the response-code extraction logic. Integration tests against live
//!     network services should be isolated and optional in CI.
//!
//! Maintenance notes:
//!   - Keep timeouts symmetric between connect/read/write where appropriate.
//!   - When adjusting the probe strategy, ensure execute_tcp preserves its
//!     semantic mapping of probe timeouts -> OutcomeClass::Hang vs Ok.

use crate::common::error::{NexsizError, Result};
use crate::common::types::{ExecutionResult, OutcomeClass, TestCase};
use crate::common::utils::Timer;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// Blocking TCP connector with per-operation timeout.
#[derive(Debug)]
pub struct TcpConnector {
    addr: SocketAddr,
    timeout: Duration,
    stream: Option<TcpStream>,
}

impl TcpConnector {
    pub fn new(addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            addr,
            timeout,
            stream: None,
        }
    }

    pub fn connect(&mut self) -> Result<()> {
        self.close();
        let stream = TcpStream::connect_timeout(&self.addr, self.timeout)
            .map_err(|e| NexsizError::Execution(format!("connect failed: {}", e)))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| NexsizError::Execution(format!("set_read_timeout: {}", e)))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| NexsizError::Execution(format!("set_write_timeout: {}", e)))?;
        let _ = stream.set_nodelay(true);
        self.stream = Some(stream);
        Ok(())
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| NexsizError::Execution("not connected".into()))?;
        stream
            .write_all(data)
            .map_err(|e| NexsizError::Execution(format!("send failed: {}", e)))?;
        Ok(())
    }

    /// Receive with multi-layer timeout strategy:
    /// 1. Primary read with configured timeout.
    /// 2. If empty, one short additional probe (1/4 timeout) to distinguish slow vs hang.
    pub fn recv(&mut self, max: usize) -> Result<(Vec<u8>, bool)> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| NexsizError::Execution("not connected".into()))?;
        let mut buf = vec![0u8; max];
        match stream.read(&mut buf) {
            Ok(0) => Err(NexsizError::ConnectionClosed),
            Ok(n) => {
                buf.truncate(n);
                Ok((buf, false))
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Secondary short probe
                let probe = self.timeout / 4;
                if !probe.is_zero() {
                    let _ = stream.set_read_timeout(Some(probe));
                    let mut probe_buf = vec![0u8; max];
                    let probe_result = stream.read(&mut probe_buf);
                    let _ = stream.set_read_timeout(Some(self.timeout));
                    match probe_result {
                        Ok(0) => Err(NexsizError::ConnectionClosed),
                        Ok(n) => {
                            probe_buf.truncate(n);
                            Ok((probe_buf, false))
                        }
                        Err(_) => Ok((Vec::new(), true)), // confirmed hang-like
                    }
                } else {
                    Ok((Vec::new(), true))
                }
            }
            Err(e) => Err(NexsizError::Execution(format!("recv failed: {}", e))),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn close(&mut self) {
        if let Some(s) = self.stream.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for TcpConnector {
    fn drop(&mut self) {
        self.close();
    }
}

/// UDP connector.
#[derive(Debug)]
pub struct UdpConnector {
    addr: SocketAddr,
    timeout: Duration,
    socket: Option<UdpSocket>,
}

impl UdpConnector {
    pub fn new(addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            addr,
            timeout,
            socket: None,
        }
    }

    pub fn bind(&mut self) -> Result<()> {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| NexsizError::Execution(format!("udp bind: {}", e)))?;
        sock.set_read_timeout(Some(self.timeout))?;
        sock.set_write_timeout(Some(self.timeout))?;
        self.socket = Some(sock);
        Ok(())
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        let sock = self
            .socket
            .as_ref()
            .ok_or_else(|| NexsizError::Execution("udp not bound".into()))?;
        sock.send_to(data, self.addr)
            .map_err(|e| NexsizError::Execution(format!("udp send: {}", e)))?;
        Ok(())
    }

    pub fn recv(&mut self, max: usize) -> Result<(Vec<u8>, bool)> {
        let sock = self
            .socket
            .as_ref()
            .ok_or_else(|| NexsizError::Execution("udp not bound".into()))?;
        let mut buf = vec![0u8; max];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                buf.truncate(n);
                Ok((buf, false))
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok((Vec::new(), true))
            }
            Err(e) => Err(NexsizError::Execution(format!("udp recv: {}", e))),
        }
    }

    pub fn is_bound(&self) -> bool {
        self.socket.is_some()
    }

    pub fn close(&mut self) {
        self.socket = None;
    }
}

/// Execute a full test case over TCP with optional connection reuse.
pub fn execute_tcp(
    connector: &mut TcpConnector,
    tc: &TestCase,
    reuse: bool,
    max_resp: usize,
) -> Result<ExecutionResult> {
    let timer = Timer::start();
    let mut responses = Vec::new();
    let mut response_codes = Vec::new();
    let mut outcome = OutcomeClass::Ok;
    let mut error = None;

    if !connector.is_connected() || !reuse {
        if let Err(e) = connector.connect() {
            return Ok(ExecutionResult {
                seed_id: tc.id,
                success: false,
                responses: vec![],
                response_codes: vec![],
                elapsed: timer.elapsed(),
                new_coverage: false,
                new_state: false,
                crash: false,
                hang: false,
                error: Some(e.to_string()),
                state_hash: 0,
                outcome: OutcomeClass::Error,
                coverage_hits: 0,
                coverage_map_hash: 0,
            });
        }
    }

    for msg in &tc.messages {
        let data = msg.serialize();
        match connector.send(&data) {
            Ok(()) => {}
            Err(e) => {
                error = Some(e.to_string());
                outcome = OutcomeClass::ConnectionReset;
                connector.close();
                break;
            }
        }

        match connector.recv(max_resp) {
            Ok((resp, timed_out)) => {
                if timed_out || resp.is_empty() {
                    outcome = OutcomeClass::Hang;
                } else {
                    let code = extract_response_code(&resp);
                    response_codes.push(code);
                    responses.push(resp);
                }
            }
            Err(NexsizError::ConnectionClosed) => {
                outcome = OutcomeClass::ConnectionReset;
                error = Some("connection closed by peer".into());
                connector.close();
                break;
            }
            Err(e) => {
                error = Some(e.to_string());
                outcome = OutcomeClass::Error;
                connector.close();
                break;
            }
        }
    }

    let elapsed = timer.elapsed();
    let mut state_hash = 0u64;
    for r in &responses {
        state_hash = crate::common::utils::hash_combine(
            state_hash,
            crate::common::utils::hash_bytes(r),
        );
    }

    let mut result = ExecutionResult {
        seed_id: tc.id,
        success: error.is_none() && outcome == OutcomeClass::Ok,
        responses,
        response_codes,
        elapsed,
        new_coverage: false,
        new_state: false,
        crash: false,
        hang: false,
        error,
        state_hash,
        outcome,
        coverage_hits: 0,
        coverage_map_hash: 0,
    };
    result = result.with_outcome(outcome);
    Ok(result)
}

/// Execute a full test case over UDP.
pub fn execute_udp(
    connector: &mut UdpConnector,
    tc: &TestCase,
    max_resp: usize,
) -> Result<ExecutionResult> {
    let timer = Timer::start();
    let mut responses = Vec::new();
    let mut response_codes = Vec::new();
    let mut outcome = OutcomeClass::Ok;
    let mut error = None;

    if !connector.is_bound() {
        if let Err(e) = connector.bind() {
            return Ok(ExecutionResult {
                seed_id: tc.id,
                success: false,
                responses: vec![],
                response_codes: vec![],
                elapsed: timer.elapsed(),
                new_coverage: false,
                new_state: false,
                crash: false,
                hang: false,
                error: Some(e.to_string()),
                state_hash: 0,
                outcome: OutcomeClass::Error,
                coverage_hits: 0,
                coverage_map_hash: 0,
            });
        }
    }

    for msg in &tc.messages {
        let data = msg.serialize();
        match connector.send(&data) {
            Ok(()) => {}
            Err(e) => {
                error = Some(e.to_string());
                outcome = OutcomeClass::Error;
                break;
            }
        }

        match connector.recv(max_resp) {
            Ok((resp, timed_out)) => {
                if timed_out || resp.is_empty() {
                    outcome = OutcomeClass::Hang;
                } else {
                    let code = extract_response_code(&resp);
                    response_codes.push(code);
                    responses.push(resp);
                }
            }
            Err(e) => {
                error = Some(e.to_string());
                outcome = OutcomeClass::Error;
                break;
            }
        }
    }

    let elapsed = timer.elapsed();
    let mut state_hash = 0u64;
    for r in &responses {
        state_hash = crate::common::utils::hash_combine(
            state_hash,
            crate::common::utils::hash_bytes(r),
        );
    }

    let mut result = ExecutionResult {
        seed_id: tc.id,
        success: error.is_none() && outcome == OutcomeClass::Ok,
        responses,
        response_codes,
        elapsed,
        new_coverage: false,
        new_state: false,
        crash: false,
        hang: false,
        error,
        state_hash,
        outcome,
        coverage_hits: 0,
        coverage_map_hash: 0,
    };
    result = result.with_outcome(outcome);
    Ok(result)
}

fn extract_response_code(resp: &[u8]) -> i32 {
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
    } else if resp.len() >= 4 {
        i32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]])
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[test]
    fn tcp_connector_creation() {
        let addr = SocketAddr::from_str("127.0.0.1:9").unwrap();
        let c = TcpConnector::new(addr, Duration::from_millis(50));
        assert!(!c.is_connected());
    }

    #[test]
    fn udp_connector_creation() {
        let addr = SocketAddr::from_str("127.0.0.1:9").unwrap();
        let c = UdpConnector::new(addr, Duration::from_millis(50));
        assert!(!c.is_bound());
    }

    #[test]
    fn extract_code_ftp_style() {
        assert_eq!(extract_response_code(b"220 Welcome\r\n"), 220);
        assert_eq!(extract_response_code(b"530 Login incorrect"), 530);
    }
}
