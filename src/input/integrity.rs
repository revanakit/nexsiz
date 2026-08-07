//! NEXSIZ – Protocol-Aware Integrity Repair
//! Author  : Revana
//! Date    : 05/08/2026
//!
//! High-quality integrity repair that keeps mutated messages valid enough
//! to reach deep protocol states. Supports:
//!   - Semantic field repair (Length / Checksum typed fields)
//!   - HTTP Content-Length + header/body reconstruction
//!   - Text-protocol CRLF normalization (FTP / SMTP)
//!   - Binary length-prefix heuristics
//!   - Multiple checksum algorithms (additive, XOR, CRC16, CRC32)

use crate::common::types::*;

// ── Checksum algorithms ──────────────────────────────────────────────────────

#[inline]
pub fn checksum_additive(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

#[inline]
pub fn checksum_xor(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc ^ b)
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF)
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// CRC-32/ISO-HDLC (poly 0xEDB88320, init 0xFFFFFFFF, xorout 0xFFFFFFFF)
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Internet checksum (one's complement, RFC 1071 style) over 16-bit words.
pub fn checksum_ones_complement(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ── Length helpers ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum Endian {
    Big,
    Little,
}

/// Write `value` into `buf` according to its length and endianness.
pub fn write_length(buf: &mut [u8], value: usize, endian: Endian) {
    match (buf.len(), endian) {
        (1, _) => buf[0] = value as u8,
        (2, Endian::Big) => buf.copy_from_slice(&(value as u16).to_be_bytes()),
        (2, Endian::Little) => buf.copy_from_slice(&(value as u16).to_le_bytes()),
        (4, Endian::Big) => buf.copy_from_slice(&(value as u32).to_be_bytes()),
        (4, Endian::Little) => buf.copy_from_slice(&(value as u32).to_le_bytes()),
        _ => {}
    }
}

/// Write a checksum value into a field buffer.
pub fn write_checksum(buf: &mut [u8], value: u64, endian: Endian) {
    match (buf.len(), endian) {
        (1, _) => buf[0] = value as u8,
        (2, Endian::Big) => buf.copy_from_slice(&(value as u16).to_be_bytes()),
        (2, Endian::Little) => buf.copy_from_slice(&(value as u16).to_le_bytes()),
        (4, Endian::Big) => buf.copy_from_slice(&(value as u32).to_be_bytes()),
        (4, Endian::Little) => buf.copy_from_slice(&(value as u32).to_le_bytes()),
        _ => {}
    }
}

// ── Semantic field repair ────────────────────────────────────────────────────

/// Repair Length and Checksum typed fields inside a single Message.
///
/// Length is recalculated as the sum of all subsequent field sizes.
/// Checksum covers every field except itself (algorithm chosen by field size).
pub fn repair_message(msg: &mut Message) {
    repair_message_ex(msg, Endian::Big, ChecksumAlgo::Additive);
}

#[derive(Debug, Clone, Copy)]
pub enum ChecksumAlgo {
    Additive,
    Xor,
    Crc16,
    Crc32,
    OnesComplement,
}

pub fn repair_message_ex(msg: &mut Message, endian: Endian, algo: ChecksumAlgo) {
    let mut length_indices = Vec::new();
    let mut checksum_indices = Vec::new();

    for (i, f) in msg.fields.iter().enumerate() {
        match f.ftype {
            FieldType::Length => length_indices.push(i),
            FieldType::Checksum => checksum_indices.push(i),
            _ => {}
        }
    }

    // Repair lengths first (payload size must be correct before checksum)
    for &idx in &length_indices {
        let after_len: usize = msg.fields[idx + 1..]
            .iter()
            .filter(|f| !matches!(f.ftype, FieldType::Checksum))
            .map(|f| f.data.len())
            .sum();
        // Also include checksum field size if present after length
        let with_chk: usize = msg.fields[idx + 1..].iter().map(|f| f.data.len()).sum();
        let value = if with_chk != after_len {
            // Prefer payload-only length (common)
            after_len
        } else {
            after_len
        };
        write_length(&mut msg.fields[idx].data, value, endian);
    }

    // Repair checksums
    for &idx in &checksum_indices {
        let mut payload = Vec::new();
        for (i, f) in msg.fields.iter().enumerate() {
            if i == idx {
                continue;
            }
            payload.extend_from_slice(&f.data);
        }

        let field = &mut msg.fields[idx];
        let value = match algo {
            ChecksumAlgo::Additive => checksum_additive(&payload) as u64,
            ChecksumAlgo::Xor => checksum_xor(&payload) as u64,
            ChecksumAlgo::Crc16 => crc16_ccitt(&payload) as u64,
            ChecksumAlgo::Crc32 => crc32_ieee(&payload) as u64,
            ChecksumAlgo::OnesComplement => checksum_ones_complement(&payload) as u64,
        };

        // Auto-select algorithm by field width when using default Additive
        let value = if matches!(algo, ChecksumAlgo::Additive) {
            match field.data.len() {
                1 => checksum_xor(&payload) as u64, // 1-byte → XOR is more natural
                2 => crc16_ccitt(&payload) as u64,
                4 => crc32_ieee(&payload) as u64,
                _ => value,
            }
        } else {
            value
        };

        write_checksum(&mut field.data, value, endian);
    }
}

// ── Protocol-aware raw-byte repair ───────────────────────────────────────────

/// Repair a raw byte buffer as if it were an HTTP message.
/// Recalculates / inserts Content-Length so the body length matches.
pub fn repair_http_raw(data: &mut Vec<u8>) {
    // Split headers / body on \r\n\r\n or \n\n
    let sep = if let Some(pos) = find_subsequence(data, b"\r\n\r\n") {
        (pos, 4)
    } else if let Some(pos) = find_subsequence(data, b"\n\n") {
        (pos, 2)
    } else {
        // No body separator – just ensure request line ends with CRLF
        ensure_crlf_termination(data);
        return;
    };

    let (header_end, sep_len) = sep;
    let body = data[header_end + sep_len..].to_vec();
    let body_len = body.len();

    let header_block = &data[..header_end];
    let header_str = String::from_utf8_lossy(header_block);

    // Rebuild headers with correct Content-Length
    let mut new_headers = String::new();
    let mut has_cl = false;
    let mut is_chunked = false;

    for line in header_str.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            new_headers.push_str(&format!("Content-Length: {}\r\n", body_len));
            has_cl = true;
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            is_chunked = true;
            new_headers.push_str(line);
            if !line.ends_with('\r') {
                new_headers.push_str("\r\n");
            } else {
                new_headers.push('\n');
            }
        } else if !line.is_empty() {
            new_headers.push_str(line);
            if !line.ends_with('\r') {
                new_headers.push_str("\r\n");
            } else {
                new_headers.push('\n');
            }
        }
    }

    if !has_cl && !is_chunked && body_len > 0 {
        new_headers.push_str(&format!("Content-Length: {}\r\n", body_len));
    }

    // Ensure header block ends with blank line
    if !new_headers.ends_with("\r\n\r\n") {
        if new_headers.ends_with("\r\n") {
            new_headers.push_str("\r\n");
        } else {
            new_headers.push_str("\r\n\r\n");
        }
    }

    let mut out = new_headers.into_bytes();
    out.extend_from_slice(&body);
    *data = out;
}

/// Ensure a text-protocol message ends with CRLF.
pub fn ensure_crlf_termination(data: &mut Vec<u8>) {
    if data.is_empty() {
        data.extend_from_slice(b"\r\n");
        return;
    }
    if data.ends_with(b"\r\n") {
        return;
    }
    if data.ends_with(b"\n") {
        data.pop();
        data.extend_from_slice(b"\r\n");
        return;
    }
    if data.ends_with(b"\r") {
        data.push(b'\n');
        return;
    }
    data.extend_from_slice(b"\r\n");
}

/// Heuristic binary length-prefix repair: treat first 1/2/4 bytes as length
/// of the remaining payload and rewrite it.
pub fn repair_binary_length_prefix(data: &mut Vec<u8>, width: usize, endian: Endian) {
    if data.len() <= width {
        return;
    }
    let payload_len = data.len() - width;
    match (width, endian) {
        (1, _) => data[0] = payload_len as u8,
        (2, Endian::Big) => {
            let v = (payload_len as u16).to_be_bytes();
            data[0] = v[0];
            data[1] = v[1];
        }
        (2, Endian::Little) => {
            let v = (payload_len as u16).to_le_bytes();
            data[0] = v[0];
            data[1] = v[1];
        }
        (4, Endian::Big) => {
            let v = (payload_len as u32).to_be_bytes();
            data[..4].copy_from_slice(&v);
        }
        (4, Endian::Little) => {
            let v = (payload_len as u32).to_le_bytes();
            data[..4].copy_from_slice(&v);
        }
        _ => {}
    }
}

/// SMTP-specific: ensure DATA body ends with &lt;CRLF&gt;.&lt;CRLF&gt; if it looks like DATA.
pub fn repair_smtp_raw(data: &mut Vec<u8>) {
    ensure_crlf_termination(data);
    // If the buffer contains a DATA command region, try to keep terminator intact
    let text = String::from_utf8_lossy(data);
    if text.to_ascii_uppercase().contains("DATA") {
        if !data.windows(5).any(|w| w == b"\r\n.\r\n") {
            // Append classic SMTP end-of-data if missing and buffer is large enough
            if data.len() > 10 {
                data.extend_from_slice(b"\r\n.\r\n");
            }
        }
    }
}

/// FTP-specific: ensure every logical line ends with CRLF.
pub fn repair_ftp_raw(data: &mut Vec<u8>) {
    // Split on existing newlines, rejoin with CRLF
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if out.is_empty() {
        ensure_crlf_termination(data);
    } else {
        *data = out;
    }
}

// ── High-level entry points ──────────────────────────────────────────────────

/// Repair every message in a test case using semantic field rules.
pub fn repair_testcase(tc: &mut TestCase) {
    for msg in &mut tc.messages {
        repair_message(msg);
    }
}

/// Protocol-aware preparation before sending.
///
/// `protocol` is a lowercase name: "http", "ftp", "smtp", "generic", …
/// When the message has typed Length/Checksum fields they are repaired first;
/// then protocol-specific raw-byte fixes are applied on the serialized form
/// and written back when the message is a single opaque Binary/String field.
pub fn prepare_for_send(tc: &mut TestCase, protocol: &str) {
    // 1. Semantic field repair
    repair_testcase(tc);

    let proto = protocol.to_ascii_lowercase();

    // 2. Protocol-specific raw repair when messages are mostly opaque
    for msg in &mut tc.messages {
        // If the message is a single field (common for text seeds / binary),
        // operate on that buffer directly.
        if msg.fields.len() == 1 {
            let field = &mut msg.fields[0];
            match proto.as_str() {
                "http" | "https" => repair_http_raw(&mut field.data),
                "ftp" => repair_ftp_raw(&mut field.data),
                "smtp" => repair_smtp_raw(&mut field.data),
                "binary" | "generic" if field.data.len() > 4 => {
                    // Heuristic: if first 2 bytes look like a plausible BE length, fix them
                    let be_len = u16::from_be_bytes([field.data[0], field.data[1]]) as usize;
                    if be_len == field.data.len() - 2 || be_len == field.data.len() - 4 {
                        repair_binary_length_prefix(&mut field.data, 2, Endian::Big);
                    }
                }
                _ => {
                    // Generic text-ish: ensure CRLF if it looks like text
                    if field.data.iter().all(|b| b.is_ascii()) && !field.data.is_empty() {
                        ensure_crlf_termination(&mut field.data);
                    }
                }
            }
        } else if proto == "http" || proto == "https" {
            // Multi-field HTTP: serialize, repair, then leave fields as-is
            // (semantic repair already handled Length fields).
            // Additionally fix Content-Length string fields by name.
            repair_http_content_length_fields(msg);
        } else if proto == "ftp" || proto == "smtp" {
            // Ensure last field that is a delimiter stays CRLF
            if let Some(last) = msg.fields.last_mut() {
                if last.data == b"\n" || last.data == b"\r" {
                    last.data = b"\r\n".to_vec();
                }
            }
        }
    }
}

/// Locate and rewrite a Content-Length header field inside a multi-field Message.
fn repair_http_content_length_fields(msg: &mut Message) {
    // Compute body size = everything after the blank-line separator field
    let mut body_len = 0usize;
    let mut past_headers = false;
    for f in &msg.fields {
        if past_headers {
            body_len += f.data.len();
        } else if f.data == b"\r\n\r\n" || f.data == b"\n\n" || f.name.contains("sep") {
            past_headers = true;
        }
    }

    for f in &mut msg.fields {
        let name_l = f.name.to_ascii_lowercase();
        let data_l = String::from_utf8_lossy(&f.data).to_ascii_lowercase();
        if name_l.contains("content-length") || data_l.starts_with("content-length:") {
            // Rewrite the whole header line
            f.data = format!("Content-Length: {}\r\n", body_len).into_bytes();
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_length_u16_be() {
        let mut msg = Message::new("t");
        msg.add_field(Field::new("len", FieldType::Length, vec![0, 0]));
        msg.add_field(Field::new("payload", FieldType::Binary, vec![1, 2, 3, 4]));
        repair_message(&mut msg);
        assert_eq!(msg.fields[0].data, vec![0, 4]);
    }

    #[test]
    fn repair_length_u32_le() {
        let mut msg = Message::new("t");
        msg.add_field(Field::new("len", FieldType::Length, vec![0, 0, 0, 0]));
        msg.add_field(Field::new("payload", FieldType::Binary, vec![9, 8, 7]));
        repair_message_ex(&mut msg, Endian::Little, ChecksumAlgo::Additive);
        assert_eq!(msg.fields[0].data, 3u32.to_le_bytes().to_vec());
    }

    #[test]
    fn repair_crc32_field() {
        let mut msg = Message::new("t");
        msg.add_field(Field::new("a", FieldType::Binary, vec![0x01, 0x02, 0x03, 0x04]));
        msg.add_field(Field::new("chk", FieldType::Checksum, vec![0, 0, 0, 0]));
        repair_message_ex(&mut msg, Endian::Big, ChecksumAlgo::Crc32);
        let expected = crc32_ieee(&[0x01, 0x02, 0x03, 0x04]).to_be_bytes();
        assert_eq!(msg.fields[1].data, expected.to_vec());
    }

    #[test]
    fn http_content_length_repair() {
        let mut data = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\nHELLO".to_vec();
        repair_http_raw(&mut data);
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("Content-Length: 5"));
        assert!(s.ends_with("HELLO"));
    }

    #[test]
    fn http_inserts_content_length_when_missing() {
        let mut data = b"POST / HTTP/1.1\r\nHost: x\r\n\r\nBODY".to_vec();
        repair_http_raw(&mut data);
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("Content-Length: 4"));
    }

    #[test]
    fn ftp_crlf_normalization() {
        let mut data = b"USER anonymous\nPASS guest\n".to_vec();
        repair_ftp_raw(&mut data);
        assert_eq!(data, b"USER anonymous\r\nPASS guest\r\n".to_vec());
    }

    #[test]
    fn binary_length_prefix() {
        let mut data = vec![0, 0, 0xAA, 0xBB, 0xCC];
        repair_binary_length_prefix(&mut data, 2, Endian::Big);
        assert_eq!(data[0], 0);
        assert_eq!(data[1], 3);
    }

    #[test]
    fn crc16_known_vector() {
        // CRC-16/CCITT-FALSE of "123456789" = 0x29B1
        let crc = crc16_ccitt(b"123456789");
        assert_eq!(crc, 0x29B1);
    }

    #[test]
    fn prepare_for_send_http() {
        let mut tc = TestCase::new(1, {
            let mut m = Message::new("req");
            m.add_field(Field::new(
                "raw",
                FieldType::Binary,
                b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99\r\n\r\nXY".to_vec(),
            ));
            vec![m]
        });
        prepare_for_send(&mut tc, "http");
        let s = String::from_utf8_lossy(&tc.messages[0].fields[0].data);
        assert!(s.contains("Content-Length: 2"));
    }
}
