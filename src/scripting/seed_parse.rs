//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Files   : nexsiz/src/scripting/seed_parse.rs
//!
//! Parse structured seed JSON into TestCase

use crate::common::types::{Field, FieldType, Message, TestCase};
use crate::scripting::json::JsonValue;

/// Build a TestCase from add_seed_structured params.
///
/// ```json
/// {
///   "name": "login",
///   "messages": [
///     {
///       "name": "user",
///       "fields": [
///         {"name":"cmd","type":"command","data":"USER"},
///         {"name":"sp","type":"binary","data":" ","protected":true},
///         {"name":"arg","type":"string","data":"anonymous"},
///         {"name":"crlf","type":"binary","data":"\r\n","protected":true}
///       ]
///     }
///   ]
/// }
/// ```
pub fn testcase_from_structured(params: &JsonValue) -> Result<TestCase, String> {
    let messages_val = params
        .get("messages")
        .ok_or_else(|| "missing messages array".to_string())?;
    let arr = match messages_val {
        JsonValue::Array(a) => a,
        _ => return Err("messages must be an array".into()),
    };
    if arr.is_empty() {
        return Err("messages array is empty".into());
    }

    let mut messages = Vec::new();
    for (i, mval) in arr.iter().enumerate() {
        let mname = mval
            .get_str("name")
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("msg{}", i));
        let mut msg = Message::new(mname);

        let fields = match mval.get("fields") {
            Some(JsonValue::Array(f)) => f,
            _ => return Err(format!("message[{}] missing fields array", i)),
        };
        for (j, fval) in fields.iter().enumerate() {
            let fname = fval
                .get_str("name")
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("f{}", j));
            let ftype = parse_field_type(fval.get_str("type").unwrap_or("binary"));
            let data = field_data(fval).ok_or_else(|| {
                format!("message[{}].fields[{}] missing/invalid data", i, j)
            })?;
            let mut field = Field::new(fname, ftype, data);
            if fval.get("protected").and_then(|v| v.as_bool()).unwrap_or(false) {
                field = field.protected();
            }
            if let Some(sz) = fval.get_u64("size") {
                field = field.with_size(sz as usize);
            }
            msg.add_field(field);
        }
        messages.push(msg);
    }

    Ok(TestCase::new(0, messages))
}

fn parse_field_type(s: &str) -> FieldType {
    match s.to_lowercase().as_str() {
        "command" | "cmd" => FieldType::Command,
        "length" | "len" => FieldType::Length,
        "checksum" | "chk" | "crc" => FieldType::Checksum,
        "numeric" | "num" | "int" => FieldType::Numeric,
        "payload" | "pay" => FieldType::Payload,
        "string" | "str" | "text" => FieldType::String,
        "binary" | "bin" | "raw" => FieldType::Binary,
        other => FieldType::Custom(other.to_string()),
    }
}

fn field_data(v: &JsonValue) -> Option<Vec<u8>> {
    // data as string / object {encoding,data} / number (single byte)
    if let Some(s) = v.get_str("data") {
        let enc = v.get_str("encoding").unwrap_or("utf8");
        return match enc {
            "base64" | "b64" => b64_decode(s).ok(),
            "hex" => hex_decode(s).ok(),
            _ => Some(s.as_bytes().to_vec()),
        };
    }
    // shorthand: whole value is string
    if let JsonValue::String(s) = v {
        return Some(s.as_bytes().to_vec());
    }
    if let Some(n) = v.get("data").and_then(|x| match x {
        JsonValue::Number(n) => Some(*n as u64),
        _ => None,
    }) {
        return Some(vec![n.min(255) as u8]);
    }
    None
}

fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: i32 = 0;
    for c in input.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let val = TABLE
            .iter()
            .position(|&x| x == c as u8)
            .ok_or_else(|| format!("invalid base64 char: {}", c))? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let s: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripting::json;

    #[test]
    fn parse_ftp_login() {
        let field = |name, ty, data, prot| {
            let mut pairs = vec![("name", json::s(name)), ("type", json::s(ty)), ("data", json::s(data))];
            // build via obj
            let mut m = std::collections::HashMap::new();
            m.insert("name".into(), json::s(name));
            m.insert("type".into(), json::s(ty));
            m.insert("data".into(), json::s(data));
            if prot {
                m.insert("protected".into(), json::b(true));
            }
            JsonValue::Object(m)
        };
        let msg = {
            let mut m = std::collections::HashMap::new();
            m.insert("name".into(), json::s("user"));
            m.insert(
                "fields".into(),
                JsonValue::Array(vec![
                    field("cmd", "command", "USER", false),
                    field("sp", "binary", " ", true),
                    field("arg", "string", "anonymous", false),
                    field("crlf", "binary", "\r\n", true),
                ]),
            );
            JsonValue::Object(m)
        };
        let params = {
            let mut m = std::collections::HashMap::new();
            m.insert("messages".into(), JsonValue::Array(vec![msg]));
            JsonValue::Object(m)
        };
        let tc = testcase_from_structured(&params).unwrap();
        assert_eq!(tc.messages.len(), 1);
        assert_eq!(tc.messages[0].fields.len(), 4);
        assert!(tc.messages[0].fields[1].protected);
        assert_eq!(tc.serialize(), b"USER anonymous\r\n");
    }
}
