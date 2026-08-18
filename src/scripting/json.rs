//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::json
//!
//! Description
//! -----------
//! Minimal, pure-stdlib JSON helpers used exclusively by the RPC control
//! plane. Implements only the subset required by the campaign-control
//! protocol (objects, strings, numbers, bools, null, and flat arrays).
//! Intentionally not a general-purpose JSON library – no serde, no streaming,
//! no arbitrary nesting beyond what the protocol needs.
//!
//! Core responsibilities
//! ---------------------
//! - Provide a lightweight JsonValue enum (Null / Bool / Number / String /
//!   Array / Object) with convenient accessors (as_str, as_f64, as_u64,
//!   as_bool, get, get_str, get_u64).
//! - Serialise JsonValue → String via stringify (stable key ordering for
//!   tests, proper escaping of control characters).
//! - Parse a JSON string → JsonValue via a minimal recursive-descent parser.
//! - Offer convenience builders (obj, s, n, b) so handlers can construct
//!   responses without verbose HashMap boilerplate.
//!
//! Supported subset
//! ----------------
//! - Values: null, true/false, numbers (integer or float, optional exponent),
//!   strings (with standard escapes including \uXXXX), arrays, objects.
//! - Objects use HashMap; stringify sorts keys for deterministic output.
//! - Nested structures are supported to the depth the protocol actually uses
//!   (typically 2–3 levels).
//! - No support for: comments, trailing commas, NaN/Infinity, big integers
//!   beyond f64, or streaming/incremental parse.
//!
//! Design constraints
//! ------------------
//! - Zero external dependencies. Keeps the binary lean and the attack surface
//!   of the control plane minimal.
//! - Fail-fast parse errors return a plain String; the RPC handler wraps them
//!   into the standard error envelope.
//! - Numbers are stored as f64; integer-looking values are emitted without a
//!   decimal point on serialise for readability.
//! - The parser is strict about trailing data after a complete value.
//!
//! API surface used by the rest of scripting/
//! ------------------------------------------
//! - parse / stringify          : request/response boundary
//! - JsonValue::{get,get_str,…} : handler param extraction
//! - obj / s / n / b            : response construction in handler & bridges
//!
//! See Also
//! --------
//! - handler.rs         : primary consumer of parse / stringify / builders
//! - protocol.rs        : method list and PROTOCOL_VERSION constants
//! - All *_bridge.rs    : use JsonValue for params and status payloads

use std::collections::HashMap;

/// Lightweight JSON value used by the RPC layer.
#[derive(Debug, Clone)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(HashMap<String, JsonValue>),
}

impl JsonValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_f64().map(|n| n as u64)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&HashMap<String, JsonValue>> {
        match self {
            JsonValue::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.as_object().and_then(|m| m.get(key))
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.as_u64())
    }
}

// ── Serialize ────────────────────────────────────────────────────────────────

pub fn stringify(v: &JsonValue) -> String {
    let mut out = String::new();
    write_value(&mut out, v);
    out
}

fn write_value(out: &mut String, v: &JsonValue) {
    match v {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(n) => {
            if n.fract() == 0.0 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64 {
                out.push_str(&format!("{}", *n as i64));
            } else {
                out.push_str(&format!("{}", n));
            }
        }
        JsonValue::String(s) => write_string(out, s),
        JsonValue::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        JsonValue::Object(map) => {
            out.push('{');
            let mut first = true;
            // Stable-ish order for tests: sort keys
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                if !first {
                    out.push(',');
                }
                first = false;
                write_string(out, k);
                out.push(':');
                write_value(out, &map[k]);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ── Parse (minimal recursive descent) ────────────────────────────────────────

pub fn parse(input: &str) -> Result<JsonValue, String> {
    let mut p = Parser {
        chars: input.chars().collect(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos < p.chars.len() {
        return Err("trailing data".into());
    }
    Ok(v)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.skip_ws();
        match self.peek() {
            Some('n') => self.parse_null(),
            Some('t') => self.parse_true(),
            Some('f') => self.parse_false(),
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('[') => self.parse_array(),
            Some('{') => self.parse_object(),
            Some('-') | Some('0'..='9') => self.parse_number(),
            other => Err(format!("unexpected {:?}", other)),
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, String> {
        for c in ['n', 'u', 'l', 'l'] {
            if self.bump() != Some(c) {
                return Err("expected null".into());
            }
        }
        Ok(JsonValue::Null)
    }

    fn parse_true(&mut self) -> Result<JsonValue, String> {
        for c in ['t', 'r', 'u', 'e'] {
            if self.bump() != Some(c) {
                return Err("expected true".into());
            }
        }
        Ok(JsonValue::Bool(true))
    }

    fn parse_false(&mut self) -> Result<JsonValue, String> {
        for c in ['f', 'a', 'l', 's', 'e'] {
            if self.bump() != Some(c) {
                return Err("expected false".into());
            }
        }
        Ok(JsonValue::Bool(false))
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some('0'..='9')) {
            self.pos += 1;
        }
        if self.peek() == Some('.') {
            self.pos += 1;
            while matches!(self.peek(), Some('0'..='9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some('0'..='9')) {
                self.pos += 1;
            }
        }
        let s: String = self.chars[start..self.pos].iter().collect();
        s.parse::<f64>()
            .map(JsonValue::Number)
            .map_err(|e| e.to_string())
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.bump() != Some('"') {
            return Err("expected \"".into());
        }
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err("unterminated string".into()),
                Some('"') => return Ok(out),
                Some('\\') => match self.bump() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('u') => {
                        let mut hex = String::new();
                        for _ in 0..4 {
                            match self.bump() {
                                Some(c) => hex.push(c),
                                None => return Err("bad \\u".into()),
                            }
                        }
                        let cp = u32::from_str_radix(&hex, 16).map_err(|e| e.to_string())?;
                        out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                    }
                    Some(c) => out.push(c),
                    None => return Err("bad escape".into()),
                },
                Some(c) => out.push(c),
            }
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, String> {
        if self.bump() != Some('[') {
            return Err("expected [".into());
        }
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.bump() {
                Some(',') => {
                    self.skip_ws();
                    continue;
                }
                Some(']') => return Ok(JsonValue::Array(items)),
                other => return Err(format!("expected , or ], got {:?}", other)),
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, String> {
        if self.bump() != Some('{') {
            return Err("expected {".into());
        }
        self.skip_ws();
        let mut map = HashMap::new();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(JsonValue::Object(map));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(':') {
                return Err("expected :".into());
            }
            let val = self.parse_value()?;
            map.insert(key, val);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some('}') => return Ok(JsonValue::Object(map)),
                other => return Err(format!("expected , or }}, got {:?}", other)),
            }
        }
    }
}

// ── Convenience builders ─────────────────────────────────────────────────────

pub fn obj(pairs: Vec<(&str, JsonValue)>) -> JsonValue {
    let mut m = HashMap::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    JsonValue::Object(m)
}

pub fn s(v: impl Into<String>) -> JsonValue {
    JsonValue::String(v.into())
}

pub fn n(v: impl Into<f64>) -> JsonValue {
    JsonValue::Number(v.into())
}

pub fn b(v: bool) -> JsonValue {
    JsonValue::Bool(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_object() {
        let v = obj(vec![
            ("method", s("stats")),
            ("id", n(1.0)),
            ("ok", b(true)),
        ]);
        let text = stringify(&v);
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed.get_str("method"), Some("stats"));
        assert_eq!(parsed.get_u64("id"), Some(1));
        assert_eq!(parsed.get("ok").and_then(|x| x.as_bool()), Some(true));
    }

    #[test]
    fn escape_string() {
        let v = s("a\"b\\c\n");
        let text = stringify(&v);
        assert!(text.contains("\\\""));
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed.as_str(), Some("a\"b\\c\n"));
    }
}
