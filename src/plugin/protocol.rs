//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::plugin::protocol
//!
//! NEXSIZ – Protocol plugins (built-in + grammar-based + JSON models)
//! Phase 4: JSON `desocket` block → ProtocolModel.desocket (SpecDesocket)

use crate::input::model::{
    DesocketSpec, FieldSpec, MessageSpec, ModelChecksum, ModelEndian, ProtocolModel,
};
use crate::common::types::FieldType;

/// Trait for protocol-specific hints used by the mutator and integrity layer.
pub trait ProtocolPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn build_model(&self) -> ProtocolModel;
}

/// Built-in protocol plugins wrapping existing constructors.
#[derive(Debug, Clone, Copy)]
pub enum BuiltinProtocol {
    Generic,
    Ftp,
    Http,
    Smtp,
    Dns,
    Mqtt,
    Smb,
    BinaryLp,
    BinaryLpLe,
}

impl BuiltinProtocol {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "generic" => Some(Self::Generic),
            "ftp" => Some(Self::Ftp),
            "http" | "https" => Some(Self::Http),
            "smtp" => Some(Self::Smtp),
            "dns" => Some(Self::Dns),
            "mqtt" => Some(Self::Mqtt),
            "smb" | "cifs" => Some(Self::Smb),
            "binary-lp" | "lp" | "binary" => Some(Self::BinaryLp),
            "binary-lp-le" | "lp-le" | "binary-le" => Some(Self::BinaryLpLe),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Ftp => "ftp",
            Self::Http => "http",
            Self::Smtp => "smtp",
            Self::Dns => "dns",
            Self::Mqtt => "mqtt",
            Self::Smb => "smb",
            Self::BinaryLp => "binary-lp",
            Self::BinaryLpLe => "binary-lp-le",
        }
    }
}

impl ProtocolPlugin for BuiltinProtocol {
    fn name(&self) -> &str {
        self.as_str()
    }

    fn build_model(&self) -> ProtocolModel {
        match self {
            Self::Generic => ProtocolModel::generic(),
            Self::Ftp => ProtocolModel::ftp(),
            Self::Http => ProtocolModel::http(),
            Self::Smtp => ProtocolModel::smtp(),
            Self::Dns => ProtocolModel::dns(),
            Self::Mqtt => ProtocolModel::mqtt(),
            Self::Smb => ProtocolModel::smb(),
            Self::BinaryLp => ProtocolModel::binary_lp(),
            Self::BinaryLpLe => ProtocolModel::binary_lp_le(),
        }
    }
}

/// A single production in a lightweight protocol grammar.
#[derive(Debug, Clone)]
pub struct GrammarProduction {
    pub name: String,
    pub tokens: Vec<Vec<u8>>,
    pub suffix: Option<Vec<u8>>,
}

impl GrammarProduction {
    pub fn new(name: impl Into<String>, tokens: Vec<&[u8]>) -> Self {
        Self {
            name: name.into(),
            tokens: tokens.into_iter().map(|t| t.to_vec()).collect(),
            suffix: None,
        }
    }

    pub fn with_suffix(mut self, suffix: &[u8]) -> Self {
        self.suffix = Some(suffix.to_vec());
        self
    }
}

/// Grammar-based protocol plugin.
pub struct GrammarProtocol {
    name: String,
    productions: Vec<GrammarProduction>,
    length_prefixed: bool,
    delimiter: Option<u8>,
    endian: ModelEndian,
    length_width: Option<usize>,
}

impl GrammarProtocol {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            productions: Vec::new(),
            length_prefixed: false,
            delimiter: None,
            endian: ModelEndian::Big,
            length_width: None,
        }
    }

    pub fn production(mut self, p: GrammarProduction) -> Self {
        self.productions.push(p);
        self
    }

    pub fn delimiter(mut self, d: u8) -> Self {
        self.delimiter = Some(d);
        self
    }

    pub fn length_prefixed(mut self, v: bool) -> Self {
        self.length_prefixed = v;
        self
    }

    pub fn endian(mut self, e: ModelEndian) -> Self {
        self.endian = e;
        self
    }

    pub fn length_width(mut self, w: usize) -> Self {
        self.length_width = Some(w);
        self
    }

    pub fn ftp_grammar() -> Self {
        Self::new("grammar-ftp")
            .delimiter(b'\n')
            .production(
                GrammarProduction::new(
                    "command",
                    vec![
                        b"USER", b"PASS", b"LIST", b"RETR", b"STOR", b"QUIT", b"SYST",
                        b"PWD", b"CWD", b"TYPE", b"PASV", b"PORT", b"MKD", b"RMD",
                        b"DELE", b"RNFR", b"RNTO", b"NOOP", b"HELP",
                    ],
                )
                .with_suffix(b"\r\n"),
            )
            .production(GrammarProduction::new(
                "arg",
                vec![
                    b"anonymous", b"guest", b"/", b"..", b"/etc/passwd", b"A",
                    b"%n", b"%s", b"127.0.0.1",
                ],
            ))
            .production(GrammarProduction::new(
                "type_code",
                vec![b"A", b"I", b"L", b"E"],
            ))
    }

    pub fn http_grammar() -> Self {
        let long_path = "/".repeat(64);
        Self::new("grammar-http")
            .delimiter(b'\n')
            .production(GrammarProduction::new(
                "method",
                vec![b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"],
            ))
            .production(GrammarProduction::new(
                "path",
                vec![
                    b"/",
                    b"/index.html",
                    b"/api",
                    b"/../",
                    b"/%00",
                    b"/admin",
                    b"?q=",
                    long_path.as_bytes(),
                ],
            ))
            .production(GrammarProduction::new(
                "version",
                vec![b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2"],
            ))
            .production(
                GrammarProduction::new(
                    "header",
                    vec![
                        b"Host:",
                        b"Content-Length:",
                        b"Content-Type:",
                        b"Connection:",
                        b"Cookie:",
                        b"User-Agent:",
                        b"Transfer-Encoding:",
                        b"X-Forwarded-For:",
                    ],
                )
                .with_suffix(b"\r\n"),
            )
            .production(GrammarProduction::new(
                "header_value",
                vec![
                    b"localhost",
                    b"keep-alive",
                    b"close",
                    b"chunked",
                    b"application/json",
                    b"0",
                    b"-1",
                    b"999999",
                ],
            ))
    }

    pub fn smtp_grammar() -> Self {
        let long_local = "a".repeat(256);
        Self::new("grammar-smtp")
            .delimiter(b'\n')
            .production(
                GrammarProduction::new(
                    "command",
                    vec![
                        b"HELO", b"EHLO", b"MAIL FROM:", b"RCPT TO:", b"DATA", b"QUIT",
                        b"RSET", b"VRFY", b"NOOP", b"STARTTLS",
                    ],
                )
                .with_suffix(b"\r\n"),
            )
            .production(GrammarProduction::new(
                "mailbox",
                vec![
                    b"<user@example.com>",
                    b"<>",
                    b"<@>",
                    b"root@localhost",
                    long_local.as_bytes(),
                ],
            ))
    }

    pub fn dns_grammar() -> Self {
        Self::new("grammar-dns")
            .length_prefixed(true)
            .length_width(2)
            .endian(ModelEndian::Big)
            .production(GrammarProduction::new(
                "qtype",
                vec![b"\x00\x01", b"\x00\x1c", b"\x00\x0f", b"\x00\x10", b"\x00\xff"],
            ))
            .production(GrammarProduction::new(
                "qclass",
                vec![b"\x00\x01", b"\x00\xff"],
            ))
            .production(GrammarProduction::new(
                "name",
                vec![
                    b"\x03www\x07example\x03com\x00",
                    b"\x00",
                    b"\xff\xff",
                ],
            ))
    }

    pub fn mqtt_grammar() -> Self {
        Self::new("grammar-mqtt")
            .length_prefixed(true)
            .production(GrammarProduction::new(
                "pkt_type",
                vec![b"\x10", b"\x20", b"\x30", b"\x80", b"\x90", b"\xc0", b"\xe0"],
            ))
            .production(GrammarProduction::new(
                "proto",
                vec![b"MQTT", b"\x04", b"\x05"],
            ))
            .production(GrammarProduction::new(
                "topic",
                vec![b"test/topic", b"#", b"+", b"$SYS"],
            ))
    }

    pub fn smb_grammar() -> Self {
        Self::new("grammar-smb")
            .length_prefixed(true)
            .length_width(4)
            .endian(ModelEndian::Big)
            .production(GrammarProduction::new(
                "magic",
                vec![b"\xffSMB", b"\xfeSMB"],
            ))
            .production(GrammarProduction::new(
                "command",
                vec![
                    b"\x00\x00", b"\x01\x00", b"\x03\x00", b"\x05\x00",
                    b"\x08\x00", b"\x09\x00", b"\x0b\x00",
                ],
            ))
            .production(GrammarProduction::new(
                "share",
                vec![b"IPC$", b"C$", b"ADMIN$", b"\\"],
            ))
    }

    pub fn generic_grammar() -> Self {
        Self::new("grammar-generic").production(GrammarProduction::new(
            "blob",
            vec![
                b"\x00",
                b"\xff",
                b"\x00\x00",
                b"\xff\xff",
                b"\x00\x00\x00\x00",
                b"\xff\xff\xff\xff",
                b"%n",
                b"%s",
                b"../",
                b"\r\n",
                b"\r\n\r\n",
            ],
        ))
    }
}

impl ProtocolPlugin for GrammarProtocol {
    fn name(&self) -> &str {
        &self.name
    }

    fn build_model(&self) -> ProtocolModel {
        let mut dictionary: Vec<Vec<u8>> = Vec::new();
        for prod in &self.productions {
            for tok in &prod.tokens {
                if !dictionary.iter().any(|d| d == tok) {
                    dictionary.push(tok.clone());
                }
            }
            if let Some(ref suf) = prod.suffix {
                if !dictionary.iter().any(|d| d == suf) {
                    dictionary.push(suf.clone());
                }
            }
        }
        for extra in [b"\x00".as_slice(), b"\xff", b"\r\n", b"A"] {
            let v = extra.to_vec();
            if !dictionary.iter().any(|d| d == &v) {
                dictionary.push(v);
            }
        }

        ProtocolModel {
            name: self.name.clone(),
            dictionary,
            length_prefixed: self.length_prefixed,
            delimiter: self.delimiter,
            endian: self.endian,
            checksum: ModelChecksum::Auto,
            messages: Vec::new(),
            length_width: self.length_width,
            sequences: Vec::new(),
            desocket: None,
        }
    }
}

pub struct ExternalProtocol {
    name: String,
    model: ProtocolModel,
}

impl ExternalProtocol {
    pub fn new(name: impl Into<String>, model: ProtocolModel) -> Self {
        Self {
            name: name.into(),
            model,
        }
    }
}

impl ProtocolPlugin for ExternalProtocol {
    fn name(&self) -> &str {
        &self.name
    }

    fn build_model(&self) -> ProtocolModel {
        self.model.clone()
    }
}

pub fn load_model_from_path(path: &str) -> Result<Box<dyn ProtocolPlugin>, String> {
    #[cfg(feature = "json-model")]
    {
        load_model_from_path_json(path)
    }
    #[cfg(not(feature = "json-model"))]
    {
        let _ = path;
        Err(
            "JSON protocol models require the `json-model` feature. \
             Rebuild with: cargo build --release --features json-model"
                .to_string(),
        )
    }
}

#[cfg(feature = "json-model")]
fn load_model_from_path_json(path: &str) -> Result<Box<dyn ProtocolPlugin>, String> {
    use serde::Deserialize;
    use std::fs;

    #[derive(Debug, Deserialize)]
    struct JsonField {
        name: String,
        #[serde(rename = "type")]
        ftype: String,
        size: Option<usize>,
        protected: Option<bool>,
        values: Option<Vec<String>>,
        endian: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct JsonMessage {
        name: String,
        fields: Option<Vec<JsonField>>,
    }

    #[derive(Debug, Deserialize)]
    struct JsonDesocket {
        sequences: Option<Vec<String>>,
        goodbye: Option<String>,
        success_on_response: Option<bool>,
    }

    #[derive(Debug, Deserialize)]
    struct JsonModel {
        name: String,
        length_prefixed: Option<bool>,
        length_width: Option<usize>,
        endian: Option<String>,
        delimiter: Option<String>,
        dictionary: Option<Vec<String>>,
        messages: Option<Vec<JsonMessage>>,
        checksum: Option<String>,
        desocket: Option<JsonDesocket>,
    }

    let data = fs::read_to_string(path).map_err(|e| format!("read {}: {}", path, e))?;
    let j: JsonModel =
        serde_json::from_str(&data).map_err(|e| format!("parse {}: {}", path, e))?;

    let endian = match j.endian.as_deref().map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("le") | Some("little") => ModelEndian::Little,
        _ => ModelEndian::Big,
    };

    let checksum = match j.checksum.as_deref().map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("additive") => ModelChecksum::Additive,
        Some("xor") => ModelChecksum::Xor,
        Some("crc16") => ModelChecksum::Crc16,
        Some("crc32") => ModelChecksum::Crc32,
        Some("ones") | Some("ones-complement") => ModelChecksum::OnesComplement,
        _ => ModelChecksum::Auto,
    };

    let delimiter = j.delimiter.and_then(|s| {
        if s.is_empty() || s == "null" {
            None
        } else if s == "\\n" || s == "\n" {
            Some(b'\n')
        } else {
            s.bytes().next()
        }
    });

    let mut dictionary = Vec::new();
    if let Some(dict) = j.dictionary {
        for entry in dict {
            dictionary.push(parse_token(&entry));
        }
    }

    let mut messages = Vec::new();
    if let Some(msgs) = j.messages {
        for jm in msgs {
            let mut ms = MessageSpec::new(jm.name);
            if let Some(fields) = jm.fields {
                for jf in fields {
                    let ftype = parse_field_type(&jf.ftype);
                    let mut fs = FieldSpec::new(jf.name, ftype);
                    if let Some(sz) = jf.size {
                        fs = fs.with_size(sz);
                    }
                    if jf.protected.unwrap_or(false) {
                        fs = fs.protected();
                    }
                    if let Some(vals) = jf.values {
                        let parsed: Vec<Vec<u8>> = vals.iter().map(|v| parse_token(v)).collect();
                        fs = fs.values(parsed);
                    }
                    if let Some(ref e) = jf.endian {
                        let e = match e.to_ascii_lowercase().as_str() {
                            "le" | "little" => ModelEndian::Little,
                            _ => ModelEndian::Big,
                        };
                        fs = fs.endian(e);
                    }
                    ms = ms.field(fs);
                }
            }
            messages.push(ms);
        }
    }

    let desocket = j.desocket.and_then(|jd| {
        let sequences: Vec<Vec<u8>> = jd
            .sequences
            .unwrap_or_default()
            .iter()
            .map(|s| parse_token(s))
            .filter(|v| !v.is_empty())
            .collect();
        if sequences.is_empty() {
            return None;
        }
        Some(DesocketSpec {
            sequences,
            goodbye: jd.goodbye.map(|g| parse_token(&g)).filter(|v| !v.is_empty()),
            success_on_response: jd.success_on_response.unwrap_or(true),
        })
    });

    let model = ProtocolModel {
        name: j.name.clone(),
        dictionary,
        length_prefixed: j.length_prefixed.unwrap_or(false),
        delimiter,
        endian,
        checksum,
        messages,
        length_width: j.length_width,
        sequences: Vec::new(),
        desocket,
    };

    Ok(Box::new(ExternalProtocol::new(j.name, model)))
}

#[cfg(feature = "json-model")]
fn parse_field_type(s: &str) -> FieldType {
    match s.to_ascii_lowercase().as_str() {
        "command" | "cmd" => FieldType::Command,
        "length" | "len" => FieldType::Length,
        "checksum" | "chk" | "crc" => FieldType::Checksum,
        "numeric" | "num" | "int" => FieldType::Numeric,
        "payload" | "pay" => FieldType::Payload,
        "string" | "str" | "text" => FieldType::String,
        "binary" | "bin" | "bytes" => FieldType::Binary,
        other => FieldType::Custom(other.to_string()),
    }
}

#[cfg(feature = "json-model")]
fn parse_token(s: &str) -> Vec<u8> {
    // Match literal backslash-x prefix ("\xNN" style tokens from JSON).
    // Use raw string — "\x" alone is an invalid numeric escape in Rust.
    if s.starts_with(r"\x") {
        let hex = s.trim_start_matches('\\').trim_start_matches('x');
        if hex.len() == 2 {
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                return vec![v];
            }
        }
    }
    if s.contains(r"\x") {
        let mut out = Vec::new();
        let mut rest = s;
        while let Some(pos) = rest.find(r"\x") {
            if pos > 0 {
                out.extend_from_slice(rest[..pos].as_bytes());
            }
            rest = &rest[pos + 2..];
            if rest.len() >= 2 {
                if let Ok(v) = u8::from_str_radix(&rest[..2], 16) {
                    out.push(v);
                    rest = &rest[2..];
                    continue;
                }
            }
            break;
        }
        out.extend_from_slice(rest.as_bytes());
        if !out.is_empty() {
            return out;
        }
    }
    s.as_bytes().to_vec()
}

pub fn resolve_protocol(name: Option<&str>) -> Box<dyn ProtocolPlugin> {
    let n = name.map(|s| s.to_lowercase());
    match n.as_deref() {
        Some("grammar-ftp") | Some("g-ftp") => Box::new(GrammarProtocol::ftp_grammar()),
        Some("grammar-http") | Some("g-http") => Box::new(GrammarProtocol::http_grammar()),
        Some("grammar-smtp") | Some("g-smtp") => Box::new(GrammarProtocol::smtp_grammar()),
        Some("grammar-dns") | Some("g-dns") => Box::new(GrammarProtocol::dns_grammar()),
        Some("grammar-mqtt") | Some("g-mqtt") => Box::new(GrammarProtocol::mqtt_grammar()),
        Some("grammar-smb") | Some("g-smb") => Box::new(GrammarProtocol::smb_grammar()),
        Some("grammar-generic") | Some("g-generic") | Some("grammar") => {
            Box::new(GrammarProtocol::generic_grammar())
        }
        Some(path) if path.ends_with(".json") || path.contains('/') || path.contains('\\') => {
            match load_model_from_path(path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[nexsiz] warning: failed to load model '{}': {}", path, e);
                    Box::new(BuiltinProtocol::Generic)
                }
            }
        }
        Some(other) => {
            if let Some(b) = BuiltinProtocol::from_name(other) {
                Box::new(b)
            } else {
                Box::new(BuiltinProtocol::Generic)
            }
        }
        None => Box::new(BuiltinProtocol::Generic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_names() {
        assert_eq!(BuiltinProtocol::Ftp.name(), "ftp");
        assert_eq!(BuiltinProtocol::Dns.name(), "dns");
        let m = BuiltinProtocol::Http.build_model();
        assert_eq!(m.name, "http");
    }

    #[test]
    fn grammar_ftp_has_commands() {
        let p = GrammarProtocol::ftp_grammar();
        let m = p.build_model();
        assert!(m.dictionary.iter().any(|t| t == b"USER"));
        assert!(m.desocket.is_none());
    }

    #[test]
    fn resolve_new_models() {
        let p = resolve_protocol(Some("dns"));
        assert_eq!(p.name(), "dns");
        assert!(p.build_model().length_prefixed);
    }

    #[test]
    fn resolve_unknown_falls_back() {
        let p = resolve_protocol(Some("unknown-xyz"));
        assert_eq!(p.name(), "generic");
    }
}
