//! NEXSIZ – Protocol plugins (built-in + grammar-based)
//! Author  : Revana
//! Date    : 04/08/2026

use crate::input::model::ProtocolModel;

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
}

impl BuiltinProtocol {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "generic" => Some(Self::Generic),
            "ftp" => Some(Self::Ftp),
            "http" => Some(Self::Http),
            "smtp" => Some(Self::Smtp),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Ftp => "ftp",
            Self::Http => "http",
            Self::Smtp => "smtp",
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
}

impl GrammarProtocol {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            productions: Vec::new(),
            length_prefixed: false,
            delimiter: None,
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
        }
    }
}

pub fn resolve_protocol(name: Option<&str>) -> Box<dyn ProtocolPlugin> {
    let n = name.map(|s| s.to_lowercase());
    match n.as_deref() {
        Some("grammar-ftp") | Some("g-ftp") => Box::new(GrammarProtocol::ftp_grammar()),
        Some("grammar-http") | Some("g-http") => Box::new(GrammarProtocol::http_grammar()),
        Some("grammar-smtp") | Some("g-smtp") => Box::new(GrammarProtocol::smtp_grammar()),
        Some("grammar-generic") | Some("g-generic") | Some("grammar") => {
            Box::new(GrammarProtocol::generic_grammar())
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
        let m = BuiltinProtocol::Http.build_model();
        assert_eq!(m.name, "http");
    }

    #[test]
    fn grammar_ftp_has_commands() {
        let p = GrammarProtocol::ftp_grammar();
        assert_eq!(p.name(), "grammar-ftp");
        let m = p.build_model();
        assert!(m.dictionary.iter().any(|t| t == b"USER"));
        assert!(m.dictionary.iter().any(|t| t == b"\r\n"));
    }

    #[test]
    fn resolve_grammar() {
        let p = resolve_protocol(Some("grammar-http"));
        assert_eq!(p.name(), "grammar-http");
        let m = p.build_model();
        assert!(m.dictionary.iter().any(|t| t == b"GET"));
    }

    #[test]
    fn resolve_unknown_falls_back() {
        let p = resolve_protocol(Some("unknown-xyz"));
        assert_eq!(p.name(), "generic");
    }
}
