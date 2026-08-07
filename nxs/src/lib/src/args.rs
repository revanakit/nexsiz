//! Global CLI contract parser (nxs/CONTRACT.md §1).
//!
//! Pure std + zero external CLI crates. Every NXS must accept these flags.

use crate::exit::ExitCode;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct Args {
    pub crash: Option<PathBuf>,
    pub target: Option<String>,
    pub event: String,
    pub model: Option<String>,
    pub minimized: Option<PathBuf>,
    pub meta: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub timeout: Option<u64>,
    pub verbose: bool,
    pub help: bool,
    pub version: bool,
    /// Remaining tokens after global options (script-specific).
    pub rest: Vec<String>,
}

impl Args {
    /// Parse from `std::env::args()`. Exits with code 1 on malformed input.
    pub fn parse() -> Self {
        let raw: Vec<String> = env::args().skip(1).collect();
        Self::from_slice(&raw)
    }

    pub fn from_slice(raw: &[String]) -> Self {
        let mut a = Args {
            event: "crash".to_string(),
            ..Default::default()
        };

        let mut i = 0;
        while i < raw.len() {
            let arg = &raw[i];
            match arg.as_str() {
                "--help" | "-h" => {
                    a.help = true;
                    i += 1;
                }
                "--version" => {
                    a.version = true;
                    i += 1;
                }
                "--verbose" | "-v" => {
                    a.verbose = true;
                    i += 1;
                }
                "--crash" => {
                    i += 1;
                    a.crash = Some(require_value(raw, i, "--crash"));
                    i += 1;
                }
                "--target" => {
                    i += 1;
                    a.target = Some(require_str(raw, i, "--target"));
                    i += 1;
                }
                "--event" => {
                    i += 1;
                    a.event = require_str(raw, i, "--event");
                    i += 1;
                }
                "--model" => {
                    i += 1;
                    a.model = Some(require_str(raw, i, "--model"));
                    i += 1;
                }
                "--minimized" => {
                    i += 1;
                    a.minimized = Some(require_value(raw, i, "--minimized"));
                    i += 1;
                }
                "--meta" => {
                    i += 1;
                    a.meta = Some(require_value(raw, i, "--meta"));
                    i += 1;
                }
                "--out" => {
                    i += 1;
                    a.out = Some(require_value(raw, i, "--out"));
                    i += 1;
                }
                "--timeout" => {
                    i += 1;
                    let s = require_str(raw, i, "--timeout");
                    a.timeout = Some(s.parse().unwrap_or_else(|_| {
                        eprintln!("error: --timeout expects integer seconds");
                        ExitCode::Error.exit();
                    }));
                    i += 1;
                }
                other if other.starts_with('-') => {
                    // Unknown global flag → treat as script-specific (forward).
                    a.rest.push(other.to_string());
                    i += 1;
                }
                other => {
                    a.rest.push(other.to_string());
                    i += 1;
                }
            }
        }

        a
    }

    /// Contract §1: at least one of --crash or --meta must be present.
    /// When --meta is present it may supply crash.path + target.
    pub fn validate_required(&self) -> Result<(), String> {
        if self.crash.is_none() && self.meta.is_none() {
            return Err("at least one of --crash or --meta is required".into());
        }
        if self.target.is_none() && self.meta.is_none() {
            return Err("--target is required when --meta is absent".into());
        }
        Ok(())
    }

    pub fn log(&self, msg: &str) {
        if self.verbose {
            eprintln!("[nxs] {}", msg);
        }
    }
}

fn require_value(raw: &[String], idx: usize, flag: &str) -> PathBuf {
    if idx >= raw.len() {
        eprintln!("error: {} requires a path argument", flag);
        ExitCode::Error.exit();
    }
    PathBuf::from(&raw[idx])
}

fn require_str(raw: &[String], idx: usize, flag: &str) -> String {
    if idx >= raw.len() {
        eprintln!("error: {} requires a value", flag);
        ExitCode::Error.exit();
    }
    raw[idx].clone()
}
