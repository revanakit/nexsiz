//! Forward-compatible metadata JSON loader (nxs/CONTRACT.md §3).
//!
//! Unknown fields are silently ignored. Missing optional fields are `None`.

use crate::exit::ExitCode;
use serde::Deserialize;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Meta {
    pub nexsiz_version: Option<String>,
    pub event: Option<String>,
    pub timestamp: Option<f64>,
    pub target: Option<Target>,
    pub model: Option<String>,
    pub crash: Option<CrashInfo>,
    pub result: Option<ResultInfo>,
    pub worker_id: Option<u32>,
    pub corpus_id: Option<u64>,
    pub output_dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Target {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CrashInfo {
    pub id: Option<String>,
    pub path: Option<String>,
    pub minimized_path: Option<String>,
    pub input_len: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResultInfo {
    pub outcome: Option<String>,
    pub error: Option<String>,
    pub elapsed_ms: Option<u64>,
    pub coverage_hits: Option<u64>,
    pub new_state: Option<bool>,
    pub response_codes: Option<Vec<u16>>,
}

impl Meta {
    /// Load from file path, or from stdin when path is "-".
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = if path.as_os_str() == "-" {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("stdin read: {}", e))?;
            buf
        } else {
            fs::read_to_string(path).map_err(|e| format!("meta open {}: {}", path.display(), e))?
        };

        serde_json::from_str(&text).map_err(|e| format!("meta parse: {}", e))
    }

    /// Resolve effective crash path: prefer CLI --crash, then meta.crash.path.
    pub fn effective_crash_path(&self, cli: &Option<PathBuf>) -> Option<PathBuf> {
        cli.clone().or_else(|| {
            self.crash
                .as_ref()
                .and_then(|c| c.path.as_ref())
                .map(PathBuf::from)
        })
    }

    /// Prefer minimised input when available.
    pub fn effective_input_path(
        &self,
        cli_crash: &Option<PathBuf>,
        cli_minimized: &Option<PathBuf>,
    ) -> Option<PathBuf> {
        cli_minimized
            .clone()
            .or_else(|| {
                self.crash
                    .as_ref()
                    .and_then(|c| c.minimized_path.as_ref())
                    .map(PathBuf::from)
            })
            .or_else(|| self.effective_crash_path(cli_crash))
    }

    /// Resolve target string "host:port".
    pub fn effective_target(&self, cli: &Option<String>) -> Option<String> {
        if let Some(t) = cli {
            return Some(t.clone());
        }
        let t = self.target.as_ref()?;
        let host = t.host.as_ref()?;
        let port = t.port?;
        Some(format!("{}:{}", host, port))
    }

    pub fn effective_model(&self, cli: &Option<String>) -> Option<String> {
        cli.clone().or_else(|| self.model.clone())
    }

    pub fn effective_event(&self, cli_event: &str) -> String {
        if cli_event != "crash" {
            return cli_event.to_string();
        }
        self.event.clone().unwrap_or_else(|| "crash".into())
    }

    pub fn crash_id(&self) -> Option<&str> {
        self.crash.as_ref().and_then(|c| c.id.as_deref())
    }
}

/// Convenience: load meta if present, otherwise empty.
pub fn load_optional(path: &Option<PathBuf>) -> Result<Meta, String> {
    match path {
        Some(p) => Meta::load(p),
        None => Ok(Meta::default()),
    }
}

/// Hard fail helper used by binaries.
pub fn load_or_exit(path: &Option<PathBuf>) -> Meta {
    match load_optional(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::Error.exit();
        }
    }
}
