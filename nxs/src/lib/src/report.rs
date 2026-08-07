//! Artefact writer (nxs/CONTRACT.md §4).

use crate::exit::ExitCode;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub nxs_id: String,
    pub nxs_version: String,
    pub exit_hint: i32,
    pub summary: String,
    pub findings: Vec<String>,
    pub artifacts: Vec<String>,
    pub target: String,
    pub crash_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

impl Report {
    pub fn new(nxs_id: &str, version: &str) -> Self {
        Self {
            nxs_id: nxs_id.to_string(),
            nxs_version: version.to_string(),
            exit_hint: ExitCode::Ok.as_i32(),
            summary: String::new(),
            findings: Vec::new(),
            artifacts: Vec::new(),
            target: String::new(),
            crash_id: None,
            extra: None,
        }
    }

    pub fn with_summary(mut self, s: impl Into<String>) -> Self {
        self.summary = s.into();
        self
    }

    pub fn with_exit_hint(mut self, code: ExitCode) -> Self {
        self.exit_hint = code.as_i32();
        self
    }

    pub fn with_target(mut self, t: impl Into<String>) -> Self {
        self.target = t.into();
        self
    }

    pub fn with_crash_id(mut self, id: Option<String>) -> Self {
        self.crash_id = id;
        self
    }

    /// Accepts `&str`, `String`, and other `AsRef<str>` without call-site `.into()`.
    pub fn add_finding(&mut self, f: impl AsRef<str>) {
        self.findings.push(f.as_ref().to_string());
    }

    /// Accepts `&str`, `String`, and other `AsRef<str>` without call-site `.into()`.
    pub fn add_artifact(&mut self, a: impl AsRef<str>) {
        self.artifacts.push(a.as_ref().to_string());
    }

    /// Write report.json under `out/` (creates directory tree).
    pub fn write(&self, out_dir: &Path) -> Result<PathBuf, String> {
        fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {}: {}", out_dir.display(), e))?;

        let path = out_dir.join("report.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("report serialize: {}", e))?;
        fs::write(&path, json).map_err(|e| format!("write {}: {}", path.display(), e))?;
        Ok(path)
    }
}
