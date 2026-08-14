//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 09/08/2026
//! Module  : nexsiz::src::nxs::resolve
//!
//! NXS resolver — categories.toml + search-path priority (CONTRACT.md §8).
//!
//! Priority:
//!   1. Absolute path in the expression
//!   2. NEXSIZ_NXS_PATH / cfg.nxs.path
//!      - Unix:    colon-separated
//!      - Windows: semicolon-separated (colon would break `C:\...`)
//!   3. ~/.nexsiz/nxs/bin/  (HOME, or USERPROFILE on Windows)
//!   4. ./nxs/bin/ (cwd)
//!   5. <exe_dir>/../nxs/bin/ and <exe_dir>/nxs/bin/

use crate::common::config::Config;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Resolved NXS executable ready for spawn.
#[derive(Debug, Clone)]
pub struct NxsSpec {
    /// Stable id e.g. "crash/auto-repro"
    pub id: String,
    /// Absolute or relative path to the executable
    pub path: PathBuf,
}

/// Resolve the list of NXS to run for `event` given the configured set expression.
pub fn resolve_nxs_list(cfg: &Config, event: &str) -> Result<Vec<NxsSpec>, String> {
    let ids = expand_expression(&cfg.nxs.set, event)?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let search = build_search_path(cfg);
    let mut out = Vec::with_capacity(ids.len());

    for id in ids {
        if let Some(path) = locate(&id, &search) {
            out.push(NxsSpec { id, path });
        } else if cfg.verbose {
            eprintln!("[nexsiz/nxs] not found in search path: {}", id);
        }
    }
    Ok(out)
}

/// Operator-facing listing: expand the set for common events and report
/// found / missing paths. Used by `--nxs-list`.
pub fn list_resolved(cfg: &Config) -> Result<Vec<(String, Option<PathBuf>)>, String> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for event in &["crash", "hang", "interesting"] {
        let ids = expand_expression(&cfg.nxs.set, event)?;
        for id in ids {
            if seen.contains(&id) {
                continue;
            }
            seen.push(id.clone());
            let search = build_search_path(cfg);
            let path = locate(&id, &search);
            out.push((id, path));
        }
    }
    if cfg.nxs.set.contains('/') || cfg.nxs.set == "external" {
        let ids = expand_expression_unfiltered(&cfg.nxs.set)?;
        let search = build_search_path(cfg);
        for id in ids {
            if seen.contains(&id) {
                continue;
            }
            seen.push(id.clone());
            let path = locate(&id, &search);
            out.push((id, path));
        }
    }
    Ok(out)
}

fn expand_expression_unfiltered(expr: &str) -> Result<Vec<String>, String> {
    let cats = load_categories();
    let mut ids = Vec::new();
    for part in expr.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if part.contains('/') {
            ids.push(part.to_string());
        } else if let Some(list) = cats.get(part) {
            for id in list {
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
        } else {
            ids.push(part.to_string());
        }
    }
    Ok(ids)
}

/// Expand a set expression into concrete NXS ids.
///
/// Supported forms:
/// - category name: "default", "crash", "hang", "safe", "intrusive", "external"
/// - concrete id:   "crash/auto-repro"
/// - comma list:    "default,hang" or "crash/auto-repro,crash/save-notify"
fn expand_expression(expr: &str, event: &str) -> Result<Vec<String>, String> {
    let cats = load_categories();
    let mut ids = Vec::new();

    for part in expr.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if part.contains('/') {
            if part.starts_with(&(event.to_string() + "/")) || !part.contains('/') {
                ids.push(part.to_string());
            } else if event == "interesting"
                || event == "new_coverage"
                || event == "new_state"
                || part.starts_with("external/")
            {
                ids.push(part.to_string());
            }
        } else if let Some(list) = cats.get(part) {
            for id in list {
                if id.starts_with(&(event.to_string() + "/"))
                    || part == "default"
                    || part == "safe"
                    || part == "external"
                    || part == event
                    || id.starts_with("external/")
                {
                    if !ids.contains(id) {
                        ids.push(id.clone());
                    }
                }
            }
        } else {
            let candidate = format!("{}/{}", event, part);
            ids.push(candidate);
        }
    }
    Ok(ids)
}

/// Split a search-path string using the platform path separator.
///
/// - Unix: `:` (classic PATH style)
/// - Windows: `;` — using `:` would incorrectly split `C:\tools\nxs`
fn split_search_paths(p: &str) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        p.split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect()
    }
    #[cfg(not(windows))]
    {
        p.split(':')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect()
    }
}

fn build_search_path(cfg: &Config) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(ref p) = cfg.nxs.path {
        dirs.extend(split_search_paths(p));
    }
    if let Ok(env_p) = env::var("NEXSIZ_NXS_PATH") {
        dirs.extend(split_search_paths(&env_p));
    }

    let home = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE"));
    if let Some(home) = home {
        dirs.push(PathBuf::from(home).join(".nexsiz").join("nxs").join("bin"));
    }

    dirs.push(PathBuf::from("nxs").join("bin"));
    dirs.push(PathBuf::from(".").join("nxs").join("bin"));

    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.join("nxs").join("bin"));
            dirs.push(parent.join("..").join("nxs").join("bin"));
            dirs.push(parent.join("..").join("..").join("nxs").join("bin"));
            dirs.push(
                parent
                    .join("..")
                    .join("..")
                    .join("..")
                    .join("nxs")
                    .join("bin"),
            );
        }
    }

    dirs
}

/// Locate an executable for the given id.
/// Tries: absolute path, `nxs-<name>`, `<name>`, `nxs-<category>-<name>`,
/// and on Windows the same names with `.exe` / `.cmd` / `.bat`.
fn locate(id: &str, search: &[PathBuf]) -> Option<PathBuf> {
    let p = Path::new(id);
    if p.is_absolute() && is_executable(p) {
        return Some(p.to_path_buf());
    }

    let name = id.rsplit('/').next().unwrap_or(id);
    let mut candidates = vec![
        format!("nxs-{}", name),
        name.to_string(),
        format!("nxs-{}", id.replace('/', "-")),
    ];

    #[cfg(windows)]
    {
        let extra: Vec<String> = candidates
            .iter()
            .flat_map(|c| {
                [
                    format!("{}.exe", c),
                    format!("{}.cmd", c),
                    format!("{}.bat", c),
                ]
            })
            .collect();
        candidates.extend(extra);
    }

    for dir in search {
        for c in &candidates {
            let candidate = dir.join(c);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = path.metadata() {
            return meta.permissions().mode() & 0o111 != 0;
        }
        return false;
    }
    #[cfg(windows)]
    {
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => {
                let ext = ext.to_ascii_lowercase();
                matches!(ext.as_str(), "exe" | "cmd" | "bat" | "com")
            }
            None => true,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        true
    }
}

fn load_categories() -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();

    map.insert(
        "default".into(),
        vec!["crash/auto-repro".into(), "crash/save-notify".into()],
    );
    map.insert(
        "crash".into(),
        vec![
            "crash/auto-repro".into(),
            "crash/differential-probe".into(),
            "crash/save-notify".into(),
        ],
    );
    map.insert("hang".into(), vec!["hang/timeout-analyzer".into()]);
    map.insert(
        "safe".into(),
        vec!["crash/auto-repro".into(), "crash/save-notify".into()],
    );
    map.insert(
        "intrusive".into(),
        vec!["crash/differential-probe".into()],
    );
    map.insert(
        "external".into(),
        vec!["external/notify-webhook".into()],
    );

    let candidates = [
        PathBuf::from("nxs").join("categories.toml"),
        PathBuf::from(".").join("nxs").join("categories.toml"),
    ];
    let mut extra = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            extra.push(parent.join("..").join("nxs").join("categories.toml"));
            extra.push(
                parent
                    .join("..")
                    .join("..")
                    .join("nxs")
                    .join("categories.toml"),
            );
            extra.push(
                parent
                    .join("..")
                    .join("..")
                    .join("..")
                    .join("nxs")
                    .join("categories.toml"),
            );
        }
    }
    for c in candidates.iter().chain(extra.iter()) {
        if let Ok(text) = fs::read_to_string(c) {
            parse_categories_toml(&text, &mut map);
            break;
        }
    }
    map
}

fn parse_categories_toml(text: &str, map: &mut HashMap<String, Vec<String>>) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let val = parts.next().unwrap_or("").trim();
        if key.is_empty() || !val.starts_with('[') {
            continue;
        }
        let inner = val.trim_start_matches('[').trim_end_matches(']');
        let list: Vec<String> = inner
            .split(',')
            .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            map.insert(key.to_string(), list);
        }
    }
}
