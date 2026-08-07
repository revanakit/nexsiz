//! NXS resolver — categories.toml + search-path priority (CONTRACT.md §8).
//!
//! Priority:
//!   1. Absolute path in the expression
//!   2. NEXSIZ_NXS_PATH / cfg.nxs.path (colon-separated)
//!   3. ~/.nexsiz/nxs/bin/
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
    // Union across primary events so category filters do not hide members.
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
    // Also surface pure external / absolute ids even if event filter dropped them.
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
///   - category name: "default", "crash", "hang", "safe", "intrusive", "external"
///   - concrete id:   "crash/auto-repro"
///   - comma list:    "default,hang" or "crash/auto-repro,crash/save-notify"
fn expand_expression(expr: &str, event: &str) -> Result<Vec<String>, String> {
    let cats = load_categories();
    let mut ids = Vec::new();

    for part in expr.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if part.contains('/') {
            // concrete id — only include if it matches the event prefix or is unprefixed
            if part.starts_with(&(event.to_string() + "/")) || !part.contains('/') {
                ids.push(part.to_string());
            } else if event == "interesting"
                || event == "new_coverage"
                || event == "new_state"
                || part.starts_with("external/")
            {
                // interesting events and external hooks may still apply
                ids.push(part.to_string());
            }
        } else if let Some(list) = cats.get(part) {
            for id in list {
                // filter by event: keep ids whose category prefix matches the event,
                // or that belong to the requested set regardless (operator intent).
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
            // treat bare name as possible concrete id under the current event
            let candidate = format!("{}/{}", event, part);
            ids.push(candidate);
        }
    }
    Ok(ids)
}

fn build_search_path(cfg: &Config) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // 2. cfg / env
    if let Some(ref p) = cfg.nxs.path {
        for d in p.split(':').filter(|s| !s.is_empty()) {
            dirs.push(PathBuf::from(d));
        }
    }
    if let Ok(env_p) = env::var("NEXSIZ_NXS_PATH") {
        for d in env_p.split(':').filter(|s| !s.is_empty()) {
            dirs.push(PathBuf::from(d));
        }
    }

    // 3. ~/.nexsiz/nxs/bin/
    if let Some(home) = env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".nexsiz/nxs/bin"));
    }

    // 4. ./nxs/bin/
    dirs.push(PathBuf::from("nxs/bin"));
    dirs.push(PathBuf::from("./nxs/bin"));

    // 5. relative to executable
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.join("nxs/bin"));
            dirs.push(parent.join("../nxs/bin"));
            // source-tree layout when running from target/release
            dirs.push(parent.join("../../nxs/bin"));
            dirs.push(parent.join("../../../nxs/bin"));
        }
    }

    dirs
}

/// Locate an executable for the given id.
/// Tries: absolute path, `nxs-<name>`, `<name>`, `nxs-<category>-<name>`.
fn locate(id: &str, search: &[PathBuf]) -> Option<PathBuf> {
    // absolute?
    let p = Path::new(id);
    if p.is_absolute() && is_executable(p) {
        return Some(p.to_path_buf());
    }

    let name = id.rsplit('/').next().unwrap_or(id);
    let candidates = [
        format!("nxs-{}", name),
        name.to_string(),
        format!("nxs-{}", id.replace('/', "-")),
    ];

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
    }
    #[cfg(not(unix))]
    {
        return true; // best-effort on non-unix
    }
    false
}

/// Minimal categories.toml parser (no external crate).
/// Expects lines like:  key = ["a", "b"]
fn load_categories() -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();

    // built-in defaults matching nxs/categories.toml
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

    // overlay from file if present
    let candidates = [
        PathBuf::from("nxs/categories.toml"),
        PathBuf::from("./nxs/categories.toml"),
    ];
    let mut extra = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            extra.push(parent.join("../nxs/categories.toml"));
            extra.push(parent.join("../../nxs/categories.toml"));
            extra.push(parent.join("../../../nxs/categories.toml"));
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
