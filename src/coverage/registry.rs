//! NEXSIZ – Coverage provider registry
//! Author  : Revana
//! Date    : 05/08/2026

use crate::coverage::map::SharedMapCoverage;
use crate::coverage::null::NullCoverage;
use crate::coverage::provider::CoverageProvider;
use crate::coverage::software::SoftwareCoverage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageKind {
    Null,
    Map,
    Software,
}

impl CoverageKind {
    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "map" | "shm" | "shared" | "afl" | "map+shm" => CoverageKind::Map,
            "software" | "soft" | "response" | "hybrid" => CoverageKind::Software,
            _ => CoverageKind::Null,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CoverageKind::Null => "null",
            CoverageKind::Map => "map",
            CoverageKind::Software => "software",
        }
    }
}

/// Resolve a coverage provider by name (no explicit SHM id).
pub fn resolve_coverage(name: Option<&str>) -> Box<dyn CoverageProvider> {
    resolve_coverage_with_shm(name, None)
}

/// Resolve coverage provider with optional POSIX SHM identifier.
///
/// - `null`     → pure black-box
/// - `map`/`shm`/`afl` → AFL-style map; attaches to `/nexsiz-cov` or `/nexsiz-cov-<id>`
/// - `software` → response-edge hybrid
///
/// SHM id sources (in order): explicit `shm_id` argument, env `NEXSIZ_SHM_ID`.
pub fn resolve_coverage_with_shm(
    name: Option<&str>,
    shm_id: Option<&str>,
) -> Box<dyn CoverageProvider> {
    let env_id = std::env::var("NEXSIZ_SHM_ID").ok();
    let effective_id = shm_id
        .map(|s| s.to_string())
        .or(env_id);

    match name.map(|s| s.to_lowercase()).as_deref() {
        Some("map") | Some("shm") | Some("shared") | Some("afl") | Some("map+shm") => {
            Box::new(SharedMapCoverage::with_shm_id(effective_id.as_deref()))
        }
        Some("software") | Some("soft") | Some("response") | Some("hybrid") => {
            Box::new(SoftwareCoverage::new())
        }
        _ => Box::new(NullCoverage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_defaults_to_null() {
        assert_eq!(resolve_coverage(None).name(), "null");
        assert_eq!(resolve_coverage(Some("unknown")).name(), "null");
    }

    #[test]
    fn resolve_map() {
        let n = resolve_coverage(Some("map")).name();
        assert!(n == "map" || n == "map+shm");
    }

    #[test]
    fn resolve_software() {
        assert_eq!(resolve_coverage(Some("software")).name(), "software");
    }
}
