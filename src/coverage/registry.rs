//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::coverage::registry
//!
//! Coverage Provider Registry
//! --------------------------
//! Centralised resolver and light-weight registry for coverage backends. This
//! module exposes a small, deterministic API to select and instantiate a
//! CoverageProvider implementation by name, with optional POSIX shared-memory
//! identifier support for map-style providers.
//!
//! Responsibilities:
//! - Map user-facing identifiers (CLI flags, config values, or environment
//!   variables) to concrete CoverageProvider implementations (Null, Map,
//!   Software).
//! - Provide a consistent precedence for SHM identifiers: explicit argument
//!   > environment variable NEXSIZ_SHM_ID > none.
//! - Keep the resolver headless and side-effect free (construction only).
//!
//! Recognised provider names:
//! - map, shm, shared, afl, map+shm  → SharedMapCoverage (AFL-style bitmap)
//! - software, soft, response, hybrid → SoftwareCoverage (response/edge hybrid)
//! - anything else / None            → NullCoverage (pure black-box, no feedback)
//!
//! Behavioural notes:
//! - resolve_coverage(name) is a convenience wrapper that forwards to
//!   resolve_coverage_with_shm(name, None).
//! - resolve_coverage_with_shm(name, shm_id) will prefer the explicit shm_id
//!   argument; if None, it falls back to the NEXSIZ_SHM_ID environment value.
//! - The resolver returns a boxed dyn CoverageProvider ready for use by the
//!   fuzzing engine; callers should not assume concrete types beyond the
//!   CoverageProvider trait contract.
//!
//! Testing and expectations:
//! - Unit tests validate defaulting semantics (unknown => "null") and that
//!   recognised identifiers instantiate the expected provider names.
//!
//! Implementation guidance:
//! - Keep mappings and name parsing case-insensitive and forgiving of common
//!   aliases to improve CLI ergonomics.
//! - Avoid performing runtime SHM creation/opening in the resolver; let the
//!   provider implementation manage resource acquisition and failure handling.

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
