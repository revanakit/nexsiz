//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::coverage::mod
//!
//! NEXSIZ – Grey-box Coverage / Instrumentation layer
//!
//! Trait-based coverage provider system that turns Nexsiz from pure
//! black-box into a true hybrid grey-box fuzzer.
//!
//! Design goals:
//!   - Zero behaviour change when provider = Null (default)
//!   - High-performance edge map (AFL-style 64 KiB) for local/SHM targets
//!   - Platform shared-memory (POSIX SHM on Linux, File Mapping on Windows)
//!     so Frida / external agents can write the same layout
//!   - Software response-edge provider as practical hybrid for remote targets
//!   - Minimal deps (only existing libc on Linux)

pub mod provider;
pub mod null;
pub mod shm;
pub mod map;
pub mod software;
pub mod registry;

pub use provider::{CoverageFeedback, CoverageProvider, MAP_SIZE};
pub use null::NullCoverage;
pub use map::SharedMapCoverage;
pub use software::SoftwareCoverage;
pub use registry::{resolve_coverage, resolve_coverage_with_shm, CoverageKind};
