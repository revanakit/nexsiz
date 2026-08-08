//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 08/08/2026
//! Files   : nexsiz/src/plugin/oracle.rs
//!
//! NEXSIZ – Expanded Differential & Sanitizer Oracle plugins (production-ready)
//! 
//! Production-grade interestingness oracles for red-team / APT fuzzing campaigns.
//!
//! ## Differential family
//! Multi-dimensional response fingerprinting against per-bucket baselines.
//! Detects behavioural divergence without requiring a second live target.
//!
//! ## Sanitizer family
//! Pattern-based detection of memory-safety and protocol anomalies that surface
//! in responses, error strings, or process-monitor output (ASan / UBSan / MSan
//! signatures, length anomalies, null-byte injection, protocol violations).
//!
//! All implementations are pure Rust, thread-safe, zero extra dependencies.

use crate::common::types::{ExecutionResult, OutcomeClass};
use crate::common::utils::{hash_bytes, hash_combine};
use crate::monitor::oracle::{
    CompositeOracle, CoverageOracle, CrashOracle, ErrorOracle, HangOracle, Oracle,
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

// Re-export the trait for plugin consumers.
pub trait OraclePlugin: Oracle {}
impl<T: Oracle + ?Sized> OraclePlugin for T {}

// ═══════════════════════════════════════════════════════════════════════════════
// Default / Strict (kept for compatibility)
// ═══════════════════════════════════════════════════════════════════════════════

pub struct DefaultOracleSet {
    inner: CompositeOracle,
}

impl DefaultOracleSet {
    pub fn new() -> Self {
        Self {
            inner: CompositeOracle::default_set(),
        }
    }
}

impl Default for DefaultOracleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for DefaultOracleSet {
    fn name(&self) -> &str {
        "default"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        if matches!(
            result.outcome,
            OutcomeClass::Crash | OutcomeClass::ConnectionReset | OutcomeClass::Hang
        ) {
            return true;
        }
        if result.coverage_hits > 0 || result.new_coverage || result.new_state {
            return true;
        }
        self.inner.is_interesting(result)
    }
}

pub struct StrictOracle;

impl Oracle for StrictOracle {
    fn name(&self) -> &str {
        "strict"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        result.crash
            || result.hang
            || matches!(
                result.outcome,
                OutcomeClass::Crash | OutcomeClass::ConnectionReset | OutcomeClass::Hang
            )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Expanded Differential Oracle (production)
// ═══════════════════════════════════════════════════════════════════════════════

/// Multi-dimensional baseline stored per fingerprint key.
#[derive(Clone, Debug)]
struct DiffBaseline {
    codes: Vec<i32>,
    body_hash: u64,
    total_len: usize,
    /// Median-ish elapsed (ms) observed so far (running average).
    elapsed_ms: u64,
    coverage_map_hash: u64,
    hits: u64,
    /// First observation timestamp (for optional aging – reserved).
    _first_seen_ms: u64,
}

/// Production differential oracle.
///
/// A result is interesting when:
/// 1. It is a crash / hang / connection-reset, or
/// 2. Its multi-dimensional fingerprint diverges from the established baseline
///    for the same coarse key by at least `min_divergence` dimensions, or
/// 3. Timing anomaly exceeds `timing_factor` × baseline elapsed (optional).
///
/// Keying is coarse (response-code sequence shape + first code) so that
/// semantically similar requests share a baseline while still catching
/// behavioural changes. Baseline is established on first observation and
/// optionally refreshed after many consistent hits.
pub struct DifferentialOracle {
    baselines: Mutex<HashMap<u64, DiffBaseline>>,
    /// Minimum number of differing dimensions required to flag (1..=5).
    min_divergence: u32,
    /// Flag if elapsed > baseline.elapsed_ms * timing_factor (0 = disabled).
    timing_factor: f64,
    /// After this many consistent hits, slowly absorb the current observation
    /// into the baseline (reduces false positives on drifting services).
    refresh_after_hits: u64,
    /// Maximum baselines retained (LRU-ish eviction by hits).
    max_baselines: usize,
}

impl DifferentialOracle {
    pub fn new() -> Self {
        Self {
            baselines: Mutex::new(HashMap::new()),
            min_divergence: 1,
            timing_factor: 0.0, // disabled by default
            refresh_after_hits: 64,
            max_baselines: 4096,
        }
    }

    pub fn with_min_divergence(mut self, d: u32) -> Self {
        self.min_divergence = d.max(1);
        self
    }

    pub fn with_timing_factor(mut self, f: f64) -> Self {
        self.timing_factor = f;
        self
    }

    pub fn with_refresh_after(mut self, n: u64) -> Self {
        self.refresh_after_hits = n;
        self
    }

    /// Coarse key: mixes response-code count, first/last code, and a hash of
    /// the full code sequence so that different protocol paths land in
    /// different buckets.
    fn fingerprint_key(result: &ExecutionResult) -> u64 {
        let mut k = result.response_codes.len() as u64;
        if let Some(&c) = result.response_codes.first() {
            k = k.wrapping_mul(31).wrapping_add(c as u64);
        }
        if let Some(&c) = result.response_codes.last() {
            k = k.wrapping_mul(37).wrapping_add(c as u64);
        }
        // Fold full sequence for better separation
        for &c in &result.response_codes {
            k = hash_combine(k, c as u64);
        }
        k
    }

    fn body_hash(result: &ExecutionResult) -> u64 {
        let mut h = 0u64;
        for r in &result.responses {
            // First 128 bytes are enough for fingerprinting; avoids hashing
            // multi-megabyte responses on every exec.
            let slice = if r.len() > 128 { &r[..128] } else { r };
            h = hash_combine(h, hash_bytes(slice));
            h = h.rotate_left(11);
        }
        h
    }

    fn total_len(result: &ExecutionResult) -> usize {
        result.responses.iter().map(|r| r.len()).sum()
    }

    /// Count differing dimensions (0..=5).
    fn divergence(base: &DiffBaseline, result: &ExecutionResult) -> u32 {
        let mut d = 0u32;

        // 1. Code sequence length
        if base.codes.len() != result.response_codes.len() {
            d += 1;
        }
        // 2. Code values (zip; extra/missing already counted above)
        for (a, b) in base.codes.iter().zip(result.response_codes.iter()) {
            if a != b {
                d += 1;
                break; // one point for any code mismatch
            }
        }
        // 3. Body content fingerprint
        if base.body_hash != Self::body_hash(result) {
            d += 1;
        }
        // 4. Total response length class (order-of-magnitude change)
        let cur_len = Self::total_len(result);
        if base.total_len == 0 {
            if cur_len > 0 {
                d += 1;
            }
        } else {
            let ratio = cur_len as f64 / base.total_len as f64;
            if !(0.5..=2.0).contains(&ratio) {
                d += 1;
            }
        }
        // 5. Coverage map hash (grey-box signal)
        if base.coverage_map_hash != 0
            && result.coverage_map_hash != 0
            && base.coverage_map_hash != result.coverage_map_hash
        {
            d += 1;
        }

        d
    }

    fn timing_anomaly(base: &DiffBaseline, result: &ExecutionResult, factor: f64) -> bool {
        if factor <= 0.0 || base.elapsed_ms == 0 {
            return false;
        }
        let cur = result.elapsed.as_millis() as u64;
        cur > (base.elapsed_ms as f64 * factor) as u64
    }
}

impl Default for DifferentialOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for DifferentialOracle {
    fn name(&self) -> &str {
        "differential"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        // Always surface hard faults
        if result.crash
            || result.hang
            || matches!(
                result.outcome,
                OutcomeClass::Crash | OutcomeClass::ConnectionReset | OutcomeClass::Hang
            )
        {
            return true;
        }

        // Nothing to compare
        if result.responses.is_empty() && result.response_codes.is_empty() {
            return false;
        }

        let key = Self::fingerprint_key(result);
        let mut map = match self.baselines.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Evict if over capacity (drop lowest-hit entries)
        if map.len() >= self.max_baselines && !map.contains_key(&key) {
            if let Some((&k, _)) = map.iter().min_by_key(|(_, b)| b.hits) {
                map.remove(&k);
            }
        }

        match map.get_mut(&key) {
            None => {
                map.insert(
                    key,
                    DiffBaseline {
                        codes: result.response_codes.clone(),
                        body_hash: Self::body_hash(result),
                        total_len: Self::total_len(result),
                        elapsed_ms: result.elapsed.as_millis() as u64,
                        coverage_map_hash: result.coverage_map_hash,
                        hits: 1,
                        _first_seen_ms: 0,
                    },
                );
                false // establishing baseline is not differential
            }
            Some(base) => {
                base.hits = base.hits.saturating_add(1);
                let d = Self::divergence(base, result);
                let timing = Self::timing_anomaly(base, result, self.timing_factor);

                if d >= self.min_divergence || timing {
                    true
                } else {
                    // Slow baseline refresh for stable observations
                    if base.hits % self.refresh_after_hits == 0 {
                        // Running average of elapsed
                        let cur_ms = result.elapsed.as_millis() as u64;
                        base.elapsed_ms = (base.elapsed_ms.saturating_add(cur_ms)) / 2;
                        // Absorb length if within reasonable band
                        let cur_len = Self::total_len(result);
                        if cur_len > 0 {
                            base.total_len = (base.total_len + cur_len) / 2;
                        }
                    }
                    false
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Sanitizer Oracles (production)
// ═══════════════════════════════════════════════════════════════════════════════

/// Known sanitizer / crash / memory-error signatures that appear in process
/// output, stderr captured by process-monitor, or error strings.
const SANITIZER_PATTERNS: &[&str] = &[
    // AddressSanitizer / LeakSanitizer / MemorySanitizer / UBSan
    "AddressSanitizer",
    "ERROR: AddressSanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "heap-use-after-free",
    "stack-use-after-return",
    "stack-use-after-scope",
    "use-after-poison",
    "double-free",
    "attempting double-free",
    "SEGV on unknown address",
    "SEGV",
    "ASAN:",
    "LeakSanitizer",
    "MemorySanitizer",
    "use-of-uninitialized-value",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "null pointer",
    "division by zero",
    "index out of bounds",
    "shift exponent",
    // Classic crash markers
    "Segmentation fault",
    "segmentation fault",
    "Bus error",
    "Aborted",
    "Aborted (core dumped)",
    "Floating point exception",
    "stack smashing detected",
    "*** stack smashing detected ***",
    "double free or corruption",
    "free(): invalid pointer",
    "malloc(): corrupted",
    "corrupted double-linked list",
    "munmap_chunk(): invalid pointer",
    // Common library / language runtime
    "panic: runtime error",
    "fatal error:",
    "runtime: out of memory",
    "java.lang.OutOfMemoryError",
    "Access violation",
    "STATUS_ACCESS_VIOLATION",
    "STATUS_STACK_BUFFER_OVERRUN",
    // Protocol / application level that often indicate serious bugs
    "Assertion failed",
    "assert(",
    "__assert_fail",
    "Backtrace:",
    "#0 0x",
];

/// Detects sanitizer and classic crash signatures in error strings and
/// response bodies (useful when the target echoes diagnostics or when a
/// process-monitor captures stderr into the result.error field).
pub struct SanitizerPatternOracle {
    /// Extra operator-supplied patterns (lower-cased at construction).
    extra: Vec<String>,
}

impl SanitizerPatternOracle {
    pub fn new() -> Self {
        Self { extra: Vec::new() }
    }

    pub fn with_extra(mut self, patterns: &[&str]) -> Self {
        self.extra = patterns.iter().map(|s| s.to_ascii_lowercase()).collect();
        self
    }

    fn matches_any(haystack: &str) -> bool {
        let lower = haystack.to_ascii_lowercase();
        for p in SANITIZER_PATTERNS {
            if lower.contains(&p.to_ascii_lowercase()) {
                return true;
            }
        }
        false
    }
}

impl Default for SanitizerPatternOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for SanitizerPatternOracle {
    fn name(&self) -> &str {
        "sanitizer-pattern"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        if let Some(ref err) = result.error {
            if Self::matches_any(err) {
                return true;
            }
            for p in &self.extra {
                if err.to_ascii_lowercase().contains(p) {
                    return true;
                }
            }
        }
        // Also scan response bodies (some servers echo diagnostics)
        for resp in &result.responses {
            if let Ok(s) = std::str::from_utf8(resp) {
                if Self::matches_any(s) {
                    return true;
                }
                for p in &self.extra {
                    if s.to_ascii_lowercase().contains(p) {
                        return true;
                    }
                }
            } else {
                // Binary response: look for ASCII substrings of patterns
                let lower_bytes: Vec<u8> = resp.iter().map(|b| b.to_ascii_lowercase()).collect();
                for p in SANITIZER_PATTERNS {
                    let needle = p.to_ascii_lowercase();
                    if contains_slice(&lower_bytes, needle.as_bytes()) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

fn contains_slice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Flags anomalous response lengths relative to a running median of recent
/// successful responses. Useful for detecting buffer over-reads that return
/// unexpectedly large payloads or truncated responses that indicate crashes.
pub struct LengthAnomalyOracle {
    recent_lens: Mutex<Vec<usize>>,
    window: usize,
    /// Flag if length > median * high_factor or < median / low_factor
    high_factor: f64,
    low_factor: f64,
    /// Absolute minimum length that is always considered anomalous when > 0
    absolute_high: usize,
}

impl LengthAnomalyOracle {
    pub fn new() -> Self {
        Self {
            recent_lens: Mutex::new(Vec::with_capacity(128)),
            window: 64,
            high_factor: 8.0,
            low_factor: 8.0,
            absolute_high: 16 * 1024 * 1024, // 16 MiB hard ceiling
        }
    }

    pub fn with_window(mut self, w: usize) -> Self {
        self.window = w.max(8);
        self
    }

    pub fn with_factors(mut self, high: f64, low: f64) -> Self {
        self.high_factor = high.max(1.5);
        self.low_factor = low.max(1.5);
        self
    }
}

impl Default for LengthAnomalyOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for LengthAnomalyOracle {
    fn name(&self) -> &str {
        "length-anomaly"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        let total: usize = result.responses.iter().map(|r| r.len()).sum();

        if total >= self.absolute_high {
            return true;
        }

        // Only learn from non-fault results
        if result.crash || result.hang {
            return false;
        }

        let mut lens = match self.recent_lens.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        if lens.len() < 8 {
            // Still warming up – just record
            if total > 0 {
                lens.push(total);
            }
            return false;
        }

        // Approximate median
        let mut sorted = lens.clone();
        sorted.sort_unstable();
        let median = sorted[sorted.len() / 2];

        let anomalous = if median == 0 {
            total > 4096 // any large body when baseline was empty
        } else {
            let high = (median as f64 * self.high_factor) as usize;
            let low = (median as f64 / self.low_factor).max(1.0) as usize;
            total > high || (total > 0 && total < low)
        };

        // Update sliding window
        if total > 0 {
            lens.push(total);
            if lens.len() > self.window {
                lens.remove(0);
            }
        }

        anomalous
    }
}

/// Detects embedded null bytes in responses that claim to be textual
/// (common indicator of buffer over-read into uninitialised memory or
/// string-termination bugs).
pub struct NullByteOracle {
    /// Only inspect responses that look mostly ASCII.
    ascii_threshold: f64,
}

impl NullByteOracle {
    pub fn new() -> Self {
        Self {
            ascii_threshold: 0.85,
        }
    }
}

impl Default for NullByteOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for NullByteOracle {
    fn name(&self) -> &str {
        "null-byte"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        for resp in &result.responses {
            if resp.is_empty() {
                continue;
            }
            let ascii_count = resp.iter().filter(|b| b.is_ascii()).count();
            let ratio = ascii_count as f64 / resp.len() as f64;
            if ratio >= self.ascii_threshold {
                // Textual response should not contain interior NUL
                if resp.iter().any(|&b| b == 0) {
                    return true;
                }
            }
        }
        false
    }
}

/// Protocol-level violation heuristics (HTTP status class jumps, unexpected
/// empty replies after successful writes, etc.).
pub struct ProtocolViolationOracle;

impl Oracle for ProtocolViolationOracle {
    fn name(&self) -> &str {
        "protocol-violation"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        // Sudden 5xx after a sequence that previously looked healthy is
        // already caught by differential; here we catch structural oddities.

        // Empty response when we expected codes
        if !result.response_codes.is_empty() && result.responses.iter().all(|r| r.is_empty()) {
            // Some protocols (FTP) legitimately have empty bodies; only flag
            // when codes indicate success but body is required (heuristic).
            if result.response_codes.iter().any(|&c| c >= 200 && c < 300) {
                // borderline – leave to differential; do not flag alone
            }
        }

        // HTTP-style: 1xx informational followed immediately by connection close
        if result.response_codes.len() == 1 {
            let c = result.response_codes[0];
            if (100..200).contains(&c)
                && matches!(result.outcome, OutcomeClass::ConnectionReset)
            {
                return true;
            }
        }

        // Multiple conflicting success/error codes in one exchange
        let has_2xx = result.response_codes.iter().any(|&c| (200..300).contains(&c));
        let has_5xx = result.response_codes.iter().any(|&c| (500..600).contains(&c));
        if has_2xx && has_5xx {
            return true;
        }

        false
    }
}

/// Composite sanitizer suite – production entry point for `-O sanitizer`.
pub struct SanitizerOracle {
    pattern: SanitizerPatternOracle,
    length: LengthAnomalyOracle,
    nullbyte: NullByteOracle,
    proto: ProtocolViolationOracle,
    crash: CrashOracle,
    hang: HangOracle,
}

impl SanitizerOracle {
    pub fn new() -> Self {
        Self {
            pattern: SanitizerPatternOracle::new(),
            length: LengthAnomalyOracle::new(),
            nullbyte: NullByteOracle::new(),
            proto: ProtocolViolationOracle,
            crash: CrashOracle,
            hang: HangOracle,
        }
    }
}

impl Default for SanitizerOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for SanitizerOracle {
    fn name(&self) -> &str {
        "sanitizer"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        self.crash.is_interesting(result)
            || self.hang.is_interesting(result)
            || self.pattern.is_interesting(result)
            || self.length.is_interesting(result)
            || self.nullbyte.is_interesting(result)
            || self.proto.is_interesting(result)
    }
}

/// Combined differential + sanitizer – recommended for deep campaigns.
pub struct DiffSanOracle {
    differential: DifferentialOracle,
    sanitizer: SanitizerOracle,
    coverage: CoverageOracle,
}

impl DiffSanOracle {
    pub fn new() -> Self {
        Self {
            differential: DifferentialOracle::new(),
            sanitizer: SanitizerOracle::new(),
            coverage: CoverageOracle,
        }
    }
}

impl Default for DiffSanOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for DiffSanOracle {
    fn name(&self) -> &str {
        "diffsan"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        self.sanitizer.is_interesting(result)
            || self.differential.is_interesting(result)
            || self.coverage.is_interesting(result)
    }
}

/// Expanded default that includes differential + sanitizer + classic signals.
/// Selected by `-O expanded` or as a drop-in upgrade path.
pub struct ExpandedOracle {
    inner: DiffSanOracle,
    error: ErrorOracle,
}

impl ExpandedOracle {
    pub fn new() -> Self {
        Self {
            inner: DiffSanOracle::new(),
            error: ErrorOracle,
        }
    }
}

impl Default for ExpandedOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for ExpandedOracle {
    fn name(&self) -> &str {
        "expanded"
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        self.inner.is_interesting(result) || self.error.is_interesting(result)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Resolver
// ═══════════════════════════════════════════════════════════════════════════════

/// Resolve oracle by name.
///
/// Supported names (case-insensitive):
///   default | strict | crash | hang | coverage | error
///   differential | diff
///   sanitizer | san
///   diffsan | differential+sanitizer
///   expanded
pub fn resolve_oracle(name: Option<&str>) -> Box<dyn Oracle> {
    match name.map(|s| s.to_lowercase()).as_deref() {
        Some("strict") => Box::new(StrictOracle),
        Some("crash") => Box::new(CrashOracle),
        Some("hang") => Box::new(HangOracle),
        Some("coverage") => Box::new(CoverageOracle),
        Some("error") => Box::new(ErrorOracle),
        Some("differential") | Some("diff") => Box::new(DifferentialOracle::new()),
        Some("sanitizer") | Some("san") => Box::new(SanitizerOracle::new()),
        Some("diffsan") | Some("differential+sanitizer") | Some("diff+san") => {
            Box::new(DiffSanOracle::new())
        }
        Some("expanded") => Box::new(ExpandedOracle::new()),
        // keep classic default for backward compatibility
        _ => Box::new(DefaultOracleSet::new()),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn result_ok(codes: Vec<i32>, body: &[u8]) -> ExecutionResult {
        ExecutionResult {
            seed_id: 1,
            success: true,
            responses: vec![body.to_vec()],
            response_codes: codes,
            elapsed: Duration::from_millis(5),
            new_coverage: false,
            new_state: false,
            crash: false,
            hang: false,
            error: None,
            state_hash: 0,
            outcome: OutcomeClass::Ok,
            coverage_hits: 0,
            coverage_map_hash: 0,
        }
    }

    fn result_with_error(err: &str) -> ExecutionResult {
        let mut r = result_ok(vec![], b"");
        r.error = Some(err.to_string());
        r.outcome = OutcomeClass::Error;
        r
    }

    #[test]
    fn differential_establishes_baseline_then_flags() {
        let o = DifferentialOracle::new();
        let r1 = result_ok(vec![200], b"OK");
        assert!(!o.is_interesting(&r1));
        let r2 = result_ok(vec![500], b"ERR");
        assert!(o.is_interesting(&r2));
    }

    #[test]
    fn differential_same_not_interesting() {
        let o = DifferentialOracle::new();
        let r1 = result_ok(vec![220], b"welcome");
        assert!(!o.is_interesting(&r1));
        let r2 = result_ok(vec![220], b"welcome");
        assert!(!o.is_interesting(&r2));
    }

    #[test]
    fn differential_length_class_change() {
        let o = DifferentialOracle::new().with_min_divergence(1);
        let r1 = result_ok(vec![200], b"short");
        assert!(!o.is_interesting(&r1));
        // 20× larger body → length dimension fires
        let big = vec![b'A'; 200];
        let r2 = result_ok(vec![200], &big);
        assert!(o.is_interesting(&r2));
    }

    #[test]
    fn differential_crash_always_interesting() {
        let o = DifferentialOracle::new();
        let mut r = result_ok(vec![], b"");
        r.crash = true;
        r.outcome = OutcomeClass::Crash;
        assert!(o.is_interesting(&r));
    }

    #[test]
    fn sanitizer_pattern_detects_asan() {
        let o = SanitizerPatternOracle::new();
        let r = result_with_error("ERROR: AddressSanitizer: heap-buffer-overflow on address");
        assert!(o.is_interesting(&r));
    }

    #[test]
    fn sanitizer_pattern_detects_segfault() {
        let o = SanitizerPatternOracle::new();
        let r = result_with_error("Segmentation fault (core dumped)");
        assert!(o.is_interesting(&r));
    }

    #[test]
    fn sanitizer_pattern_scans_body() {
        let o = SanitizerPatternOracle::new();
        let mut r = result_ok(vec![500], b"Internal: AddressSanitizer: stack-buffer-overflow");
        r.error = None;
        assert!(o.is_interesting(&r));
    }

    #[test]
    fn sanitizer_pattern_clean() {
        let o = SanitizerPatternOracle::new();
        let r = result_ok(vec![200], b"OK");
        assert!(!o.is_interesting(&r));
    }

    #[test]
    fn null_byte_in_text() {
        let o = NullByteOracle::new();
        let mut body = b"HTTP/1.1 200 OK\r\n".to_vec();
        body.push(0);
        body.extend_from_slice(b"more");
        let r = result_ok(vec![200], &body);
        assert!(o.is_interesting(&r));
    }

    #[test]
    fn null_byte_clean_text() {
        let o = NullByteOracle::new();
        let r = result_ok(vec![200], b"HTTP/1.1 200 OK\r\n");
        assert!(!o.is_interesting(&r));
    }

    #[test]
    fn protocol_violation_2xx_and_5xx() {
        let o = ProtocolViolationOracle;
        let r = result_ok(vec![200, 500], b"");
        assert!(o.is_interesting(&r));
    }

    #[test]
    fn length_anomaly_absolute() {
        let o = LengthAnomalyOracle::new();
        let huge = vec![0u8; 17 * 1024 * 1024];
        let r = result_ok(vec![200], &huge);
        assert!(o.is_interesting(&r));
    }

    #[test]
    fn sanitizer_composite_fires_on_asan() {
        let o = SanitizerOracle::new();
        let r = result_with_error("AddressSanitizer: heap-use-after-free");
        assert!(o.is_interesting(&r));
    }

    #[test]
    fn diffsan_combines() {
        let o = DiffSanOracle::new();
        // sanitizer path
        let r = result_with_error("double-free detected");
        assert!(o.is_interesting(&r));
        // differential path
        let r1 = result_ok(vec![250], b"OK");
        assert!(!o.is_interesting(&r1));
        let r2 = result_ok(vec![550], b"FAIL");
        assert!(o.is_interesting(&r2));
    }

    #[test]
    fn resolve_names() {
        assert_eq!(resolve_oracle(Some("differential")).name(), "differential");
        assert_eq!(resolve_oracle(Some("diff")).name(), "differential");
        assert_eq!(resolve_oracle(Some("sanitizer")).name(), "sanitizer");
        assert_eq!(resolve_oracle(Some("san")).name(), "sanitizer");
        assert_eq!(resolve_oracle(Some("diffsan")).name(), "diffsan");
        assert_eq!(resolve_oracle(Some("expanded")).name(), "expanded");
        assert_eq!(resolve_oracle(Some("strict")).name(), "strict");
        assert_eq!(resolve_oracle(None).name(), "default");
    }

    #[test]
    fn expanded_includes_error() {
        let o = ExpandedOracle::new();
        let r = result_with_error("some i/o failure");
        // error oracle fires even without sanitizer pattern
        assert!(o.is_interesting(&r));
    }
}
