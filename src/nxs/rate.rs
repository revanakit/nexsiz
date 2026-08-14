//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 09/08/2026
//! Module  : nexsiz::src::nxs::rate
//!
//! NXS spawn rate limiting and deduplication
//!
//! Purpose
//! - In-process rate limiter and deduplication ledger for spawning external NXS (next-stage)
//!   analysis processes. Ensures the fuzzer does not overwhelm downstream tooling by applying
//!   per-(event,crash,nxs) cooldowns, per-event caps, and a campaign-wide total cap.
//!
//! Design & guarantees
//! - In-memory, process-local ledger: no disk/network I/O, no external coordination.
//! - Thread-safe via a single Mutex protecting the ledger; the lock is held only for microseconds
//!   during checks and updates to keep contention minimal in high-throughput scenarios.
//! - Time complexity: O(1) amortized checks and updates. Memory usage grows with the number
//!   of unique (event,crash_id,nxs_id) keys; a bounded opportunistic prune keeps the map size in check.
//!
//! Data model
//! - recent: HashMap keyed by "{event}|{crash_id}|{nxs_id}" → Entry { last: Instant } (cooldown enforcement).
//! - per_event: HashMap keyed by event → u64 counter (per-event cap enforcement).
//! - total: u64 counter (campaign-wide cap).
//!
//! API semantics
//! - check_and_record(event, crash_id, nxs_id, cooldown, max_per_event, max_total) → RateDecision
//!   • cooldown: minimum interval between identical (event, crash_id, nxs_id) spawns.
//!   • max_per_event: 0 means "unlimited" for that event.
//!   • max_total: 0 means "unlimited" campaign-wide.
//!   • On Allow the ledger is updated (recent entry inserted/renewed, per-event counter incremented, total++). 
//!   • Decisions: Allow, DenyCooldown, DenyPerEventCap, DenyTotalCap.
//!
//! Pruning policy
//! - To prevent unbounded growth, the ledger opportunistically prunes `recent` when its length
//!   exceeds 4096 entries, removing entries older than (now - cooldown - 1s). This keeps memory
//!   stable while retaining recent keys needed for cooldown checks.
//!
//! Concurrency & usage notes
//! - The module is designed to be called from hot paths; the Mutex ensures correctness but callers
//!   should avoid extremely high-frequency loops that can cause contention. If distributed rate-limiting
//!   is required (cluster-wide), implement an external coordinator — this module is not suitable for that.
//! - All time comparisons use Instant to avoid wall-clock jumps.
//!
//! Testing recommendations
//! - Unit tests for all RateDecision branches (cooldown, per-event cap, total cap, allow).
//! - Concurrency tests that exercise multiple threads calling check_and_record concurrently.
//! - Tests that verify pruning behavior and ensure the ledger remains bounded under load.
//!
//! Observability
//! - Expose lightweight stats() (total, recent.len()) for monitoring/logging and to aid debugging
//!   when a campaign appears to be rate-limited unexpectedly.
//!
//! See also
//! - nxs::spawn, nxs::reaper, and nxs::mod for how decisions affect NXS process lifecycle.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Decision returned by the rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    DenyCooldown,
    DenyPerEventCap,
    DenyTotalCap,
}

struct Entry {
    last: Instant,
}

struct Ledger {
    /// key = "{event}|{crash_id}|{nxs_id}"
    recent: HashMap<String, Entry>,
    /// key = event → count this campaign
    per_event: HashMap<String, u64>,
    total: u64,
}

impl Ledger {
    fn new() -> Self {
        Self {
            recent: HashMap::new(),
            per_event: HashMap::new(),
            total: 0,
        }
    }
}

static LEDGER: Mutex<Option<Ledger>> = Mutex::new(None);

fn with_ledger<F, R>(f: F) -> R
where
    F: FnOnce(&mut Ledger) -> R,
{
    let mut guard = LEDGER.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(Ledger::new());
    }
    f(guard.as_mut().unwrap())
}

/// Check whether a spawn is allowed; if allowed, record it.
///
/// `cooldown` — minimum interval between identical (event, crash_id, nxs_id).
/// `max_per_event` — 0 = unlimited.
/// `max_total` — 0 = unlimited.
pub fn check_and_record(
    event: &str,
    crash_id: &str,
    nxs_id: &str,
    cooldown: Duration,
    max_per_event: u64,
    max_total: u64,
) -> RateDecision {
    with_ledger(|led| {
        if max_total > 0 && led.total >= max_total {
            return RateDecision::DenyTotalCap;
        }
        let ev_count = led.per_event.get(event).copied().unwrap_or(0);
        if max_per_event > 0 && ev_count >= max_per_event {
            return RateDecision::DenyPerEventCap;
        }

        let key = format!("{}|{}|{}", event, crash_id, nxs_id);
        let now = Instant::now();
        if let Some(entry) = led.recent.get(&key) {
            if now.duration_since(entry.last) < cooldown {
                return RateDecision::DenyCooldown;
            }
        }

        // Allow → record
        led.recent.insert(key, Entry { last: now });
        *led.per_event.entry(event.to_string()).or_insert(0) += 1;
        led.total += 1;

        // Opportunistic prune of stale cooldown entries (keep map bounded)
        if led.recent.len() > 4096 {
            let cutoff = now - cooldown - Duration::from_secs(1);
            led.recent.retain(|_, e| e.last >= cutoff);
        }

        RateDecision::Allow
    })
}

/// Campaign stats for logging / status.
pub fn stats() -> (u64, usize) {
    with_ledger(|led| (led.total, led.recent.len()))
}
