//! NXS spawn rate limiting and deduplication
//!
//! Process-local ledger:
//! - Per (event, crash_id, nxs_id) cooldown window
//! - Per-event spawn counter
//! - Campaign-wide total spawn counter
//!
//! Designed for high-throughput campaigns: O(1) checks, no I/O, no locks beyond
//! a single Mutex held for microseconds. When NXS is disabled the module is never
//! entered.

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
