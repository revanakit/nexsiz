//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::common::types
//!
//! NEXSIZ — NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Module: nexsiz::common::types
//!
//! Summary:
//! Core data-type definitions shared across Nexsiz layers: semantic field types
//! and fields (FieldType, Field), ordered message containers (Message), test-case
//! seeds (TestCase), execution outcomes/results (ExecutionResult, OutcomeClass),
//! lightweight state descriptors (StateDescriptor), and campaign statistics
//! (CampaignStats).
//!
//! Technical notes:
//! - Message and TestCase serialization is a simple concatenation of field bytes
//!   (Message::serialize, TestCase::serialize). Any framing or protocol-specific
//!   encoding must be handled by the consumer (executor/mutator).
//! - FieldType::Length and FieldType::Checksum are semantic hints intended for
//!   mutators/instrumentors — length and checksum values should be recomputed by
//!   the mutation or execution layer when fields are modified.
//! - Field.size (Option<usize>) expresses an optional fixed-size constraint.
//!   Field.protected marks fields that mutators should avoid modifying
//!   aggressively (e.g., critical headers or protocol opcodes).
//! - Message.meta stores optional per-message metadata (direction, required
//!   state, etc.) that state machines, schedulers, or validators may use to
//!   enforce ordering and validity rules.
//! - OutcomeClass exists to provide finer-grained execution classification; the
//!   Default variant is preserved for compatibility with external observers
//!   (for example, LibAFL) that rely on skip/serialization semantics.
//! - These types are intentionally representational and minimal: responsibilities
//!   such as recalculating lengths/checksums, instrumentation, and coverage
//!   bookkeeping belong to the executor, mutator, and instrumentor layers that
//!   consume these structures.
//!
//! This header provides a concise developer-facing overview; refer to the type
//! definitions below for implementation details.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// Unique identifier for a test case / seed.
pub type SeedId = u64;

/// Semantic field types that a protocol message can contain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FieldType {
    /// Fixed or variable command / opcode
    Command,
    /// Length prefix (will be auto-recalculated after mutation when possible)
    Length,
    /// Checksum / CRC / integrity field (recomputed when possible)
    Checksum,
    /// Numeric value (integers of various widths)
    Numeric,
    /// Opaque or structured payload
    Payload,
    /// String / text field
    String,
    /// Binary blob with no known semantics
    Binary,
    /// Custom user-defined field
    Custom(String),
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldType::Command => write!(f, "CMD"),
            FieldType::Length => write!(f, "LEN"),
            FieldType::Checksum => write!(f, "CHK"),
            FieldType::Numeric => write!(f, "NUM"),
            FieldType::Payload => write!(f, "PAY"),
            FieldType::String => write!(f, "STR"),
            FieldType::Binary => write!(f, "BIN"),
            FieldType::Custom(s) => write!(f, "CUS({})", s),
        }
    }
}

/// A single semantic field inside a message.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ftype: FieldType,
    pub data: Vec<u8>,
    /// Optional fixed size constraint (None = variable)
    pub size: Option<usize>,
    /// Whether this field should be protected from aggressive mutation
    pub protected: bool,
}

impl Field {
    pub fn new(name: impl Into<String>, ftype: FieldType, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            ftype,
            data,
            size: None,
            protected: false,
        }
    }

    pub fn with_size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    pub fn protected(mut self) -> Self {
        self.protected = true;
        self
    }
}

/// A single protocol message composed of ordered semantic fields.
#[derive(Debug, Clone)]
pub struct Message {
    pub name: String,
    pub fields: Vec<Field>,
    /// Optional message-level metadata (e.g. direction, required state)
    pub meta: HashMap<String, String>,
}

impl Message {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            meta: HashMap::new(),
        }
    }

    pub fn add_field(&mut self, field: Field) {
        self.fields.push(field);
    }

    /// Serialize the message into a raw byte buffer (simple concatenation).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for f in &self.fields {
            buf.extend_from_slice(&f.data);
        }
        buf
    }

    /// Total serialized size.
    pub fn len(&self) -> usize {
        self.fields.iter().map(|f| f.data.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A complete test case: ordered sequence of messages (the core input unit).
#[derive(Debug, Clone)]
pub struct TestCase {
    pub id: SeedId,
    pub messages: Vec<Message>,
    /// Parent seed id (for corpus genealogy)
    pub parent: Option<SeedId>,
    /// Generation / mutation depth
    pub depth: u32,
    /// Energy / priority score used by the scheduler
    pub energy: f64,
    /// Last observed state hash after execution
    pub last_state: Option<u64>,
    /// Whether this test case discovered new coverage
    pub interesting: bool,
}

impl TestCase {
    pub fn new(id: SeedId, messages: Vec<Message>) -> Self {
        Self {
            id,
            messages,
            parent: None,
            depth: 0,
            energy: 1.0,
            last_state: None,
            interesting: false,
        }
    }

    /// Flatten the entire test case into a single byte stream
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for msg in &self.messages {
            buf.extend_from_slice(&msg.serialize());
        }
        buf
    }

    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
}

/// Classification of an execution outcome for clearer triage.
///
/// `Default` is required by LibAFL observers that use `#[serde(skip)]` on this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutcomeClass {
    #[default]
    Ok,
    /// Target closed the connection (possible crash or protocol abort)
    ConnectionReset,
    /// No response within timeout layers (possible hang)
    Hang,
    /// Explicit crash signal / process death / abrupt error
    Crash,
    /// I/O or configuration error (not necessarily a bug in the target)
    Error,
}

/// Result of executing a single test case against the target.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub seed_id: SeedId,
    pub success: bool,
    pub responses: Vec<Vec<u8>>,
    pub response_codes: Vec<i32>,
    pub elapsed: Duration,
    pub new_coverage: bool,
    pub new_state: bool,
    pub crash: bool,
    pub hang: bool,
    pub error: Option<String>,
    /// Hash of the observed state after this execution
    pub state_hash: u64,
    /// Finer-grained outcome classification
    pub outcome: OutcomeClass,
    /// Number of new coverage edges discovered (grey-box feedback)
    pub coverage_hits: u32,
    /// Hash of the coverage map observed this execution
    pub coverage_map_hash: u64,
}

impl ExecutionResult {
    pub fn is_interesting(&self) -> bool {
        self.new_coverage || self.new_state || self.crash || self.hang || self.coverage_hits > 0
    }

    pub fn with_outcome(mut self, outcome: OutcomeClass) -> Self {
        self.outcome = outcome;
        match outcome {
            OutcomeClass::Crash | OutcomeClass::ConnectionReset => {
                self.crash = true;
            }
            OutcomeClass::Hang => {
                self.hang = true;
            }
            _ => {}
        }
        self
    }
}

/// Lightweight state descriptor used by the hybrid state model.
#[derive(Debug, Clone, Default)]
pub struct StateDescriptor {
    /// Primary state identifier (response-code driven or instrumented)
    pub id: u64,
    /// Optional human-readable label
    pub label: String,
    /// Variables extracted from the target (grey-box)
    pub variables: HashMap<String, u64>,
    /// Selective memory hash (when instrumentation provides it)
    pub mem_hash: u64,
    /// Number of times this state has been observed
    pub hit_count: u64,
}

/// High-level statistics collected during a campaign.
#[derive(Debug, Clone, Default)]
pub struct CampaignStats {
    pub execs: u64,
    pub crashes: u64,
    pub hangs: u64,
    pub timeouts: u64,
    pub new_paths: u64,
    pub new_states: u64,
    pub corpus_size: usize,
    pub start_time: Option<std::time::Instant>,
    pub last_find: Option<std::time::Instant>,
}

impl CampaignStats {
    pub fn execs_per_sec(&self) -> f64 {
        match self.start_time {
            Some(start) => {
                let secs = start.elapsed().as_secs_f64();
                if secs > 0.0 {
                    self.execs as f64 / secs
                } else {
                    0.0
                }
            }
            None => 0.0,
        }
    }
}
