//! Canonical exit codes from nxs/CONTRACT.md §2.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Completed normally, no further vulnerability indication
    Ok = 0,
    /// Operational error (missing file, unreachable target, invalid args)
    Error = 1,
    /// Indication of further vulnerability / successful exploit-assist → escalate
    Escalate = 2,
    /// Internal timeout
    Timeout = 3,
    /// Interrupted / cancelled
    Interrupted = 4,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    pub fn exit(self) -> ! {
        std::process::exit(self.as_i32());
    }
}

/// Script-specific success variants start at ≥10 (document in nxs.toml).
pub const SCRIPT_SUCCESS_BASE: i32 = 10;
