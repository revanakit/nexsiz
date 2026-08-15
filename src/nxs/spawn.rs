//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::nxs::spawn
//!
//! Purpose
//! - Provide a small, dependency-free helper to spawn external NXS (next-stage)
//!   analysis binaries non-blocking, following the command-line contract (CONTRACT.md §1).
//!
//! Responsibilities
//! - Construct the contract CLI invocation and return a spawned `Child` immediately so
//!   the fuzzer hot-path is never blocked waiting for external analysis to complete.
//! - Apply a conservative stdio policy (null by default, inherited in verbose mode)
//!   to prevent noisy NXS processes from filling pipes and stalling the engine.
//! - Apply platform-appropriate detach semantics so spawned processes do not receive
//!   control-C/console events intended for the parent fuzzer process.
//!
//! CLI contract & argument mapping
//! - The spawned binary is invoked with the mandatory contract flags:
//!   --crash <path> (optional), --minimized <path> (optional), --meta <path> (optional),
//!   --target <host:port>, --event <name>, --model <name> (optional), --out <dir> (optional), -v (verbose).
//! - Arguments are passed as separate Command::arg elements (no shell interpolation) for safety.
//!
//! I/O and detach policy
//! - Default: stdin/stdout/stderr → Stdio::null to fully isolate the NXS process.
//! - Verbose mode: stdout/stderr are inherited so operator-visible diagnostics flow to console.
//! - Unix: call setsid() in pre_exec to create a new session (fully detached).
//! - Windows: use CREATE_NEW_PROCESS_GROUP to avoid parent console Ctrl-C propagation.
//!
//! Error handling & semantics
//! - Returns Result<Child, String>; spawn failures return a human-readable error string
//!   including the target path to simplify operator diagnostics.
//! - Creation of per-NXS out_dir is attempted but failures are non-fatal for spawn: callers
//!   should handle downstream consequences (e.g., missing output sidecars).
//!
//! Safety & best practices
//! - Callers must ensure each returned Child is eventually reaped (the reaper module
//!   is the intended consumer) to avoid zombies and to observe exit codes.
//! - The function avoids shelling out and does not expose the parent process file
//!   descriptors to children (except in verbose/inherit mode where intentional).
//!
//! Testing recommendations
//! - Unit tests for argument composition and correct handling of optional parameters.
//! - Platform-specific tests for detach behavior (setsid / creation flags) via integration tests.
//! - End-to-end tests that spawn a short-lived helper binary and verify the fuzzer remains non-blocking,
//!   stdio isolation behaves as expected, and spawn failures produce clear error messages.
//!
//! References
//! - Contract: nxs/CONTRACT.md §1 — authoritative specification for CLI flags and exit semantics.
//! - See nxs::reaper for how spawned Child handles are consumed and observed.
    
use crate::nxs::resolve::NxsSpec;
use std::fs;
use std::process::{Child, Command, Stdio};

/// Spawn a single NXS executable with the mandatory contract CLI.
///
/// Returns the `Child` on success so the async reaper can observe its exit code.
pub fn spawn_nxs(
    spec: &NxsSpec,
    crash_path: Option<&str>,
    minimized_path: Option<&str>,
    meta_path: Option<&str>,
    target: &str,
    event: &str,
    model: Option<&str>,
    out_dir: Option<&str>,
    verbose: bool,
) -> Result<Child, String> {
    if let Some(dir) = out_dir {
        let _ = fs::create_dir_all(dir);
    }

    let mut cmd = Command::new(&spec.path);

    if let Some(p) = crash_path {
        if !p.is_empty() {
            cmd.arg("--crash").arg(p);
        }
    }
    if let Some(p) = minimized_path {
        if !p.is_empty() {
            cmd.arg("--minimized").arg(p);
        }
    }
    if let Some(p) = meta_path {
        cmd.arg("--meta").arg(p);
    }
    cmd.arg("--target").arg(target);
    cmd.arg("--event").arg(event);
    if let Some(m) = model {
        cmd.arg("--model").arg(m);
    }
    if let Some(d) = out_dir {
        cmd.arg("--out").arg(d);
    }
    if verbose {
        cmd.arg("-v");
    }

    // Detach stdio so a noisy or blocking NXS cannot stall the fuzzer.
    if verbose {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    } else {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }

    // Detach from the fuzzer's process group / console so Ctrl-C on the
    // fuzzer does not immediately tear down in-flight NXS actors.
    // Operator can still kill the tree explicitly if desired (future flag).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                // setsid() — new session, fully detached
                if libc::setsid() == -1 {
                    // non-fatal; continue anyway
                }
                Ok(())
            });
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP (0x200): child gets its own process group
        // and does not receive console Ctrl-C events aimed at the parent.
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }

    match cmd.spawn() {
        Ok(child) => Ok(child),
        Err(e) => Err(format!("{}: {}", spec.path.display(), e)),
    }
}
