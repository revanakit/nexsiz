//! Non-blocking NXS process spawn (CONTRACT.md §1).
//!
//! Spawn returns a `Child` immediately. The caller (or the async reaper)
//! is responsible for eventually reaping it so zombies are avoided and
//! exit codes can be observed without blocking the fuzzer hot-path.
//!
//! Stdio is null (or inherited only when verbose) so a noisy NXS cannot
//! fill pipes and stall the engine.

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

    // On Unix, start a new process group so the child survives fuzzer SIGINT
    // unless the operator explicitly wants joint teardown (future flag).
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

    match cmd.spawn() {
        Ok(child) => Ok(child),
        Err(e) => Err(format!("{}: {}", spec.path.display(), e)),
    }
}
