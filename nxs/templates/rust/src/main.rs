//! NXS template (Rust) — honour the contract in nxs/CONTRACT.md
//! Replace the body with real post-event logic.

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("nxs-template — custom NXS skeleton");
        eprintln!("Usage: nxs-template --crash <path> --target <host:port> [options]");
        process::exit(0);
    }
    if args.iter().any(|a| a == "--version") {
        println!("nxs-template 0.1.0 (id=custom/template)");
        process::exit(0);
    }

    // Minimal required argument check (real implementation should use the shared lib)
    let has_crash = args.iter().any(|a| a == "--crash");
    let has_meta = args.iter().any(|a| a == "--meta");
    let has_target = args.iter().any(|a| a == "--target");

    if !has_crash && !has_meta {
        eprintln!("error: at least one of --crash or --meta is required");
        process::exit(1);
    }
    if !has_target && !has_meta {
        eprintln!("error: --target is required when --meta is absent");
        process::exit(1);
    }

    // TODO: load meta, re-execute, differential probe, write report.json, etc.
    eprintln!("[nxs-template] skeleton — replace with real logic");
    process::exit(0);
}
