//! Hand-rolled JSON meta writer (nxs/CONTRACT.md §3).
//! Pure stdlib — no serde. Forward-compatible: unknown fields are simply omitted.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Context supplied by the engine for a single event.
pub struct MetaContext<'a> {
    pub nexsiz_version: &'a str,
    pub event: &'a str,
    pub target_host: &'a str,
    pub target_port: u16,
    pub target_protocol: &'a str,
    pub model: &'a str,
    pub crash_id: &'a str,
    pub crash_path: &'a str,
    pub minimized_path: &'a str,
    pub input_len: usize,
    pub outcome: &'a str,
    pub error: Option<&'a str>,
    pub elapsed_ms: u64,
    pub coverage_hits: u64,
    pub new_state: bool,
    pub response_codes: &'a [i32],
    pub corpus_id: u64,
    pub output_dir: &'a str,
}

/// Write the CONTRACT.md minimal schema to `path`.
/// Creates parent directories as needed.
pub fn write_meta(path: &str, ctx: &MetaContext<'_>) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let input_len = if ctx.input_len > 0 {
        ctx.input_len
    } else if !ctx.crash_path.is_empty() {
        fs::metadata(ctx.crash_path)
            .map(|m| m.len() as usize)
            .unwrap_or(0)
    } else {
        0
    };

    let mut buf = String::with_capacity(1024);
    buf.push_str("{\n");
    push_str(&mut buf, "nexsiz_version", ctx.nexsiz_version);
    buf.push_str(",\n");
    push_str(&mut buf, "event", ctx.event);
    buf.push_str(",\n");
    buf.push_str(&format!("  \"timestamp\": {:.3},\n", timestamp));

    // target
    buf.push_str("  \"target\": {\n");
    push_str_indent(&mut buf, "host", ctx.target_host, 4);
    buf.push_str(",\n");
    buf.push_str(&format!("    \"port\": {},\n", ctx.target_port));
    push_str_indent(&mut buf, "protocol", ctx.target_protocol, 4);
    buf.push_str("\n  },\n");

    push_str(&mut buf, "model", ctx.model);
    buf.push_str(",\n");

    // crash
    buf.push_str("  \"crash\": {\n");
    push_str_indent(&mut buf, "id", ctx.crash_id, 4);
    buf.push_str(",\n");
    push_str_indent(&mut buf, "path", ctx.crash_path, 4);
    buf.push_str(",\n");
    if !ctx.minimized_path.is_empty() {
        push_str_indent(&mut buf, "minimized_path", ctx.minimized_path, 4);
        buf.push_str(",\n");
    }
    buf.push_str(&format!("    \"input_len\": {}\n", input_len));
    buf.push_str("  },\n");

    // result
    buf.push_str("  \"result\": {\n");
    push_str_indent(&mut buf, "outcome", ctx.outcome, 4);
    buf.push_str(",\n");
    if let Some(err) = ctx.error {
        push_str_indent(&mut buf, "error", err, 4);
        buf.push_str(",\n");
    }
    buf.push_str(&format!("    \"elapsed_ms\": {},\n", ctx.elapsed_ms));
    buf.push_str(&format!("    \"coverage_hits\": {},\n", ctx.coverage_hits));
    buf.push_str(&format!("    \"new_state\": {},\n", ctx.new_state));
    buf.push_str("    \"response_codes\": [");
    for (i, c) in ctx.response_codes.iter().enumerate() {
        if i > 0 {
            buf.push_str(", ");
        }
        buf.push_str(&c.to_string());
    }
    buf.push_str("]\n  },\n");

    buf.push_str(&format!("  \"corpus_id\": {},\n", ctx.corpus_id));
    push_str(&mut buf, "output_dir", ctx.output_dir);
    buf.push_str("\n}\n");

    let mut f = fs::File::create(path).map_err(|e| format!("create {}: {}", path, e))?;
    f.write_all(buf.as_bytes())
        .map_err(|e| format!("write {}: {}", path, e))?;
    Ok(())
}

fn push_str(buf: &mut String, key: &str, val: &str) {
    buf.push_str(&format!("  \"{}\": \"{}\"", key, escape_json(val)));
}

fn push_str_indent(buf: &mut String, key: &str, val: &str, indent: usize) {
    for _ in 0..indent {
        buf.push(' ');
    }
    buf.push_str(&format!("\"{}\": \"{}\"", key, escape_json(val)));
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
