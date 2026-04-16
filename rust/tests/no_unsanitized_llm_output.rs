//! CI guard: detect raw filesystem calls in tool modules that bypass the
//! path jail. Prevents regressions where a new tool (or a refactor of an
//! existing one) accidentally reaches into `std::fs` directly instead of
//! routing through `pathjail::open_in_jail` / `pathjail::read_in_jail` or
//! the jailed wrappers in `ctx_read`.
//!
//! HOW IT WORKS: this test scans `src/tools/*.rs` and `src/core/patterns/*.rs`
//! for calls to `std::fs::read`, `std::fs::read_to_string`, `File::open`,
//! and `std::fs::write` that appear outside of:
//!   1. Test blocks (`#[cfg(test)]` / `mod tests`)
//!   2. Files explicitly whitelisted in `TOOL_WHITELIST` below
//!
//! HOW TO UPDATE: when you add a new tool that legitimately needs a raw
//! filesystem call (e.g. for a non-LLM-facing operation like cache housekeeping),
//! add its file stem and reason to `TOOL_WHITELIST` below and document why
//! the jail is not applicable.
//!
//! This test runs in CI alongside the normal test suite. It catches new leaks
//! while the rest of the hardening plan is still in progress.

use std::fs;
use std::path::Path;

/// Files in `src/tools/` that are ALLOWED to contain raw `std::fs` calls,
/// along with the reason. Every entry should ideally be temporary — Phase B+
/// should migrate each one behind the jail or a fenced wrapper.
///
/// Format: `(filename_stem, reason)`
const TOOL_WHITELIST: &[(&str, &str)] = &[
    // ctx_read: `read_file_lossy` is the un-jailed variant kept for internal
    // callers (CLI, cache). The MCP entry points go through `read_through_jail`.
    // Phase B3 will read directly from the jailed FD and remove this.
    ("ctx_read", "read_file_lossy is internal-only; MCP paths are jailed via read_through_jail"),
    // ctx_edit: the `std::fs::write` calls are inside the jailed wrapper
    // (jail_edit_target validates the path first). The `std::fs::read` is
    // also post-jail-check. Acceptable for Phase 0.
    ("ctx_edit", "reads/writes are post-jail_edit_target validation"),
    // ctx_search: reads individual files via std::fs::read_to_string after
    // the jail validated the search root. Walker doesn't follow symlinks.
    ("ctx_search", "file reads are under the jailed search root; walker doesn't follow symlinks"),
    // ctx_execute: runs commands for the user — not an LLM file-read path.
    ("ctx_execute", "command execution, not file-read for LLM context"),
    // ctx_knowledge: reads/writes to ~/.lean-ctx/knowledge/ — internal
    // persistent store, not LLM-supplied paths.
    ("ctx_knowledge", "internal knowledge store under ~/.lean-ctx/, not LLM-supplied paths"),
    // ctx_session: reads/writes to ~/.lean-ctx/sessions/ — internal.
    ("ctx_session", "internal session store under ~/.lean-ctx/"),
    // ctx_overview: reads project files for overview generation — delegates
    // to ctx_read internally which is jailed.
    ("ctx_overview", "delegates to ctx_read which is jailed"),
    // ctx_preload: same as ctx_overview.
    ("ctx_preload", "delegates to ctx_read which is jailed"),
    // ctx_agent: internal agent registry under ~/.lean-ctx/.
    ("ctx_agent", "internal agent store under ~/.lean-ctx/"),
    // ctx_shell: compression only — receives already-captured output.
    ("ctx_shell", "compression of already-captured output, no fs reads"),
    // ctx_compress: internal cache operations.
    ("ctx_compress", "internal compression, no LLM-supplied paths"),
    // ctx_benchmark: reads project files for benchmarking.
    ("ctx_benchmark", "internal benchmarking utility"),
    // ctx_discover: reads shell history.
    ("ctx_discover", "reads shell history files, not LLM-supplied paths"),
    // ctx_impact / ctx_architecture / ctx_graph: dependency analysis.
    ("ctx_impact", "dependency analysis, paths from project graph not LLM"),
    ("ctx_architecture", "architecture analysis, paths from project graph"),
    ("ctx_graph", "graph analysis"),
    ("ctx_graph_diagram", "graph diagram rendering"),
    // ctx_heatmap: internal analytics.
    ("ctx_heatmap", "internal analytics"),
    // ctx_wrapped / ctx_metrics / ctx_cost: reporting.
    ("ctx_wrapped", "reporting"),
    ("ctx_metrics", "reporting"),
    ("ctx_cost", "reporting"),
    // ctx_delta / ctx_dedup / ctx_fill / ctx_context / ctx_response /
    // ctx_compress_memory / ctx_outline / ctx_symbol / ctx_routes /
    // ctx_intent / ctx_semantic_search: operate on cached content, not raw fs.
    ("ctx_delta", "operates on cache"),
    ("ctx_dedup", "operates on cache"),
    ("ctx_fill", "operates on cache"),
    ("ctx_context", "operates on cache"),
    ("ctx_response", "text compression"),
    ("ctx_compress_memory", "memory compression"),
    ("ctx_outline", "operates on cache"),
    ("ctx_symbol", "operates on cache"),
    ("ctx_routes", "operates on cache"),
    ("ctx_intent", "operates on cache"),
    ("ctx_semantic_search", "internal embedding index"),
    ("ctx_share", "multi-agent sharing, internal"),
    ("ctx_task", "task orchestration, internal"),
    ("ctx_callees", "call graph analysis"),
    ("ctx_callers", "call graph analysis"),
    ("ctx_analyze", "entropy analysis utility"),
    // autonomy.rs: delegates to ctx_overview/ctx_preload which are jailed.
    ("autonomy", "delegates to jailed tools"),
    // mod.rs: tool registration, no fs calls.
    ("mod", "tool registration boilerplate"),
];

/// Patterns that indicate a raw filesystem call. We look for these in
/// non-test, non-whitelisted lines of tool source files.
const DANGEROUS_PATTERNS: &[&str] = &[
    "std::fs::read(",
    "std::fs::read_to_string(",
    "std::fs::read_dir(",
    "std::fs::write(",
    "File::open(",
    "File::create(",
    "fs::read(",
    "fs::read_to_string(",
    "fs::write(",
    "fs::read_dir(",
];

#[test]
fn no_raw_fs_calls_in_unjailed_tools() {
    let tools_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tools");
    assert!(
        tools_dir.is_dir(),
        "expected src/tools/ at {:?}",
        tools_dir
    );

    let whitelisted_stems: Vec<&str> = TOOL_WHITELIST.iter().map(|(s, _)| *s).collect();

    let mut violations = Vec::new();

    for entry in fs::read_dir(&tools_dir).expect("read src/tools/") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }

        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if whitelisted_stems.contains(&stem) {
            continue;
        }

        let content = fs::read_to_string(&path).expect("read tool source");

        // Skip everything inside `#[cfg(test)]` or `mod tests` blocks.
        // Heuristic: once we see `#[cfg(test)]` or `mod tests {`, the rest
        // of the file is test code. Good enough for a CI lint.
        let production_code = if let Some(pos) = content.find("#[cfg(test)]") {
            &content[..pos]
        } else if let Some(pos) = content.find("mod tests {") {
            &content[..pos]
        } else {
            &content
        };

        for (line_no, line) in production_code.lines().enumerate() {
            let trimmed = line.trim();
            // Skip comments.
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
            {
                continue;
            }

            for pattern in DANGEROUS_PATTERNS {
                if trimmed.contains(pattern) {
                    violations.push(format!(
                        "  {}:{}: {} (file: {})",
                        stem,
                        line_no + 1,
                        pattern,
                        path.display()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n\nCI GUARD: raw filesystem calls found in non-whitelisted tool modules.\n\
         These must route through pathjail::open_in_jail / pathjail::read_in_jail.\n\
         If the call is intentionally unjailed, add the file stem to TOOL_WHITELIST\n\
         in tests/no_unsanitized_llm_output.rs with a justification.\n\n\
         Violations:\n{}\n",
        violations.join("\n")
    );
}

/// Same scan for `src/core/patterns/*.rs` — the compressor outputs.
/// These don't do fs reads, but if someone adds one, it bypasses the jail.
#[test]
fn no_raw_fs_calls_in_pattern_compressors() {
    let patterns_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/patterns");
    if !patterns_dir.is_dir() {
        // If patterns dir doesn't exist (unlikely), skip gracefully.
        return;
    }

    let mut violations = Vec::new();

    for entry in fs::read_dir(&patterns_dir).expect("read patterns/") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }

        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        // mod.rs in patterns/ is the dispatch logic — allow it.
        // deps_cmd.rs reads dependency files (package.json, Cargo.toml, etc.)
        // from paths discovered by the project walker, not from LLM input.
        if stem == "mod" || stem == "deps_cmd" {
            continue;
        }

        let content = fs::read_to_string(&path).expect("read pattern source");
        let production_code = if let Some(pos) = content.find("#[cfg(test)]") {
            &content[..pos]
        } else {
            &content
        };

        for (line_no, line) in production_code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
            {
                continue;
            }
            for pattern in DANGEROUS_PATTERNS {
                if trimmed.contains(pattern) {
                    violations.push(format!(
                        "  patterns/{}:{}: {}",
                        stem,
                        line_no + 1,
                        pattern
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n\nCI GUARD: raw filesystem calls found in pattern compressor modules.\n\
         Pattern compressors should only operate on string data, not the filesystem.\n\
         If you need to read a file, route through ctx_read or pathjail.\n\n\
         Violations:\n{}\n",
        violations.join("\n")
    );
}
