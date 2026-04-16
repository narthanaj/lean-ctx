use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::core::pathjail;
use crate::core::protocol;
use crate::core::tokens::count_tokens;

/// Apply the project jail to an LLM-supplied directory argument. Returns
/// the canonicalized path or an error string.
///
/// `ignore::WalkBuilder` does NOT follow symlinks by default — no
/// `.follow_links(true)` call appears in this module — so once we've
/// verified the root is inside the jail, every directory entry the walker
/// yields is also inside. Per-entry jail checks would be prohibitively
/// expensive for deep trees.
fn jail_tree_root(path: &str) -> Result<PathBuf, String> {
    if path.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
        return Err(format!(
            "ERROR: path '{path}' contains forbidden characters (blocked by lean-ctx path jail)"
        ));
    }
    let jail_root = pathjail::session_jail_root()
        .map_err(|e| format!("ERROR: {e} (blocked by lean-ctx path jail)"))?;
    let target = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        jail_root.join(path)
    };
    let canonical = std::fs::canonicalize(&target)
        .map_err(|e| format!("ERROR: cannot resolve '{path}': {e}"))?;
    let mut allowed = vec![jail_root];
    allowed.extend(pathjail::allow_list_roots());
    if !allowed.iter().any(|r| canonical.starts_with(r)) {
        return Err(format!(
            "ERROR: '{path}' is outside the project jail (blocked by lean-ctx path jail)"
        ));
    }
    Ok(canonical)
}

pub fn handle(path: &str, depth: usize, show_hidden: bool) -> (String, usize) {
    // Phase 0 security gate. Validate the user-supplied root lives inside
    // the project jail before the walker enumerates it.
    let canonical_root = match jail_tree_root(path) {
        Ok(r) => r,
        Err(e) => return (e, 0),
    };
    let root = canonical_root.as_path();
    if !root.is_dir() {
        return (format!("ERROR: {path} is not a directory"), 0);
    }

    let raw_output = generate_raw_tree(root, depth, show_hidden);
    let compact_output = generate_compact_tree(root, depth, show_hidden);

    let raw_tokens = count_tokens(&raw_output);
    let compact_tokens = count_tokens(&compact_output);
    let savings = protocol::format_savings(raw_tokens, compact_tokens);

    (format!("{compact_output}\n{savings}"), raw_tokens)
}

fn generate_compact_tree(root: &Path, max_depth: usize, show_hidden: bool) -> String {
    let mut lines = Vec::new();
    let mut entries: Vec<(usize, String, bool, usize)> = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(!show_hidden)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .max_depth(Some(max_depth))
        .sort_by_file_name(|a, b| a.cmp(b))
        .build();

    for entry in walker.filter_map(|e| e.ok()) {
        if entry.depth() == 0 {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();

        let depth = entry.depth();
        let is_dir = entry.file_type().is_some_and(|ft| ft.is_dir());

        let file_count = if is_dir {
            count_files_in_dir(entry.path())
        } else {
            0
        };

        entries.push((depth, name, is_dir, file_count));
    }

    for (depth, name, is_dir, file_count) in &entries {
        let indent = "  ".repeat(depth.saturating_sub(1));
        if *is_dir {
            lines.push(format!("{indent}{name}/ ({file_count})"));
        } else {
            lines.push(format!("{indent}{name}"));
        }
    }

    lines.join("\n")
}

fn generate_raw_tree(root: &Path, depth: usize, show_hidden: bool) -> String {
    let mut lines = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(!show_hidden)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .max_depth(Some(depth))
        .sort_by_file_name(|a, b| a.cmp(b))
        .build();

    for entry in walker.filter_map(|e| e.ok()) {
        if entry.depth() == 0 {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy();
        lines.push(rel.to_string());
    }

    lines.join("\n")
}

fn count_files_in_dir(dir: &Path) -> usize {
    WalkBuilder::new(dir)
        .hidden(false)
        .git_ignore(true)
        .max_depth(Some(5))
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_savings_are_reasonable() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let (output, original) = handle(dir, 3, false);
        let compact_tokens = count_tokens(&output);

        eprintln!("=== ctx_tree savings test ===");
        eprintln!("  original (raw) tokens: {original}");
        eprintln!("  compact tokens:        {compact_tokens}");
        eprintln!(
            "  savings:               {}",
            original.saturating_sub(compact_tokens)
        );

        assert!(
            original < 5000,
            "raw tree at depth 3 should be < 5000 tokens, got {original}"
        );
        assert!(original > 0, "raw tree should have some tokens");
        if original > compact_tokens {
            let ratio = (original - compact_tokens) as f64 / original as f64;
            eprintln!("  savings ratio:         {:.1}%", ratio * 100.0);
            assert!(
                ratio < 0.90,
                "savings ratio should be < 90% for same-depth comparison, got {:.1}%",
                ratio * 100.0
            );
        }
    }
}
