use std::path::Path;

use ignore::WalkBuilder;

use crate::core::protocol;
use crate::core::tokens::count_tokens;

pub fn handle(path: &str, depth: usize, show_hidden: bool) -> (String, usize) {
    let root = Path::new(path);
    if !root.is_dir() {
        return (format!("ERROR: {path} is not a directory"), 0);
    }

    let raw_output = generate_raw_tree(root);
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

fn generate_raw_tree(root: &Path) -> String {
    let mut lines = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .sort_by_file_name(|a, b| a.cmp(b))
        .build();

    for entry in walker.filter_map(|e| e.ok()) {
        if entry.depth() == 0 {
            continue;
        }
        lines.push(
            entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .to_string(),
        );
    }

    lines.join("\n")
}

fn count_files_in_dir(dir: &Path) -> usize {
    WalkBuilder::new(dir)
        .hidden(true)
        .git_ignore(true)
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
        .count()
}
