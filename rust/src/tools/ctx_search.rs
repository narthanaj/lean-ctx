use std::collections::HashSet;
use std::path::Path;

use ignore::WalkBuilder;
use regex::Regex;

use crate::core::pathjail;
use crate::core::protocol;
use crate::core::symbol_map::{self, SymbolMap};
use crate::core::tokens::count_tokens;
use crate::tools::CrpMode;

const MAX_FILE_SIZE: u64 = 512_000;
const MAX_WALK_DEPTH: usize = 20;

/// Apply the project jail to a user-supplied search root and return a
/// usable PathBuf. Errors are stringified for direct return from `handle`.
///
/// The walker below does NOT follow symlinks by default (`ignore::WalkBuilder`
/// requires `.follow_links(true)` to enable it, which we never call), so
/// every file the walker yields is inside the root we validated here. That
/// means we don't need to run the jail check on each file individually —
/// which would be prohibitively expensive for a recursive search.
fn jail_search_root(dir: &str) -> Result<std::path::PathBuf, String> {
    let jail_root = pathjail::session_jail_root()
        .map_err(|e| format!("ERROR: {e} (blocked by lean-ctx path jail)"))?;

    // A search root is a directory, so the regular `open_in_jail` (which
    // rejects non-regular files) can't vet it. Run the containment check
    // at the path level instead — that's enough because the walker's
    // no-follow-symlinks default means it can't escape later.
    let target = if Path::new(dir).is_absolute() {
        std::path::PathBuf::from(dir)
    } else {
        jail_root.join(dir)
    };
    let canonical = std::fs::canonicalize(&target)
        .map_err(|e| format!("ERROR: cannot resolve '{dir}': {e}"))?;

    let mut allowed = vec![jail_root];
    allowed.extend(pathjail::allow_list_roots());
    if !allowed.iter().any(|r| canonical.starts_with(r)) {
        return Err(format!(
            "ERROR: '{dir}' is outside the project jail (blocked by lean-ctx path jail)"
        ));
    }
    Ok(canonical)
}

pub fn handle(
    pattern: &str,
    dir: &str,
    ext_filter: Option<&str>,
    max_results: usize,
    _crp_mode: CrpMode,
    respect_gitignore: bool,
) -> (String, usize) {
    let re = match Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => return (format!("ERROR: invalid regex: {e}"), 0),
    };

    // Phase 0 security gate. Validates `dir` lives inside the project jail
    // before the walker can enumerate it. Reject NUL/CR/LF in the input as
    // a pre-check against smuggling via filename parsers.
    if dir.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
        return (
            format!("ERROR: path '{dir}' contains forbidden characters (blocked by lean-ctx path jail)"),
            0,
        );
    }
    let canonical_root = match jail_search_root(dir) {
        Ok(r) => r,
        Err(e) => return (e, 0),
    };
    let root = canonical_root.as_path();
    if !root.exists() {
        return (format!("ERROR: {dir} does not exist"), 0);
    }

    let walker = WalkBuilder::new(root)
        .hidden(true)
        .max_depth(Some(MAX_WALK_DEPTH))
        .git_ignore(respect_gitignore)
        .git_global(respect_gitignore)
        .git_exclude(respect_gitignore)
        .build();

    let mut matches = Vec::new();
    let mut raw_result_lines = Vec::new();
    let mut files_searched = 0u32;
    let mut files_skipped_size = 0u32;
    let mut files_skipped_encoding = 0u32;

    for entry in walker.filter_map(|e| e.ok()) {
        if entry.file_type().is_none_or(|ft| ft.is_dir()) {
            continue;
        }

        // Phase 0 security: reject symlink entries. WalkBuilder doesn't
        // follow symlinks for directory traversal, but it still yields
        // symlink DirEntry items. read_to_string below would dereference
        // the symlink and read the target — potentially outside the jail.
        if entry.file_type().is_some_and(|ft| ft.is_symlink()) {
            continue;
        }

        let path = entry.path();

        if is_binary_ext(path) || is_generated_file(path) {
            continue;
        }

        if let Some(ext) = ext_filter {
            let file_ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if file_ext != ext {
                continue;
            }
        }

        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > MAX_FILE_SIZE {
                files_skipped_size += 1;
                continue;
            }
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                files_skipped_encoding += 1;
                continue;
            }
        };

        files_searched += 1;

        for (i, line) in content.lines().enumerate() {
            if re.is_match(line) {
                let short_path = protocol::shorten_path(&path.to_string_lossy());
                let full_path = path.to_string_lossy();
                raw_result_lines.push(format!("{full_path}:{}: {}", i + 1, line.trim()));
                matches.push(format!("{short_path}:{} {}", i + 1, line.trim()));
                if matches.len() >= max_results {
                    break;
                }
            }
        }

        if matches.len() >= max_results {
            break;
        }
    }

    if matches.is_empty() {
        let mut msg = format!("0 matches for '{pattern}' in {files_searched} files");
        if files_skipped_size > 0 {
            msg.push_str(&format!(" ({files_skipped_size} large files skipped)"));
        }
        if files_skipped_encoding > 0 {
            msg.push_str(&format!(
                " ({files_skipped_encoding} files skipped: binary/encoding)"
            ));
        }
        return (msg, 0);
    }

    let mut result = format!(
        "{} matches in {} files:\n{}",
        matches.len(),
        files_searched,
        matches.join("\n")
    );

    if files_skipped_size > 0 {
        result.push_str(&format!("\n({files_skipped_size} files >512KB skipped)"));
    }
    if files_skipped_encoding > 0 {
        result.push_str(&format!(
            "\n({files_skipped_encoding} files skipped: binary/encoding)"
        ));
    }

    let scope_hint = monorepo_scope_hint(&matches, dir);

    {
        let file_ext = ext_filter.unwrap_or("rs");
        let mut sym = SymbolMap::new();
        let idents = symbol_map::extract_identifiers(&result, file_ext);
        for ident in &idents {
            sym.register(ident);
        }
        if sym.len() >= 3 {
            let sym_table = sym.format_table();
            let compressed = sym.apply(&result);
            let original_tok = count_tokens(&result);
            let compressed_tok = count_tokens(&compressed) + count_tokens(&sym_table);
            let net_saving = original_tok.saturating_sub(compressed_tok);
            if original_tok > 0 && net_saving * 100 / original_tok >= 5 {
                result = format!("{compressed}{sym_table}");
            }
        }
    }

    if let Some(hint) = scope_hint {
        result.push_str(&hint);
    }

    let raw_output = raw_result_lines.join("\n");
    let raw_tokens = count_tokens(&raw_output);
    let sent = count_tokens(&result);
    let savings = protocol::format_savings(raw_tokens, sent);

    (format!("{result}\n{savings}"), raw_tokens)
}

fn is_binary_ext(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(
        ext,
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "ico"
            | "svg"
            | "woff"
            | "woff2"
            | "ttf"
            | "eot"
            | "pdf"
            | "zip"
            | "tar"
            | "gz"
            | "br"
            | "zst"
            | "bz2"
            | "xz"
            | "mp3"
            | "mp4"
            | "webm"
            | "ogg"
            | "wasm"
            | "so"
            | "dylib"
            | "dll"
            | "exe"
            | "lock"
            | "map"
            | "snap"
            | "patch"
            | "db"
            | "sqlite"
            | "parquet"
            | "arrow"
            | "bin"
            | "o"
            | "a"
            | "class"
            | "pyc"
            | "pyo"
    )
}

fn is_generated_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with(".min.js")
        || name.ends_with(".min.css")
        || name.ends_with(".bundle.js")
        || name.ends_with(".chunk.js")
        || name.ends_with(".d.ts")
        || name.ends_with(".js.map")
        || name.ends_with(".css.map")
}

fn monorepo_scope_hint(matches: &[String], search_dir: &str) -> Option<String> {
    let top_dirs: HashSet<&str> = matches
        .iter()
        .filter_map(|m| {
            let path = m.split(':').next()?;
            let relative = path.strip_prefix("./").unwrap_or(path);
            let relative = relative.strip_prefix(search_dir).unwrap_or(relative);
            let relative = relative.strip_prefix('/').unwrap_or(relative);
            relative.split('/').next()
        })
        .collect();

    if top_dirs.len() > 3 {
        let mut dirs: Vec<&&str> = top_dirs.iter().collect();
        dirs.sort();
        let dir_list: Vec<String> = dirs.iter().take(6).map(|d| format!("'{d}'")).collect();
        let extra = if top_dirs.len() > 6 {
            format!(", +{} more", top_dirs.len() - 6)
        } else {
            String::new()
        };
        Some(format!(
            "\n\nResults span {} directories ({}{}). \
             Use the 'path' parameter to scope to a specific service, \
             e.g. path=\"{}/\".",
            top_dirs.len(),
            dir_list.join(", "),
            extra,
            dirs[0]
        ))
    } else {
        None
    }
}
