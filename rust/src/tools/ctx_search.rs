use std::path::Path;

use ignore::WalkBuilder;
use regex::Regex;

use crate::core::protocol;
use crate::core::symbol_map::{self, SymbolMap};
use crate::core::tokens::count_tokens;
use crate::tools::CrpMode;

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

    let root = Path::new(dir);
    if !root.exists() {
        return (format!("ERROR: {dir} does not exist"), 0);
    }

    let walker = WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(respect_gitignore)
        .git_global(respect_gitignore)
        .git_exclude(respect_gitignore)
        .build();

    let mut matches = Vec::new();
    let mut files_searched = 0u32;
    let mut matched_file_tokens = 0usize;

    for entry in walker.filter_map(|e| e.ok()) {
        if entry.file_type().is_none_or(|ft| ft.is_dir()) {
            continue;
        }

        let path = entry.path();

        if is_binary_ext(path) {
            continue;
        }

        if let Some(ext) = ext_filter {
            let file_ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if file_ext != ext {
                continue;
            }
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        files_searched += 1;
        let mut file_has_match = false;

        for (i, line) in content.lines().enumerate() {
            if re.is_match(line) {
                if !file_has_match {
                    file_has_match = true;
                    matched_file_tokens += count_tokens(&content);
                }
                let short_path = protocol::shorten_path(&path.to_string_lossy());
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
        return (
            format!("0 matches for '{pattern}' in {files_searched} files"),
            0,
        );
    }

    let mut result = format!(
        "{} matches in {} files:\n{}",
        matches.len(),
        files_searched,
        matches.join("\n")
    );

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

    let sent = count_tokens(&result);
    let savings = protocol::format_savings(matched_file_tokens, sent);

    (format!("{result}\n{savings}"), matched_file_tokens)
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
    )
}
