use std::path::Path;

use crate::core::cache::SessionCache;
use crate::core::compressor;
use crate::core::deps;
use crate::core::entropy;
use crate::core::protocol;
use crate::core::signatures;
use crate::core::tokens::count_tokens;

pub fn handle(cache: &mut SessionCache, path: &str, mode: &str) -> String {
    let file_ref = cache.get_file_ref(path);
    let short = protocol::shorten_path(path);
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if mode == "diff" {
        return handle_diff(cache, path, &file_ref);
    }

    if let Some(existing) = cache.get(path) {
        if mode == "full" {
            let msg = format!(
                "{file_ref}={short} [cached {}t {}L ∅]",
                existing.read_count + 1,
                existing.line_count
            );
            let (_, _is_hit) = cache.store(path, existing.content.clone());
            return msg;
        }
        let content = existing.content.clone();
        let original_tokens = existing.original_tokens;
        return process_mode(&content, mode, &file_ref, &short, ext, original_tokens);
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return format!("ERROR: {e}"),
    };

    let (entry, _is_hit) = cache.store(path, content.clone());

    if mode == "full" {
        let tokens = entry.original_tokens;
        let header = build_header(&file_ref, &short, ext, &content, entry.line_count, true);
        let output = format!("{header}\n{content}");
        let sent = count_tokens(&output);
        let savings = protocol::format_savings(tokens, sent);
        return format!("{output}\n{savings}");
    }

    process_mode(&content, mode, &file_ref, &short, ext, entry.original_tokens)
}

fn build_header(file_ref: &str, short: &str, ext: &str, content: &str, line_count: usize, include_deps: bool) -> String {
    let mut header = format!("{file_ref}={short} [{line_count}L +]");

    if include_deps {
        let dep_info = deps::extract_deps(content, ext);
        if !dep_info.imports.is_empty() {
            let imports_str: Vec<&str> = dep_info.imports.iter().take(8).map(|s| s.as_str()).collect();
            header.push_str(&format!(" deps:[{}]", imports_str.join(",")));
        }
        if !dep_info.exports.is_empty() {
            let exports_str: Vec<&str> = dep_info.exports.iter().take(8).map(|s| s.as_str()).collect();
            header.push_str(&format!(" exports:[{}]", exports_str.join(",")));
        }
    }

    header
}

fn process_mode(content: &str, mode: &str, file_ref: &str, short: &str, ext: &str, original_tokens: usize) -> String {
    let line_count = content.lines().count();

    match mode {
        "signatures" => {
            let sigs = signatures::extract_signatures(content, ext);
            let dep_info = deps::extract_deps(content, ext);

            let mut output = format!("{file_ref}={short} [{line_count}L]");
            if !dep_info.imports.is_empty() {
                let imports_str: Vec<&str> = dep_info.imports.iter().take(8).map(|s| s.as_str()).collect();
                output.push_str(&format!(" deps:[{}]", imports_str.join(",")));
            }
            for sig in &sigs {
                output.push('\n');
                output.push_str(&sig.to_compact());
            }
            let sent = count_tokens(&output);
            let savings = protocol::format_savings(original_tokens, sent);
            format!("{output}\n{savings}")
        }
        "map" => {
            let sigs = signatures::extract_signatures(content, ext);
            let dep_info = deps::extract_deps(content, ext);

            let mut output = format!("{file_ref}={short} [{line_count}L]");

            if !dep_info.imports.is_empty() {
                output.push_str("\n  deps: ");
                output.push_str(&dep_info.imports.join(", "));
            }

            if !dep_info.exports.is_empty() {
                output.push_str("\n  exports: ");
                output.push_str(&dep_info.exports.join(", "));
            }

            let key_sigs: Vec<&signatures::Signature> = sigs
                .iter()
                .filter(|s| s.is_exported || s.indent == 0)
                .collect();

            if !key_sigs.is_empty() {
                output.push_str("\n  API:");
                for sig in &key_sigs {
                    output.push_str(&format!("\n    {}", sig.to_compact()));
                }
            }

            let sent = count_tokens(&output);
            let savings = protocol::format_savings(original_tokens, sent);
            format!("{output}\n{savings}")
        }
        "aggressive" => {
            let compressed = compressor::aggressive_compress(content);
            let header = build_header(file_ref, short, ext, content, line_count, true);
            let sent = count_tokens(&compressed);
            let savings = protocol::format_savings(original_tokens, sent);
            format!("{header}\n{compressed}\n{savings}")
        }
        "entropy" => {
            let result = entropy::entropy_compress(content);
            let avg_h = entropy::analyze_entropy(content).avg_entropy;
            let header = build_header(file_ref, short, ext, content, line_count, false);
            let mut output = format!("{header} (H̄={avg_h:.1})");
            for tech in &result.techniques {
                output.push('\n');
                output.push_str(tech);
            }
            output.push('\n');
            output.push_str(&result.output);
            let sent = count_tokens(&output);
            let savings = protocol::format_savings(original_tokens, sent);
            format!("{output}\n{savings}")
        }
        _ => {
            let header = build_header(file_ref, short, ext, content, line_count, true);
            format!("{header}\n{content}")
        }
    }
}

fn handle_diff(cache: &mut SessionCache, path: &str, file_ref: &str) -> String {
    let short = protocol::shorten_path(path);
    let old_content = cache.get(path).map(|e| e.content.clone());

    let new_content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return format!("ERROR: {e}"),
    };

    let original_tokens = count_tokens(&new_content);

    let diff_output = if let Some(old) = &old_content {
        compressor::diff_content(old, &new_content)
    } else {
        format!("[first read]\n{new_content}")
    };

    cache.store(path, new_content);

    let sent = count_tokens(&diff_output);
    let savings = protocol::format_savings(original_tokens, sent);
    format!("{file_ref}={short} [diff]\n{diff_output}\n{savings}")
}
