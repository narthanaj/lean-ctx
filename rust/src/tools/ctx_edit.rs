use std::path::{Path, PathBuf};

use crate::core::cache::SessionCache;
use crate::core::pathjail;
use crate::core::tokens::count_tokens;

pub struct EditParams {
    pub path: String,
    pub old_string: String,
    pub new_string: String,
    pub replace_all: bool,
    pub create: bool,
}

/// Apply the project jail to an LLM-supplied edit target path. Unlike the
/// read-side jail, edits may target a file that does not yet exist (when
/// `create: true`), so we can't rely on `open_in_jail`'s existence check.
/// Instead we validate the *parent* directory is inside the jail and
/// prevent `..` escape via the same logical-normalize pass pathjail uses
/// internally.
///
/// Returns the absolute path cleared for write, or an LLM-surfaceable error
/// string. The jail is applied at this tool boundary rather than inside
/// `std::fs::write` so CLI-driven writes (which aren't attacker-influenced)
/// continue to work.
fn jail_edit_target(path: &str, allow_create: bool) -> Result<PathBuf, String> {
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

    // For an existing file we can canonicalize. For create-new we can't —
    // the file isn't there yet — so we canonicalize the nearest existing
    // ancestor and append the remaining suffix, verifying the ancestor
    // lands inside the jail.
    let canonical = match std::fs::canonicalize(&target) {
        Ok(p) => p,
        Err(_) if allow_create => {
            // Walk up until we find an ancestor that exists; canonicalize
            // that; re-append the tail. If no ancestor exists, the write
            // will fail anyway and we let that happen with a normal I/O
            // error downstream.
            // Walk up until we hit an existing ancestor, collecting the
            // non-existent tail components front-to-back so we can re-join
            // them in order after canonicalizing the ancestor.
            //
            // Note: we can't use `Path::join` on an empty PathBuf to start
            // — that produces a trailing slash on the first iteration
            // (e.g. `Path::new("file.txt").join("")` == `"file.txt/"`).
            // Collecting names into a Vec and joining at the end avoids it.
            let mut ancestor = target.as_path();
            let mut tail_names: Vec<std::ffi::OsString> = Vec::new();
            while !ancestor.exists() {
                match ancestor.file_name() {
                    Some(name) => tail_names.push(name.to_os_string()),
                    None => return Err(format!("ERROR: cannot resolve '{path}'")),
                }
                match ancestor.parent() {
                    Some(p) => ancestor = p,
                    None => return Err(format!("ERROR: cannot resolve '{path}'")),
                }
            }
            let canon_ancestor = std::fs::canonicalize(ancestor)
                .map_err(|e| format!("ERROR: cannot resolve '{path}': {e}"))?;
            let mut out = canon_ancestor;
            for name in tail_names.iter().rev() {
                out.push(name);
            }
            out
        }
        Err(e) => return Err(format!("ERROR: cannot resolve '{path}': {e}")),
    };

    let mut allowed = vec![jail_root];
    allowed.extend(pathjail::allow_list_roots());
    if !allowed.iter().any(|r| canonical.starts_with(r)) {
        return Err(format!(
            "ERROR: '{path}' is outside the project jail (blocked by lean-ctx path jail)"
        ));
    }
    Ok(canonical)
}

pub fn handle(cache: &mut SessionCache, params: EditParams) -> String {
    let file_path = &params.path;

    // Phase 0 security gate. Both create-new and edit-existing go through
    // the same jail — an attacker-supplied path to `/etc/crontab` is as bad
    // as one to `/etc/shadow`. We also enforce the size cap on the read
    // path for edit-existing so a 10 GiB file can't OOM us before replace.
    let jailed_path = match jail_edit_target(file_path, params.create) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let jailed_str = jailed_path.to_string_lossy().to_string();
    let file_path: &str = &jailed_str;

    if params.create {
        return handle_create(cache, file_path, &params.new_string);
    }

    // Enforce MAX_READ_BYTES for the pre-edit read. If the file is over cap,
    // refuse the edit rather than silently truncate — partial edits would be
    // catastrophic. Use the FD-based jail open so we can fstat safely.
    let jail_root = match pathjail::session_jail_root() {
        Ok(r) => r,
        Err(e) => return format!("ERROR: {e} (blocked by lean-ctx path jail)"),
    };
    match pathjail::open_in_jail(file_path, &jail_root) {
        Ok(jailed) if jailed.size_bytes > pathjail::max_read_bytes() => {
            return format!(
                "ERROR: {file_path} is {} bytes, exceeds MAX_READ_BYTES ({}). \
                 Refusing to edit an oversized file. Adjust LCTX_MAX_READ_BYTES or edit manually.",
                jailed.size_bytes,
                pathjail::max_read_bytes()
            );
        }
        Ok(_) => { /* size OK, proceed */ }
        Err(e) => return format!("ERROR: {e} (blocked by lean-ctx path jail)"),
    }

    let raw_bytes = match std::fs::read(file_path) {
        Ok(b) => b,
        Err(e) => return format!("ERROR: cannot read {file_path}: {e}"),
    };

    let content = String::from_utf8_lossy(&raw_bytes).into_owned();

    if params.old_string.is_empty() {
        return "ERROR: old_string must not be empty (use create=true to create a new file)".into();
    }

    let uses_crlf = content.contains("\r\n");
    let old_str = &params.old_string;
    let new_str = &params.new_string;

    let occurrences = content.matches(old_str).count();

    if occurrences > 0 {
        return do_replace(
            cache,
            file_path,
            &content,
            old_str,
            new_str,
            occurrences,
            &params,
        );
    }

    // Direct match failed -- try CRLF/LF normalization
    if uses_crlf && !old_str.contains('\r') {
        let old_crlf = old_str.replace('\n', "\r\n");
        let occ = content.matches(&old_crlf).count();
        if occ > 0 {
            let new_crlf = new_str.replace('\n', "\r\n");
            return do_replace(
                cache, file_path, &content, &old_crlf, &new_crlf, occ, &params,
            );
        }
    } else if !uses_crlf && old_str.contains("\r\n") {
        let old_lf = old_str.replace("\r\n", "\n");
        let occ = content.matches(&old_lf).count();
        if occ > 0 {
            let new_lf = new_str.replace("\r\n", "\n");
            return do_replace(cache, file_path, &content, &old_lf, &new_lf, occ, &params);
        }
    }

    // Still not found -- try trimmed trailing whitespace per line
    let normalized_content = trim_trailing_per_line(&content);
    let normalized_old = trim_trailing_per_line(old_str);
    if !normalized_old.is_empty() && normalized_content.contains(&normalized_old) {
        let line_sep = if uses_crlf { "\r\n" } else { "\n" };
        let adapted_new = adapt_new_string_to_line_sep(new_str, line_sep);
        let adapted_old = find_original_span(&content, &normalized_old);
        if let Some(original_match) = adapted_old {
            let occ = content.matches(&original_match).count();
            return do_replace(
                cache,
                file_path,
                &content,
                &original_match,
                &adapted_new,
                occ,
                &params,
            );
        }
    }

    let preview = if old_str.len() > 80 {
        format!("{}...", &old_str[..77])
    } else {
        old_str.clone()
    };
    let hint = if uses_crlf {
        " (file uses CRLF line endings)"
    } else {
        ""
    };
    format!(
        "ERROR: old_string not found in {file_path}{hint}. \
         Make sure it matches exactly (including whitespace/indentation).\n\
         Searched for: {preview}"
    )
}

fn do_replace(
    cache: &mut SessionCache,
    file_path: &str,
    content: &str,
    old_str: &str,
    new_str: &str,
    occurrences: usize,
    params: &EditParams,
) -> String {
    if occurrences > 1 && !params.replace_all {
        return format!(
            "ERROR: old_string found {occurrences} times in {file_path}. \
             Use replace_all=true to replace all, or provide more context to make old_string unique."
        );
    }

    let new_content = if params.replace_all {
        content.replace(old_str, new_str)
    } else {
        content.replacen(old_str, new_str, 1)
    };

    if let Err(e) = std::fs::write(file_path, &new_content) {
        return format!("ERROR: cannot write {file_path}: {e}");
    }

    cache.invalidate(file_path);

    let old_lines = content.lines().count();
    let new_lines = new_content.lines().count();
    let line_delta = new_lines as i64 - old_lines as i64;
    let delta_str = if line_delta > 0 {
        format!("+{line_delta}")
    } else {
        format!("{line_delta}")
    };

    let old_tokens = count_tokens(&params.old_string);
    let new_tokens = count_tokens(&params.new_string);

    let replaced_str = if params.replace_all && occurrences > 1 {
        format!("{occurrences} replacements")
    } else {
        "1 replacement".into()
    };

    let short = Path::new(file_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| file_path.to_string());

    format!("✓ {short}: {replaced_str}, {delta_str} lines ({old_tokens}→{new_tokens} tok)")
}

fn handle_create(cache: &mut SessionCache, file_path: &str, content: &str) -> String {
    if let Some(parent) = Path::new(file_path).parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return format!("ERROR: cannot create directory {}: {e}", parent.display());
            }
        }
    }

    if let Err(e) = std::fs::write(file_path, content) {
        return format!("ERROR: cannot write {file_path}: {e}");
    }

    cache.invalidate(file_path);

    let lines = content.lines().count();
    let tokens = count_tokens(content);
    let short = Path::new(file_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| file_path.to_string());

    format!("✓ created {short}: {lines} lines, {tokens} tok")
}

fn trim_trailing_per_line(s: &str) -> String {
    s.lines()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
}

fn adapt_new_string_to_line_sep(s: &str, sep: &str) -> String {
    let normalized = s.replace("\r\n", "\n");
    if sep == "\r\n" {
        normalized.replace('\n', "\r\n")
    } else {
        normalized
    }
}

/// Find the original (un-trimmed) span in `content` that matches `normalized_needle`
/// after trailing-whitespace trimming per line.
fn find_original_span(content: &str, normalized_needle: &str) -> Option<String> {
    let needle_lines: Vec<&str> = normalized_needle.lines().collect();
    if needle_lines.is_empty() {
        return None;
    }

    let content_lines: Vec<&str> = content.lines().collect();

    'outer: for start in 0..content_lines.len() {
        if start + needle_lines.len() > content_lines.len() {
            break;
        }
        for (i, nl) in needle_lines.iter().enumerate() {
            if content_lines[start + i].trim_end() != *nl {
                continue 'outer;
            }
        }
        let sep = if content.contains("\r\n") {
            "\r\n"
        } else {
            "\n"
        };
        return Some(content_lines[start..start + needle_lines.len()].join(sep));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Tests create tempfiles in `std::env::temp_dir()` for isolation, which
    /// lives outside any real project root. This helper registers that
    /// directory in `LCTX_ALLOW_PATH` once per process so the path-jail
    /// accepts them — equivalent to what a real user does when they need
    /// to read outside their repo.
    fn init_test_allow_path() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let tmp = std::env::temp_dir();
            // Canonicalize so the string-prefix check matches what the jail
            // observes after canonicalization.
            let tmp = std::fs::canonicalize(&tmp).unwrap_or(tmp);
            let existing = std::env::var(crate::core::pathjail::ENV_ALLOW_PATHS).unwrap_or_default();
            let joined = if existing.is_empty() {
                tmp.display().to_string()
            } else {
                format!("{}:{}", existing, tmp.display())
            };
            std::env::set_var(crate::core::pathjail::ENV_ALLOW_PATHS, joined);
        });
    }

    fn make_temp(content: &str) -> NamedTempFile {
        init_test_allow_path();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn replace_single_occurrence() {
        let f = make_temp("fn hello() {\n    println!(\"hello\");\n}\n");
        let mut cache = SessionCache::new();
        let result = handle(
            &mut cache,
            EditParams {
                path: f.path().to_str().unwrap().to_string(),
                old_string: "hello".into(),
                new_string: "world".into(),
                replace_all: false,
                create: false,
            },
        );
        assert!(result.contains("ERROR"), "should fail: 'hello' appears 2x");
    }

    #[test]
    fn replace_all() {
        let f = make_temp("aaa bbb aaa\n");
        let mut cache = SessionCache::new();
        let result = handle(
            &mut cache,
            EditParams {
                path: f.path().to_str().unwrap().to_string(),
                old_string: "aaa".into(),
                new_string: "ccc".into(),
                replace_all: true,
                create: false,
            },
        );
        assert!(result.contains("2 replacements"));
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert_eq!(content, "ccc bbb ccc\n");
    }

    #[test]
    fn not_found_error() {
        let f = make_temp("some content\n");
        let mut cache = SessionCache::new();
        let result = handle(
            &mut cache,
            EditParams {
                path: f.path().to_str().unwrap().to_string(),
                old_string: "nonexistent".into(),
                new_string: "x".into(),
                replace_all: false,
                create: false,
            },
        );
        assert!(result.contains("ERROR: old_string not found"));
    }

    #[test]
    fn create_new_file() {
        init_test_allow_path();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/new_file.txt");
        let mut cache = SessionCache::new();
        let result = handle(
            &mut cache,
            EditParams {
                path: path.to_str().unwrap().to_string(),
                old_string: String::new(),
                new_string: "line1\nline2\nline3\n".into(),
                replace_all: false,
                create: true,
            },
        );
        assert!(
            result.contains("created new_file.txt"),
            "unexpected result: {result}"
        );
        assert!(result.contains("3 lines"));
        assert!(path.exists());
    }

    #[test]
    fn unique_match_succeeds() {
        let f = make_temp("fn main() {\n    let x = 42;\n}\n");
        let mut cache = SessionCache::new();
        let result = handle(
            &mut cache,
            EditParams {
                path: f.path().to_str().unwrap().to_string(),
                old_string: "let x = 42".into(),
                new_string: "let x = 99".into(),
                replace_all: false,
                create: false,
            },
        );
        assert!(result.contains("✓"));
        assert!(result.contains("1 replacement"));
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert!(content.contains("let x = 99"));
    }

    #[test]
    fn crlf_file_with_lf_search() {
        let f = make_temp("line1\r\nline2\r\nline3\r\n");
        let mut cache = SessionCache::new();
        let result = handle(
            &mut cache,
            EditParams {
                path: f.path().to_str().unwrap().to_string(),
                old_string: "line1\nline2".into(),
                new_string: "changed1\nchanged2".into(),
                replace_all: false,
                create: false,
            },
        );
        assert!(result.contains("✓"), "CRLF fallback should work: {result}");
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert!(
            content.contains("changed1\r\nchanged2"),
            "new_string should be adapted to CRLF: {content:?}"
        );
        assert!(
            content.contains("\r\nline3\r\n"),
            "rest of file should keep CRLF: {content:?}"
        );
    }

    #[test]
    fn lf_file_with_crlf_search() {
        let f = make_temp("line1\nline2\nline3\n");
        let mut cache = SessionCache::new();
        let result = handle(
            &mut cache,
            EditParams {
                path: f.path().to_str().unwrap().to_string(),
                old_string: "line1\r\nline2".into(),
                new_string: "a\r\nb".into(),
                replace_all: false,
                create: false,
            },
        );
        assert!(result.contains("✓"), "LF fallback should work: {result}");
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert!(
            content.contains("a\nb"),
            "new_string should be adapted to LF: {content:?}"
        );
    }

    #[test]
    fn trailing_whitespace_tolerance() {
        let f = make_temp("  let x = 1;  \n  let y = 2;\n");
        let mut cache = SessionCache::new();
        let result = handle(
            &mut cache,
            EditParams {
                path: f.path().to_str().unwrap().to_string(),
                old_string: "  let x = 1;\n  let y = 2;".into(),
                new_string: "  let x = 10;\n  let y = 20;".into(),
                replace_all: false,
                create: false,
            },
        );
        assert!(
            result.contains("✓"),
            "trailing whitespace tolerance should work: {result}"
        );
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert!(content.contains("let x = 10;"));
        assert!(content.contains("let y = 20;"));
    }

    #[test]
    fn crlf_with_trailing_whitespace() {
        let f = make_temp("  const a = 1;  \r\n  const b = 2;\r\n");
        let mut cache = SessionCache::new();
        let result = handle(
            &mut cache,
            EditParams {
                path: f.path().to_str().unwrap().to_string(),
                old_string: "  const a = 1;\n  const b = 2;".into(),
                new_string: "  const a = 10;\n  const b = 20;".into(),
                replace_all: false,
                create: false,
            },
        );
        assert!(
            result.contains("✓"),
            "CRLF + trailing whitespace should work: {result}"
        );
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert!(content.contains("const a = 10;"));
        assert!(content.contains("const b = 20;"));
    }
}
