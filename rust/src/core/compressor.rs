use similar::{ChangeTag, TextDiff};

pub fn aggressive_compress(content: &str, ext: Option<&str>) -> String {
    let mut result = Vec::new();
    let is_python = matches!(ext, Some("py"));
    let is_html = matches!(ext, Some("html" | "htm" | "xml" | "svg"));
    let is_sql = matches!(ext, Some("sql"));
    let is_shell = matches!(ext, Some("sh" | "bash" | "zsh" | "fish"));

    let mut in_block_comment = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        if in_block_comment {
            if trimmed.contains("*/") || (is_html && trimmed.contains("-->")) {
                in_block_comment = false;
            }
            continue;
        }

        if trimmed.starts_with("/*") || (is_html && trimmed.starts_with("<!--")) {
            if !(trimmed.contains("*/") || trimmed.contains("-->")) {
                in_block_comment = true;
            }
            continue;
        }

        if trimmed.starts_with("//") && !trimmed.starts_with("///") {
            continue;
        }
        if trimmed.starts_with('*') || trimmed.starts_with("*/") {
            continue;
        }
        if is_python && trimmed.starts_with('#') {
            continue;
        }
        if is_sql && trimmed.starts_with("--") {
            continue;
        }
        if is_shell && trimmed.starts_with('#') && !trimmed.starts_with("#!") {
            continue;
        }
        if !is_python && trimmed.starts_with('#') && trimmed.contains('[') {
            continue;
        }

        if trimmed == "}" || trimmed == "};" || trimmed == ");" || trimmed == "});" {
            result.push(trimmed.to_string());
            continue;
        }

        let normalized = normalize_indentation(line);
        result.push(normalized);
    }

    result.join("\n")
}

fn normalize_indentation(line: &str) -> String {
    let content = line.trim_start();
    let leading = line.len() - content.len();
    let has_tabs = line.starts_with('\t');
    let reduced = if has_tabs { leading } else { leading / 2 };
    format!("{}{}", " ".repeat(reduced), content)
}

pub fn diff_content(old_content: &str, new_content: &str) -> String {
    if old_content == new_content {
        return "∅ no changes".to_string();
    }

    let diff = TextDiff::from_lines(old_content, new_content);
    let mut changes = Vec::new();
    let mut additions = 0usize;
    let mut deletions = 0usize;

    for change in diff.iter_all_changes() {
        let line_no = change.new_index().or(change.old_index()).map(|i| i + 1);
        let text = change.value().trim_end_matches('\n');
        match change.tag() {
            ChangeTag::Insert => {
                additions += 1;
                if let Some(n) = line_no {
                    changes.push(format!("+{n}: {text}"));
                }
            }
            ChangeTag::Delete => {
                deletions += 1;
                if let Some(n) = line_no {
                    changes.push(format!("-{n}: {text}"));
                }
            }
            ChangeTag::Equal => {}
        }
    }

    if changes.is_empty() {
        return "∅ no changes".to_string();
    }

    changes.push(format!("\n∂ +{additions}/-{deletions} lines"));
    changes.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_insertion() {
        let old = "line1\nline2\nline3";
        let new = "line1\nline2\nnew_line\nline3";
        let result = diff_content(old, new);
        assert!(result.contains("+"), "should show additions");
        assert!(result.contains("new_line"));
    }

    #[test]
    fn test_diff_deletion() {
        let old = "line1\nline2\nline3";
        let new = "line1\nline3";
        let result = diff_content(old, new);
        assert!(result.contains("-"), "should show deletions");
        assert!(result.contains("line2"));
    }

    #[test]
    fn test_diff_no_changes() {
        let content = "same\ncontent";
        assert_eq!(diff_content(content, content), "∅ no changes");
    }

    #[test]
    fn test_aggressive_strips_comments() {
        let code = "fn main() {\n    // a comment\n    let x = 1;\n}";
        let result = aggressive_compress(code, Some("rs"));
        assert!(!result.contains("// a comment"));
        assert!(result.contains("let x = 1"));
    }

    #[test]
    fn test_aggressive_python_comments() {
        let code = "def main():\n    # comment\n    x = 1";
        let result = aggressive_compress(code, Some("py"));
        assert!(!result.contains("# comment"));
        assert!(result.contains("x = 1"));
    }

    #[test]
    fn test_aggressive_preserves_doc_comments() {
        let code = "/// Doc comment\nfn main() {}";
        let result = aggressive_compress(code, Some("rs"));
        assert!(result.contains("/// Doc comment"));
    }

    #[test]
    fn test_aggressive_block_comment() {
        let code = "/* start\n * middle\n */ end\nfn main() {}";
        let result = aggressive_compress(code, Some("rs"));
        assert!(!result.contains("start"));
        assert!(!result.contains("middle"));
        assert!(result.contains("fn main()"));
    }
}
