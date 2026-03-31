use std::path::PathBuf;

const MARKER: &str = "# lean-ctx — Context Engineering Layer";
const END_MARKER: &str = "<!-- /lean-ctx -->";
const RULES_VERSION: &str = "lean-ctx-rules-v3";

// ---------------------------------------------------------------------------
// Rules content for SHARED config files (appended to user's existing config).
// Concise but forceful — these live alongside user's own rules.
// Used for: CLAUDE.md, instructions.md, GEMINI.md, copilot-instructions.md
// ---------------------------------------------------------------------------
const RULES_SHARED: &str = r#"# lean-ctx — Context Engineering Layer
<!-- lean-ctx-rules-v3 -->

CRITICAL RULE: You have lean-ctx MCP tools connected. You MUST use them for ALL file reads,
shell commands, and code searches. Using native tools instead wastes tokens and is FORBIDDEN.

## Tool replacements (MANDATORY — no exceptions):
| FORBIDDEN | USE INSTEAD | Saves |
|-----------|-------------|-------|
| Read, cat, head, tail | ctx_read | 40-90% via caching + compression |
| Shell, bash, terminal | ctx_shell | 30-70% via pattern compression |
| Grep, rg, search | ctx_search | 50-80% via compact results |
| ls, find, tree | ctx_tree | 60-85% via directory maps |

## Native tools to keep using (no lean-ctx replacement):
Write, StrReplace, Delete, Glob — use these normally.

## If you catch yourself about to use Read, Shell, Grep, or ls:
STOP. Use ctx_read, ctx_shell, ctx_search, or ctx_tree instead. Every time.
<!-- /lean-ctx -->"#;

// ---------------------------------------------------------------------------
// Rules content for DEDICATED lean-ctx rule files (we control entire file).
// Detailed with examples — these are standalone lean-ctx instruction files.
// Used for: Windsurf, Zed, Cline, Roo Code, OpenCode, Continue, Aider
// ---------------------------------------------------------------------------
const RULES_DEDICATED: &str = r#"# lean-ctx — Context Engineering Layer
<!-- lean-ctx-rules-v3 -->

You are connected to the lean-ctx MCP server, which provides optimized replacements for
built-in file, shell, and search tools. Using the lean-ctx tools is MANDATORY — not optional.

## MANDATORY tool replacements:

| FORBIDDEN tool | REQUIRED replacement | Why |
|----------------|---------------------|-----|
| `Read` / `cat` / `head` / `tail` | `ctx_read(path)` | Cached reads, 6 compression modes, re-reads cost ~13 tokens |
| `Shell` / `bash` / terminal | `ctx_shell(command)` | Pattern-based output compression for git, npm, cargo, docker |
| `Grep` / `rg` / `search` | `ctx_search(pattern, path)` | Compact context-aware results, token-efficient |
| `ls` / `find` / `tree` | `ctx_tree(path, depth)` | Compact directory maps with file counts |

## ctx_read modes (use the right mode for the job):
- `full` — default, cached read. Use for files you will edit.
- `map` — dependency graph + exports + key signatures. Use for context-only files.
- `signatures` — API surface only. Use for large files you just need the structure of.
- `diff` — changed lines only. Use after your own edits to verify.
- `aggressive` — syntax stripped. Use for very large files.
- `entropy` — Shannon + Jaccard filtering. Use for noisy files.
- `lines:N-M` — specific line range. Use when you know exactly what you need.

## Tools you KEEP using (no lean-ctx replacement):
- `Write` — create/overwrite files
- `StrReplace` — edit files in place
- `Delete` — delete files
- `Glob` — find files by glob pattern

## ABSOLUTE RULES — violations waste user tokens:
1. NEVER use `Read` to read a file — always use `ctx_read`
2. NEVER use `Shell` to run a command — always use `ctx_shell`
3. NEVER use `Grep` or `rg` to search — always use `ctx_search`
4. NEVER use `ls`, `find`, `cat`, `head`, `tail` — always use `ctx_tree` or `ctx_read`
5. You do NOT need to `ctx_read` a file before creating it with `Write`
6. If `ctx_read` returns "cached" and you need fresh content, set `fresh=true`

## Proactive tools (use without being asked):
- `ctx_overview(task)` — at session start, get task-relevant project map
- `ctx_compress` — when context grows large, create checkpoint
- `ctx_metrics` — periodically verify token savings
<!-- /lean-ctx -->"#;

// ---------------------------------------------------------------------------
// Rules for Cursor MDC format (dedicated file with frontmatter).
// alwaysApply: true ensures this is loaded into EVERY conversation.
// ---------------------------------------------------------------------------
const RULES_CURSOR_MDC: &str = r#"---
description: "lean-ctx: ALWAYS use ctx_read/ctx_shell/ctx_search/ctx_tree instead of Read/Shell/Grep/ls"
alwaysApply: true
---

# lean-ctx — Context Engineering Layer
<!-- lean-ctx-rules-v3 -->

You are connected to the lean-ctx MCP server. You MUST use lean-ctx tools for ALL file reads,
shell commands, and code searches. Using native tools instead is FORBIDDEN — it wastes tokens.

## MANDATORY tool replacements:

| FORBIDDEN | USE INSTEAD | Why |
|-----------|-------------|-----|
| `Read` / `cat` / `head` / `tail` | `ctx_read(path)` | Cached, 6 compression modes, re-reads ~13 tokens |
| `Shell` / `bash` / terminal | `ctx_shell(command)` | Pattern compression for git/npm/cargo/docker output |
| `Grep` / `rg` / `search` | `ctx_search(pattern, path)` | Compact, token-efficient results |
| `ls` / `find` / `tree` | `ctx_tree(path, depth)` | Compact directory maps with file counts |

## ctx_read modes:
- `full` — cached read (for files you edit)
- `map` — deps + API (context-only files)
- `signatures` — API surface only
- `diff` — changed lines after edits
- `aggressive` — syntax stripped
- `entropy` — Shannon + Jaccard filtering
- `lines:N-M` — specific range

## Keep using (no lean-ctx replacement):
`Write`, `StrReplace`, `Delete`, `Glob` — use normally.

## NEVER do this:
- NEVER use `Read` to read files — use `ctx_read`
- NEVER use `Shell` to run commands — use `ctx_shell`
- NEVER use `Grep` to search code — use `ctx_search`
- NEVER use `ls`, `find`, `cat`, `head`, `tail` — use `ctx_tree` or `ctx_read`
- If `ctx_read` returns "cached", use `fresh=true` to re-read

## Proactive (use without being asked):
- `ctx_overview(task)` at session start
- `ctx_compress` when context grows large
- `ctx_metrics` to verify savings
<!-- /lean-ctx -->"#;

// ---------------------------------------------------------------------------

struct RulesTarget {
    name: &'static str,
    path: PathBuf,
    format: RulesFormat,
}

enum RulesFormat {
    SharedMarkdown,
    DedicatedMarkdown,
    CursorMdc,
}

pub struct InjectResult {
    pub injected: Vec<String>,
    pub updated: Vec<String>,
    pub already: Vec<String>,
    pub errors: Vec<String>,
}

pub fn inject_all_rules(home: &std::path::Path) -> InjectResult {
    let targets = build_rules_targets(home);

    let mut result = InjectResult {
        injected: Vec::new(),
        updated: Vec::new(),
        already: Vec::new(),
        errors: Vec::new(),
    };

    for target in &targets {
        if !is_tool_detected(target, home) {
            continue;
        }

        match inject_rules(target) {
            Ok(RulesResult::Injected) => result.injected.push(target.name.to_string()),
            Ok(RulesResult::Updated) => result.updated.push(target.name.to_string()),
            Ok(RulesResult::AlreadyPresent) => result.already.push(target.name.to_string()),
            Err(e) => result.errors.push(format!("{}: {e}", target.name)),
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Injection logic
// ---------------------------------------------------------------------------

enum RulesResult {
    Injected,
    Updated,
    AlreadyPresent,
}

fn rules_content(format: &RulesFormat) -> &'static str {
    match format {
        RulesFormat::SharedMarkdown => RULES_SHARED,
        RulesFormat::DedicatedMarkdown => RULES_DEDICATED,
        RulesFormat::CursorMdc => RULES_CURSOR_MDC,
    }
}

fn inject_rules(target: &RulesTarget) -> Result<RulesResult, String> {
    if target.path.exists() {
        let content = std::fs::read_to_string(&target.path).map_err(|e| e.to_string())?;
        if content.contains(MARKER) {
            if content.contains(RULES_VERSION) {
                return Ok(RulesResult::AlreadyPresent);
            }
            ensure_parent(&target.path)?;
            return match target.format {
                RulesFormat::SharedMarkdown => replace_markdown_section(&target.path, &content),
                RulesFormat::DedicatedMarkdown | RulesFormat::CursorMdc => {
                    write_dedicated(&target.path, rules_content(&target.format))
                }
            };
        }
    }

    ensure_parent(&target.path)?;

    match target.format {
        RulesFormat::SharedMarkdown => append_to_shared(&target.path),
        RulesFormat::DedicatedMarkdown | RulesFormat::CursorMdc => {
            write_dedicated(&target.path, rules_content(&target.format))
        }
    }
}

fn ensure_parent(path: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn append_to_shared(path: &std::path::Path) -> Result<RulesResult, String> {
    let mut content = if path.exists() {
        std::fs::read_to_string(path).map_err(|e| e.to_string())?
    } else {
        String::new()
    };

    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    if !content.is_empty() {
        content.push('\n');
    }
    content.push_str(RULES_SHARED);
    content.push('\n');

    std::fs::write(path, content).map_err(|e| e.to_string())?;
    Ok(RulesResult::Injected)
}

fn replace_markdown_section(path: &std::path::Path, content: &str) -> Result<RulesResult, String> {
    let start = content.find(MARKER);
    let end = content.find(END_MARKER);

    let new_content = match (start, end) {
        (Some(s), Some(e)) => {
            let before = &content[..s];
            let after_end = e + END_MARKER.len();
            let after = content[after_end..].trim_start_matches('\n');
            let mut result = before.to_string();
            result.push_str(RULES_SHARED);
            if !after.is_empty() {
                result.push('\n');
                result.push_str(after);
            }
            result
        }
        (Some(s), None) => {
            let before = &content[..s];
            let mut result = before.to_string();
            result.push_str(RULES_SHARED);
            result.push('\n');
            result
        }
        _ => return Ok(RulesResult::AlreadyPresent),
    };

    std::fs::write(path, new_content).map_err(|e| e.to_string())?;
    Ok(RulesResult::Updated)
}

fn write_dedicated(path: &std::path::Path, content: &'static str) -> Result<RulesResult, String> {
    let is_update = path.exists() && {
        let existing = std::fs::read_to_string(path).unwrap_or_default();
        existing.contains(MARKER)
    };

    std::fs::write(path, content).map_err(|e| e.to_string())?;

    if is_update {
        Ok(RulesResult::Updated)
    } else {
        Ok(RulesResult::Injected)
    }
}

// ---------------------------------------------------------------------------
// Tool detection
// ---------------------------------------------------------------------------

fn is_tool_detected(target: &RulesTarget, home: &std::path::Path) -> bool {
    match target.name {
        "Claude Code" => {
            if command_exists("claude") {
                return true;
            }
            home.join(".claude.json").exists() || home.join(".claude").exists()
        }
        "Codex CLI" => home.join(".codex").exists() || command_exists("codex"),
        "Cursor" => home.join(".cursor").exists(),
        "Windsurf" => home.join(".codeium/windsurf").exists(),
        "Gemini CLI" => home.join(".gemini").exists(),
        "VS Code / Copilot" => detect_vscode_installed(home),
        "Zed" => home.join(".config/zed").exists(),
        "Cline" => detect_extension_installed(home, "saoudrizwan.claude-dev"),
        "Roo Code" => detect_extension_installed(home, "rooveterinaryinc.roo-cline"),
        "OpenCode" => home.join(".config/opencode").exists(),
        "Continue" => detect_extension_installed(home, "continue.continue"),
        "Aider" => command_exists("aider") || home.join(".aider.conf.yml").exists(),
        "Amp" => command_exists("amp") || home.join(".ampcoder").exists(),
        _ => false,
    }
}

fn command_exists(name: &str) -> bool {
    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("where")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    #[cfg(not(target_os = "windows"))]
    let result = std::process::Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    result
}

fn detect_vscode_installed(home: &std::path::Path) -> bool {
    let check_dir = |dir: PathBuf| -> bool {
        dir.join("settings.json").exists() || dir.join("mcp.json").exists()
    };

    #[cfg(target_os = "macos")]
    if check_dir(home.join("Library/Application Support/Code/User")) {
        return true;
    }
    #[cfg(target_os = "linux")]
    if check_dir(home.join(".config/Code/User")) {
        return true;
    }
    #[cfg(target_os = "windows")]
    if let Ok(appdata) = std::env::var("APPDATA") {
        if check_dir(PathBuf::from(&appdata).join("Code/User")) {
            return true;
        }
    }
    false
}

fn detect_extension_installed(home: &std::path::Path, extension_id: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        if home
            .join(format!(
                "Library/Application Support/Code/User/globalStorage/{extension_id}"
            ))
            .exists()
        {
            return true;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if home
            .join(format!(".config/Code/User/globalStorage/{extension_id}"))
            .exists()
        {
            return true;
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if std::path::PathBuf::from(&appdata)
                .join(format!("Code/User/globalStorage/{extension_id}"))
                .exists()
            {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Target definitions
// ---------------------------------------------------------------------------

fn build_rules_targets(home: &std::path::Path) -> Vec<RulesTarget> {
    vec![
        // --- Shared config files (append-only) ---
        RulesTarget {
            name: "Claude Code",
            path: home.join(".claude/CLAUDE.md"),
            format: RulesFormat::SharedMarkdown,
        },
        RulesTarget {
            name: "Codex CLI",
            path: home.join(".codex/instructions.md"),
            format: RulesFormat::SharedMarkdown,
        },
        RulesTarget {
            name: "Gemini CLI",
            path: home.join(".gemini/GEMINI.md"),
            format: RulesFormat::SharedMarkdown,
        },
        RulesTarget {
            name: "VS Code / Copilot",
            path: copilot_instructions_path(home),
            format: RulesFormat::SharedMarkdown,
        },
        // --- Dedicated lean-ctx rule files ---
        RulesTarget {
            name: "Cursor",
            path: home.join(".cursor/rules/lean-ctx.mdc"),
            format: RulesFormat::CursorMdc,
        },
        RulesTarget {
            name: "Windsurf",
            path: home.join(".codeium/windsurf/rules/lean-ctx.md"),
            format: RulesFormat::DedicatedMarkdown,
        },
        RulesTarget {
            name: "Zed",
            path: home.join(".config/zed/rules/lean-ctx.md"),
            format: RulesFormat::DedicatedMarkdown,
        },
        RulesTarget {
            name: "Cline",
            path: home.join(".cline/rules/lean-ctx.md"),
            format: RulesFormat::DedicatedMarkdown,
        },
        RulesTarget {
            name: "Roo Code",
            path: home.join(".roo/rules/lean-ctx.md"),
            format: RulesFormat::DedicatedMarkdown,
        },
        RulesTarget {
            name: "OpenCode",
            path: home.join(".config/opencode/rules/lean-ctx.md"),
            format: RulesFormat::DedicatedMarkdown,
        },
        RulesTarget {
            name: "Continue",
            path: home.join(".continue/rules/lean-ctx.md"),
            format: RulesFormat::DedicatedMarkdown,
        },
        RulesTarget {
            name: "Aider",
            path: home.join(".aider/rules/lean-ctx.md"),
            format: RulesFormat::DedicatedMarkdown,
        },
        RulesTarget {
            name: "Amp",
            path: home.join(".ampcoder/rules/lean-ctx.md"),
            format: RulesFormat::DedicatedMarkdown,
        },
    ]
}

fn copilot_instructions_path(home: &std::path::Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        return home.join("Library/Application Support/Code/User/github-copilot-instructions.md");
    }
    #[cfg(target_os = "linux")]
    {
        return home.join(".config/Code/User/github-copilot-instructions.md");
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("Code/User/github-copilot-instructions.md");
        }
    }
    #[allow(unreachable_code)]
    home.join(".config/Code/User/github-copilot-instructions.md")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_rules_have_markers() {
        assert!(RULES_SHARED.contains(MARKER));
        assert!(RULES_SHARED.contains(END_MARKER));
        assert!(RULES_SHARED.contains(RULES_VERSION));
    }

    #[test]
    fn dedicated_rules_have_markers() {
        assert!(RULES_DEDICATED.contains(MARKER));
        assert!(RULES_DEDICATED.contains(END_MARKER));
        assert!(RULES_DEDICATED.contains(RULES_VERSION));
    }

    #[test]
    fn cursor_mdc_has_markers_and_frontmatter() {
        assert!(RULES_CURSOR_MDC.contains(MARKER));
        assert!(RULES_CURSOR_MDC.contains(END_MARKER));
        assert!(RULES_CURSOR_MDC.contains(RULES_VERSION));
        assert!(RULES_CURSOR_MDC.contains("alwaysApply: true"));
    }

    #[test]
    fn shared_rules_contain_forbidden_table() {
        assert!(RULES_SHARED.contains("FORBIDDEN"));
        assert!(RULES_SHARED.contains("ctx_read"));
        assert!(RULES_SHARED.contains("ctx_shell"));
        assert!(RULES_SHARED.contains("ctx_search"));
        assert!(RULES_SHARED.contains("ctx_tree"));
    }

    #[test]
    fn dedicated_rules_contain_modes() {
        assert!(RULES_DEDICATED.contains("full"));
        assert!(RULES_DEDICATED.contains("map"));
        assert!(RULES_DEDICATED.contains("signatures"));
        assert!(RULES_DEDICATED.contains("diff"));
        assert!(RULES_DEDICATED.contains("aggressive"));
        assert!(RULES_DEDICATED.contains("entropy"));
    }

    #[test]
    fn replace_section_with_end_marker() {
        let old = "user stuff\n\n# lean-ctx — Context Engineering Layer\n<!-- lean-ctx-rules-v2 -->\nold rules\n<!-- /lean-ctx -->\nmore user stuff\n";
        let path = std::env::temp_dir().join("test_replace_with_end.md");
        std::fs::write(&path, old).unwrap();

        let result = replace_markdown_section(&path, old).unwrap();
        assert!(matches!(result, RulesResult::Updated));

        let new_content = std::fs::read_to_string(&path).unwrap();
        assert!(new_content.contains("lean-ctx-rules-v3"));
        assert!(new_content.starts_with("user stuff"));
        assert!(new_content.contains("more user stuff"));
        assert!(!new_content.contains("lean-ctx-rules-v2"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn replace_section_without_end_marker() {
        let old = "user stuff\n\n# lean-ctx — Context Engineering Layer\nold rules only\n";
        let path = std::env::temp_dir().join("test_replace_no_end.md");
        std::fs::write(&path, old).unwrap();

        let result = replace_markdown_section(&path, old).unwrap();
        assert!(matches!(result, RulesResult::Updated));

        let new_content = std::fs::read_to_string(&path).unwrap();
        assert!(new_content.contains("lean-ctx-rules-v3"));
        assert!(new_content.starts_with("user stuff"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn append_to_shared_preserves_existing() {
        let path = std::env::temp_dir().join("test_append_shared.md");
        std::fs::write(&path, "existing user rules\n").unwrap();

        let result = append_to_shared(&path).unwrap();
        assert!(matches!(result, RulesResult::Injected));

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("existing user rules"));
        assert!(content.contains(MARKER));
        assert!(content.contains(END_MARKER));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_dedicated_creates_file() {
        let path = std::env::temp_dir().join("test_write_dedicated.md");
        if path.exists() {
            std::fs::remove_file(&path).ok();
        }

        let result = write_dedicated(&path, RULES_DEDICATED).unwrap();
        assert!(matches!(result, RulesResult::Injected));

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(MARKER));
        assert!(content.contains("ctx_read modes"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_dedicated_updates_existing() {
        let path = std::env::temp_dir().join("test_write_dedicated_update.md");
        std::fs::write(&path, "# lean-ctx — Context Engineering Layer\nold version").unwrap();

        let result = write_dedicated(&path, RULES_DEDICATED).unwrap();
        assert!(matches!(result, RulesResult::Updated));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn target_count() {
        let home = std::path::PathBuf::from("/tmp/fake_home");
        let targets = build_rules_targets(&home);
        assert_eq!(targets.len(), 13);
    }
}
