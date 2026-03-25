use std::path::PathBuf;

pub fn install_agent_hook(agent: &str) {
    match agent {
        "claude" | "claude-code" => install_claude_hook(),
        "cursor" => install_cursor_hook(),
        "gemini" => install_gemini_hook(),
        "codex" => install_codex_hook(),
        "windsurf" => install_windsurf_rules(),
        "cline" | "roo" => install_cline_rules(),
        "copilot" => install_claude_hook(),
        _ => {
            eprintln!("Unknown agent: {agent}");
            eprintln!("Supported: claude, cursor, gemini, codex, windsurf, cline, copilot");
            std::process::exit(1);
        }
    }
}

fn install_claude_hook() {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => { eprintln!("Cannot resolve home directory"); return; }
    };

    let hooks_dir = home.join(".claude").join("hooks");
    let _ = std::fs::create_dir_all(&hooks_dir);

    let script_path = hooks_dir.join("lean-ctx-rewrite.sh");
    let script = r#"#!/usr/bin/env bash
# lean-ctx PreToolUse hook — rewrites bash commands to lean-ctx equivalents
set -euo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | grep -o '"tool_name":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ "$TOOL" != "Bash" ] && [ "$TOOL" != "bash" ]; then
  exit 0
fi

CMD=$(echo "$INPUT" | grep -o '"command":"[^"]*"' | head -1 | cut -d'"' -f4)

if echo "$CMD" | grep -q "^lean-ctx "; then
  exit 0
fi

REWRITE=""
case "$CMD" in
  git\ *)       REWRITE="lean-ctx -c $CMD" ;;
  gh\ *)        REWRITE="lean-ctx -c $CMD" ;;
  cargo\ *)     REWRITE="lean-ctx -c $CMD" ;;
  npm\ *)       REWRITE="lean-ctx -c $CMD" ;;
  pnpm\ *)      REWRITE="lean-ctx -c $CMD" ;;
  yarn\ *)      REWRITE="lean-ctx -c $CMD" ;;
  docker\ *)    REWRITE="lean-ctx -c $CMD" ;;
  kubectl\ *)   REWRITE="lean-ctx -c $CMD" ;;
  pip\ *|pip3\ *)  REWRITE="lean-ctx -c $CMD" ;;
  ruff\ *)      REWRITE="lean-ctx -c $CMD" ;;
  go\ *)        REWRITE="lean-ctx -c $CMD" ;;
  curl\ *)      REWRITE="lean-ctx -c $CMD" ;;
  grep\ *|rg\ *)  REWRITE="lean-ctx -c $CMD" ;;
  find\ *)      REWRITE="lean-ctx -c $CMD" ;;
  cat\ *|head\ *|tail\ *)  REWRITE="lean-ctx -c $CMD" ;;
  ls\ *|ls)     REWRITE="lean-ctx -c $CMD" ;;
  eslint*|prettier*|tsc*)  REWRITE="lean-ctx -c $CMD" ;;
  pytest*|ruff\ *|mypy*)   REWRITE="lean-ctx -c $CMD" ;;
  aws\ *)       REWRITE="lean-ctx -c $CMD" ;;
  helm\ *)      REWRITE="lean-ctx -c $CMD" ;;
  *)            exit 0 ;;
esac

if [ -n "$REWRITE" ]; then
  echo "{\"command\":\"$REWRITE\"}"
fi
"#;

    write_file(&script_path, script);
    make_executable(&script_path);

    let settings_path = home.join(".claude").join("settings.json");
    let settings_content = if settings_path.exists() {
        std::fs::read_to_string(&settings_path).unwrap_or_default()
    } else {
        String::new()
    };

    if settings_content.contains("lean-ctx-rewrite") {
        println!("Claude Code hook already configured.");
    } else {
        let hook_entry = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash|bash",
                    "hooks": [{
                        "type": "command",
                        "command": script_path.to_string_lossy()
                    }]
                }]
            }
        });

        if settings_content.is_empty() {
            write_file(&settings_path, &serde_json::to_string_pretty(&hook_entry).unwrap());
        } else if let Ok(mut existing) = serde_json::from_str::<serde_json::Value>(&settings_content) {
            if let Some(obj) = existing.as_object_mut() {
                obj.insert("hooks".to_string(), hook_entry["hooks"].clone());
                write_file(&settings_path, &serde_json::to_string_pretty(&existing).unwrap());
            }
        }
        println!("Installed Claude Code PreToolUse hook at {}", script_path.display());
    }
}

fn install_cursor_hook() {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => { eprintln!("Cannot resolve home directory"); return; }
    };

    let hooks_dir = home.join(".cursor").join("hooks");
    let _ = std::fs::create_dir_all(&hooks_dir);

    let script_path = hooks_dir.join("lean-ctx-rewrite.sh");
    let script = r#"#!/usr/bin/env bash
# lean-ctx Cursor hook — rewrites shell commands
set -euo pipefail
INPUT=$(cat)
CMD=$(echo "$INPUT" | grep -o '"command":"[^"]*"' | head -1 | cut -d'"' -f4 2>/dev/null || echo "")
if [ -z "$CMD" ] || echo "$CMD" | grep -q "^lean-ctx "; then exit 0; fi
case "$CMD" in
  git\ *|gh\ *|cargo\ *|npm\ *|pnpm\ *|docker\ *|kubectl\ *|pip\ *|ruff\ *|go\ *|curl\ *|grep\ *|rg\ *|find\ *|ls\ *|ls|cat\ *|aws\ *|helm\ *)
    echo "{\"command\":\"lean-ctx -c $CMD\"}" ;;
  *) exit 0 ;;
esac
"#;

    write_file(&script_path, script);
    make_executable(&script_path);

    let hooks_json = home.join(".cursor").join("hooks.json");
    let hook_config = serde_json::json!({
        "hooks": [{
            "event": "preToolUse",
            "matcher": {
                "tool": "terminal_command"
            },
            "command": script_path.to_string_lossy()
        }]
    });

    let content = if hooks_json.exists() {
        std::fs::read_to_string(&hooks_json).unwrap_or_default()
    } else {
        String::new()
    };

    if content.contains("lean-ctx-rewrite") {
        println!("Cursor hook already configured.");
    } else {
        write_file(&hooks_json, &serde_json::to_string_pretty(&hook_config).unwrap());
        println!("Installed Cursor hook at {}", hooks_json.display());
    }

    println!("Restart Cursor to activate.");
}

fn install_gemini_hook() {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => { eprintln!("Cannot resolve home directory"); return; }
    };

    let hooks_dir = home.join(".gemini").join("hooks");
    let _ = std::fs::create_dir_all(&hooks_dir);

    let script_path = hooks_dir.join("lean-ctx-hook-gemini.sh");
    let script = r#"#!/usr/bin/env bash
# lean-ctx Gemini CLI BeforeTool hook
set -euo pipefail
INPUT=$(cat)
CMD=$(echo "$INPUT" | grep -o '"command":"[^"]*"' | head -1 | cut -d'"' -f4 2>/dev/null || echo "")
if [ -z "$CMD" ] || echo "$CMD" | grep -q "^lean-ctx "; then exit 0; fi
case "$CMD" in
  git\ *|gh\ *|cargo\ *|npm\ *|pnpm\ *|docker\ *|kubectl\ *|pip\ *|ruff\ *|go\ *|curl\ *|grep\ *|rg\ *|find\ *|ls\ *|ls|cat\ *|aws\ *|helm\ *)
    echo "{\"command\":\"lean-ctx -c $CMD\"}" ;;
  *) exit 0 ;;
esac
"#;

    write_file(&script_path, script);
    make_executable(&script_path);

    let settings_path = home.join(".gemini").join("settings.json");
    let settings_content = if settings_path.exists() {
        std::fs::read_to_string(&settings_path).unwrap_or_default()
    } else {
        String::new()
    };

    if settings_content.contains("lean-ctx") {
        println!("Gemini CLI hook already configured.");
    } else {
        let hook_config = serde_json::json!({
            "hooks": {
                "BeforeTool": [{
                    "command": script_path.to_string_lossy()
                }]
            }
        });

        if settings_content.is_empty() {
            write_file(&settings_path, &serde_json::to_string_pretty(&hook_config).unwrap());
        } else if let Ok(mut existing) = serde_json::from_str::<serde_json::Value>(&settings_content) {
            if let Some(obj) = existing.as_object_mut() {
                obj.insert("hooks".to_string(), hook_config["hooks"].clone());
                write_file(&settings_path, &serde_json::to_string_pretty(&existing).unwrap());
            }
        }
        println!("Installed Gemini CLI hook at {}", script_path.display());
    }
}

fn install_codex_hook() {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => { eprintln!("Cannot resolve home directory"); return; }
    };

    let codex_dir = home.join(".codex");
    let _ = std::fs::create_dir_all(&codex_dir);

    let agents_path = codex_dir.join("AGENTS.md");
    let agents_content = "# Global Agent Instructions\n\n@LEAN-CTX.md\n";

    let lean_ctx_md = codex_dir.join("LEAN-CTX.md");
    let lean_ctx_content = r#"# lean-ctx — Token Optimization

Prefix all shell commands with `lean-ctx -c` for compressed output:

```bash
lean-ctx -c git status    # instead of: git status
lean-ctx -c cargo test    # instead of: cargo test
lean-ctx -c ls src/       # instead of: ls src/
```

This saves 60-90% tokens per command. Works with: git, cargo, npm, pnpm, docker, kubectl, pip, ruff, go, curl, grep, find, ls, aws, helm, and 75+ more commands.
"#;

    if agents_path.exists() {
        let content = std::fs::read_to_string(&agents_path).unwrap_or_default();
        if content.contains("lean-ctx") || content.contains("LEAN-CTX") {
            println!("Codex AGENTS.md already configured.");
            return;
        }
    }

    write_file(&agents_path, agents_content);
    write_file(&lean_ctx_md, lean_ctx_content);
    println!("Installed Codex instructions at {}", codex_dir.display());
}

fn install_windsurf_rules() {
    let rules_path = PathBuf::from(".windsurfrules");
    if rules_path.exists() {
        let content = std::fs::read_to_string(&rules_path).unwrap_or_default();
        if content.contains("lean-ctx") {
            println!(".windsurfrules already configured.");
            return;
        }
    }

    let rules = r#"# lean-ctx Shell Optimization
# Prefix all shell commands with `lean-ctx -c` for 60-90% token savings.
# Example: `lean-ctx -c git status` instead of `git status`
# Supported: git, cargo, npm, pnpm, docker, kubectl, pip, ruff, go, curl, grep, find, ls, aws, helm, and 75+ more.

When running shell commands, always prefix them with `lean-ctx -c` to compress output and save tokens. For example:
- `lean-ctx -c git status` instead of `git status`
- `lean-ctx -c cargo test` instead of `cargo test`
- `lean-ctx -c npm install` instead of `npm install`
"#;

    write_file(&rules_path, rules);
    println!("Installed .windsurfrules in current project.");
}

fn install_cline_rules() {
    let rules_path = PathBuf::from(".clinerules");
    if rules_path.exists() {
        let content = std::fs::read_to_string(&rules_path).unwrap_or_default();
        if content.contains("lean-ctx") {
            println!(".clinerules already configured.");
            return;
        }
    }

    let rules = r#"# lean-ctx Shell Optimization
# Prefix all shell commands with `lean-ctx -c` for 60-90% token savings.

When running shell commands, always prefix them with `lean-ctx -c` to compress output. For example:
- `lean-ctx -c git status` instead of `git status`
- `lean-ctx -c cargo test` instead of `cargo test`
- `lean-ctx -c ls src/` instead of `ls src/`

Supported commands: git, cargo, npm, pnpm, docker, kubectl, pip, ruff, go, curl, grep, find, ls, aws, helm, and 75+ more.
"#;

    write_file(&rules_path, rules);
    println!("Installed .clinerules in current project.");
}

fn write_file(path: &PathBuf, content: &str) {
    if let Err(e) = std::fs::write(path, content) {
        eprintln!("Error writing {}: {e}", path.display());
    }
}

#[cfg(unix)]
fn make_executable(path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn make_executable(_path: &PathBuf) {}
