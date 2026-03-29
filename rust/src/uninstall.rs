use std::fs;
use std::path::{Path, PathBuf};

pub fn run() {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => {
            eprintln!("  ✗ Could not determine home directory");
            return;
        }
    };

    println!("\n  lean-ctx uninstall\n  ──────────────────────────────────\n");

    let mut removed_any = false;

    removed_any |= remove_shell_hook(&home);
    removed_any |= remove_mcp_configs(&home);
    removed_any |= remove_data_dir(&home);

    println!();

    if removed_any {
        println!("  ──────────────────────────────────");
        println!("  lean-ctx configuration removed.\n");
    } else {
        println!("  Nothing to remove — lean-ctx was not configured.\n");
    }

    print_binary_removal_instructions();
}

fn remove_shell_hook(home: &Path) -> bool {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let mut removed = false;

    let rc_files: Vec<PathBuf> = vec![
        home.join(".zshrc"),
        home.join(".bashrc"),
        home.join(".config/fish/config.fish"),
        #[cfg(windows)]
        home.join("Documents/PowerShell/Microsoft.PowerShell_profile.ps1"),
    ];

    for rc in &rc_files {
        if !rc.exists() {
            continue;
        }
        let content = match fs::read_to_string(rc) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !content.contains("lean-ctx") {
            continue;
        }

        let cleaned = remove_lean_ctx_block(&content);
        if cleaned.trim() != content.trim() {
            if let Err(e) = fs::write(rc, &cleaned) {
                eprintln!("  ✗ Failed to update {}: {}", rc.display(), e);
            } else {
                let short = shorten(rc, home);
                println!("  ✓ Shell hook removed from {short}");
                removed = true;
            }
        }
    }

    if !removed && !shell.is_empty() {
        println!("  · No shell hook found");
    }

    removed
}

fn remove_mcp_configs(home: &Path) -> bool {
    let configs: Vec<(&str, PathBuf)> = vec![
        ("Cursor", home.join(".cursor/mcp.json")),
        ("Claude Code", home.join(".claude.json")),
        ("Windsurf", home.join(".codeium/windsurf/mcp_config.json")),
        ("Gemini CLI", home.join(".gemini/settings/mcp.json")),
        (
            "Antigravity",
            home.join(".gemini/antigravity/mcp_config.json"),
        ),
        ("Codex CLI", home.join(".codex/config.toml")),
        ("OpenCode", home.join(".config/opencode/opencode.json")),
        ("Qwen Code", home.join(".qwen/mcp.json")),
        ("Trae", home.join(".trae/mcp.json")),
        ("Amazon Q Developer", home.join(".aws/amazonq/mcp.json")),
        ("JetBrains IDEs", home.join(".jb-mcp.json")),
    ];

    let mut removed = false;

    for (name, path) in &configs {
        if !path.exists() {
            continue;
        }
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !content.contains("lean-ctx") {
            continue;
        }

        if let Some(cleaned) = remove_lean_ctx_from_json(&content) {
            if let Err(e) = fs::write(path, &cleaned) {
                eprintln!("  ✗ Failed to update {} config: {}", name, e);
            } else {
                println!("  ✓ MCP config removed from {name}");
                removed = true;
            }
        }
    }

    let zed_path = zed_settings_path(home);
    if zed_path.exists() {
        if let Ok(content) = fs::read_to_string(&zed_path) {
            if content.contains("lean-ctx") {
                println!(
                    "  ⚠ Zed: manually remove lean-ctx from {}",
                    shorten(&zed_path, home)
                );
            }
        }
    }

    let vscode_path = vscode_mcp_path();
    if vscode_path.exists() {
        if let Ok(content) = fs::read_to_string(&vscode_path) {
            if content.contains("lean-ctx") {
                if let Some(cleaned) = remove_lean_ctx_from_json(&content) {
                    if let Err(e) = fs::write(&vscode_path, &cleaned) {
                        eprintln!("  ✗ Failed to update VS Code config: {e}");
                    } else {
                        println!("  ✓ MCP config removed from VS Code / Copilot");
                        removed = true;
                    }
                }
            }
        }
    }

    removed
}

fn remove_data_dir(home: &Path) -> bool {
    let data_dir = home.join(".lean-ctx");
    if !data_dir.exists() {
        println!("  · No data directory found");
        return false;
    }

    match fs::remove_dir_all(&data_dir) {
        Ok(_) => {
            println!("  ✓ Data directory removed (~/.lean-ctx/)");
            true
        }
        Err(e) => {
            eprintln!("  ✗ Failed to remove ~/.lean-ctx/: {e}");
            false
        }
    }
}

fn print_binary_removal_instructions() {
    let binary_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "lean-ctx".to_string());

    println!("  To complete uninstallation, remove the binary:\n");

    if binary_path.contains(".cargo") {
        println!("    cargo uninstall lean-ctx\n");
    } else if binary_path.contains("homebrew") || binary_path.contains("Cellar") {
        println!("    brew uninstall lean-ctx\n");
    } else {
        println!("    rm {binary_path}\n");
    }

    println!("  Then restart your shell.\n");
}

fn remove_lean_ctx_block(content: &str) -> String {
    if content.contains("# lean-ctx shell hook — end") {
        return remove_lean_ctx_block_by_marker(content);
    }
    remove_lean_ctx_block_legacy(content)
}

fn remove_lean_ctx_block_by_marker(content: &str) -> String {
    let mut result = String::new();
    let mut in_block = false;

    for line in content.lines() {
        if !in_block && line.contains("lean-ctx shell hook") && !line.contains("end") {
            in_block = true;
            continue;
        }
        if in_block {
            if line.trim() == "# lean-ctx shell hook — end" {
                in_block = false;
            }
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}

fn remove_lean_ctx_block_legacy(content: &str) -> String {
    let mut result = String::new();
    let mut in_block = false;

    for line in content.lines() {
        if line.contains("lean-ctx shell hook") {
            in_block = true;
            continue;
        }
        if in_block {
            if line.trim() == "fi" || line.trim() == "end" || line.trim().is_empty() {
                if line.trim() == "fi" || line.trim() == "end" {
                    in_block = false;
                }
                continue;
            }
            if !line.starts_with("alias ") && !line.starts_with('\t') && !line.starts_with("if ") {
                in_block = false;
                result.push_str(line);
                result.push('\n');
            }
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}

fn remove_lean_ctx_from_json(content: &str) -> Option<String> {
    let mut parsed: serde_json::Value = serde_json::from_str(content).ok()?;

    let modified =
        if let Some(servers) = parsed.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
            servers.remove("lean-ctx").is_some()
        } else {
            false
        };

    if modified {
        Some(serde_json::to_string_pretty(&parsed).ok()? + "\n")
    } else {
        None
    }
}

fn shorten(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => path.display().to_string(),
    }
}

fn zed_settings_path(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Zed/settings.json")
    } else {
        home.join(".config/zed/settings.json")
    }
}

fn vscode_mcp_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        dirs::home_dir()
            .unwrap_or_default()
            .join("Library/Application Support/Code/User/settings.json")
    } else if cfg!(target_os = "windows") {
        dirs::home_dir()
            .unwrap_or_default()
            .join("AppData/Roaming/Code/User/settings.json")
    } else {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".config/Code/User/settings.json")
    }
}
