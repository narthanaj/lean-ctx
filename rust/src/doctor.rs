//! Environment diagnostics for lean-ctx installation and integration.

use std::net::TcpListener;
use std::path::PathBuf;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const BOLD: &str = "\x1b[1m";
const RST: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const WHITE: &str = "\x1b[97m";
const YELLOW: &str = "\x1b[33m";

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Outcome {
    ok: bool,
    line: String,
}

fn print_check(outcome: &Outcome) {
    let mark = if outcome.ok {
        format!("{GREEN}✓{RST}")
    } else {
        format!("{RED}✗{RST}")
    };
    println!("  {mark}  {}", outcome.line);
}

fn path_in_path_env() -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("lean-ctx");
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

fn resolve_lean_ctx_binary() -> Option<PathBuf> {
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("command -v lean-ctx")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

fn lean_ctx_version_from_path() -> Outcome {
    let output = match std::process::Command::new("lean-ctx")
        .args(["--version"])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return Outcome {
                ok: false,
                line: format!(
                    "{BOLD}lean-ctx version{RST}  {RED}failed to run `lean-ctx --version`: {e}{RST}"
                ),
            };
        }
    };
    if !output.status.success() {
        return Outcome {
            ok: false,
            line: format!(
                "{BOLD}lean-ctx version{RST}  {RED}`lean-ctx --version` exited with {}{RST}",
                output.status.code().unwrap_or(-1)
            ),
        };
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        return Outcome {
            ok: false,
            line: format!("{BOLD}lean-ctx version{RST}  {RED}empty output{RST}"),
        };
    }
    Outcome {
        ok: true,
        line: format!("{BOLD}lean-ctx version{RST}  {WHITE}{text}{RST}"),
    }
}

fn rc_contains_lean_ctx(path: &PathBuf) -> bool {
    match std::fs::read_to_string(path) {
        Ok(s) => s.contains("lean-ctx"),
        Err(_) => false,
    }
}

fn shell_aliases_outcome() -> Outcome {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => {
            return Outcome {
                ok: false,
                line: format!(
                    "{BOLD}Shell aliases{RST}  {RED}could not resolve home directory{RST}"
                ),
            };
        }
    };
    let zsh = home.join(".zshrc");
    let bash = home.join(".bashrc");
    let zsh_ok = rc_contains_lean_ctx(&zsh);
    let bash_ok = rc_contains_lean_ctx(&bash);
    if zsh_ok || bash_ok {
        let mut parts = Vec::new();
        if zsh_ok {
            parts.push(format!("{DIM}~/.zshrc{RST}"));
        }
        if bash_ok {
            parts.push(format!("{DIM}~/.bashrc{RST}"));
        }
        Outcome {
            ok: true,
            line: format!(
                "{BOLD}Shell aliases{RST}  {GREEN}lean-ctx referenced in {}{RST}",
                parts.join(", ")
            ),
        }
    } else {
        Outcome {
            ok: false,
            line: format!(
                "{BOLD}Shell aliases{RST}  {RED}no \"lean-ctx\" in ~/.zshrc or ~/.bashrc{RST}"
            ),
        }
    }
}

fn mcp_config_outcome() -> Outcome {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => {
            return Outcome {
                ok: false,
                line: format!(
                    "{BOLD}MCP config{RST}  {RED}could not resolve home directory{RST}"
                ),
            };
        }
    };
    let path = home.join(".cursor").join("mcp.json");
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            if content.contains("lean-ctx") {
                Outcome {
                    ok: true,
                    line: format!(
                        "{BOLD}MCP config{RST}  {GREEN}{DIM}~/.cursor/mcp.json{RST} contains lean-ctx"
                    ),
                }
            } else {
                Outcome {
                    ok: false,
                    line: format!(
                        "{BOLD}MCP config{RST}  {RED}{DIM}~/.cursor/mcp.json{RST} exists but does not reference lean-ctx"
                    ),
                }
            }
        }
        Err(_) => Outcome {
            ok: false,
            line: format!(
                "{BOLD}MCP config{RST}  {RED}missing or unreadable {DIM}~/.cursor/mcp.json{RST}"
            ),
        },
    }
}

fn port_3333_outcome() -> Outcome {
    match TcpListener::bind("127.0.0.1:3333") {
        Ok(_listener) => Outcome {
            ok: true,
            line: format!(
                "{BOLD}Dashboard port 3333{RST}  {GREEN}available on 127.0.0.1{RST}"
            ),
        },
        Err(e) => Outcome {
            ok: false,
            line: format!(
                "{BOLD}Dashboard port 3333{RST}  {RED}not available: {e}{RST}"
            ),
        },
    }
}

/// Run diagnostic checks and print colored results to stdout.
pub fn run() {
    let mut passed = 0u32;
    let total = 8u32;

    println!("{BOLD}{WHITE}lean-ctx doctor{RST}  {DIM}diagnostics{RST}\n");

    // 1) Binary on PATH
    let path_bin = resolve_lean_ctx_binary();
    let also_in_path_dirs = path_in_path_env();
    let bin_ok = path_bin.is_some() || also_in_path_dirs;
    if bin_ok {
        passed += 1;
    }
    let bin_line = if let Some(p) = path_bin {
        format!(
            "{BOLD}lean-ctx in PATH{RST}  {WHITE}{}{RST}",
            p.display()
        )
    } else if also_in_path_dirs {
        format!(
            "{BOLD}lean-ctx in PATH{RST}  {YELLOW}found via PATH walk (not resolved by `command -v`){RST}"
        )
    } else {
        format!("{BOLD}lean-ctx in PATH{RST}  {RED}not found{RST}")
    };
    print_check(&Outcome {
        ok: bin_ok,
        line: bin_line,
    });

    // 2) Version from PATH binary
    let ver = if bin_ok {
        lean_ctx_version_from_path()
    } else {
        Outcome {
            ok: false,
            line: format!(
                "{BOLD}lean-ctx version{RST}  {RED}skipped (binary not in PATH){RST}"
            ),
        }
    };
    if ver.ok {
        passed += 1;
    }
    print_check(&ver);

    // 3) ~/.lean-ctx directory
    let lean_dir = dirs::home_dir().map(|h| h.join(".lean-ctx"));
    let dir_outcome = match &lean_dir {
        Some(p) if p.is_dir() => {
            passed += 1;
            Outcome {
                ok: true,
                line: format!(
                    "{BOLD}~/.lean-ctx/{RST}  {GREEN}exists{RST}  {DIM}{}{RST}",
                    p.display()
                ),
            }
        }
        Some(p) => Outcome {
            ok: false,
            line: format!(
                "{BOLD}~/.lean-ctx/{RST}  {RED}missing or not a directory{RST}  {DIM}{}{RST}",
                p.display()
            ),
        },
        None => Outcome {
            ok: false,
            line: format!("{BOLD}~/.lean-ctx/{RST}  {RED}could not resolve home directory{RST}"),
        },
    };
    print_check(&dir_outcome);

    // 4) stats.json + size
    let stats_path = lean_dir.as_ref().map(|d| d.join("stats.json"));
    let stats_outcome = match stats_path.as_ref().and_then(|p| std::fs::metadata(p).ok()) {
        Some(m) if m.is_file() => {
            passed += 1;
            let size = m.len();
            Outcome {
                ok: true,
                line: format!(
                    "{BOLD}stats.json{RST}  {GREEN}exists{RST}  {WHITE}{size} bytes{RST}  {DIM}{}{RST}",
                    stats_path.as_ref().unwrap().display()
                ),
            }
        }
        Some(_m) => Outcome {
            ok: false,
            line: format!(
                "{BOLD}stats.json{RST}  {RED}not a file{RST}  {DIM}{}{RST}",
                stats_path.as_ref().unwrap().display()
            ),
        },
        None => Outcome {
            ok: false,
            line: match &stats_path {
                Some(p) => format!(
                    "{BOLD}stats.json{RST}  {RED}missing{RST}  {DIM}{}{RST}",
                    p.display()
                ),
                None => format!("{BOLD}stats.json{RST}  {RED}could not resolve path{RST}"),
            },
        },
    };
    print_check(&stats_outcome);

    // 5) config.toml (missing is OK)
    let config_path = lean_dir.as_ref().map(|d| d.join("config.toml"));
    let config_outcome = match &config_path {
        Some(p) => match std::fs::metadata(p) {
            Ok(m) if m.is_file() => {
                passed += 1;
                Outcome {
                    ok: true,
                    line: format!(
                        "{BOLD}config.toml{RST}  {GREEN}exists{RST}  {DIM}{}{RST}",
                        p.display()
                    ),
                }
            }
            Ok(_) => Outcome {
                ok: false,
                line: format!(
                    "{BOLD}config.toml{RST}  {RED}exists but is not a regular file{RST}  {DIM}{}{RST}",
                    p.display()
                ),
            },
            Err(_) => {
                passed += 1;
                Outcome {
                    ok: true,
                    line: format!(
                        "{BOLD}config.toml{RST}  {YELLOW}not found, using defaults{RST}  {DIM}(expected at {}){RST}",
                        p.display()
                    ),
                }
            }
        },
        None => Outcome {
            ok: false,
            line: format!("{BOLD}config.toml{RST}  {RED}could not resolve path{RST}"),
        },
    };
    print_check(&config_outcome);

    // 6) Shell aliases
    let aliases = shell_aliases_outcome();
    if aliases.ok {
        passed += 1;
    }
    print_check(&aliases);

    // 7) MCP
    let mcp = mcp_config_outcome();
    if mcp.ok {
        passed += 1;
    }
    print_check(&mcp);

    // 8) Port
    let port = port_3333_outcome();
    if port.ok {
        passed += 1;
    }
    print_check(&port);

    println!();
    println!(
        "  {BOLD}{WHITE}Summary:{RST}  {GREEN}{passed}{RST}{DIM}/{total}{RST} checks passed"
    );
    println!(
        "  {DIM}This binary: lean-ctx {VERSION} (Cargo package version){RST}"
    );
}
