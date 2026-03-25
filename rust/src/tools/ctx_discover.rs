use std::collections::HashMap;

use crate::core::tokens::count_tokens;

const COMPRESSIBLE_COMMANDS: &[(&str, &str, &str)] = &[
    ("git", "git status/diff/log/add/commit/push", "80-95%"),
    ("cargo", "cargo build/test/clippy", "80-95%"),
    ("npm", "npm install/run/test", "60-85%"),
    ("pnpm", "pnpm install/run/test", "60-85%"),
    ("yarn", "yarn install/run/test", "60-85%"),
    ("docker", "docker ps/images/logs/build", "60-80%"),
    ("kubectl", "kubectl get/describe/logs", "60-80%"),
    ("pip", "pip install/list/freeze", "60-85%"),
    ("go", "go test/build/vet", "75-90%"),
    ("ruff", "ruff check/format", "80-90%"),
    ("eslint", "eslint/biome lint", "80-90%"),
    ("prettier", "prettier --check", "70-80%"),
    ("tsc", "TypeScript compiler", "80-90%"),
    ("curl", "HTTP requests", "60-80%"),
    ("grep", "grep/rg search", "50-80%"),
    ("find", "find files", "50-70%"),
    ("ls", "directory listing", "50-70%"),
    ("pytest", "Python tests", "85-95%"),
    ("rspec", "Ruby tests", "60-80%"),
    ("aws", "AWS CLI", "60-80%"),
    ("helm", "Kubernetes Helm", "60-80%"),
    ("terraform", "Terraform", "60-80%"),
    ("ansible", "Ansible", "60-80%"),
    ("prisma", "Prisma ORM", "70-85%"),
    ("cmake", "CMake build", "60-80%"),
    ("bazel", "Bazel build", "60-80%"),
    ("zig", "Zig build/test", "60-80%"),
    ("swift", "Swift build/test", "60-80%"),
    ("deno", "Deno runtime", "60-80%"),
    ("bun", "Bun runtime", "60-80%"),
    ("composer", "PHP Composer", "60-80%"),
    ("mix", "Elixir Mix", "60-80%"),
];

pub fn discover_from_history(history: &[String], limit: usize) -> String {
    let mut missed: HashMap<&str, u32> = HashMap::new();
    let mut already_optimized = 0u32;
    let mut total_commands = 0u32;

    for cmd in history {
        let trimmed = cmd.trim();
        if trimmed.is_empty() { continue; }
        total_commands += 1;

        if trimmed.starts_with("lean-ctx ") {
            already_optimized += 1;
            continue;
        }

        for (prefix, _, _) in COMPRESSIBLE_COMMANDS {
            if trimmed.starts_with(prefix) || trimmed.starts_with(&format!("{prefix} ")) {
                *missed.entry(prefix).or_insert(0) += 1;
                break;
            }
        }
    }

    if missed.is_empty() {
        return format!("No missed savings found in last {total_commands} commands. \
            {already_optimized} already optimized.");
    }

    let mut sorted: Vec<_> = missed.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let mut result = Vec::new();
    result.push(format!("Analyzed {total_commands} commands ({already_optimized} already optimized):"));
    result.push(String::new());

    let total_missed: u32 = sorted.iter().map(|(_, c)| c).sum();
    result.push(format!("{total_missed} commands could benefit from lean-ctx:"));
    result.push(String::new());

    for (prefix, count) in sorted.iter().take(limit) {
        let info = COMPRESSIBLE_COMMANDS.iter()
            .find(|(p, _, _)| p == prefix)
            .map(|(_, desc, savings)| format!("{desc} ({savings})"))
            .unwrap_or_default();
        result.push(format!("  {count:>4}x  {prefix:<12} {info}"));
    }

    let est_tokens_per_cmd = 500;
    let est_savings_pct = 0.75;
    let potential = (total_missed as f64 * est_tokens_per_cmd as f64 * est_savings_pct) as usize;
    let potential_usd = potential as f64 * 2.50 / 1_000_000.0;

    result.push(String::new());
    result.push(format!("Estimated potential: ~{potential} tokens saved (~${potential_usd:.2})"));
    result.push(String::new());
    result.push("Fix: run 'lean-ctx init --global' to auto-compress all commands.".to_string());
    result.push("Or:  run 'lean-ctx init --agent <tool>' for AI tool hooks.".to_string());

    let output = result.join("\n");
    let tokens = count_tokens(&output);
    format!("{output}\n\n[{tokens} tok]")
}
