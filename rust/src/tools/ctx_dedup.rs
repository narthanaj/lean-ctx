use std::collections::HashMap;

use crate::core::cache::SessionCache;
use crate::core::tokens::count_tokens;

pub fn handle(cache: &SessionCache) -> String {
    let entries = cache.get_all_entries();
    if entries.len() < 2 {
        return "Need at least 2 cached files for cross-file deduplication analysis.".to_string();
    }

    let mut import_patterns: HashMap<String, Vec<String>> = HashMap::new();
    let mut boilerplate_blocks: HashMap<String, Vec<String>> = HashMap::new();

    for (path, entry) in &entries {
        let lines: Vec<&str> = entry.content.lines().collect();

        let imports: Vec<&str> = lines.iter().copied()
            .filter(|l| {
                let t = l.trim();
                t.starts_with("import ") || t.starts_with("use ") ||
                t.starts_with("from ") || t.starts_with("require(") ||
                t.starts_with("#include")
            })
            .collect();

        for imp in &imports {
            let key = imp.trim().to_string();
            import_patterns.entry(key).or_default().push(path.to_string());
        }

        for chunk in lines.chunks(5) {
            if chunk.len() == 5 {
                let block = chunk.join("\n");
                let block_trimmed = block.trim().to_string();
                if !block_trimmed.is_empty() && count_tokens(&block_trimmed) > 10 {
                    boilerplate_blocks.entry(block_trimmed).or_default().push(path.to_string());
                }
            }
        }
    }

    let shared_imports: Vec<_> = import_patterns.iter()
        .filter(|(_, files)| files.len() >= 2)
        .collect();

    let shared_blocks: Vec<_> = boilerplate_blocks.iter()
        .filter(|(_, files)| {
            let unique: std::collections::HashSet<_> = files.iter().collect();
            unique.len() >= 2
        })
        .collect();

    let mut result = Vec::new();
    result.push(format!("Cross-file deduplication analysis ({} cached files):", entries.len()));

    if !shared_imports.is_empty() {
        let total_import_tokens: usize = shared_imports.iter()
            .map(|(imp, files)| count_tokens(imp) * (files.len() - 1))
            .sum();

        result.push(format!("\nShared imports ({}, ~{total_import_tokens} redundant tokens):",
            shared_imports.len()));
        for (imp, files) in shared_imports.iter().take(10) {
            let short_files: Vec<String> = files.iter()
                .map(|f| crate::core::protocol::shorten_path(f))
                .collect();
            result.push(format!("  {imp}"));
            result.push(format!("    in: {}", short_files.join(", ")));
        }
        if shared_imports.len() > 10 {
            result.push(format!("  ... +{} more", shared_imports.len() - 10));
        }
    }

    if !shared_blocks.is_empty() {
        let total_block_tokens: usize = shared_blocks.iter()
            .map(|(block, files)| {
                let unique: std::collections::HashSet<_> = files.iter().collect();
                count_tokens(block) * (unique.len() - 1)
            })
            .sum();

        result.push(format!("\nShared code blocks ({}, ~{total_block_tokens} redundant tokens):",
            shared_blocks.len()));
        for (block, files) in shared_blocks.iter().take(5) {
            let unique: std::collections::HashSet<_> = files.iter().collect();
            let preview = block.lines().next().unwrap_or("...");
            result.push(format!("  \"{preview}...\" (in {} files)", unique.len()));
        }
    }

    if shared_imports.is_empty() && shared_blocks.is_empty() {
        result.push("\nNo significant cross-file duplication detected.".to_string());
    } else {
        let total_savings: usize = shared_imports.iter()
            .map(|(imp, files)| count_tokens(imp) * (files.len() - 1))
            .sum::<usize>()
            + shared_blocks.iter()
                .map(|(block, files)| {
                    let unique: std::collections::HashSet<_> = files.iter().collect();
                    count_tokens(block) * (unique.len() - 1)
                })
                .sum::<usize>();

        result.push(format!("\nTotal potential savings: ~{total_savings} tokens"));
    }

    result.join("\n")
}
