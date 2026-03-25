use crate::core::tokens::count_tokens;
use crate::tools::CrpMode;

pub fn handle(response: &str, crp_mode: CrpMode) -> String {
    let original_tokens = count_tokens(response);

    if original_tokens <= 100 {
        return response.to_string();
    }

    let compressed = if crp_mode.is_tdd() {
        compress_tdd(response)
    } else {
        compress_standard(response)
    };

    let compressed_tokens = count_tokens(&compressed);
    let savings = original_tokens.saturating_sub(compressed_tokens);
    let pct = if original_tokens > 0 {
        (savings as f64 / original_tokens as f64 * 100.0) as u32
    } else {
        0
    };

    if savings < 20 {
        return response.to_string();
    }

    format!("{compressed}\n[response compressed: {original_tokens}→{compressed_tokens} tok, -{pct}%]")
}

fn compress_standard(text: &str) -> String {
    let mut result = Vec::new();
    let mut prev_empty = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            if !prev_empty {
                result.push(String::new());
                prev_empty = true;
            }
            continue;
        }
        prev_empty = false;

        if is_filler_line(trimmed) {
            continue;
        }

        result.push(line.to_string());
    }

    result.join("\n")
}

fn compress_tdd(text: &str) -> String {
    let mut result = Vec::new();
    let mut prev_empty = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            if !prev_empty {
                prev_empty = true;
            }
            continue;
        }
        prev_empty = false;

        if is_filler_line(trimmed) {
            continue;
        }

        let compressed = apply_tdd_shortcuts(trimmed);
        result.push(compressed);
    }

    result.join("\n")
}

fn is_filler_line(line: &str) -> bool {
    let l = line.to_lowercase();

    if l.starts_with("note:") || l.starts_with("hint:") {
        return false;
    }

    let fillers = [
        "here's what i", "let me explain", "i'll now", "as you can see",
        "this is because", "in this case", "basically,", "essentially,",
        "it's worth noting", "it should be noted", "as mentioned",
        "now, let's", "going forward", "moving on", "with that said",
    ];
    fillers.iter().any(|f| l.starts_with(f))
}

fn apply_tdd_shortcuts(line: &str) -> String {
    let mut result = line.to_string();

    let replacements = [
        ("function", "fn"),
        ("configuration", "cfg"),
        ("implementation", "impl"),
        ("dependencies", "deps"),
        ("request", "req"),
        ("response", "res"),
        ("context", "ctx"),
        ("returns ", "→ "),
        ("therefore", "∴"),
        ("approximately", "≈"),
        ("successfully", "✓"),
        (" is not ", " ≠ "),
        (" equals ", " = "),
        (" and ", " & "),
        ("error", "err"),
    ];

    for (from, to) in &replacements {
        result = result.replace(from, to);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filler_detection() {
        assert!(is_filler_line("Here's what I found"));
        assert!(is_filler_line("Let me explain how this works"));
        assert!(!is_filler_line("fn main() {}"));
        assert!(!is_filler_line("Note: important detail"));
    }

    #[test]
    fn test_tdd_shortcuts() {
        let result = apply_tdd_shortcuts("the function returns successfully");
        assert!(result.contains("fn"));
        assert!(result.contains("→"));
        assert!(result.contains("✓"));
    }
}
