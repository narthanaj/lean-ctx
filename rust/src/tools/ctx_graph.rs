use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::core::deps;
use crate::core::signatures;
use crate::core::tokens::count_tokens;

#[derive(Debug, Default)]
pub struct ProjectGraph {
    nodes: HashMap<String, FileNode>,
    edges: Vec<Edge>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct FileNode {
    path: String,
    language: String,
    exports: Vec<String>,
    line_count: usize,
    token_count: usize,
}

#[derive(Debug)]
struct Edge {
    from: String,
    to: String,
    kind: EdgeKind,
}

#[derive(Debug)]
#[allow(dead_code)]
enum EdgeKind {
    Import,
    Call,
}

impl ProjectGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, path: &str, content: &str) {
        let ext = Path::new(path).extension().and_then(|e| e.to_str()).unwrap_or("");
        let dep_info = deps::extract_deps(content, ext);
        let sigs = signatures::extract_signatures(content, ext);

        let exports: Vec<String> = sigs.iter()
            .filter(|s| s.is_exported)
            .map(|s| s.name.clone())
            .collect();

        let node = FileNode {
            path: path.to_string(),
            language: ext.to_string(),
            exports,
            line_count: content.lines().count(),
            token_count: count_tokens(content),
        };

        self.nodes.insert(path.to_string(), node);

        for imp in &dep_info.imports {
            self.edges.push(Edge {
                from: path.to_string(),
                to: imp.clone(),
                kind: EdgeKind::Import,
            });
        }
    }

    pub fn format_summary(&self) -> String {
        if self.nodes.is_empty() {
            return "Empty graph. Use ctx_graph with action 'build' first.".to_string();
        }

        let mut result = Vec::new();
        result.push(format!("Project Graph: {} files, {} edges", self.nodes.len(), self.edges.len()));

        let mut by_lang: HashMap<&str, (usize, usize)> = HashMap::new();
        for node in self.nodes.values() {
            let entry = by_lang.entry(&node.language).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += node.token_count;
        }
        result.push("\nLanguages:".to_string());
        let mut langs: Vec<_> = by_lang.iter().collect();
        langs.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
        for (lang, (count, tokens)) in &langs {
            result.push(format!("  {lang}: {count} files, {tokens} tok"));
        }

        let mut import_counts: HashMap<&str, usize> = HashMap::new();
        for edge in &self.edges {
            if matches!(edge.kind, EdgeKind::Import) {
                *import_counts.entry(&edge.to).or_insert(0) += 1;
            }
        }
        let mut hotspots: Vec<_> = import_counts.iter().collect();
        hotspots.sort_by(|a, b| b.1.cmp(a.1));

        if !hotspots.is_empty() {
            result.push(format!("\nMost imported ({}):", hotspots.len().min(10)));
            for (module, count) in hotspots.iter().take(10) {
                result.push(format!("  {module}: imported by {count} files"));
            }
        }

        let isolated: Vec<_> = self.nodes.keys()
            .filter(|path| {
                !self.edges.iter().any(|e| &e.from == *path || &e.to == *path)
            })
            .collect();
        if !isolated.is_empty() && isolated.len() <= 10 {
            result.push(format!("\nIsolated files ({}):", isolated.len()));
            for path in &isolated {
                result.push(format!("  {}", crate::core::protocol::shorten_path(path)));
            }
        }

        result.join("\n")
    }

    pub fn get_related_files(&self, path: &str, depth: usize) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: Vec<(String, usize)> = vec![(path.to_string(), 0)];
        let mut related = Vec::new();

        while let Some((current, d)) = queue.pop() {
            if d > depth || visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());
            if current != path {
                related.push(current.clone());
            }

            for edge in &self.edges {
                if edge.from == current && !visited.contains(&edge.to) {
                    queue.push((edge.to.clone(), d + 1));
                }
                if edge.to == current && !visited.contains(&edge.from) {
                    queue.push((edge.from.clone(), d + 1));
                }
            }
        }

        related
    }
}

pub fn handle(action: &str, path: Option<&str>, root: &str) -> String {
    match action {
        "build" => {
            let mut graph = ProjectGraph::new();
            let walker = walkdir::WalkDir::new(root).max_depth(8);
            let mut file_count = 0usize;

            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() { continue; }
                let file_path = entry.path().to_string_lossy().to_string();
                let path_lower = file_path.to_lowercase();

                if path_lower.contains("node_modules") || path_lower.contains("target/debug") ||
                   path_lower.contains("target/release") || path_lower.contains(".git/") ||
                   path_lower.contains("dist/") || path_lower.contains("build/") ||
                   path_lower.contains("vendor/") {
                    continue;
                }

                let ext = Path::new(&file_path).extension().and_then(|e| e.to_str()).unwrap_or("");
                if !matches!(ext, "rs" | "ts" | "tsx" | "js" | "jsx" | "py" | "go" | "java" |
                    "c" | "cpp" | "h" | "rb" | "cs" | "kt" | "swift" | "php" | "ex" | "exs") {
                    continue;
                }

                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    graph.add_file(&file_path, &content);
                    file_count += 1;
                }

                if file_count >= 500 {
                    break;
                }
            }

            graph.format_summary()
        }
        "related" => {
            let target = match path {
                Some(p) => p,
                None => return "path is required for 'related' action".to_string(),
            };

            let mut graph = ProjectGraph::new();
            if let Ok(content) = std::fs::read_to_string(target) {
                graph.add_file(target, &content);
            }

            let ext = Path::new(target).extension().and_then(|e| e.to_str()).unwrap_or("");
            if let Ok(content) = std::fs::read_to_string(target) {
                let dep_info = deps::extract_deps(&content, ext);
                for imp in &dep_info.imports {
                    let possible_paths = resolve_import(imp, target, root);
                    for p in &possible_paths {
                        if let Ok(c) = std::fs::read_to_string(p) {
                            graph.add_file(p, &c);
                        }
                    }
                }
            }

            let related = graph.get_related_files(target, 2);
            if related.is_empty() {
                return format!("No related files found for {}", crate::core::protocol::shorten_path(target));
            }
            let mut result = format!("Files related to {} ({}):\n",
                crate::core::protocol::shorten_path(target), related.len());
            for r in &related {
                result.push_str(&format!("  {}\n", crate::core::protocol::shorten_path(r)));
            }
            result
        }
        _ => "Unknown action. Use: build, related".to_string(),
    }
}

fn resolve_import(import: &str, from_file: &str, _root: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let from_dir = Path::new(from_file).parent().unwrap_or(Path::new("."));

    let cleaned = import.trim_matches('"').trim_matches('\'');

    if cleaned.starts_with('.') {
        let resolved = from_dir.join(cleaned);
        for ext in &["", ".rs", ".ts", ".tsx", ".js", ".jsx", ".py", ".go"] {
            let with_ext = format!("{}{ext}", resolved.display());
            if Path::new(&with_ext).exists() {
                candidates.push(with_ext);
            }
        }
        let index_path = resolved.join("index.ts");
        if index_path.exists() {
            candidates.push(index_path.to_string_lossy().to_string());
        }
        let mod_path = resolved.join("mod.rs");
        if mod_path.exists() {
            candidates.push(mod_path.to_string_lossy().to_string());
        }
    }

    candidates
}
