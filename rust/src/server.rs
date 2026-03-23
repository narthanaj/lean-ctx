use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};
use rmcp::ErrorData;
use serde_json::{json, Map, Value};

use crate::tools::LeanCtxServer;

impl ServerHandler for LeanCtxServer {
    fn get_info(&self) -> ServerInfo {
        let capabilities = ServerCapabilities::builder()
            .enable_tools()
            .build();

        InitializeResult::new(capabilities)
            .with_server_info(Implementation::new("lean-ctx", "1.0.0"))
            .with_instructions(
                "lean-ctx MCP. Use ctx_read(path,mode) instead of Read. Use ctx_shell(cmd) instead of Shell. \
                ctx_read modes: full(cached), map(deps+API), signatures, diff, aggressive, entropy. \
                Re-reads=~13tok. File refs: F1,F2.. persist in session."
            )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        async {
            Ok(ListToolsResult {
                tools: vec![
                    tool_def(
                        "ctx_read",
                        "Smart file read with session-aware caching and 6 compression modes. \
                        Re-reads cost ~13 tokens. Modes: full (cached read), signatures (API surface), \
                        map (dependency graph + exports + key signatures — use for context files you won't edit), \
                        diff (changed lines only), aggressive (syntax stripped), \
                        entropy (Shannon + Jaccard).",
                        json!({
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Absolute file path to read" },
                                "mode": {
                                    "type": "string",
                                    "enum": ["full", "signatures", "map", "diff", "aggressive", "entropy"],
                                    "description": "Compression mode (default: full). Use 'map' for context-only files."
                                }
                            },
                            "required": ["path"]
                        }),
                    ),
                    tool_def(
                        "ctx_tree",
                        "Token-efficient directory listing with file counts per directory.",
                        json!({
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Directory path (default: .)" },
                                "depth": { "type": "integer", "description": "Max depth (default: 3)" },
                                "show_hidden": { "type": "boolean", "description": "Show hidden files" }
                            }
                        }),
                    ),
                    tool_def(
                        "ctx_shell",
                        "Execute a shell command and compress output using pattern-based compression. \
                        Recognizes git, npm, cargo, docker, tsc. Use instead of running commands directly.",
                        json!({
                            "type": "object",
                            "properties": {
                                "command": { "type": "string", "description": "Shell command to execute" }
                            },
                            "required": ["command"]
                        }),
                    ),
                    tool_def(
                        "ctx_search",
                        "Search files for a regex pattern. Returns only matching lines with compact context.",
                        json!({
                            "type": "object",
                            "properties": {
                                "pattern": { "type": "string", "description": "Regex pattern" },
                                "path": { "type": "string", "description": "Directory to search" },
                                "ext": { "type": "string", "description": "File extension filter" },
                                "max_results": { "type": "integer", "description": "Max results (default: 20)" }
                            },
                            "required": ["pattern"]
                        }),
                    ),
                    tool_def(
                        "ctx_compress",
                        "Compress all cached files into an ultra-compact checkpoint. \
                        Use when conversations get long to create a memory snapshot.",
                        json!({
                            "type": "object",
                            "properties": {
                                "include_signatures": { "type": "boolean", "description": "Include signatures (default: true)" }
                            }
                        }),
                    ),
                    tool_def(
                        "ctx_benchmark",
                        "Benchmark a file against all compression strategies with exact tiktoken counts.",
                        json!({
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "File path to benchmark" }
                            },
                            "required": ["path"]
                        }),
                    ),
                    tool_def(
                        "ctx_metrics",
                        "Session statistics with tiktoken-measured token counts, cache hit rates, and per-tool savings.",
                        json!({
                            "type": "object",
                            "properties": {}
                        }),
                    ),
                    tool_def(
                        "ctx_analyze",
                        "Information-theoretic analysis using Shannon entropy and Jaccard similarity. \
                        Recommends the optimal compression mode for a file.",
                        json!({
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "File path to analyze" }
                            },
                            "required": ["path"]
                        }),
                    ),
                ],
                ..Default::default()
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, ErrorData>> + Send + '_ {
        async move {
            let name = &request.name;
            let args = &request.arguments;

            let result_text = match name.as_ref() {
                "ctx_read" => {
                    let path = get_str(args, "path")
                        .ok_or_else(|| ErrorData::invalid_params("path is required", None))?;
                    let mode = get_str(args, "mode").unwrap_or_else(|| "full".to_string());
                    let mut cache = self.cache.write().await;
                    let output = crate::tools::ctx_read::handle(&mut cache, &path, &mode);
                    let original = cache.get(&path).map_or(0, |e| e.original_tokens);
                    let tokens = crate::core::tokens::count_tokens(&output);
                    drop(cache);
                    self.record_call("ctx_read", original, original.saturating_sub(tokens), Some(mode)).await;
                    output
                }
                "ctx_tree" => {
                    let path = get_str(args, "path").unwrap_or_else(|| ".".to_string());
                    let depth = get_int(args, "depth").unwrap_or(3) as usize;
                    let show_hidden = get_bool(args, "show_hidden").unwrap_or(false);
                    crate::tools::ctx_tree::handle(&path, depth, show_hidden)
                }
                "ctx_shell" => {
                    let command = get_str(args, "command")
                        .ok_or_else(|| ErrorData::invalid_params("command is required", None))?;
                    let output = execute_command(&command);
                    let result = crate::tools::ctx_shell::handle(&command, &output);
                    let original = crate::core::tokens::count_tokens(&output);
                    let sent = crate::core::tokens::count_tokens(&result);
                    self.record_call("ctx_shell", original, original.saturating_sub(sent), None).await;
                    result
                }
                "ctx_search" => {
                    let pattern = get_str(args, "pattern")
                        .ok_or_else(|| ErrorData::invalid_params("pattern is required", None))?;
                    let path = get_str(args, "path").unwrap_or_else(|| ".".to_string());
                    let ext = get_str(args, "ext");
                    let max = get_int(args, "max_results").unwrap_or(20) as usize;
                    crate::tools::ctx_search::handle(&pattern, &path, ext.as_deref(), max)
                }
                "ctx_compress" => {
                    let include_sigs = get_bool(args, "include_signatures").unwrap_or(true);
                    let cache = self.cache.read().await;
                    let result = crate::tools::ctx_compress::handle(&cache, include_sigs);
                    drop(cache);
                    self.record_call("ctx_compress", 0, 0, None).await;
                    result
                }
                "ctx_benchmark" => {
                    let path = get_str(args, "path")
                        .ok_or_else(|| ErrorData::invalid_params("path is required", None))?;
                    crate::tools::ctx_benchmark::handle(&path)
                }
                "ctx_metrics" => {
                    let cache = self.cache.read().await;
                    let calls = self.tool_calls.read().await;
                    crate::tools::ctx_metrics::handle(&cache, &calls)
                }
                "ctx_analyze" => {
                    let path = get_str(args, "path")
                        .ok_or_else(|| ErrorData::invalid_params("path is required", None))?;
                    crate::tools::ctx_analyze::handle(&path)
                }
                _ => {
                    return Err(ErrorData::invalid_params(
                        format!("Unknown tool: {name}"),
                        None,
                    ));
                }
            };

            Ok(CallToolResult::success(vec![Content::text(result_text)]))
        }
    }
}

fn tool_def(name: &'static str, description: &'static str, schema_value: Value) -> Tool {
    let schema: Map<String, Value> = match schema_value {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    Tool::new(name, description, Arc::new(schema))
}

fn get_str(args: &Option<serde_json::Map<String, Value>>, key: &str) -> Option<String> {
    args.as_ref()?.get(key)?.as_str().map(|s| s.to_string())
}

fn get_int(args: &Option<serde_json::Map<String, Value>>, key: &str) -> Option<i64> {
    args.as_ref()?.get(key)?.as_i64()
}

fn get_bool(args: &Option<serde_json::Map<String, Value>>, key: &str) -> Option<bool> {
    args.as_ref()?.get(key)?.as_bool()
}

fn execute_command(command: &str) -> String {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stdout.is_empty() {
                stderr.to_string()
            } else if stderr.is_empty() {
                stdout.to_string()
            } else {
                format!("{stdout}\n{stderr}")
            }
        }
        Err(e) => format!("ERROR: {e}"),
    }
}
