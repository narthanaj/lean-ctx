#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SessionCache } from './core/session-cache.js';
import { startSession, flushSession } from './core/store.js';
import { registerCtxRead } from './tools/ctx-read.js';
import { registerCtxTree } from './tools/ctx-tree.js';
import { registerCtxShell } from './tools/ctx-shell.js';
import { registerCtxMetrics } from './tools/ctx-metrics.js';
import { registerCtxBenchmark } from './tools/ctx-benchmark.js';
import { registerCtxCompress } from './tools/ctx-compress.js';
import { registerCtxAnalyze } from './tools/ctx-analyze.js';

const projectRoot = process.env.LEAN_CTX_ROOT || process.cwd();
const projectName = projectRoot.split('/').pop() || 'unknown';

const server = new McpServer({
  name: 'lean-ctx',
  version: '0.5.0',
});

const cache = new SessionCache();
startSession(projectName);

registerCtxRead(server, cache);
registerCtxTree(server, cache);
registerCtxShell(server, cache);
registerCtxMetrics(server, cache);
registerCtxBenchmark(server, cache);
registerCtxCompress(server, cache);
registerCtxAnalyze(server);

process.on('SIGINT', () => { flushSession(); process.exit(0); });
process.on('SIGTERM', () => { flushSession(); process.exit(0); });
process.on('exit', () => { flushSession(); });

const transport = new StdioServerTransport();
await server.connect(transport);
