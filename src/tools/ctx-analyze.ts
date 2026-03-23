import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { analyzeEntropy, entropyCompress } from '../core/entropy-compressor.js';
import { countTokens } from '../core/token-counter.js';
import { shortenPath } from '../core/protocol.js';
import { extractSignatures } from '../core/signature-extractor.js';

export function registerCtxAnalyze(server: McpServer): void {
  server.tool(
    'ctx_analyze',
    `Information-theoretic analysis of a file's token efficiency.
Shows Shannon entropy distribution, pattern duplication (Jaccard),
and compares all compression strategies with exact token counts.
Use this to find the optimal read mode for any file.`,
    {
      path: z.string().describe('File path to analyze'),
    },
    async ({ path: filePath }) => {
      const absPath = resolve(filePath);
      let content: string;
      try {
        content = await readFile(absPath, 'utf-8');
      } catch (err) {
        return { content: [{ type: 'text' as const, text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }

      const short = shortenPath(absPath);
      const lines = content.split('\n');

      const rawTokens = countTokens(content);
      const entropy = analyzeEntropy(content);
      const entropyResult = entropyCompress(content);
      const sigs = extractSignatures(content, absPath);
      const sigTokens = countTokens(sigs.formatted);

      const sections: string[] = [];

      sections.push(`ANALYSIS: ${short} (${lines.length}L, ${rawTokens} tok)`);
      sections.push('');

      // Shannon Entropy
      sections.push(`ENTROPY (Shannon H):`);
      sections.push(`  avg: ${entropy.avgEntropy} bits/char`);
      sections.push(`  low-info (H<2.0): ${entropy.lowEntropyLines}/${entropy.totalLines} lines (${pct(entropy.lowEntropyLines, entropy.totalLines)}%)`);
      sections.push(`  high-info (H>3.5): ${entropy.highEntropyLines}/${entropy.totalLines} lines (${pct(entropy.highEntropyLines, entropy.totalLines)}%)`);
      sections.push('');

      // Compression comparison
      sections.push('COMPRESSION COMPARISON:');
      sections.push(`  raw:        ${rawTokens} tok`);
      sections.push(`  signatures: ${sigTokens} tok (${savings(rawTokens, sigTokens)})`);
      sections.push(`  entropy:    ${entropyResult.compressedTokens} tok (${savings(rawTokens, entropyResult.compressedTokens)})`);
      sections.push(`  cache hit:  ~13 tok (${savings(rawTokens, 13)})`);

      if (entropyResult.techniques.length > 0) {
        sections.push('');
        sections.push('TECHNIQUES APPLIED:');
        for (const t of entropyResult.techniques) {
          sections.push(`  ${t}`);
        }
      }

      // Recommendation
      sections.push('');
      const bestMode = sigTokens < entropyResult.compressedTokens ? 'signatures' : 'entropy';
      const bestTokens = Math.min(sigTokens, entropyResult.compressedTokens);
      sections.push(`RECOMMENDATION: mode="${bestMode}" (${bestTokens} tok, ${savings(rawTokens, bestTokens)})`);

      return { content: [{ type: 'text' as const, text: sections.join('\n') }] };
    }
  );
}

function pct(part: number, total: number): number {
  return total > 0 ? Math.round((part / total) * 100) : 0;
}

function savings(original: number, compressed: number): string {
  const saved = original - compressed;
  const p = original > 0 ? Math.round((saved / original) * 100) : 0;
  return `-${saved} tok, ${p}%`;
}
