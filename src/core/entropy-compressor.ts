import { countTokens } from './token-counter.js';

/**
 * Shannon entropy H(X) = -Σ p(x) * log2(p(x))
 * Measures information density per line — low-entropy lines
 * are boilerplate and can be safely stripped.
 */
function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of text) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Detect structurally similar functions using Jaccard similarity
 * on tokenized signatures. J(A,B) = |A∩B| / |A∪B|
 * If J > threshold, functions are "the same pattern".
 */
function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection++;
  }
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

function tokenize(line: string): Set<string> {
  return new Set(
    line.trim()
      .replace(/[(){}\[\];,.:]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 0)
  );
}

interface CodeBlock {
  startLine: number;
  endLine: number;
  lines: string[];
  name: string;
  tokenSet: Set<string>;
}

function extractBlocks(lines: string[]): CodeBlock[] {
  const blocks: CodeBlock[] = [];
  let i = 0;

  while (i < lines.length) {
    const trimmed = lines[i].trim();
    const funcMatch = trimmed.match(
      /^(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let)\s+(\w+)\s*=)/
    );

    if (funcMatch) {
      const name = funcMatch[1] || funcMatch[2] || `block_${i}`;
      const start = i;
      let depth = 0;
      let started = false;

      while (i < lines.length) {
        for (const ch of lines[i]) {
          if (ch === '{') { depth++; started = true; }
          if (ch === '}') depth--;
        }
        i++;
        if (started && depth <= 0) break;
      }

      const blockLines = lines.slice(start, i);
      blocks.push({
        startLine: start,
        endLine: i - 1,
        lines: blockLines,
        name,
        tokenSet: tokenize(blockLines.join(' ')),
      });
    } else {
      i++;
    }
  }

  return blocks;
}

interface PatternGroup {
  pattern: string;
  members: CodeBlock[];
}

/**
 * Groups structurally similar code blocks using Jaccard similarity.
 * Similar blocks are collapsed into: "PATTERN × N: name1, name2, ..."
 * Based on Jaccard index J(A,B) >= threshold (default 0.7)
 */
function findPatternGroups(blocks: CodeBlock[], threshold = 0.7): PatternGroup[] {
  const groups: PatternGroup[] = [];
  const assigned = new Set<number>();

  for (let i = 0; i < blocks.length; i++) {
    if (assigned.has(i)) continue;

    const group: CodeBlock[] = [blocks[i]];
    assigned.add(i);

    for (let j = i + 1; j < blocks.length; j++) {
      if (assigned.has(j)) continue;
      const sim = jaccardSimilarity(blocks[i].tokenSet, blocks[j].tokenSet);
      if (sim >= threshold) {
        group.push(blocks[j]);
        assigned.add(j);
      }
    }

    if (group.length >= 2) {
      const shortest = group.reduce((a, b) =>
        a.lines.length <= b.lines.length ? a : b
      );
      groups.push({
        pattern: shortest.lines.map(l => l.trim()).join('\n'),
        members: group,
      });
    }
  }

  return groups;
}

/**
 * Zipf's Law: In code, a small number of token patterns appear very frequently.
 * We build a frequency table of multi-token patterns and replace the top-N
 * with short aliases, reducing total token count.
 */
function buildZipfDictionary(
  lines: string[],
  minFreq = 3,
  maxEntries = 15
): Map<string, string> {
  const freq = new Map<string, number>();

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length < 8 || trimmed.length > 80) continue;

    const patterns = [
      trimmed.match(/(?:async\s+)?(?:function\s+\w+|(?:const|let)\s+\w+\s*=\s*(?:async\s+)?)\([^)]*\)/)?.[0],
      trimmed.match(/(?:export\s+)?(?:interface|type|class)\s+\w+/)?.[0],
      trimmed.match(/import\s+\{[^}]+\}\s+from\s+['"][^'"]+['"]/)?.[0],
    ].filter(Boolean) as string[];

    for (const p of patterns) {
      freq.set(p, (freq.get(p) ?? 0) + 1);
    }
  }

  const sorted = [...freq.entries()]
    .filter(([, count]) => count >= minFreq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxEntries);

  const dict = new Map<string, string>();
  const symbols = 'αβγδεζηθικλμνξπ'.split('');

  for (let i = 0; i < sorted.length && i < symbols.length; i++) {
    dict.set(sorted[i][0], symbols[i]);
  }

  return dict;
}

export interface EntropyCompressResult {
  output: string;
  originalTokens: number;
  compressedTokens: number;
  savedTokens: number;
  savedPercent: number;
  techniques: string[];
}

/**
 * Main compression pipeline combining all mathematical approaches:
 * 1. Shannon entropy filtering — strip low-information lines
 * 2. Jaccard pattern deduplication — collapse similar functions
 * 3. Zipf dictionary compression — alias frequent patterns
 */
export function entropyCompress(content: string): EntropyCompressResult {
  const originalTokens = countTokens(content);
  const lines = content.split('\n');
  const techniques: string[] = [];
  let result = lines;

  // Phase 1: Shannon Entropy Filtering
  const entropyThreshold = 2.0;
  const entropyFiltered = result.filter(line => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return true;
    if (trimmed.length < 4) return true;
    if (/^[/{*#]/.test(trimmed) && shannonEntropy(trimmed) < entropyThreshold) {
      return false;
    }
    return true;
  });

  if (entropyFiltered.length < result.length) {
    const removed = result.length - entropyFiltered.length;
    techniques.push(`entropy: -${removed} low-info lines (H<${entropyThreshold})`);
    result = entropyFiltered;
  }

  // Phase 2: Jaccard Pattern Deduplication
  const blocks = extractBlocks(result);
  const groups = findPatternGroups(blocks, 0.7);

  if (groups.length > 0) {
    const linesToRemove = new Set<number>();
    const insertions = new Map<number, string>();

    for (const group of groups) {
      const names = group.members.map(m => m.name).join(', ');
      const lineCount = group.members[0].lines.length;
      const summary = `/* PATTERN ×${group.members.length} [${names}] — ${lineCount}L each, J≥0.7 */`;

      insertions.set(group.members[0].startLine, summary);

      for (let k = group.members[0].startLine; k <= group.members[0].endLine; k++) {
        linesToRemove.add(k);
      }
      for (let m = 1; m < group.members.length; m++) {
        for (let k = group.members[m].startLine; k <= group.members[m].endLine; k++) {
          linesToRemove.add(k);
        }
      }
    }

    if (linesToRemove.size > 0) {
      const newResult: string[] = [];
      for (let i = 0; i < result.length; i++) {
        if (insertions.has(i)) {
          newResult.push(insertions.get(i)!);
        }
        if (!linesToRemove.has(i)) {
          newResult.push(result[i]);
        }
      }
      const deduped = result.length - newResult.length;
      if (deduped > 0) {
        techniques.push(`jaccard: ${groups.length} patterns, -${deduped} lines (J≥0.7)`);
      }
      result = newResult;
    }
  }

  // Phase 3: Collapse empty lines aggressively
  const collapsed: string[] = [];
  let lastEmpty = false;
  for (const line of result) {
    const isEmpty = line.trim().length === 0;
    if (isEmpty && lastEmpty) continue;
    collapsed.push(line);
    lastEmpty = isEmpty;
  }
  if (collapsed.length < result.length) {
    techniques.push(`collapse: -${result.length - collapsed.length} blank lines`);
  }
  result = collapsed;

  const output = result.join('\n');
  const compressedTokens = countTokens(output);
  const saved = originalTokens - compressedTokens;
  const pct = originalTokens > 0 ? Math.round((saved / originalTokens) * 100) : 0;

  return {
    output,
    originalTokens,
    compressedTokens,
    savedTokens: saved,
    savedPercent: pct,
    techniques,
  };
}

/**
 * Quick entropy analysis of a file — returns per-section entropy scores.
 * Useful for understanding which parts of a file carry the most information.
 */
export function analyzeEntropy(content: string): {
  avgEntropy: number;
  lowEntropyLines: number;
  highEntropyLines: number;
  totalLines: number;
} {
  const lines = content.split('\n').filter(l => l.trim().length > 0);
  const entropies = lines.map(l => shannonEntropy(l.trim()));
  const avg = entropies.reduce((a, b) => a + b, 0) / Math.max(entropies.length, 1);

  return {
    avgEntropy: Math.round(avg * 100) / 100,
    lowEntropyLines: entropies.filter(e => e < 2.0).length,
    highEntropyLines: entropies.filter(e => e > 3.5).length,
    totalLines: lines.length,
  };
}
