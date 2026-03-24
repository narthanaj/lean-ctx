use md5::{Digest, Md5};
use std::collections::HashMap;

use super::tokens::count_tokens;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CacheEntry {
    pub content: String,
    pub hash: String,
    pub line_count: usize,
    pub original_tokens: usize,
    pub read_count: u32,
    pub path: String,
}

#[derive(Debug)]
pub struct CacheStats {
    pub total_reads: u64,
    pub cache_hits: u64,
    pub total_original_tokens: u64,
    pub total_sent_tokens: u64,
    pub files_tracked: usize,
}

#[allow(dead_code)]
impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        if self.total_reads == 0 {
            return 0.0;
        }
        (self.cache_hits as f64 / self.total_reads as f64) * 100.0
    }

    pub fn tokens_saved(&self) -> u64 {
        self.total_original_tokens.saturating_sub(self.total_sent_tokens)
    }

    pub fn savings_percent(&self) -> f64 {
        if self.total_original_tokens == 0 {
            return 0.0;
        }
        (self.tokens_saved() as f64 / self.total_original_tokens as f64) * 100.0
    }
}

pub struct SessionCache {
    entries: HashMap<String, CacheEntry>,
    file_refs: HashMap<String, String>,
    next_ref: usize,
    stats: CacheStats,
}

impl SessionCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            file_refs: HashMap::new(),
            next_ref: 1,
            stats: CacheStats {
                total_reads: 0,
                cache_hits: 0,
                total_original_tokens: 0,
                total_sent_tokens: 0,
                files_tracked: 0,
            },
        }
    }

    pub fn get_file_ref(&mut self, path: &str) -> String {
        if let Some(r) = self.file_refs.get(path) {
            return r.clone();
        }
        let r = format!("F{}", self.next_ref);
        self.next_ref += 1;
        self.file_refs.insert(path.to_string(), r.clone());
        r
    }

    pub fn get(&self, path: &str) -> Option<&CacheEntry> {
        self.entries.get(path)
    }

    pub fn record_cache_hit(&mut self, path: &str) -> Option<&CacheEntry> {
        let ref_label = self.file_refs.get(path).cloned().unwrap_or_else(|| "F?".to_string());
        if let Some(entry) = self.entries.get_mut(path) {
            entry.read_count += 1;
            self.stats.total_reads += 1;
            self.stats.cache_hits += 1;
            self.stats.total_original_tokens += entry.original_tokens as u64;
            let hit_msg = format!("{ref_label} [cached {}t {}L ∅]", entry.read_count, entry.line_count);
            self.stats.total_sent_tokens += count_tokens(&hit_msg) as u64;
            Some(entry)
        } else {
            None
        }
    }

    pub fn store(&mut self, path: &str, content: String) -> (CacheEntry, bool) {
        let hash = compute_md5(&content);
        let line_count = content.lines().count();
        let original_tokens = count_tokens(&content);

        self.stats.total_reads += 1;
        self.stats.total_original_tokens += original_tokens as u64;

        if let Some(existing) = self.entries.get_mut(path) {
            if existing.hash == hash {
                existing.read_count += 1;
                self.stats.cache_hits += 1;
                let hit_msg = format!(
                    "{} [cached {}t {}L ∅]",
                    self.file_refs.get(path).unwrap_or(&"F?".to_string()),
                    existing.read_count,
                    existing.line_count,
                );
                let sent = count_tokens(&hit_msg) as u64;
                self.stats.total_sent_tokens += sent;
                return (existing.clone(), true);
            }
            existing.content = content;
            existing.hash = hash.clone();
            existing.line_count = line_count;
            existing.original_tokens = original_tokens;
            existing.read_count += 1;
            self.stats.total_sent_tokens += original_tokens as u64;
            return (existing.clone(), false);
        }

        self.get_file_ref(path);

        let entry = CacheEntry {
            content,
            hash,
            line_count,
            original_tokens,
            read_count: 1,
            path: path.to_string(),
        };

        self.entries.insert(path.to_string(), entry.clone());
        self.stats.files_tracked += 1;
        self.stats.total_sent_tokens += original_tokens as u64;
        (entry, false)
    }

    pub fn get_all_entries(&self) -> Vec<(&String, &CacheEntry)> {
        self.entries.iter().collect()
    }

    pub fn get_stats(&self) -> &CacheStats {
        &self.stats
    }

    pub fn file_ref_map(&self) -> &HashMap<String, String> {
        &self.file_refs
    }

    pub fn invalidate(&mut self, path: &str) -> bool {
        self.entries.remove(path).is_some()
    }

    pub fn clear(&mut self) -> usize {
        let count = self.entries.len();
        self.entries.clear();
        self.file_refs.clear();
        self.next_ref = 1;
        self.stats = CacheStats {
            total_reads: 0,
            cache_hits: 0,
            total_original_tokens: 0,
            total_sent_tokens: 0,
            files_tracked: 0,
        };
        count
    }
}

fn compute_md5(content: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}
