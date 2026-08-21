//! strategy — adaptive technique selection by historical success score.
//! [DONE], unit tested. Pure in-memory logic, no OS dependency.

use dashmap::DashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// Hard cap so a long-lived process cannot grow the score table without
/// bound (every distinct SNI × technique is otherwise a permanent entry).
const MAX_STRATEGY_ENTRIES: usize = 4096;

/// Score for one (domain, technique) pair. Atomic so concurrent
/// connection handlers can update it without locking the whole map.
#[derive(Debug, Default)]
pub struct Score(AtomicI64);

impl Score {
    pub fn value(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Per-domain, per-technique score table.
/// Key: (domain, technique_name).
#[derive(Clone)]
pub struct StrategyTable {
    scores: Arc<DashMap<(String, String), Arc<Score>>>,
}

impl StrategyTable {
    pub fn new() -> Self {
        Self {
            scores: Arc::new(DashMap::new()),
        }
    }

    fn entry(&self, domain: &str, technique: &str) -> Arc<Score> {
        let key = (domain.to_string(), technique.to_string());
        if let Some(existing) = self.scores.get(&key) {
            return existing.clone();
        }
        if self.scores.len() >= MAX_STRATEGY_ENTRIES {
            // Ephemeral: do not remember a new domain once the table is
            // full. Existing keys still update. Slight TOCTOU overshoot
            // under concurrency is acceptable.
            return Arc::new(Score::default());
        }
        self.scores
            .entry(key)
            .or_insert_with(|| Arc::new(Score::default()))
            .clone()
    }

    /// 1. Pick the technique with the highest recorded score for this
    /// domain out of `candidates`. Ties broken by input order (first
    /// wins) so behavior is deterministic and testable. Untried
    /// techniques start at score 0, same as a technique that broke even.
    pub fn select_best(&self, domain: &str, candidates: &[&str]) -> Option<String> {
        // NOTE: deliberately not `Iterator::max_by_key` — on a tie, that
        // returns the LAST matching element, but ties should keep
        // deterministic first-input-wins semantics.
        let mut best: Option<(&str, i64)> = None;
        for &name in candidates {
            let score = self.entry(domain, name).value();
            match best {
                Some((_, best_score)) if score <= best_score => {}
                _ => best = Some((name, score)),
            }
        }
        best.map(|(name, _)| name.to_string())
    }

    /// 2. Atomically update a technique's score: +1 on success, -2 on
    /// failure/RST (asymmetric penalty so a technique that gets flagged
    /// by DPI drops out of rotation faster than one that merely hasn't
    /// been tried much).
    pub fn update_score(&self, domain: &str, technique: &str, success: bool) -> i64 {
        let delta = if success { 1 } else { -2 };
        self.entry(domain, technique)
            .0
            .fetch_add(delta, Ordering::Relaxed)
            + delta
    }

    /// 4. Per-domain tracking: list every technique tried against a given
    /// domain and its current score.
    pub fn per_domain_scores(&self, domain: &str) -> Vec<(String, i64)> {
        self.scores
            .iter()
            .filter(|entry| entry.key().0 == domain)
            .map(|entry| (entry.key().1.clone(), entry.value().value()))
            .collect()
    }

    /// Flattened `domain|technique -> score` view, used by the dashboard.
    pub fn all_scores(&self) -> Vec<(String, i64)> {
        self.scores
            .iter()
            .map(|entry| (format!("{}|{}", entry.key().0, entry.key().1), entry.value().value()))
            .collect()
    }
}

impl Default for StrategyTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of one A/B probe against a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    /// Handshake to the IP fails/resets even with a plain SNI-less probe
    /// (or a probe to an unrelated SNI on the same IP) -> IP is blocked.
    IpBlock,
    /// Plain IP-level probe succeeds but a probe carrying the real SNI
    /// fails -> filtering keys on SNI content, not the destination IP.
    SniBlock,
    /// Both probes succeeded.
    NotBlocked,
    /// Both probes failed the same way; cannot distinguish IP- from
    /// SNI-based blocking from this evidence alone.
    Inconclusive,
}

/// 3. Decide block type from two parallel probe outcomes: an SNI-less
/// (or decoy-SNI) connection attempt vs. one carrying the real SNI.
/// Pass in booleans (`true` = probe succeeded) collected by the caller
/// after running both probes concurrently — this function only holds the
/// decision table so it's independently testable.
pub fn ab_test_block_type(plain_probe_ok: bool, real_sni_probe_ok: bool) -> BlockType {
    match (plain_probe_ok, real_sni_probe_ok) {
        (true, true) => BlockType::NotBlocked,
        (true, false) => BlockType::SniBlock,
        (false, true) => BlockType::Inconclusive, // shouldn't happen; real SNI worked but plain didn't
        (false, false) => BlockType::IpBlock,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_best_picks_highest_score() {
        let table = StrategyTable::new();
        table.update_score("example.com", "frag", true);
        table.update_score("example.com", "frag", true);
        table.update_score("example.com", "case", false);
        let best = table.select_best("example.com", &["frag", "case"]);
        assert_eq!(best.as_deref(), Some("frag"));
    }

    #[test]
    fn select_best_ties_prefer_first_input() {
        let table = StrategyTable::new();
        let best = table.select_best("example.com", &["a", "b"]);
        assert_eq!(best.as_deref(), Some("a"));
    }

    #[test]
    fn update_score_asymmetric_penalty() {
        let table = StrategyTable::new();
        assert_eq!(table.update_score("d", "t", true), 1);
        assert_eq!(table.update_score("d", "t", false), -1);
        assert_eq!(table.update_score("d", "t", false), -3);
    }

    #[test]
    fn per_domain_scores_isolated_from_other_domains() {
        let table = StrategyTable::new();
        table.update_score("a.com", "x", true);
        table.update_score("b.com", "x", true);
        let scores = table.per_domain_scores("a.com");
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].0, "x");
    }

    #[test]
    fn ab_test_decision_table() {
        assert_eq!(ab_test_block_type(true, true), BlockType::NotBlocked);
        assert_eq!(ab_test_block_type(true, false), BlockType::SniBlock);
        assert_eq!(ab_test_block_type(false, false), BlockType::IpBlock);
        assert_eq!(ab_test_block_type(false, true), BlockType::Inconclusive);
    }
}
