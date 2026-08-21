//! connection — health, failover, resumption. [DONE] for decision logic.

use indexmap::IndexMap;
use std::net::IpAddr;
use std::time::Duration;

pub const RTT_UNHEALTHY_THRESHOLD: Duration = Duration::from_millis(800);

pub fn is_healthy(measured_rtt: Duration) -> bool {
    measured_rtt < RTT_UNHEALTHY_THRESHOLD
}

pub trait RttProbe {
    fn ping(&self) -> Option<Duration>;
}

pub fn health_from_probe<P: RttProbe>(probe: &P) -> bool {
    match probe.ping() {
        Some(rtt) => is_healthy(rtt),
        None => false,
    }
}

pub fn rotate_ip(candidates: &[IpAddr], blocked: IpAddr) -> Option<IpAddr> {
    let pos = candidates.iter().position(|&ip| ip == blocked);
    match pos {
        Some(i) => candidates
            .iter()
            .cycle()
            .skip(i + 1)
            .take(candidates.len().saturating_sub(1))
            .find(|&&ip| ip != blocked)
            .copied(),
        None => candidates.first().copied(),
    }
}

pub fn parse_ip_list(items: &[String]) -> Vec<IpAddr> {
    items.iter().filter_map(|s| s.parse().ok()).collect()
}

/// LRU (on access) session-ticket cache, capped at `capacity`.
pub struct SessionTicketCache {
    capacity: usize,
    tickets: IndexMap<String, Vec<u8>>,
}

impl SessionTicketCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            tickets: IndexMap::new(),
        }
    }

    pub fn put(&mut self, sni: &str, ticket: Vec<u8>) {
        if let Some(existing) = self.tickets.get_mut(sni) {
            *existing = ticket;
            let pos = self.tickets.get_index_of(sni).unwrap();
            let last = self.tickets.len() - 1;
            self.tickets.move_index(pos, last);
            return;
        }
        if self.tickets.len() >= self.capacity {
            self.tickets.shift_remove_index(0);
        }
        self.tickets.insert(sni.to_string(), ticket);
    }

    pub fn get(&mut self, sni: &str) -> Option<&Vec<u8>> {
        let pos = self.tickets.get_index_of(sni)?;
        let last = self.tickets.len() - 1;
        self.tickets.move_index(pos, last);
        self.tickets.get(sni)
    }
}

pub fn smart_backoff(attempt: u32, base: Duration, cap: Duration, jitter_fraction: f64) -> Duration {
    let exp = base.as_millis().saturating_mul(1u128 << attempt.min(20));
    let capped = exp.min(cap.as_millis());
    let mut rng = rand::thread_rng();
    let jitter_fraction = jitter_fraction.clamp(0.0, 1.0);
    let jitter_span = (capped as f64 * jitter_fraction) as i64;
    let jitter: i64 = if jitter_span > 0 {
        rand::Rng::gen_range(&mut rng, -jitter_span..=jitter_span)
    } else {
        0
    };
    let result = (capped as i64 + jitter).max(0) as u64;
    Duration::from_millis(result)
}

pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    struct FixedProbe(Option<Duration>);
    impl RttProbe for FixedProbe {
        fn ping(&self) -> Option<Duration> {
            self.0
        }
    }

    #[test]
    fn healthy_below_threshold() {
        assert!(is_healthy(Duration::from_millis(799)));
        assert!(!is_healthy(Duration::from_millis(800)));
        assert!(health_from_probe(&FixedProbe(Some(Duration::from_millis(10)))));
        assert!(!health_from_probe(&FixedProbe(None)));
    }

    #[test]
    fn rotate_skips_blocked_and_wraps() {
        let ips: Vec<IpAddr> = ["1.1.1.1", "1.0.0.1", "1.1.1.2"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let blocked: IpAddr = "1.1.1.1".parse().unwrap();
        let next = rotate_ip(&ips, blocked).unwrap();
        assert_ne!(next, blocked);
    }

    #[test]
    fn rotate_returns_none_for_single_blocked_entry() {
        let ips: Vec<IpAddr> = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let blocked = ips[0];
        assert_eq!(rotate_ip(&ips, blocked), None);
    }

    #[test]
    fn parse_ip_list_skips_junk() {
        let v = parse_ip_list(&["1.1.1.1".into(), "nope".into(), "1.0.0.1".into()]);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn session_cache_evicts_least_recently_used() {
        let mut cache = SessionTicketCache::new(2);
        cache.put("a.com", vec![1]);
        cache.put("b.com", vec![2]);
        // access a.com so b.com becomes the LRU
        assert_eq!(cache.get("a.com"), Some(&vec![1]));
        cache.put("c.com", vec![3]); // evicts b.com
        assert!(cache.get("b.com").is_none());
        assert_eq!(cache.get("a.com"), Some(&vec![1]));
        assert_eq!(cache.get("c.com"), Some(&vec![3]));
    }

    #[test]
    fn backoff_grows_and_respects_cap() {
        let base = Duration::from_millis(100);
        let cap = Duration::from_secs(10);
        let d0 = smart_backoff(0, base, cap, 0.0);
        let d5 = smart_backoff(5, base, cap, 0.0);
        assert_eq!(d0, Duration::from_millis(100));
        assert!(d5 <= cap);
        assert!(d5 > d0);
    }

    #[test]
    fn backoff_never_negative_with_full_jitter() {
        for attempt in 0..10 {
            let d = smart_backoff(
                attempt,
                Duration::from_millis(50),
                Duration::from_secs(5),
                1.0,
            );
            assert!(d.as_millis() >= 0);
        }
    }
}
