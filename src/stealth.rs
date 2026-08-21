//! stealth — 15 anti-fingerprint / anti-analysis techniques. [PARTIAL]
//! DNSSEC is a presence heuristic (not a crypto validator). WFP DNS
//! blocking and the kill-switch *spawn* stay opt-in / stub at the FFI
//! layer; command construction is sanitised.

use rand::seq::SliceRandom;
use rand::Rng;
use rand_distr::{Distribution, Normal};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Duration;

pub fn add_dynamic_jitter() -> Duration {
    let normal = Normal::new(20.0_f64, 10.0_f64).expect("valid normal params");
    let mut rng = rand::thread_rng();
    let sample = normal.sample(&mut rng).max(0.0);
    Duration::from_micros((sample * 1000.0) as u64)
}

pub fn add_random_padding(payload: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(0..=128);
    let mut out = payload.to_vec();
    out.extend((0..n).map(|_| rng.gen::<u8>()));
    out
}

pub fn normalize_ttl(current: u8) -> u8 {
    if current > 96 {
        128
    } else {
        64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOption {
    pub kind: u8,
    pub bytes: Vec<u8>,
}

/// Chrome-like order: MSS, NOP, WScale, NOP, NOP, SACK, Timestamp.
pub fn fake_tcp_options(ts_val: u32, ts_ecr: u32) -> Vec<TcpOption> {
    vec![
        TcpOption {
            kind: 2,
            bytes: 1460u16.to_be_bytes().to_vec(),
        },
        TcpOption {
            kind: 1,
            bytes: vec![],
        }, // NOP
        TcpOption {
            kind: 3,
            bytes: vec![7],
        },
        TcpOption {
            kind: 1,
            bytes: vec![],
        },
        TcpOption {
            kind: 1,
            bytes: vec![],
        },
        TcpOption {
            kind: 4,
            bytes: vec![],
        },
        TcpOption {
            kind: 8,
            bytes: [ts_val.to_be_bytes(), ts_ecr.to_be_bytes()].concat(),
        },
    ]
}

/// Serialize options to on-wire bytes, NOP-padded to a 4-byte multiple.
/// Options whose payload would overflow the 1-byte length field are
/// skipped rather than wrapping (which would produce a corrupt TCP
/// header the kernel might still try to parse).
pub fn encode_tcp_options(opts: &[TcpOption]) -> Vec<u8> {
    let mut out = Vec::new();
    for o in opts {
        match o.kind {
            0 | 1 => out.push(o.kind),
            _ => {
                if o.bytes.len() > 253 {
                    continue;
                }
                out.push(o.kind);
                out.push((2 + o.bytes.len()) as u8);
                out.extend_from_slice(&o.bytes);
            }
        }
    }
    while out.len() % 4 != 0 {
        out.push(1);
    }
    out
}

pub trait CertCache {
    fn has_valid_cert_for(&self, sni: &str) -> bool;
}

/// Empty cache = no pinning (allow every SNI). Non-empty = allow-list.
#[derive(Debug, Default, Clone)]
pub struct MemoryCertCache {
    pub valid: HashSet<String>,
}

impl CertCache for MemoryCertCache {
    fn has_valid_cert_for(&self, sni: &str) -> bool {
        self.valid.is_empty() || self.valid.contains(sni)
    }
}

pub fn match_sni_cert(cache: &dyn CertCache, sni: &str) -> bool {
    cache.has_valid_cert_for(sni)
}

pub fn shuffle_cipher_suites(suites: &mut [u16]) {
    suites.shuffle(&mut rand::thread_rng());
}

pub const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
    0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

pub fn add_grease_values(list: &mut Vec<u16>) {
    let mut rng = rand::thread_rng();
    let grease = GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())];
    let pos = rng.gen_range(0..=list.len());
    list.insert(pos, grease);
}

#[derive(Debug, Clone)]
pub struct BrowserFingerprint {
    pub name: &'static str,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
}

pub fn simulate_browser_fingerprint(browser: &str) -> BrowserFingerprint {
    match browser {
        "firefox" => BrowserFingerprint {
            name: "firefox",
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8],
            extensions: vec![0x0000, 0x0017, 0x0023, 0x000D, 0x002B, 0x002D, 0x0033],
            elliptic_curves: vec![0x001D, 0x0017, 0x0018],
        },
        _ => BrowserFingerprint {
            name: "chrome",
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xC02B, 0xC02C, 0xC02F, 0xC030],
            extensions: vec![0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010],
            elliptic_curves: vec![0x001D, 0x0017, 0x0018],
        },
    }
}

/// Apply GREASE + shuffle to a fingerprint template (JA3 shape, not a
/// pinned hash of a specific Chrome build).
pub fn shape_fingerprint(fp: &mut BrowserFingerprint) {
    shuffle_cipher_suites(&mut fp.cipher_suites);
    add_grease_values(&mut fp.cipher_suites);
    add_grease_values(&mut fp.extensions);
}

pub fn hash_sensitive(value: &str, salt: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Per-process random salt for `hash_sensitive`. A fixed/known salt would
/// let an attacker with access to the logs reverse common domain names by
/// dictionary; a random per-run salt raises that cost substantially.
pub fn run_salt() -> &'static [u8] {
    use std::sync::OnceLock;
    static SALT: OnceLock<Vec<u8>> = OnceLock::new();
    SALT.get_or_init(|| {
        let mut rng = rand::thread_rng();
        (0..16).map(|_| rng.gen::<u8>()).collect()
    })
}

/// Random bearer token for the opt-in local web dashboard. 128 bits of
/// entropy, hex-encoded; printed to the log so the operator can enter it.
pub fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
}

/// PARTIAL DNSSEC check: look for an RRSIG (type 46) in a DNS message.
/// This is **not** a cryptographic chain validation.
pub fn validate_dnssec(response_bytes: &[u8]) -> Result<bool, crate::error::DpiGuardError> {
    if response_bytes.len() < 12 {
        return Ok(false);
    }
    let ancount = u16::from_be_bytes([response_bytes[6], response_bytes[7]]) as usize;
    let nscount = u16::from_be_bytes([response_bytes[8], response_bytes[9]]) as usize;
    let arcount = u16::from_be_bytes([response_bytes[10], response_bytes[11]]) as usize;
    let mut pos = 12usize;
    // skip question (QNAME + QTYPE + QCLASS)
    if skip_name(response_bytes, &mut pos).is_err() || pos + 4 > response_bytes.len() {
        return Ok(false);
    }
    pos += 4;
    let records = ancount.saturating_add(nscount).saturating_add(arcount);
    for _ in 0..records {
        if skip_name(response_bytes, &mut pos).is_err() || pos + 10 > response_bytes.len() {
            return Ok(false);
        }
        let rtype = u16::from_be_bytes([response_bytes[pos], response_bytes[pos + 1]]);
        let rdlen = u16::from_be_bytes([response_bytes[pos + 8], response_bytes[pos + 9]]) as usize;
        pos += 10;
        if rtype == 46 {
            return Ok(true);
        }
        pos = pos.saturating_add(rdlen);
        if pos > response_bytes.len() {
            return Ok(false);
        }
    }
    Ok(false)
}

fn skip_name(msg: &[u8], pos: &mut usize) -> Result<(), ()> {
    let mut hops = 0;
    loop {
        if *pos >= msg.len() || hops > 16 {
            return Err(());
        }
        let len = msg[*pos];
        if len == 0 {
            *pos += 1;
            return Ok(());
        }
        if len & 0xC0 == 0xC0 {
            *pos += 2;
            return Ok(());
        }
        *pos += 1 + len as usize;
        hops += 1;
    }
}

pub use crate::dns_guard::block_port_53_except_localhost as prevent_dns_leak;

pub fn randomize_window_size(base: u16) -> u16 {
    let delta: i32 = rand::thread_rng().gen_range(-256..=256);
    (base as i32 + delta).clamp(1024, 65535) as u16
}

/// XOR a sparse random mask onto `padding` so ~25% of bits flip. Does
/// not replace the buffer with independent random bytes.
pub fn inject_noise_entropy(padding: &mut [u8]) {
    let mut rng = rand::thread_rng();
    for b in padding.iter_mut() {
        let mask = rng.gen::<u8>() & rng.gen::<u8>();
        *b ^= mask;
    }
}

pub fn deep_sleep_idle(elapsed_idle: Duration, threshold: Duration) -> bool {
    elapsed_idle >= threshold
}

pub const DEFAULT_IDLE_THRESHOLD: Duration = Duration::from_secs(120);

/// Adapter names may only contain ASCII letters, digits, space, `_`, `-`.
/// Anything else is rejected so `;`, `"`, `|` cannot form a second command.
pub fn sanitize_adapter_name(adapter_name: &str) -> Result<String, crate::error::DpiGuardError> {
    if adapter_name.is_empty()
        || !adapter_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_')
    {
        return Err(crate::error::DpiGuardError::OutOfRange(
            "kill-switch adapter name must be [A-Za-z0-9 _-]+".into(),
        ));
    }
    Ok(adapter_name.to_string())
}

pub fn kill_switch_command(adapter_name: &str) -> Result<String, crate::error::DpiGuardError> {
    let name = sanitize_adapter_name(adapter_name)?;
    Ok(format!(
        "Disable-NetAdapter -Name \"{}\" -Confirm:$false",
        name
    ))
}

/// Never auto-spawned. Callers that opt in must pass `enable_kill_switch`.
pub fn kill_switch_trigger(adapter_name: &str, enable: bool) -> Result<Option<String>, crate::error::DpiGuardError> {
    if !enable {
        return Ok(None);
    }
    Ok(Some(kill_switch_command(adapter_name)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_is_non_negative_and_roughly_bounded() {
        for _ in 0..1000 {
            let d = add_dynamic_jitter();
            assert!(d.as_millis() < 200);
        }
    }

    #[test]
    fn padding_bounded_0_to_128() {
        for _ in 0..50 {
            let out = add_random_padding(b"x");
            assert!(out.len() >= 1 && out.len() <= 1 + 128);
        }
    }

    #[test]
    fn ttl_normalizes_to_64_or_128() {
        assert_eq!(normalize_ttl(60), 64);
        assert_eq!(normalize_ttl(96), 64);
        assert_eq!(normalize_ttl(97), 128);
        assert_eq!(normalize_ttl(255), 128);
    }

    #[test]
    fn fake_options_contain_mss_1460_and_nops() {
        let opts = fake_tcp_options(111, 0);
        let mss = opts.iter().find(|o| o.kind == 2).unwrap();
        assert_eq!(mss.bytes, 1460u16.to_be_bytes().to_vec());
        assert!(opts.iter().any(|o| o.kind == 1));
        let wire = encode_tcp_options(&opts);
        assert_eq!(wire.len() % 4, 0);
        assert_eq!(wire[0], 2);
        assert_eq!(wire[4], 1); // NOP before WScale
    }

    #[test]
    fn shuffle_preserves_multiset() {
        let mut suites = vec![1, 2, 3, 4, 5];
        let original = suites.clone();
        shuffle_cipher_suites(&mut suites);
        let mut sorted = suites.clone();
        sorted.sort();
        let mut orig_sorted = original.clone();
        orig_sorted.sort();
        assert_eq!(sorted, orig_sorted);
    }

    #[test]
    fn grease_value_is_from_the_rfc_table() {
        let mut list = vec![1, 2, 3];
        add_grease_values(&mut list);
        assert_eq!(list.len(), 4);
        assert!(list.iter().any(|v| GREASE_VALUES.contains(v)));
    }

    #[test]
    fn hash_sensitive_is_deterministic_and_salted() {
        let a = hash_sensitive("1.2.3.4", b"salt1");
        let b = hash_sensitive("1.2.3.4", b"salt1");
        let c = hash_sensitive("1.2.3.4", b"salt2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn run_salt_is_stable_within_a_process() {
        assert_eq!(run_salt(), run_salt());
        assert!(!run_salt().is_empty());
    }

    #[test]
    fn generate_token_is_32_hex_chars() {
        let t = generate_token();
        assert_eq!(t.len(), 32);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn window_size_stays_in_range() {
        for _ in 0..200 {
            let w = randomize_window_size(65535);
            assert!(w >= 1024 && w <= 65535);
        }
    }

    #[test]
    fn deep_sleep_threshold_boundary() {
        assert!(!deep_sleep_idle(
            Duration::from_secs(119),
            DEFAULT_IDLE_THRESHOLD
        ));
        assert!(deep_sleep_idle(
            Duration::from_secs(120),
            DEFAULT_IDLE_THRESHOLD
        ));
    }

    #[test]
    fn kill_switch_rejects_injection() {
        assert!(kill_switch_command("Wi-Fi\"; Remove-Item C:\\").is_err());
        assert!(kill_switch_command("Wi-Fi; calc").is_err());
        let cmd = kill_switch_command("Wi-Fi").unwrap();
        assert!(cmd.contains("Wi-Fi"));
        assert!(!kill_switch_trigger("Wi-Fi", false).unwrap().is_some());
    }

    #[test]
    fn noise_flips_only_a_fraction_of_bits() {
        let orig = vec![0u8; 64];
        let mut pad = orig.clone();
        inject_noise_entropy(&mut pad);
        let flipped_bits: u32 = orig
            .iter()
            .zip(pad.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        // 64 bytes * 8 bits * ~0.25 = ~128; allow a wide band.
        assert!(flipped_bits > 0);
        assert!(flipped_bits < 64 * 8);
    }

    #[test]
    fn empty_cert_cache_allows_all() {
        let cache = MemoryCertCache::default();
        assert!(match_sni_cert(&cache, "anything.example"));
    }

    #[test]
    fn dnssec_detects_rrsig_type() {
        // Tiny fake DNS message: header + root question + one RRSIG answer.
        // ID=0, flags=0, QD=1, AN=1, NS=0, AR=0
        let mut msg = vec![0u8; 12];
        msg[5] = 1; // QDCOUNT
        msg[7] = 1; // ANCOUNT
        msg.push(0); // QNAME root
        msg.extend_from_slice(&1u16.to_be_bytes()); // A
        msg.extend_from_slice(&1u16.to_be_bytes()); // IN
        msg.push(0); // NAME root
        msg.extend_from_slice(&46u16.to_be_bytes()); // RRSIG
        msg.extend_from_slice(&1u16.to_be_bytes()); // IN
        msg.extend_from_slice(&0u32.to_be_bytes()); // TTL
        msg.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
        assert!(validate_dnssec(&msg).unwrap());
        assert!(!validate_dnssec(&[0u8; 11]).unwrap());
    }

    #[test]
    fn shape_fingerprint_adds_grease() {
        let mut fp = simulate_browser_fingerprint("chrome");
        let n = fp.cipher_suites.len();
        shape_fingerprint(&mut fp);
        assert_eq!(fp.cipher_suites.len(), n + 1);
    }
}
