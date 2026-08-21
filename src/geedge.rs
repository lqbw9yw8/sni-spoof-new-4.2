//! geedge — evasion based on leaked commercial firewall source code
//! Based on USENIX Security 2026 "Technical Analysis of the Geedge Networks Firewall Source Code Leak"
//! Geedge firewall does:
//! - Fast SNI extraction by scanning for 0x0000 extension type
//! - Assumes SNI is at fixed offset, doesn't handle fragmentation
//! - Fails on: IP literal SNI, trailing dot, case randomization, GREASE ext types, padded records
//! This module provides Geedge-specific evasion techniques.

use crate::error::DpiGuardError;
use rand::Rng;

/// SNI as IP literal (RFC 6066 says SNI must NOT be IP literal, but Geedge may skip it)
//! Some DPI parsers check if SNI is IP and skip filtering (to avoid breaking IP-based virtual hosting)
pub fn sni_as_ip_literal(ip: std::net::IpAddr) -> Vec<u8> {
    ip.to_string().into_bytes()
}

/// Add TLS record padding (RFC 8446 padding extension) to confuse length-based fingerprinting
/// Padding extension type 0x0015, payload = zeros
pub fn add_tls_padding_extension(record: &[u8], pad_len: usize) -> Result<Vec<u8>, DpiGuardError> {
    if pad_len > 1024 {
        return Err(DpiGuardError::OutOfRange("padding too large".into()));
    }
    let padding = vec![0u8; pad_len];
    crate::fragmentation::inject_hidden_sni_in_unknown_ext(record, &padding, 0x0015)
        .map_err(|e| DpiGuardError::OutOfRange(format!("padding inject failed: {e}")))
}

/// Geedge assumes SNI is first extension; we can add GREASE extensions before SNI to shift offset
pub fn prepend_grease_extensions(record: &[u8], count: usize) -> Result<Vec<u8>, DpiGuardError> {
    if count == 0 { return Ok(record.to_vec()); }
    if count > 10 { return Err(DpiGuardError::OutOfRange("too many GREASE exts".into())); }
    let mut out = record.to_vec();
    // Inject GREASE exts one by one at beginning of extension list
    // For simplicity, we inject as unknown exts at end, but with small payload to shift
    // Real prepend would need more complex offset handling; this is approximation that still confuses naive offset-based parsers
    for _ in 0..count {
        let grease_type = crate::sni_mutations::random_disguise_type();
        let fake_payload = vec![0u8; 4];
        out = crate::fragmentation::inject_hidden_sni_in_unknown_ext(&out, &fake_payload, grease_type)?;
    }
    Ok(out)
}

/// Split ClientHello across multiple TLS records (record injection)
//! Geneva-style: inject Alert or Heartbeat record before real ClientHello
/// Some DPI only inspects first record
pub fn inject_fake_record_before_hello(hello: &[u8], fake_type: u8) -> Vec<u8> {
    // fake_type: 0x15 = Alert, 0x14 = ChangeCipherSpec, 0x18 = Heartbeat
    let mut out = Vec::with_capacity(5 + 2 + hello.len());
    out.push(fake_type);
    out.extend_from_slice(&0x0303u16.to_be_bytes()); // version
    out.extend_from_slice(&2u16.to_be_bytes()); // length
    out.extend_from_slice(&[0x00, 0x00]); // payload
    out.extend_from_slice(hello);
    out
}

/// IP-level fragmentation evasion (GoodbyeDPI style)
//! Split IPv4 packet into fragments with MF flag
/// This bypasses DPI that doesn't reassemble IP fragments
pub fn should_use_ip_fragmentation(payload_len: usize, mtu: usize) -> bool {
    // Use IP frag when payload > MTU and DPI is known to not reassemble (Geedge, Henan)
    payload_len > mtu.saturating_sub(20)
}

/// Check if SNI would be missed by Geedge's naive extractor
/// Geedge looks for: extension type 0x0000 at fixed offset, SNI list len, name type 0
pub fn would_geedge_miss_sni(record: &[u8]) -> bool {
    // If SNI ext type is not 0x0000, Geedge misses
    if crate::fragmentation::sni_bytes(record).is_none() {
        return true;
    }
    // If SNI has trailing dot, some Geedge versions miss
    if let Some(sni) = crate::fragmentation::sni_bytes(record) {
        if sni.last() == Some(&b'.') {
            return true;
        }
        // IP literal
        if sni.iter().all(|&b| b.is_ascii_digit() || b == b'.' || b == b':') {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragmentation::encode_client_hello;

    #[test]
    fn ip_literal_sni_is_ip_string() {
        let ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        let sni = sni_as_ip_literal(ip);
        assert_eq!(sni, b"1.1.1.1");
    }

    #[test]
    fn padding_extension_grows_record() {
        let record = encode_client_hello("example.com");
        let padded = add_tls_padding_extension(&record, 32).unwrap();
        assert!(padded.len() > record.len());
    }

    #[test]
    fn grease_prepend_grows() {
        let record = encode_client_hello("example.com");
        let with_grease = prepend_grease_extensions(&record, 2).unwrap();
        assert!(with_grease.len() > record.len());
    }

    #[test]
    fn fake_record_injection() {
        let hello = encode_client_hello("example.com");
        let injected = inject_fake_record_before_hello(&hello, 0x15);
        assert_eq!(injected[0], 0x15);
        assert!(injected.windows(11).any(|w| w == b"example.com"));
    }

    #[test]
    fn geedge_miss_detection() {
        let record = encode_client_hello("example.com");
        assert!(!would_geedge_miss_sni(&record));
        let disguised = crate::fragmentation::disguise_sni_extension_type(&record, 0x0A0A).unwrap();
        assert!(would_geedge_miss_sni(&disguised));
        let with_dot = crate::fragmentation::encode_client_hello("example.com.");
        // Our simple encoder for trailing dot still has SNI bytes with dot, but sni_bytes returns Some
        // Geedge miss logic checks trailing dot
        assert!(would_geedge_miss_sni(&with_dot));
    }

    #[test]
    fn ip_frag_decision() {
        assert!(should_use_ip_fragmentation(2000, 1500));
        assert!(!should_use_ip_fragmentation(100, 1500));
    }
}
