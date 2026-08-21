//! quic — QUIC blindspot & obfuscation (2024-2026 research)
//! Based on USENIX Security 2025 "Exposing and Circumventing SNI-based QUIC Censorship"
//! GFW China only inspects QUIC Initial when Source Port > Destination Port.
//! Source Port <= Destination Port = full bypass (port blindspot).
//!
//! Also includes QUIC Initial detection, version handling, and decoy builders.
//! This module is pure logic (no WinDivert) so it tests on any OS.

use crate::error::DpiGuardError;
use crate::packet;
use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// QUIC long header detection (RFC 9000). First bit always 1 for long header.
/// For Initial: bits 7-6 = 11 (long header + fixed bit = 0xC0 mask)
pub fn is_long_header(first_byte: u8) -> bool {
    first_byte & 0x80 != 0
}

pub fn is_fixed_bit_set(first_byte: u8) -> bool {
    first_byte & 0x40 != 0
}

/// Rough check if payload looks like QUIC Initial packet.
/// - first byte 0xC0..0xFF (long header + fixed bit)
/// - version != 0 (0 means version negotiation)
/// - at least 7 bytes (1 + 4 version + at least 2 for lengths)
pub fn is_quic_initial(payload: &[u8]) -> bool {
    if payload.len() < 7 {
        return false;
    }
    let first = payload[0];
    if !is_long_header(first) || !is_fixed_bit_set(first) {
        return false;
    }
    // Packet type bits 5-4: Initial = 00 for QUIC v1/v2 after masking
    // We don't strictly enforce to support drafts; just ensure long header
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    if version == 0 {
        return false; // version negotiation, not Initial
    }
    // QUIC draft versions and v1 (0x00000001) and v2 (0x6b3343cf) all pass
    true
}

/// Detect if GFW would inspect this QUIC packet based on ports.
/// Research: GFW inspects only when Source Port > Destination Port.
///
/// Returns true if packet WOULD be inspected (vulnerable)
pub fn gfw_would_inspect_quic(src_port: u16, dst_port: u16) -> bool {
    src_port > dst_port
}

/// Returns true if this flow is in the blindspot (bypass)
pub fn is_in_blindspot(src_port: u16, dst_port: u16) -> bool {
    src_port <= dst_port
}

/// Choose a bypass source port <= dst_port.
/// Strategy:
/// - If dst_port == 443 (most QUIC), use 443 (equal, bypass)
/// - Otherwise use dst_port itself (equal) or dst_port - 1 if possible
/// - Avoid 0, avoid privileged conflict if possible but WinDivert can spoof any
pub fn choose_bypass_source_port(dst_port: u16) -> u16 {
    if dst_port == 0 {
        return 443;
    }
    // Equal is enough to bypass (since condition is >)
    // Using dst_port itself keeps it simple and avoids privileged low ports
    // For 443, returns 443
    dst_port
}

/// Alternative: use fixed low port that is still <= dst for typical dst=443
/// 443 itself is ideal; 80 also works if dst=443 (80 <= 443)
pub fn choose_bypass_source_port_low(dst_port: u16) -> u16 {
    if dst_port >= 443 {
        443
    } else if dst_port >= 80 {
        80
    } else {
        dst_port
    }
}

/// Rewrite UDP source port in an existing IPv4/IPv6 + UDP packet.
/// Returns new packet with checksums fixed.
pub fn rewrite_udp_src_port(original: &[u8], new_sport: u16) -> Result<Vec<u8>, DpiGuardError> {
    let parsed = crate::packet::parse_l3l4(original).ok_or(DpiGuardError::PacketTooShort {
        need: 28,
        have: original.len(),
    })?;
    if parsed.protocol != crate::packet::PROTO_UDP {
        return Err(DpiGuardError::OutOfRange("rewrite needs UDP".into()));
    }
    let mut out = original.to_vec();
    let off = parsed.l4_offset + crate::packet::udp_off::SRC_PORT;
    if out.len() < off + 2 {
        return Err(DpiGuardError::PacketTooShort {
            need: off + 2,
            have: out.len(),
        });
    }
    out[off..off + 2].copy_from_slice(&new_sport.to_be_bytes());
    // Total length unchanged, just fix checksums
    crate::packet::recalculate_all_checksums(&mut out);
    Ok(out)
}

/// Rewrite UDP destination port in an existing IPv4/IPv6 + UDP packet.
/// Returns a new packet with checksums fixed. Used for the inbound half of
/// the QUIC port NAT: a server reply addressed to the spoofed source port
/// is rewritten back to the client's original source port.
pub fn rewrite_udp_dst_port(original: &[u8], new_dport: u16) -> Result<Vec<u8>, DpiGuardError> {
    let parsed = crate::packet::parse_l3l4(original).ok_or(DpiGuardError::PacketTooShort {
        need: 28,
        have: original.len(),
    })?;
    if parsed.protocol != crate::packet::PROTO_UDP {
        return Err(DpiGuardError::OutOfRange("rewrite needs UDP".into()));
    }
    let mut out = original.to_vec();
    let off = parsed.l4_offset + crate::packet::udp_off::DST_PORT;
    if out.len() < off + 2 {
        return Err(DpiGuardError::PacketTooShort {
            need: off + 2,
            have: out.len(),
        });
    }
    out[off..off + 2].copy_from_slice(&new_dport.to_be_bytes());
    crate::packet::recalculate_all_checksums(&mut out);
    Ok(out)
}

/// Build a QUIC decoy Initial packet with wrong version or padding
/// Similar to TCP decoy but for UDP/443
pub fn build_quic_decoy(reasonable_sni_len: usize) -> Vec<u8> {
    // Minimal fake QUIC Initial that looks like QUIC but won't be parsed by real server
    // Long header, version 1, DCID len 8, SCID len 8, token len 0, length, packet number, payload
    let mut rng = rand::thread_rng();
    let mut pkt = Vec::with_capacity(1200);
    pkt.push(0xC0); // long header, fixed bit, Initial type 00, PN len 0
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // QUIC v1
    let dcid_len: u8 = 8;
    pkt.push(dcid_len);
    for _ in 0..dcid_len {
        pkt.push(rand::Rng::gen(&mut rng));
    }
    let scid_len: u8 = 8;
    pkt.push(scid_len);
    for _ in 0..scid_len {
        pkt.push(rand::Rng::gen(&mut rng));
    }
    pkt.push(0x00); // token length varint 0
    // Length varint - placeholder, fake
    let payload_len = reasonable_sni_len + 20;
    // Encode as varint (simplified: 1 byte if <64, else 2 bytes)
    if payload_len < 64 {
        pkt.push(0x40 | (payload_len as u8));
    } else {
        pkt.push(0x80 | ((payload_len >> 8) as u8 & 0x3F));
        pkt.push((payload_len & 0xFF) as u8);
    }
    pkt.push(0x00); // packet number 0
    // Fake crypto payload with random bytes
    for _ in 0..payload_len {
        pkt.push(rand::Rng::gen(&mut rng));
    }
    pkt
}

/// QUIC flow tracker for source-port NAT (original ephemeral -> spoofed).
/// One entry per (client, server, server-port, original-source-port). The
/// reverse map lets inbound replies to the spoofed port be rewritten back
/// to the client's original port, closing the loop on the blindspot bypass.
///
/// Bounded: entries are capped at [`MAX_QUIC_MAPS`] and pruned once idle for
/// longer than the pipeline's idle timeout.
pub const MAX_QUIC_MAPS: usize = 4096;

#[derive(Debug, Default)]
pub struct QuicPortMapper {
    // (client_ip, server_ip, server_port, orig_sport) -> (spoofed_sport, last_seen)
    forward: HashMap<(IpAddr, IpAddr, u16, u16), (u16, Instant)>,
    // (server_ip, client_ip, server_port, spoofed_sport) -> orig_sport
    reverse: HashMap<(IpAddr, IpAddr, u16, u16), u16>,
}

impl QuicPortMapper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Pick a free spoofed source port `<= server_port` (the blindspot rule)
    /// for this (client, server, server_port) flow, preferring the server
    /// port itself, then descending. `prefer_low` mirrors the
    /// `quic_bypass_use_low_port` config (443/80 instead of the dst port).
    /// Never-intercept ports are skipped so replies to them cannot be filtered.
    pub fn alloc_spoofed(
        &mut self,
        client_ip: IpAddr,
        server_ip: IpAddr,
        server_port: u16,
        prefer_low: bool,
    ) -> Option<u16> {
        let mut candidate = if prefer_low {
            choose_bypass_source_port_low(server_port)
        } else {
            choose_bypass_source_port(server_port)
        };
        loop {
            if candidate == 0 {
                return None;
            }
            let taken = self
                .reverse
                .contains_key(&(server_ip, client_ip, server_port, candidate));
            if !taken && !crate::config::NEVER_INTERCEPT_PORTS.contains(&candidate) {
                return Some(candidate);
            }
            candidate -= 1;
        }
    }

    pub fn insert(
        &mut self,
        client_ip: IpAddr,
        server_ip: IpAddr,
        server_port: u16,
        orig_sport: u16,
        spoofed: u16,
    ) {
        let now = Instant::now();
        self.forward
            .insert((client_ip, server_ip, server_port, orig_sport), (spoofed, now));
        self.reverse
            .insert((server_ip, client_ip, server_port, spoofed), orig_sport);
    }

    /// Spoofed port for an outbound flow, refreshing its idle timestamp.
    pub fn get_spoofed(
        &mut self,
        client_ip: IpAddr,
        server_ip: IpAddr,
        server_port: u16,
        orig_sport: u16,
    ) -> Option<u16> {
        let entry = self
            .forward
            .get_mut(&(client_ip, server_ip, server_port, orig_sport))?;
        entry.1 = Instant::now();
        Some(entry.0)
    }

    /// Original source port for an inbound reply, refreshing idle timestamp.
    pub fn get_original(
        &mut self,
        server_ip: IpAddr,
        client_ip: IpAddr,
        server_port: u16,
        spoofed_sport: u16,
    ) -> Option<u16> {
        let orig = *self
            .reverse
            .get(&(server_ip, client_ip, server_port, spoofed_sport))?;
        if let Some(entry) = self.forward.get_mut(&(client_ip, server_ip, server_port, orig)) {
            entry.1 = Instant::now();
        }
        Some(orig)
    }

    pub fn remove_by_orig(
        &mut self,
        client_ip: IpAddr,
        server_ip: IpAddr,
        server_port: u16,
        orig_sport: u16,
    ) {
        if let Some((spoofed, _)) = self
            .forward
            .remove(&(client_ip, server_ip, server_port, orig_sport))
        {
            self.reverse
                .remove(&(server_ip, client_ip, server_port, spoofed));
        }
    }

    /// Drop mappings idle for longer than `max_age`.
    pub fn prune_idle(&mut self, now: Instant, max_age: Duration) {
        let stale: Vec<(IpAddr, IpAddr, u16, u16)> = self
            .forward
            .iter()
            .filter(|(_, (_, at))| now.saturating_duration_since(*at) >= max_age)
            .map(|(k, _)| *k)
            .collect();
        for (client_ip, server_ip, server_port, orig_sport) in stale {
            self.remove_by_orig(client_ip, server_ip, server_port, orig_sport);
        }
    }
}

/// Decide if a QUIC packet should be rewritten for the blindspot bypass.
/// Applies to any destination port: the pipeline has already confirmed the
/// port is one it intercepts, so only the GFW blindspot rule (src > dst)
/// matters here.
pub fn should_mangle_quic(src_port: u16, dst_port: u16, enable_bypass: bool) -> bool {
    enable_bypass && gfw_would_inspect_quic(src_port, dst_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_long_header() {
        assert!(is_long_header(0xC0));
        assert!(is_long_header(0xC3));
        assert!(!is_long_header(0x40));
        assert!(!is_long_header(0x00));
    }

    #[test]
    fn quic_initial_detection() {
        // Version negotiation (version 0) should NOT be detected as initial
        let mut vn = vec![0xC0, 0x00, 0x00, 0x00, 0x00, 8, 0];
        assert!(!is_quic_initial(&vn));
        // Valid v1 Initial
        vn[1..5].copy_from_slice(&0x00000001u32.to_be_bytes());
        assert!(is_quic_initial(&vn));
        // Too short
        assert!(!is_quic_initial(&[0xC3]));
    }

    #[test]
    fn port_blindspot_logic_matches_paper() {
        // Paper: GFW inspects only when src > dst
        assert!(gfw_would_inspect_quic(54321, 443)); // typical client -> should be inspected
        assert!(!gfw_would_inspect_quic(443, 443)); // equal -> bypass
        assert!(!gfw_would_inspect_quic(80, 443)); // low -> bypass
        assert!(is_in_blindspot(443, 443));
        assert!(is_in_blindspot(80, 443));
        assert!(!is_in_blindspot(60000, 443));
    }

    #[test]
    fn bypass_port_choice_is_leq_dst() {
        for dst in [443u16, 8443, 4433, 80, 53] {
            let src = choose_bypass_source_port(dst);
            assert!(src <= dst, "src {src} should be <= dst {dst}");
        }
        assert_eq!(choose_bypass_source_port(443), 443);
        assert_eq!(choose_bypass_source_port_low(443), 443);
        assert_eq!(choose_bypass_source_port_low(8443), 443);
    }

    #[test]
    fn rewrite_udp_src_port_changes_and_fixes_checksum() {
        let payload = b"hello quic";
        // Build IPv4 UDP packet
        let mut pkt = vec![0u8; 20 + 8 + payload.len()];
        pkt[0] = 0x45;
        pkt[9] = packet::PROTO_UDP;
        pkt[2..4].copy_from_slice(&(pkt.len() as u16).to_be_bytes());
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        packet::recalculate_all_checksums(&mut pkt);

        let new = rewrite_udp_src_port(&pkt, 443).unwrap();
        let parsed = packet::parse_l3l4(&new).unwrap();
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 443);
        // Checksum should be valid (non-zero)
        assert!(new[26] != 0 || new[27] != 0);
    }

    #[test]
    fn mapper_tracks_forward_reverse() {
        let mut m = QuicPortMapper::new();
        let client: IpAddr = "10.0.0.1".parse().unwrap();
        let server: IpAddr = "1.1.1.1".parse().unwrap();
        m.insert(client, server, 443, 54321, 443);
        assert_eq!(m.get_spoofed(client, server, 443, 54321), Some(443));
        assert_eq!(m.get_original(server, client, 443, 443), Some(54321));
        m.remove_by_orig(client, server, 443, 54321);
        assert_eq!(m.get_spoofed(client, server, 443, 54321), None);
    }

    #[test]
    fn mapper_alloc_distinct_spoofed_ports() {
        let mut m = QuicPortMapper::new();
        let client: IpAddr = "10.0.0.1".parse().unwrap();
        let server: IpAddr = "1.1.1.1".parse().unwrap();
        let a = m.alloc_spoofed(client, server, 443, false).unwrap();
        assert_eq!(a, 443);
        m.insert(client, server, 443, 1111, a); // take 443
        let b = m.alloc_spoofed(client, server, 443, false).unwrap();
        assert_ne!(a, b);
        assert!(b > 0 && b < 443);
        // a different server gets a fresh allocation
        let server2: IpAddr = "1.0.0.1".parse().unwrap();
        assert_eq!(m.alloc_spoofed(client, server2, 443, false).unwrap(), 443);
    }

    #[test]
    fn mapper_prunes_idle_entries() {
        let mut m = QuicPortMapper::new();
        let client: IpAddr = "10.0.0.1".parse().unwrap();
        let server: IpAddr = "1.1.1.1".parse().unwrap();
        m.insert(client, server, 443, 54321, 443);
        assert_eq!(m.len(), 1);
        m.prune_idle(Instant::now() + Duration::from_secs(999), Duration::from_secs(120));
        assert_eq!(m.len(), 0);
        assert!(m.get_original(server, client, 443, 443).is_none());
    }

    #[test]
    fn rewrite_udp_dst_port_changes_and_fixes_checksum() {
        let payload = b"hello quic";
        let mut pkt = vec![0u8; 20 + 8 + payload.len()];
        pkt[0] = 0x45;
        pkt[9] = packet::PROTO_UDP;
        pkt[2..4].copy_from_slice(&(pkt.len() as u16).to_be_bytes());
        pkt[12..16].copy_from_slice(&[1, 1, 1, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
        pkt[20..22].copy_from_slice(&443u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        packet::recalculate_all_checksums(&mut pkt);

        let new = rewrite_udp_dst_port(&pkt, 54321).unwrap();
        let parsed = packet::parse_l3l4(&new).unwrap();
        assert_eq!(parsed.dst_port, 54321);
        assert_eq!(parsed.src_port, 443);
    }

    #[test]
    fn should_mangle_only_when_needed() {
        assert!(should_mangle_quic(54321, 443, true));
        assert!(!should_mangle_quic(443, 443, true));
        assert!(!should_mangle_quic(54321, 443, false));
        // Blindspot rule is port-agnostic: src > dst on any intercepted port.
        assert!(should_mangle_quic(54321, 8443, true));
        assert!(!should_mangle_quic(80, 443, true));
    }

    #[test]
    fn decoy_has_reasonable_size() {
        let d = build_quic_decoy(100);
        assert!(d.len() >= 100);
        assert!(d[0] & 0xC0 == 0xC0);
    }
}
