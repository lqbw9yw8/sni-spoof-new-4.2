//! packet — IPv4/IPv6 + TCP/UDP view and RFC 1071 checksums. [DONE]
//!
//! Thin, allocation-light helpers over on-wire buffers. Every reader
//! validates lengths before indexing so a truncated packet cannot panic
//! the capture loop.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::DpiGuardError;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// RFC 1071 one's-complement checksum. Caller zeros the checksum field
/// first and, for TCP/UDP, prepends the correct pseudo-header.
pub fn checksum_rfc1071(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn tcp_checksum_v4(src: [u8; 4], dst: [u8; 4], tcp_segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp_segment.len() + 1);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.push(0);
    buf.push(PROTO_TCP);
    buf.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(tcp_segment);
    if tcp_segment.len() % 2 == 1 {
        buf.push(0);
    }
    checksum_rfc1071(&buf)
}

pub fn tcp_checksum_v6(src: [u8; 16], dst: [u8; 16], tcp_segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + tcp_segment.len() + 1);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&(tcp_segment.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, PROTO_TCP]);
    buf.extend_from_slice(tcp_segment);
    if tcp_segment.len() % 2 == 1 {
        buf.push(0);
    }
    checksum_rfc1071(&buf)
}

pub fn udp_checksum_v4(src: [u8; 4], dst: [u8; 4], udp_segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + udp_segment.len() + 1);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.push(0);
    buf.push(PROTO_UDP);
    buf.extend_from_slice(&(udp_segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(udp_segment);
    if udp_segment.len() % 2 == 1 {
        buf.push(0);
    }
    udp_checksum_nonzero(checksum_rfc1071(&buf))
}

pub fn udp_checksum_v6(src: [u8; 16], dst: [u8; 16], udp_segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + udp_segment.len() + 1);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&(udp_segment.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, PROTO_UDP]);
    buf.extend_from_slice(udp_segment);
    if udp_segment.len() % 2 == 1 {
        buf.push(0);
    }
    udp_checksum_nonzero(checksum_rfc1071(&buf))
}

/// RFC 768: a computed UDP checksum of 0 is transmitted as 0xFFFF.
fn udp_checksum_nonzero(cksum: u16) -> u16 {
    if cksum == 0 {
        0xFFFF
    } else {
        cksum
    }
}

/// Bound `buf` to the IPv4 Total Length / IPv6 Payload Length so ethernet
/// padding or a oversized WinDivert buffer cannot leak into TLS parse or
/// TCP checksums. Truncated packets (header length > buffer) keep the
/// bytes we have so the caller can still fail-open.
pub fn l3_slice(buf: &[u8]) -> Option<&[u8]> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] >> 4 {
        4 => {
            if buf.len() < 20 {
                return None;
            }
            let total = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            if total < 20 {
                return None;
            }
            Some(&buf[..total.min(buf.len())])
        }
        6 => {
            if buf.len() < 40 {
                return None;
            }
            let total = 40usize.saturating_add(u16::from_be_bytes([buf[4], buf[5]]) as usize);
            Some(&buf[..total.min(buf.len())])
        }
        _ => None,
    }
}

/// Read-only view over an IPv4 header at the start of `buf`.
pub struct Ipv4View<'a> {
    pub buf: &'a [u8],
    ihl: usize,
}

impl<'a> Ipv4View<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 20 || (buf[0] >> 4) != 4 {
            return None;
        }
        let ihl = ((buf[0] & 0x0F) as usize).saturating_mul(4);
        if ihl < 20 || buf.len() < ihl {
            return None;
        }
        Some(Self { buf, ihl })
    }

    pub fn ihl_bytes(&self) -> usize {
        self.ihl
    }
    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.buf[2], self.buf[3]])
    }
    pub fn ttl(&self) -> u8 {
        self.buf[8]
    }
    pub fn protocol(&self) -> u8 {
        self.buf[9]
    }
    pub fn src(&self) -> [u8; 4] {
        [self.buf[12], self.buf[13], self.buf[14], self.buf[15]]
    }
    pub fn dst(&self) -> [u8; 4] {
        [self.buf[16], self.buf[17], self.buf[18], self.buf[19]]
    }
    pub fn payload(&self) -> &'a [u8] {
        if self.buf.len() < self.ihl {
            &[]
        } else {
            &self.buf[self.ihl..]
        }
    }
}

/// IPv6 header view (40-byte base header, no extension-header walk).
pub struct Ipv6View<'a> {
    pub buf: &'a [u8],
}

impl<'a> Ipv6View<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 40 || (buf[0] >> 4) != 6 {
            return None;
        }
        Some(Self { buf })
    }
    pub fn payload_len(&self) -> u16 {
        u16::from_be_bytes([self.buf[4], self.buf[5]])
    }
    pub fn next_header(&self) -> u8 {
        self.buf[6]
    }
    pub fn hop_limit(&self) -> u8 {
        self.buf[7]
    }
    pub fn src(&self) -> [u8; 16] {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.buf[8..24]);
        a
    }
    pub fn dst(&self) -> [u8; 16] {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.buf[24..40]);
        a
    }
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[40..]
    }
}

pub fn set_ttl(buf: &mut [u8], ttl: u8) {
    if buf.len() < 1 {
        return;
    }
    match buf[0] >> 4 {
        4 if buf.len() > 8 => buf[8] = ttl,
        6 if buf.len() > 7 => buf[7] = ttl,
        _ => {}
    }
}

pub fn recalc_ipv4_checksum(buf: &mut [u8]) {
    if buf.len() < 20 || (buf[0] >> 4) != 4 {
        return;
    }
    let ihl = ((buf[0] & 0x0F) as usize).saturating_mul(4);
    if ihl < 20 || buf.len() < ihl {
        return;
    }
    buf[10] = 0;
    buf[11] = 0;
    let cksum = checksum_rfc1071(&buf[..ihl]);
    buf[10..12].copy_from_slice(&cksum.to_be_bytes());
}

pub fn set_l3_total_len(buf: &mut [u8], total: usize) {
    if buf.len() < 1 {
        return;
    }
    match buf[0] >> 4 {
        4 if buf.len() >= 4 => {
            let t = (total as u16).to_be_bytes();
            buf[2] = t[0];
            buf[3] = t[1];
        }
        6 if buf.len() >= 6 => {
            let payload = total.saturating_sub(40) as u16;
            let t = payload.to_be_bytes();
            buf[4] = t[0];
            buf[5] = t[1];
        }
        _ => {}
    }
}

pub mod tcp_off {
    pub const SRC_PORT: usize = 0;
    pub const DST_PORT: usize = 2;
    pub const SEQ: usize = 4;
    pub const ACK: usize = 8;
    pub const DATAOFF: usize = 12;
    pub const FLAGS: usize = 13;
    pub const WINDOW: usize = 14;
    pub const CHECKSUM: usize = 16;
}

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;

pub mod udp_off {
    pub const SRC_PORT: usize = 0;
    pub const DST_PORT: usize = 2;
    pub const LEN: usize = 4;
    pub const CHECKSUM: usize = 6;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3 {
    Ipv4,
    Ipv6,
}

/// Parsed L3+L4 offsets. All offsets are from the start of `buf`.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub l3: L3,
    pub l3_header_len: usize,
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub l4_offset: usize,
    pub l4_header_len: usize,
    pub payload_offset: usize,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: Option<u8>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_window: Option<u16>,
}

impl ParsedPacket {
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        if buf.len() <= self.payload_offset {
            &[]
        } else {
            &buf[self.payload_offset..]
        }
    }

    pub fn tcp_header_len(tcp: &[u8]) -> Option<usize> {
        if tcp.len() < 20 {
            return None;
        }
        let doff = ((tcp[tcp_off::DATAOFF] >> 4) & 0x0F) as usize * 4;
        if doff < 20 || tcp.len() < doff {
            None
        } else {
            Some(doff)
        }
    }
}

pub fn parse_l3l4(buf: &[u8]) -> Option<ParsedPacket> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] >> 4 {
        4 => parse_ipv4_l4(buf),
        6 => parse_ipv6_l4(buf),
        _ => None,
    }
}

fn parse_ipv4_l4(buf: &[u8]) -> Option<ParsedPacket> {
    let v = Ipv4View::parse(buf)?;
    let l3_header_len = v.ihl_bytes();
    let protocol = v.protocol();
    let src = IpAddr::V4(Ipv4Addr::from(v.src()));
    let dst = IpAddr::V4(Ipv4Addr::from(v.dst()));
    parse_l4(
        buf,
        L3::Ipv4,
        l3_header_len,
        protocol,
        src,
        dst,
        l3_header_len,
    )
}

fn parse_ipv6_l4(buf: &[u8]) -> Option<ParsedPacket> {
    let v = Ipv6View::parse(buf)?;
    // Only handle TCP/UDP directly in the base header (no extension headers).
    let protocol = v.next_header();
    if protocol != PROTO_TCP && protocol != PROTO_UDP {
        return None;
    }
    let src = IpAddr::V6(Ipv6Addr::from(v.src()));
    let dst = IpAddr::V6(Ipv6Addr::from(v.dst()));
    parse_l4(buf, L3::Ipv6, 40, protocol, src, dst, 40)
}

fn parse_l4(
    buf: &[u8],
    l3: L3,
    l3_header_len: usize,
    protocol: u8,
    src: IpAddr,
    dst: IpAddr,
    l4_offset: usize,
) -> Option<ParsedPacket> {
    match protocol {
        PROTO_TCP => {
            let tcp = buf.get(l4_offset..)?;
            let l4_header_len = ParsedPacket::tcp_header_len(tcp)?;
            let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            let tcp_seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let tcp_ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
            let tcp_window = u16::from_be_bytes([tcp[14], tcp[15]]);
            Some(ParsedPacket {
                l3,
                l3_header_len,
                protocol,
                src,
                dst,
                l4_offset,
                l4_header_len,
                payload_offset: l4_offset + l4_header_len,
                src_port,
                dst_port,
                tcp_flags: Some(tcp[tcp_off::FLAGS]),
                tcp_seq: Some(tcp_seq),
                tcp_ack: Some(tcp_ack),
                tcp_window: Some(tcp_window),
            })
        }
        PROTO_UDP => {
            if buf.len() < l4_offset + 8 {
                return None;
            }
            let udp = &buf[l4_offset..];
            let src_port = u16::from_be_bytes([udp[0], udp[1]]);
            let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
            Some(ParsedPacket {
                l3,
                l3_header_len,
                protocol,
                src,
                dst,
                l4_offset,
                l4_header_len: 8,
                payload_offset: l4_offset + 8,
                src_port,
                dst_port,
                tcp_flags: None,
                tcp_seq: None,
                tcp_ack: None,
                tcp_window: None,
            })
        }
        _ => None,
    }
}

/// Recalculate IPv4 header checksum (no-op on IPv6) and TCP/UDP checksum.
/// Checksums cover only the L3 packet (IPv4 Total Length / IPv6 payload
/// length), never trailing padding.
pub fn recalculate_all_checksums(pkt: &mut Vec<u8>) {
    if pkt.is_empty() {
        return;
    }
    let end = l3_slice(pkt).map(|s| s.len()).unwrap_or(pkt.len());
    match pkt[0] >> 4 {
        4 => {
            recalc_ipv4_checksum(pkt);
            let Some(view) = Ipv4View::parse(pkt) else {
                return;
            };
            let ih = view.ihl_bytes();
            if end < ih {
                return;
            }
            let proto = view.protocol();
            let src = view.src();
            let dst = view.dst();
            match proto {
                PROTO_TCP => {
                    let off = ih + tcp_off::CHECKSUM;
                    if pkt.len() >= off + 2 {
                        pkt[off..off + 2].copy_from_slice(&[0, 0]);
                        let cksum = tcp_checksum_v4(src, dst, &pkt[ih..end]);
                        pkt[off..off + 2].copy_from_slice(&cksum.to_be_bytes());
                    }
                }
                PROTO_UDP => {
                    let off = ih + udp_off::CHECKSUM;
                    if pkt.len() >= off + 2 {
                        pkt[off..off + 2].copy_from_slice(&[0, 0]);
                        let cksum = udp_checksum_v4(src, dst, &pkt[ih..end]);
                        pkt[off..off + 2].copy_from_slice(&cksum.to_be_bytes());
                    }
                }
                _ => {}
            }
        }
        6 => {
            if pkt.len() < 40 || end < 40 {
                return;
            }
            let proto = pkt[6];
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&pkt[8..24]);
            dst.copy_from_slice(&pkt[24..40]);
            if proto == PROTO_TCP {
                let off = 40 + tcp_off::CHECKSUM;
                if pkt.len() >= off + 2 {
                    pkt[off..off + 2].copy_from_slice(&[0, 0]);
                    let cksum = tcp_checksum_v6(src, dst, &pkt[40..end]);
                    pkt[off..off + 2].copy_from_slice(&cksum.to_be_bytes());
                }
            } else if proto == PROTO_UDP {
                let off = 40 + udp_off::CHECKSUM;
                if pkt.len() >= off + 2 {
                    pkt[off..off + 2].copy_from_slice(&[0, 0]);
                    let cksum = udp_checksum_v6(src, dst, &pkt[40..end]);
                    pkt[off..off + 2].copy_from_slice(&cksum.to_be_bytes());
                }
            }
        }
        _ => {}
    }
}

/// Replace the L4 payload of an existing packet, fix lengths + checksums,
/// and optionally overwrite the TCP sequence number.
pub fn rebuild_with_payload(
    original: &[u8],
    new_payload: &[u8],
    seq_override: Option<u32>,
) -> Result<Vec<u8>, DpiGuardError> {
    let parsed = parse_l3l4(original).ok_or(DpiGuardError::PacketTooShort {
        need: 40,
        have: original.len(),
    })?;
    let header_end = parsed.payload_offset;
    if original.len() < header_end {
        return Err(DpiGuardError::PacketTooShort {
            need: header_end,
            have: original.len(),
        });
    }
    let mut out = Vec::with_capacity(header_end + new_payload.len());
    out.extend_from_slice(&original[..header_end]);
    out.extend_from_slice(new_payload);
    if let Some(seq) = seq_override {
        let off = parsed.l4_offset + tcp_off::SEQ;
        if out.len() >= off + 4 {
            out[off..off + 4].copy_from_slice(&seq.to_be_bytes());
        }
    }
    set_l3_total_len(&mut out, out.len());
    recalculate_all_checksums(&mut out);
    Ok(out)
}

/// Split a TCP packet's payload into `chunk_size`-byte TCP segments,
/// incrementing SEQ for each subsequent segment.
pub fn tcp_segment_payload(
    original: &[u8],
    chunk_size: usize,
) -> Result<Vec<Vec<u8>>, DpiGuardError> {
    let parsed = parse_l3l4(original).ok_or(DpiGuardError::PacketTooShort {
        need: 40,
        have: original.len(),
    })?;
    if parsed.protocol != PROTO_TCP {
        return Ok(vec![original.to_vec()]);
    }
    let payload = parsed.payload(original);
    if payload.is_empty() {
        return Ok(vec![original.to_vec()]);
    }
    let chunk_size = chunk_size.max(1);
    let seq0 = parsed.tcp_seq.unwrap_or(0);
    let mut out = Vec::new();
    let mut sent = 0usize;
    while sent < payload.len() {
        let end = (sent + chunk_size).min(payload.len());
        let pkt = rebuild_with_payload(
            original,
            &payload[sent..end],
            Some(seq0.wrapping_add(sent as u32)),
        )?;
        out.push(pkt);
        sent = end;
    }
    Ok(out)
}

/// Build a minimal IPv4+TCP packet (20+20 headers) around `payload`.
pub fn wrap_ipv4_tcp(
    payload: &[u8],
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    flags: u8,
) -> Vec<u8> {
    let total = 40 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[32] = 0x50; // data offset 5
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    pkt[40..].copy_from_slice(payload);
    recalculate_all_checksums(&mut pkt);
    pkt
}

/// Build a minimal IPv6+TCP packet around `payload`.
pub fn wrap_ipv6_tcp(
    payload: &[u8],
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    seq: u32,
    flags: u8,
) -> Vec<u8> {
    let total = 40 + 20 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pkt[6] = PROTO_TCP;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src);
    pkt[24..40].copy_from_slice(&dst);
    pkt[40..42].copy_from_slice(&sport.to_be_bytes());
    pkt[42..44].copy_from_slice(&dport.to_be_bytes());
    pkt[44..48].copy_from_slice(&seq.to_be_bytes());
    pkt[52] = 0x50;
    pkt[53] = flags;
    pkt[54..56].copy_from_slice(&65535u16.to_be_bytes());
    pkt[60..].copy_from_slice(payload);
    recalculate_all_checksums(&mut pkt);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_known_bytes() {
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let cksum = checksum_rfc1071(&data);
        let mut check_sum: u32 = 0;
        for chunk in data.chunks_exact(2) {
            check_sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        check_sum += cksum as u32;
        while check_sum >> 16 != 0 {
            check_sum = (check_sum & 0xFFFF) + (check_sum >> 16);
        }
        assert_eq!(check_sum as u16, 0xFFFF);
    }

    #[test]
    fn ipv4_parse_rejects_bad_ihl_and_short_buffers() {
        assert!(Ipv4View::parse(&[]).is_none());
        assert!(Ipv4View::parse(&[0x45, 0, 0]).is_none());
        let mut too_big_ihl = vec![0u8; 20];
        too_big_ihl[0] = 0x4F; // IHL=15 → 60 bytes needed
        assert!(Ipv4View::parse(&too_big_ihl).is_none());
        recalc_ipv4_checksum(&mut []);
        recalc_ipv4_checksum(&mut [0x45]);
    }

    #[test]
    fn wrap_ipv4_roundtrip_ports() {
        let pkt = wrap_ipv4_tcp(b"hi", [10, 0, 0, 1], [10, 0, 0, 2], 1234, 443, 1, TCP_FLAG_ACK);
        let p = parse_l3l4(&pkt).unwrap();
        assert_eq!(p.dst_port, 443);
        assert_eq!(p.src_port, 1234);
        assert_eq!(p.payload(&pkt), b"hi");
        assert_eq!(p.l4_header_len, 20);
    }

    #[test]
    fn wrap_ipv6_roundtrip() {
        let pkt = wrap_ipv6_tcp(
            b"hi",
            [0; 16],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            1111,
            443,
            9,
            TCP_FLAG_ACK,
        );
        let p = parse_l3l4(&pkt).unwrap();
        assert_eq!(p.l3, L3::Ipv6);
        assert_eq!(p.dst_port, 443);
        assert_eq!(p.payload(&pkt), b"hi");
    }

    #[test]
    fn tcp_segment_splits_and_advances_seq() {
        let pkt = wrap_ipv4_tcp(
            b"abcdef",
            [1, 1, 1, 1],
            [2, 2, 2, 2],
            1,
            443,
            100,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let segs = tcp_segment_payload(&pkt, 2).unwrap();
        assert_eq!(segs.len(), 3);
        let p0 = parse_l3l4(&segs[0]).unwrap();
        let p1 = parse_l3l4(&segs[1]).unwrap();
        assert_eq!(p0.tcp_seq, Some(100));
        assert_eq!(p1.tcp_seq, Some(102));
        assert_eq!(p0.payload(&segs[0]), b"ab");
    }

    #[test]
    fn l3_slice_drops_ethernet_padding() {
        let mut pkt = wrap_ipv4_tcp(b"hi", [1, 1, 1, 1], [2, 2, 2, 2], 1, 443, 1, TCP_FLAG_ACK);
        let wire_len = pkt.len();
        pkt.extend_from_slice(&[0xAAu8; 32]);
        let clipped = l3_slice(&pkt).unwrap();
        assert_eq!(clipped.len(), wire_len);
        assert!(!clipped.contains(&0xAA));
    }

    #[test]
    fn l3_slice_rejects_undersize_ipv4_total_len() {
        let mut pkt = wrap_ipv4_tcp(b"", [1, 1, 1, 1], [2, 2, 2, 2], 1, 443, 1, 0);
        pkt[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert!(l3_slice(&pkt).is_none());
    }

    #[test]
    fn checksum_ignores_trailing_padding() {
        let mut pkt = wrap_ipv4_tcp(b"hi", [1, 1, 1, 1], [2, 2, 2, 2], 1, 443, 1, TCP_FLAG_ACK);
        let before = pkt[36..38].to_vec();
        pkt.extend_from_slice(&[0xFFu8; 16]);
        recalculate_all_checksums(&mut pkt);
        assert_eq!(&pkt[36..38], before.as_slice());
    }
}
