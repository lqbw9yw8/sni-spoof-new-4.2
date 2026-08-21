//! fooling — 8 TCP-layer deception techniques. [DONE] for construction.
//!
//! SYN-ACK/RST "swap endpoint" foolers are built here; the pipeline only
//! emits them when `enable_swap_foolers` is on (off by default). Live
//! decoys used by default are TTL-limited, wrong-checksum copies of the
//! *outbound* ClientHello (same 5-tuple as the real flow).

use crate::error::DpiGuardError;
use crate::packet::{self, tcp_off};

fn ihl(pkt: &[u8]) -> Result<usize, DpiGuardError> {
    packet::Ipv4View::parse(pkt)
        .map(|v| v.ihl_bytes())
        .ok_or(DpiGuardError::PacketTooShort {
            need: 20,
            have: pkt.len(),
        })
}

pub fn build_wrong_checksum(pkt: &mut [u8]) -> Result<(), DpiGuardError> {
    let parsed = packet::parse_l3l4(pkt).ok_or(DpiGuardError::PacketTooShort {
        need: 40,
        have: pkt.len(),
    })?;
    if parsed.protocol != packet::PROTO_TCP {
        return Err(DpiGuardError::OutOfRange("wrong_checksum needs TCP".into()));
    }
    let off = parsed.l4_offset + tcp_off::CHECKSUM;
    if pkt.len() < off + 2 {
        return Err(DpiGuardError::PacketTooShort {
            need: off + 2,
            have: pkt.len(),
        });
    }
    let correct = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
    let mut wrong = !correct;
    if wrong == correct {
        wrong = wrong.wrapping_add(1);
    }
    pkt[off..off + 2].copy_from_slice(&wrong.to_be_bytes());
    Ok(())
}

pub fn build_tcp_md5sig_option() -> [u8; 18] {
    let mut opt = [0u8; 18];
    opt[0] = 19;
    opt[1] = 18;
    let mut rng = rand::thread_rng();
    for b in opt[2..].iter_mut() {
        *b = rand::Rng::gen(&mut rng);
    }
    opt
}

pub fn build_synack_fooler(
    template_syn: &[u8],
    fake_seq: u32,
    fake_ack: u32,
) -> Result<Vec<u8>, DpiGuardError> {
    build_flagged_control_packet(
        template_syn,
        packet::TCP_FLAG_SYN | packet::TCP_FLAG_ACK,
        fake_seq,
        fake_ack,
        true,
    )
}

pub fn build_rst_fooler(template_syn: &[u8], fake_seq: u32) -> Result<Vec<u8>, DpiGuardError> {
    build_flagged_control_packet(template_syn, packet::TCP_FLAG_RST, fake_seq, 0, true)
}

fn build_flagged_control_packet(
    template: &[u8],
    flags: u8,
    seq: u32,
    ack: u32,
    swap_endpoints: bool,
) -> Result<Vec<u8>, DpiGuardError> {
    let parsed = packet::parse_l3l4(template).ok_or(DpiGuardError::PacketTooShort {
        need: 40,
        have: template.len(),
    })?;
    if parsed.protocol != packet::PROTO_TCP {
        return Err(DpiGuardError::OutOfRange("control packet needs TCP".into()));
    }
    let ih = parsed.l3_header_len;
    let tcp_hdr = parsed.l4_header_len;
    let mut out = template[..ih + tcp_hdr].to_vec();
    if swap_endpoints {
        match parsed.l3 {
            packet::L3::Ipv4 => {
                let src = out[12..16].to_vec();
                let dst = out[16..20].to_vec();
                out[12..16].copy_from_slice(&dst);
                out[16..20].copy_from_slice(&src);
            }
            packet::L3::Ipv6 => {
                let src = out[8..24].to_vec();
                let dst = out[24..40].to_vec();
                out[8..24].copy_from_slice(&dst);
                out[24..40].copy_from_slice(&src);
            }
        }
        let sp = out[ih + tcp_off::SRC_PORT..ih + tcp_off::SRC_PORT + 2].to_vec();
        let dp = out[ih + tcp_off::DST_PORT..ih + tcp_off::DST_PORT + 2].to_vec();
        out[ih + tcp_off::SRC_PORT..ih + tcp_off::SRC_PORT + 2].copy_from_slice(&dp);
        out[ih + tcp_off::DST_PORT..ih + tcp_off::DST_PORT + 2].copy_from_slice(&sp);
    }
    out[ih + tcp_off::SEQ..ih + tcp_off::SEQ + 4].copy_from_slice(&seq.to_be_bytes());
    out[ih + tcp_off::ACK..ih + tcp_off::ACK + 4].copy_from_slice(&ack.to_be_bytes());
    out[ih + tcp_off::FLAGS] = flags;
    packet::set_l3_total_len(&mut out, out.len());
    packet::recalculate_all_checksums(&mut out);
    Ok(out)
}

pub fn tcp_wrap_packet(pkt: &[u8], extra_option_bytes: usize) -> Result<Vec<u8>, DpiGuardError> {
    let ih = ihl(pkt)?;
    if pkt.len() < ih + 20 {
        return Err(DpiGuardError::PacketTooShort {
            need: ih + 20,
            have: pkt.len(),
        });
    }
    let old_tcp_hdr_len = packet::ParsedPacket::tcp_header_len(&pkt[ih..]).ok_or(
        DpiGuardError::PacketTooShort {
            need: ih + 20,
            have: pkt.len(),
        },
    )?;
    let pad = (4 - (extra_option_bytes % 4)) % 4;
    let extra = extra_option_bytes + pad;
    let new_tcp_hdr_len = old_tcp_hdr_len + extra;
    if new_tcp_hdr_len > 60 {
        return Err(DpiGuardError::OutOfRange(
            "TCP header would exceed 60-byte max (data offset is 4 bits)".into(),
        ));
    }

    let mut out = Vec::with_capacity(ih + new_tcp_hdr_len + (pkt.len() - ih - old_tcp_hdr_len));
    out.extend_from_slice(&pkt[..ih + old_tcp_hdr_len]);
    out.extend(std::iter::repeat(1u8).take(extra));
    out.extend_from_slice(&pkt[ih + old_tcp_hdr_len..]);

    out[ih + 12] = (((new_tcp_hdr_len / 4) as u8) << 4) | (out[ih + 12] & 0x0F);
    packet::set_l3_total_len(&mut out, out.len());
    packet::recalculate_all_checksums(&mut out);
    Ok(out)
}

pub fn udp_len_fooling(pkt: &mut [u8], delta: i32) -> Result<(), DpiGuardError> {
    let parsed = packet::parse_l3l4(pkt).ok_or(DpiGuardError::PacketTooShort {
        need: 28,
        have: pkt.len(),
    })?;
    if parsed.protocol != packet::PROTO_UDP {
        return Err(DpiGuardError::OutOfRange("udp_len_fooling needs UDP".into()));
    }
    let len_off = parsed.l4_offset + packet::udp_off::LEN;
    let real_len = u16::from_be_bytes([pkt[len_off], pkt[len_off + 1]]) as i32;
    let new_len = (real_len + delta).clamp(8, u16::MAX as i32) as u16;
    pkt[len_off..len_off + 2].copy_from_slice(&new_len.to_be_bytes());
    Ok(())
}

/// Build a UDP decoy from a real UDP packet: clone, apply length delta.
pub fn build_udp_len_decoy(pkt: &[u8], delta: i32) -> Result<Vec<u8>, DpiGuardError> {
    let mut out = pkt.to_vec();
    udp_len_fooling(&mut out, delta)?;
    Ok(out)
}

pub fn disorder_mode(fragments: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = fragments;
    if out.len() >= 2 {
        out.swap(0, 1);
    }
    out
}

pub fn reverse_mode(payload: &[u8], n: usize) -> (Vec<u8>, Vec<u8>) {
    let n = n.min(payload.len());
    let mut reversed_prefix = payload[..n].to_vec();
    reversed_prefix.reverse();
    let mut garbled = reversed_prefix;
    garbled.extend_from_slice(&payload[n..]);
    (garbled, payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_ipv4_tcp_packet() -> Vec<u8> {
        packet::wrap_ipv4_tcp(b"", [10, 0, 0, 1], [10, 0, 0, 2], 1, 443, 1, 0)
    }

    #[test]
    fn wrong_checksum_actually_changes_field() {
        let mut pkt = minimal_ipv4_tcp_packet();
        let before = u16::from_be_bytes([pkt[36], pkt[37]]);
        build_wrong_checksum(&mut pkt).unwrap();
        let after = u16::from_be_bytes([pkt[36], pkt[37]]);
        assert_ne!(before, after);
    }

    #[test]
    fn md5sig_option_has_correct_kind_and_len() {
        let opt = build_tcp_md5sig_option();
        assert_eq!(opt[0], 19);
        assert_eq!(opt[1], 18);
    }

    #[test]
    fn synack_fooler_swaps_endpoints_and_sets_flags() {
        let template = minimal_ipv4_tcp_packet();
        let pkt = build_synack_fooler(&template, 1000, 2000).unwrap();
        assert_eq!(&pkt[12..16], &[10, 0, 0, 2]);
        assert_eq!(pkt[20 + 13], packet::TCP_FLAG_SYN | packet::TCP_FLAG_ACK);
    }

    #[test]
    fn rst_fooler_sets_rst_flag_only() {
        let template = minimal_ipv4_tcp_packet();
        let pkt = build_rst_fooler(&template, 123).unwrap();
        assert_eq!(pkt[20 + 13], packet::TCP_FLAG_RST);
    }

    #[test]
    fn tcp_wrap_increases_header_len_and_pads_to_multiple_of_4() {
        let pkt = minimal_ipv4_tcp_packet();
        let out = tcp_wrap_packet(&pkt, 3).unwrap();
        let ih = ihl(&out).unwrap();
        let new_hdr_len = (((out[ih + 12] >> 4) & 0x0F) as usize) * 4;
        assert_eq!(new_hdr_len % 4, 0);
        assert!(new_hdr_len > 20);
    }

    #[test]
    fn udp_len_fooling_applies_delta() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[1, 1, 1, 1]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 2]);
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes());
        udp_len_fooling(&mut pkt, 100).unwrap();
        let new_len = u16::from_be_bytes([pkt[24], pkt[25]]);
        assert_eq!(new_len, 108);
        let decoy = build_udp_len_decoy(&pkt, -10).unwrap();
        assert_ne!(decoy[24..26], pkt[24..26]);
    }

    #[test]
    fn disorder_mode_swaps_first_two() {
        let frags = vec![vec![0], vec![1], vec![2]];
        let out = disorder_mode(frags);
        assert_eq!(out, vec![vec![1], vec![0], vec![2]]);
    }

    #[test]
    fn reverse_mode_reverses_only_prefix() {
        let (garbled, correct) = reverse_mode(b"HELLOworld", 5);
        assert_eq!(&garbled[..5], b"OLLEH");
        assert_eq!(&garbled[5..], b"world");
        assert_eq!(correct, b"HELLOworld".to_vec());
    }
}
