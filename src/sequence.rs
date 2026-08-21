//! sequence — decoy-packet / out-of-window SEQ techniques. [DONE] for
//! construction; the capture loop sends the bytes.

use crate::error::DpiGuardError;
use crate::packet::{self, tcp_off};
use std::time::Duration;

/// Shift SEQ by a signed offset with defined wrapping (negative offsets
/// work; values outside i32 still wrap via i128).
pub fn calculate_wrong_seq(real_seq: u32, offset: i64) -> u32 {
    (real_seq as i128).wrapping_add(offset as i128) as u32
}

/// Place SEQ just past the advertised receive window so a real stack
/// drops the decoy while a loose DPI parser still consumes it.
pub fn calculate_wrong_seq_outside_window(real_seq: u32, window: u16) -> u32 {
    real_seq.wrapping_add(window as u32).wrapping_add(1)
}

/// Build a decoy: same IP/TCP **header including options** as `template`,
/// SEQ overwritten, payload replaced.
pub fn build_decoy_packet(
    template: &[u8],
    fake_seq: u32,
    decoy_payload: &[u8],
) -> Result<Vec<u8>, DpiGuardError> {
    let view = packet::Ipv4View::parse(template).ok_or(DpiGuardError::PacketTooShort {
        need: 20,
        have: template.len(),
    })?;
    let ihl = view.ihl_bytes();
    if template.len() < ihl + 20 {
        return Err(DpiGuardError::PacketTooShort {
            need: ihl + 20,
            have: template.len(),
        });
    }
    let tcp = &template[ihl..];
    let tcp_hdr_len = packet::ParsedPacket::tcp_header_len(tcp).ok_or(
        DpiGuardError::PacketTooShort {
            need: ihl + 20,
            have: template.len(),
        },
    )?;
    let mut out = template[..ihl + tcp_hdr_len].to_vec();
    out[ihl + tcp_off::SEQ..ihl + tcp_off::SEQ + 4].copy_from_slice(&fake_seq.to_be_bytes());
    out.extend_from_slice(decoy_payload);

    packet::set_l3_total_len(&mut out, out.len());
    packet::recalculate_all_checksums(&mut out);
    Ok(out)
}

pub fn inject_ttl_limited_decoy(decoy: &mut Vec<u8>, ttl: u8) {
    packet::set_ttl(decoy, ttl);
    packet::recalculate_all_checksums(decoy);
}

/// Send decoy, wait `race_condition_fix_delay`, then send real. Order is
/// sequential on purpose — `join!` would race the NIC.
pub async fn send_simultaneous<F, Fut>(
    real: Vec<u8>,
    decoy: Vec<u8>,
    send_fn: F,
) -> Result<(), DpiGuardError>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<(), DpiGuardError>>,
{
    send_fn(decoy).await?;
    tokio::time::sleep(race_condition_fix_delay()).await;
    send_fn(real).await?;
    Ok(())
}

pub fn add_padding_to_decoy(decoy_payload: &[u8], target_len: usize) -> Vec<u8> {
    let mut out = decoy_payload.to_vec();
    if out.len() < target_len {
        out.resize(target_len, 0u8);
    }
    out
}

pub fn race_condition_fix_delay() -> Duration {
    Duration::from_micros(50)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_seq_wraps_correctly() {
        assert_eq!(calculate_wrong_seq(u32::MAX, 1), 0);
        assert_eq!(calculate_wrong_seq(100, 50), 150);
        assert_eq!(calculate_wrong_seq(100, -1), 99);
        assert_eq!(calculate_wrong_seq(0, -1), u32::MAX);
    }

    #[test]
    fn outside_window_is_past_wnd() {
        assert_eq!(calculate_wrong_seq_outside_window(10, 100), 111);
    }

    #[test]
    fn padding_extends_to_target() {
        let out = add_padding_to_decoy(&[1, 2, 3], 8);
        assert_eq!(out.len(), 8);
        assert_eq!(&out[..3], &[1, 2, 3]);
    }

    #[test]
    fn padding_never_truncates() {
        let out = add_padding_to_decoy(&[1, 2, 3, 4, 5], 2);
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn race_delay_is_50_microseconds() {
        assert_eq!(race_condition_fix_delay(), Duration::from_micros(50));
    }

    fn packet_with_tcp_option() -> Vec<u8> {
        // 20-byte IP + 24-byte TCP (one NOP*4 option block)
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[2..4].copy_from_slice(&44u16.to_be_bytes());
        pkt[32] = 0x60; // data offset = 6 (24 bytes)
        pkt[33] = 0;
        pkt[36] = 1;
        pkt[37] = 1;
        pkt[38] = 1;
        pkt[39] = 1;
        packet::recalculate_all_checksums(&mut pkt);
        pkt
    }

    #[test]
    fn decoy_packet_keeps_tcp_options_and_sets_seq() {
        let template = packet_with_tcp_option();
        let decoy = build_decoy_packet(&template, 0xdeadbeef, b"bait").unwrap();
        let view = packet::Ipv4View::parse(&decoy).unwrap();
        let ihl = view.ihl_bytes();
        let hdr_len = packet::ParsedPacket::tcp_header_len(&decoy[ihl..]).unwrap();
        assert_eq!(hdr_len, 24);
        let seq = u32::from_be_bytes([
            decoy[ihl + 4],
            decoy[ihl + 5],
            decoy[ihl + 6],
            decoy[ihl + 7],
        ]);
        assert_eq!(seq, 0xdeadbeef);
        assert_eq!(&decoy[ihl + hdr_len..], b"bait");
        let mut sum: u32 = 0;
        for chunk in decoy[..20].chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF);
    }

    #[test]
    fn ttl_limited_decoy_sets_low_ttl() {
        let template = packet_with_tcp_option();
        let mut decoy = build_decoy_packet(&template, 1, b"x").unwrap();
        inject_ttl_limited_decoy(&mut decoy, 8);
        assert_eq!(decoy[8], 8);
    }

    #[tokio::test]
    async fn send_simultaneous_sends_decoy_then_real() {
        use std::sync::{Arc, Mutex};
        let order = Arc::new(Mutex::new(Vec::new()));
        let order2 = order.clone();
        let send = move |pkt: Vec<u8>| {
            let order = order2.clone();
            async move {
                order.lock().unwrap().push(pkt);
                Ok(())
            }
        };
        send_simultaneous(vec![2], vec![1], send).await.unwrap();
        assert_eq!(*order.lock().unwrap(), vec![vec![1], vec![2]]);
    }
}
