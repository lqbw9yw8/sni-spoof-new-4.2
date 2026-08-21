//! doh — DNS-over-HTTPS resolution (A records). [DONE]
//!
//! Resolves a hostname through a DoH endpoint so the query never travels as
//! plaintext over UDP/53 where an inline DPI or local observer could log it.
//! Fail-closed by design: there is deliberately **no** plain-DNS fallback —
//! if DoH fails, the caller gets an error rather than a leaked query.
//!
//! IP literals are returned as-is (no DNS at all), so configuring an IP for
//! the relay destination is the zero-leak option.

use crate::error::DpiGuardError;
use rand::Rng;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

pub const DEFAULT_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";
const DOH_TIMEOUT: Duration = Duration::from_secs(10);

/// base64url (RFC 4648 §5) without padding — the encoding DoH GET expects.
pub fn b64url_no_pad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 0x3F] as char);
        out.push(TABLE[(n >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out.trim_end_matches('=').to_string()
}

fn build_a_query(host: &str) -> Result<Vec<u8>, DpiGuardError> {
    let mut q = Vec::with_capacity(host.len() + 18);
    let id: u16 = rand::thread_rng().gen();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR = 0
    for label in host.split('.') {
        if label.is_empty() {
            continue; // tolerate a trailing dot
        }
        if label.len() > 63 {
            return Err(DpiGuardError::Resolution(format!(
                "label too long in host {host:?}"
            )));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    Ok(q)
}

fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize, DpiGuardError> {
    let mut hops = 0usize;
    loop {
        if pos >= msg.len() || hops > 32 {
            return Err(DpiGuardError::Resolution("malformed DNS name".into()));
        }
        let len = msg[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: the name is fully encoded elsewhere, so
            // this position only occupies the 2-byte pointer.
            return Ok(pos + 2);
        }
        pos += 1 + len as usize;
        hops += 1;
    }
}

fn parse_a_records(resp: &[u8]) -> Result<Vec<IpAddr>, DpiGuardError> {
    if resp.len() < 12 {
        return Err(DpiGuardError::Resolution("short DNS response".into()));
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(DpiGuardError::Resolution(format!("DNS RCODE {rcode}")));
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(resp, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if rtype == 1 && rdlen == 4 && pos + 4 <= resp.len() {
            out.push(IpAddr::V4(Ipv4Addr::new(
                resp[pos],
                resp[pos + 1],
                resp[pos + 2],
                resp[pos + 3],
            )));
        }
        pos += rdlen;
    }
    Ok(out)
}

/// Resolve `host` to IPv4 addresses over DoH. An IP literal is returned
/// unchanged (no network). Returns all A records in order.
pub fn resolve_a_v4(host: &str, doh_url: &str) -> Result<Vec<IpAddr>, DpiGuardError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let query = build_a_query(host)?;
    let url = format!("{}?dns={}", doh_url.trim_end_matches('/'), b64url_no_pad(&query));
    let response = ureq::get(&url)
        .timeout(DOH_TIMEOUT)
        .call()
        .map_err(|e| DpiGuardError::Resolution(format!("DoH request failed: {e}")))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .map_err(|e| DpiGuardError::Resolution(format!("DoH read failed: {e}")))?;
    let ips = parse_a_records(&body)?;
    if ips.is_empty() {
        return Err(DpiGuardError::Resolution(format!(
            "no A records for {host}"
        )));
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_matches_rfc_vectors() {
        assert_eq!(b64url_no_pad(b""), "");
        assert_eq!(b64url_no_pad(b"f"), "Zg");
        assert_eq!(b64url_no_pad(b"fo"), "Zm8");
        assert_eq!(b64url_no_pad(b"foo"), "Zm9v");
        assert_eq!(b64url_no_pad(b"foob"), "Zm9vYg");
        assert_eq!(b64url_no_pad(b"fooba"), "Zm9vYmE");
        assert_eq!(b64url_no_pad(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn query_has_header_question_and_qtype_a() {
        let q = build_a_query("example.com").unwrap();
        assert!(q.len() >= 12 + 13 + 4);
        assert_eq!(q[2], 0x01); // RD flag
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT
        // QTYPE A + QCLASS IN at the tail
        let tail = &q[q.len() - 4..];
        assert_eq!(tail, &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn parse_extracts_a_records_and_honours_rcode() {
        // Header: id, flags 0x8180 (QR|RD|RA, RCODE=0), QD=1, AN=1.
        let mut m = vec![0u8; 12];
        m[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        m[2] = 0x81;
        m[3] = 0x80;
        m[5] = 1;
        m[7] = 1;
        // Question: example.com A IN
        m.extend_from_slice(b"\x07example\x03com\x00");
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer: name ptr 0xC00C, A, IN, TTL 60, RDLEN 4, 1.2.3.4
        m.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        m.extend_from_slice(&[0x00, 0x00, 0x00, 60]);
        m.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
        m.extend_from_slice(&[1, 2, 3, 4]);

        let ips = parse_a_records(&m).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);

        // NXDOMAIN (RCODE=3) must be an error, not an empty list.
        let mut nx = m.clone();
        nx[3] = 0x83;
        assert!(parse_a_records(&nx).is_err());
    }

    #[test]
    fn ip_literal_skips_network() {
        let ips = resolve_a_v4("1.2.3.4", DEFAULT_DOH_URL).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn malformed_label_rejected() {
        let big = "a".repeat(64);
        assert!(build_a_query(&big).is_err());
    }
}
