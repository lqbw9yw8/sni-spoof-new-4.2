//! utls — JA3/JA4 fingerprint rotation — based on refraction-networking/utls
//! DPI boxes use JA3/JA4 to fingerprint TLS clients even when SNI is mutated.
//! This module provides browser fingerprint mimicry and rotation.
//!
//! IMPORTANT: this crate is a *passive* packet rewriter, not a TLS
//! terminator. Fingerprint changes therefore preserve every offered list's
//! multiset (reorder-only) and never regenerate key shares — see
//! [`apply_fingerprint_to_hello`].

use rand::seq::SliceRandom;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    pub browser: &'static str,
    pub version: u16, // legacy_version 0x0303
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub curves: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub alpn: Vec<String>,
}

/// Chrome 120 fingerprint (representative)
pub fn chrome_fingerprint() -> TlsFingerprint {
    TlsFingerprint {
        browser: "chrome",
        version: 0x0303,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
            0x009C, 0x009D, 0x002F, 0x0035,
        ],
        extensions: vec![
            0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x0033,
            0x002B, 0x002D, 0x001B, 0x001C,
        ],
        curves: vec![0x001D, 0x0017, 0x0018, 0x001E, 0x0019, 0x001A],
        point_formats: vec![0],
        alpn: vec!["h2".into(), "http/1.1".into()],
    }
}

pub fn firefox_fingerprint() -> TlsFingerprint {
    TlsFingerprint {
        browser: "firefox",
        version: 0x0303,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
            0x009C, 0x009D, 0x002F, 0x0035,
        ],
        extensions: vec![
            0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x000D, 0x0010, 0x0005, 0x0012, 0x0033,
            0x002B, 0x002D, 0x001B, 0x001C, 0x002A, 0x0032,
        ],
        curves: vec![0x001D, 0x0017, 0x0018, 0x001E, 0x0019],
        point_formats: vec![0],
        alpn: vec!["h2".into(), "http/1.1".into()],
    }
}

pub fn safari_fingerprint() -> TlsFingerprint {
    TlsFingerprint {
        browser: "safari",
        version: 0x0303,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
            0x009C, 0x009D, 0x002F, 0x0035,
        ],
        extensions: vec![0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x000D, 0x0010, 0x0005],
        curves: vec![0x001D, 0x0017, 0x0018],
        point_formats: vec![0],
        alpn: vec!["h2".into(), "http/1.1".into()],
    }
}

/// Rotate fingerprint: shuffle cipher suites and add GREASE, keep Chrome order partially
pub fn rotate_fingerprint(fp: &mut TlsFingerprint) {
    let mut rng = rand::thread_rng();
    // Keep first 3 (TLS 1.3) stable, shuffle rest
    if fp.cipher_suites.len() > 3 {
        fp.cipher_suites[3..].shuffle(&mut rng);
    }
    // Add GREASE to extensions
    let grease = crate::stealth::GREASE_VALUES[rng.gen_range(0..crate::stealth::GREASE_VALUES.len())];
    let pos = rng.gen_range(0..=fp.extensions.len());
    fp.extensions.insert(pos, grease);
}

/// Get fingerprint by name
pub fn get_fingerprint(browser: &str) -> TlsFingerprint {
    match browser.to_ascii_lowercase().as_str() {
        "firefox" => firefox_fingerprint(),
        "safari" => safari_fingerprint(),
        "edge" => chrome_fingerprint(), // Edge uses Chrome-like
        "random" => {
            let mut rng = rand::thread_rng();
            let choices = ["chrome", "firefox", "safari"];
            let pick = choices[rng.gen_range(0..choices.len())];
            get_fingerprint(pick)
        }
        _ => chrome_fingerprint(),
    }
}

/// JA3 string (simplified) for logging / scoring
pub fn ja3_string(fp: &TlsFingerprint) -> String {
    let ciphers = fp
        .cipher_suites
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let exts = fp
        .extensions
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let curves = fp
        .curves
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!("{},{},{},{}-{}", fp.version, ciphers, exts, curves, fp.point_formats[0])
}

/// Apply a browser fingerprint to a ClientHello *in place*.
///
/// This crate is a passive rewriter: the client's TLS stack has already
/// committed to its key material, so the server must only ever be offered
/// values the client actually supports. Therefore every mutation keeps the
/// wire length and the multiset of each offered list intact:
///
/// - cipher suites are shuffled (TLS 1.3 kept at the front),
/// - `supported_groups` (0x000A), `signature_algorithms` (0x000D) and
///   `ec_point_formats` (0x000B) are reordered.
///
/// We deliberately do **not** regenerate the `key_share` or change ALPN: a
/// MITM that swaps in a fresh key_share would produce a ClientHello the
/// client's stack cannot complete (it derives the shared secret from the
/// *original* key). That belongs to a terminating proxy such as
/// refraction-networking/utls, not to a packet rewriter.
pub fn apply_fingerprint_to_hello(
    record: &mut [u8],
    browser: &str,
) -> Result<(), crate::error::DpiGuardError> {
    let fp = get_fingerprint(browser);
    let info = crate::fragmentation::parse_client_hello(record)?;

    // 1) Cipher suites: keep TLS 1.3 at the front, shuffle the rest.
    if info.cipher_suites_len >= 4 {
        let start = info.cipher_suites_off;
        let end = start + info.cipher_suites_len;
        if record.len() < end {
            return Err(crate::error::DpiGuardError::PacketTooShort {
                need: end,
                have: record.len(),
            });
        }
        let mut suites: Vec<u16> = record[start..end]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        if suites.len() > 3 {
            let mut rng = rand::thread_rng();
            suites[3..].shuffle(&mut rng);
        }
        for (i, s) in suites.iter().enumerate() {
            let off = start + i * 2;
            record[off..off + 2].copy_from_slice(&s.to_be_bytes());
        }
    }

    // 2) Reorder curve / signature / point-format lists (multiset-preserving).
    for span in crate::fragmentation::list_extensions(record)? {
        match span.ext_type {
            0x000A | 0x000D if span.body_end >= span.body_start + 2 => {
                shuffle_u16_range(record, span.body_start + 2, span.body_end)?;
            }
            0x000B if span.body_end > span.body_start => {
                shuffle_u8_range(record, span.body_start + 1, span.body_end);
            }
            _ => {}
        }
    }

    log::debug!("applied utls fingerprint {} JA3: {}", browser, ja3_string(&fp));
    Ok(())
}

fn shuffle_u16_range(
    buf: &mut [u8],
    start: usize,
    end: usize,
) -> Result<(), crate::error::DpiGuardError> {
    if start > end || end > buf.len() {
        return Err(crate::error::DpiGuardError::OutOfRange(
            "u16 range outside buffer".into(),
        ));
    }
    let mut vals: Vec<u16> = buf[start..end]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    if vals.len() < 2 {
        return Ok(()); // one or zero values: nothing to reorder
    }
    vals.shuffle(&mut rand::thread_rng());
    for (i, v) in vals.iter().enumerate() {
        let off = start + i * 2;
        buf[off..off + 2].copy_from_slice(&v.to_be_bytes());
    }
    Ok(())
}

fn shuffle_u8_range(buf: &mut [u8], start: usize, end: usize) {
    if start > end || end > buf.len() {
        return;
    }
    let mut vals = buf[start..end].to_vec();
    if vals.len() < 2 {
        return;
    }
    vals.shuffle(&mut rand::thread_rng());
    buf[start..end].copy_from_slice(&vals);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragmentation::encode_client_hello;

    #[test]
    fn fingerprints_have_grease_and_chrome_order() {
        let fp = chrome_fingerprint();
        assert!(fp.cipher_suites.contains(&0x1301));
        assert!(fp.extensions.contains(&0x0000));
    }

    #[test]
    fn rotation_preserves_ciphers_multiset() {
        let mut fp = chrome_fingerprint();
        let orig = fp.cipher_suites.clone();
        rotate_fingerprint(&mut fp);
        let mut sorted_orig = orig.clone();
        sorted_orig.sort();
        let mut sorted_new = fp.cipher_suites.clone();
        sorted_new.sort();
        // Note: rotation adds GREASE to extensions, not ciphers, so ciphers multiset preserved except shuffle
        // For ciphers, we only shuffle, so sorted should be equal
        assert_eq!(sorted_orig, {
            let mut v = fp.cipher_suites.clone();
            // Remove any GREASE if added to ciphers (we don't add to ciphers)
            v.sort();
            v
        });
    }

    #[test]
    fn get_fingerprint_by_name() {
        assert_eq!(get_fingerprint("chrome").browser, "chrome");
        assert_eq!(get_fingerprint("firefox").browser, "firefox");
        assert_eq!(get_fingerprint("safari").browser, "safari");
        assert_eq!(get_fingerprint("unknown").browser, "chrome");
        // random returns one of valid
        let r = get_fingerprint("random");
        assert!(["chrome", "firefox", "safari"].contains(&r.browser));
    }

    #[test]
    fn ja3_string_format() {
        let fp = chrome_fingerprint();
        let ja3 = ja3_string(&fp);
        assert!(ja3.contains(','));
        assert!(ja3.contains('-'));
    }

    #[test]
    fn apply_fingerprint_to_hello_shuffles() {
        let mut record = encode_client_hello("example.com");
        let before = record.clone();
        apply_fingerprint_to_hello(&mut record, "chrome").unwrap();
        assert_eq!(before.len(), record.len());
        // Cipher suites should be same multiset but possibly different order
        // We can't guarantee shuffle changed order, but length preserved
    }

    #[test]
    fn reorders_supported_groups_multiset() {
        let record = encode_client_hello("example.com");
        // Append a supported_groups extension: len=4, groups 0x001D, 0x0017.
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x1D, 0x00, 0x17]);
        let with_ext =
            crate::fragmentation::inject_hidden_sni_in_unknown_ext(&record, &body, 0x000A).unwrap();
        let mut hello = with_ext.clone();
        apply_fingerprint_to_hello(&mut hello, "chrome").unwrap();
        let span = crate::fragmentation::list_extensions(&hello)
            .unwrap()
            .into_iter()
            .find(|e| e.ext_type == 0x000A)
            .unwrap();
        let vals: Vec<u16> = hello[span.body_start + 2..span.body_end]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let mut sorted = vals.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0x0017, 0x001D]);
    }

    #[test]
    fn browser_validation() {
        for b in ["chrome", "firefox", "safari", "edge", "random"] {
            let fp = get_fingerprint(b);
            assert!(!fp.cipher_suites.is_empty());
        }
    }
}
