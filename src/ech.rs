//! ech — Encrypted Client Hello (ECH) handling — [PARTIAL]
//! Based on draft-ietf-tls-esni and Cloudflare blog.
//! ECH encrypts the real SNI in an inner ClientHello, outer SNI is benign.
//! This module implements:
//! - GREASE ECH extension injection
//! - Outer SNI handling
//! - ECHConfig parsing stub (needs DNS HTTPS/SVCB fetch, out of scope for pure lib)
//! 
//! Real ECH needs HPKE crypto, out of scope. This module provides the
//! structure and bypass via GREASE and outer SNI.

use crate::error::DpiGuardError;
use rand::Rng;

/// ECH extension type (draft, value 0xFE0D)
pub const ECH_EXTENSION_TYPE: u16 = 0xFE0D;

/// GREASE values for ECH (RFC 8701 style)
pub const ECH_GREASE_TYPES: [u16; 6] = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0xFAFA];

#[derive(Debug, Clone)]
pub struct EchConfig {
    pub public_name: String,
    pub raw: Vec<u8>,
}

/// Stub: parse ECHConfig from DNS HTTPS record (RFC 8484, SVCB)
// In real impl, fetch from DNS over HTTPS and parse
pub fn parse_ech_config_from_https_record(record: &[u8]) -> Result<EchConfig, DpiGuardError> {
    if record.len() < 10 {
        return Err(DpiGuardError::OutOfRange("ECHConfig too short".into()));
    }
    // Stub: just check presence of ECH (type 5 in SVCB)
    // Real parsing needs DNS wire format
    Ok(EchConfig {
        public_name: "public.example.com".to_string(),
        raw: record.to_vec(),
    })
}

/// Inject GREASE ECH extension (fake) to confuse DPI that fingerprints ECH
/// This adds an extension with GREASE type and random payload
pub fn inject_ech_grease_ext(record: &[u8]) -> Result<Vec<u8>, DpiGuardError> {
    let mut rng = rand::thread_rng();
    let grease_type = ECH_GREASE_TYPES[rng.gen_range(0..ECH_GREASE_TYPES.len())];
    let payload_len = rng.gen_range(8..=32);
    let mut payload = Vec::with_capacity(payload_len);
    for _ in 0..payload_len {
        payload.push(rng.gen::<u8>());
    }
    crate::fragmentation::inject_hidden_sni_in_unknown_ext(record, &payload, grease_type)
        .map_err(|e| DpiGuardError::OutOfRange(format!("ECH GREASE inject failed: {e}")))
}

/// Build outer ClientHello with benign SNI for ECH
/// outer SNI = public name (e.g., cloudflare-ech.com), inner = real (encrypted in real ECH)
pub fn build_outer_sni_for_ech(real_record: &[u8], public_name: &str) -> Result<Vec<u8>, DpiGuardError> {
    crate::fragmentation::front_sni_with_benign(real_record, public_name.as_bytes())
}

/// Check if ClientHello already contains ECH extension
pub fn has_ech_extension(record: &[u8]) -> bool {
    // Scan for extension type 0xFE0D
    if record.len() < 50 { return false; }
    // Rough scan: look for FE0D in extension area
    record.windows(2).any(|w| u16::from_be_bytes([w[0], w[1]]) == ECH_EXTENSION_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragmentation::encode_client_hello;

    #[test]
    fn ech_grease_injection_grows_record() {
        let record = encode_client_hello("example.com");
        let with_grease = inject_ech_grease_ext(&record).unwrap();
        assert!(with_grease.len() > record.len());
    }

    #[test]
    fn outer_sni_for_ech_replaces_sni() {
        let record = encode_client_hello("real.example.com");
        let outer = build_outer_sni_for_ech(&record, "public.example.com").unwrap();
        let (s,e) = crate::fragmentation::calculate_smart_split_points(&outer).unwrap();
        assert_eq!(&outer[s..e], b"public.example.com");
    }

    #[test]
    fn detects_ech_extension_presence() {
        let record = encode_client_hello("example.com");
        assert!(!has_ech_extension(&record));
        // Manually inject FE0D
        let mut fake = record.clone();
        fake.extend_from_slice(&[0xFE, 0x0D, 0x00, 0x00]);
        assert!(has_ech_extension(&fake));
    }

    #[test]
    fn parse_ech_config_stub() {
        let cfg = parse_ech_config_from_https_record(&vec![0u8; 20]).unwrap();
        assert!(!cfg.public_name.is_empty());
    }
}
