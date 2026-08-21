//! sni_mutations — 12 SNI-string mutation techniques. [DONE]
//!
//! Functions take/return the SNI host_name field, not a whole TLS record.
//! `mutate_sni_full` chains a subset per [`MutationProfile`]. Wiring the
//! result back into a ClientHello (length fields included) is
//! `fragmentation::splice_sni`.

use rand::Rng;
use std::str::FromStr;

pub fn inject_null_byte(sni: &[u8]) -> Vec<u8> {
    let mut out = sni.to_vec();
    if out.is_empty() {
        out.push(0);
        return out;
    }
    let pos = rand::thread_rng().gen_range(0..=out.len());
    out.insert(pos, 0);
    out
}

pub fn explode_subdomains(sni: &[u8]) -> Vec<u8> {
    let base = String::from_utf8_lossy(sni).to_string();
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(10..=14);
    let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut labels: Vec<String> = Vec::with_capacity(n);
    for _ in 0..n {
        let len = rng.gen_range(1..=8);
        let label: String = (0..len)
            .map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char)
            .collect();
        labels.push(label);
    }
    labels.push(base);
    labels.join(".").into_bytes()
}

pub fn randomize_case_sni(sni: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    sni.iter()
        .map(|&b| {
            if b.is_ascii_alphabetic() && rng.gen_bool(0.5) {
                if b.is_ascii_lowercase() {
                    b.to_ascii_uppercase()
                } else {
                    b.to_ascii_lowercase()
                }
            } else {
                b
            }
        })
        .collect()
}

pub fn add_trailing_dot(sni: &[u8]) -> Vec<u8> {
    let mut out = sni.to_vec();
    if out.last() != Some(&b'.') {
        out.push(b'.');
    }
    out
}

pub fn inject_whitespace(sni: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let ws: u8 = if rng.gen_bool(0.5) { 0x20 } else { 0x09 };
    let mut out = sni.to_vec();
    if rng.gen_bool(0.5) {
        out.insert(0, ws);
    } else {
        out.push(ws);
    }
    out
}

pub fn inject_underscore(sni: &[u8]) -> Vec<u8> {
    sni.iter()
        .map(|&b| if b == b'-' { b'_' } else { b })
        .collect()
}

/// Homoglyphs produce non-ASCII SNI, which RFC 6066 does not allow in
/// host_name. Kept for experiments; **not** part of any default profile.
pub fn apply_homoglyphs(sni: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(sni).to_string();
    let map = |c: char| -> char {
        match c {
            'a' => '\u{0430}',
            'e' => '\u{0435}',
            'o' => '\u{043E}',
            'p' => '\u{0440}',
            'c' => '\u{0441}',
            'x' => '\u{0445}',
            'i' => '\u{0456}',
            _ => c,
        }
    };
    let mut rng = rand::thread_rng();
    s.chars()
        .map(|c| if rng.gen_bool(0.3) { map(c) } else { c })
        .collect::<String>()
        .into_bytes()
}

pub fn insert_consecutive_dots(sni: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(sni.len() + 2);
    let dot_positions: Vec<usize> = sni
        .iter()
        .enumerate()
        .filter(|(_, &b)| b == b'.')
        .map(|(i, _)| i)
        .collect();
    if dot_positions.is_empty() {
        out.extend_from_slice(sni);
        out.push(b'.');
        return out;
    }
    let pick = dot_positions[rand::thread_rng().gen_range(0..dot_positions.len())];
    out.extend_from_slice(&sni[..=pick]);
    out.push(b'.');
    out.extend_from_slice(&sni[pick + 1..]);
    out
}

pub fn force_length_overflow(sni: &[u8]) -> Vec<u8> {
    let mut out = sni.to_vec();
    let filler = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    while out.len() <= 255 {
        out.splice(0..0, filler.iter().copied());
    }
    out
}

pub fn append_port_suffix(sni: &[u8]) -> Vec<u8> {
    let mut out = sni.to_vec();
    out.extend_from_slice(b":443");
    out
}

/// Preset combinations. Stealth/ChinaGfw/RussiaDpi only use mutations
/// that stay inside the DNS LDH / FQDN alphabet so SNI-routed CDNs still
/// work. Aggressive is opt-in and *will* break many real servers.
/// ChinaRegional/Henan are new 2025 profiles for regional firewalls that
/// need combined TCP+TLS fragmentation (see Henan Firewall research).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationProfile {
    ChinaGfw,
    RussiaDpi,
    Stealth,
    Aggressive,
    ChinaRegional,
    Henan,
}

impl MutationProfile {
    pub const ALL: [MutationProfile; 6] = [
        MutationProfile::Stealth,
        MutationProfile::ChinaGfw,
        MutationProfile::RussiaDpi,
        MutationProfile::Aggressive,
        MutationProfile::ChinaRegional,
        MutationProfile::Henan,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            MutationProfile::ChinaGfw => "ChinaGfw",
            MutationProfile::RussiaDpi => "RussiaDpi",
            MutationProfile::Stealth => "Stealth",
            MutationProfile::Aggressive => "Aggressive",
            MutationProfile::ChinaRegional => "ChinaRegional",
            MutationProfile::Henan => "Henan",
        }
    }

    /// Case-only (and trailing-dot) mutations keep the same DNS identity
    /// for cert / virtual-host matching.
    pub fn preserves_identity(self) -> bool {
        matches!(
            self,
            MutationProfile::Stealth
                | MutationProfile::ChinaGfw
                | MutationProfile::RussiaDpi
                | MutationProfile::ChinaRegional
                | MutationProfile::Henan
        )
    }

    /// Recommended TCP chunk size for this profile (0 = no fragmentation)
    /// Henan/ChinaRegional need small chunks 24-32 to beat stateless parsers.
    pub fn recommended_fragment_size(self) -> usize {
        match self {
            MutationProfile::Henan => 24,
            MutationProfile::ChinaRegional => 32,
            MutationProfile::Stealth => 64,
            MutationProfile::ChinaGfw => 64,
            MutationProfile::RussiaDpi => 0, // Russia often doesn't need fragmentation
            MutationProfile::Aggressive => 32,
        }
    }

    /// Whether this profile benefits from QUIC port blindspot bypass
    pub fn uses_quic_bypass(self) -> bool {
        matches!(
            self,
            MutationProfile::ChinaGfw | MutationProfile::ChinaRegional | MutationProfile::Henan
        )
    }

    /// Whether this profile should use disorder mode (TCP reordering)
    pub fn uses_disorder(self) -> bool {
        matches!(
            self,
            MutationProfile::ChinaRegional | MutationProfile::Henan | MutationProfile::Aggressive
        )
    }
}

impl FromStr for MutationProfile {
    type Err = crate::error::DpiGuardError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ChinaGfw" => Ok(MutationProfile::ChinaGfw),
            "RussiaDpi" => Ok(MutationProfile::RussiaDpi),
            "Stealth" => Ok(MutationProfile::Stealth),
            "Aggressive" => Ok(MutationProfile::Aggressive),
            "ChinaRegional" => Ok(MutationProfile::ChinaRegional),
            "Henan" => Ok(MutationProfile::Henan),
            other => Err(crate::error::DpiGuardError::Config(format!(
                "unknown mutation_profile {other:?}; expected Stealth, ChinaGfw, RussiaDpi, Aggressive, ChinaRegional, Henan"
            ))),
        }
    }
}

pub fn get_mutation_profile(profile: MutationProfile) -> Vec<fn(&[u8]) -> Vec<u8>> {
    match profile {
        // GFW: cheap, identity-preserving. Real evasion is TCP
        // fragmentation + TTL decoys in the pipeline, not exploding SNI.
        MutationProfile::ChinaGfw => vec![randomize_case_sni],
        MutationProfile::RussiaDpi => vec![add_trailing_dot],
        // Whitespace / null / homoglyphs break real TLS stacks — not stealth.
        MutationProfile::Stealth => vec![randomize_case_sni],
        // Regional: case + trailing dot - still identity-preserving but more entropy
        MutationProfile::ChinaRegional => vec![randomize_case_sni, add_trailing_dot],
        MutationProfile::Henan => vec![randomize_case_sni, add_trailing_dot],
        MutationProfile::Aggressive => vec![
            inject_null_byte,
            explode_subdomains,
            randomize_case_sni,
            inject_underscore,
            insert_consecutive_dots,
            force_length_overflow,
            append_port_suffix,
        ],
    }
}

/// Record-level mutation: SNI disguise as unknown extension (GREASE/private range)
/// Returns new TLS record with SNI extension type changed. This is NOT an SNI-byte mutation,
/// it's a record-level transformation. Used by ChinaRegional/Henan/AggressivePlus.
pub fn disguise_sni_record(record: &[u8], new_type: u16) -> Result<Vec<u8>, crate::error::DpiGuardError> {
    crate::fragmentation::disguise_sni_extension_type(record, new_type)
}

pub const SNI_DISGUISE_GREASE_TYPES: [u16; 8] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0xFAFA,
];
pub const SNI_DISGUISE_PRIVATE_RANGE: (u16, u16) = (0xFF00, 0xFFFF);

pub fn random_disguise_type() -> u16 {
    let mut rng = rand::thread_rng();
    if rng.gen_bool(0.5) {
        SNI_DISGUISE_GREASE_TYPES[rng.gen_range(0..SNI_DISGUISE_GREASE_TYPES.len())]
    } else {
        rng.gen_range(SNI_DISGUISE_PRIVATE_RANGE.0..=SNI_DISGUISE_PRIVATE_RANGE.1)
    }
}

pub fn mutate_sni_full(sni: &[u8], profile: MutationProfile) -> Vec<u8> {
    let chain = get_mutation_profile(profile);
    let mut buf = sni.to_vec();
    for f in chain {
        buf = f(&buf);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_byte_inserted() {
        let out = inject_null_byte(b"example.com");
        assert_eq!(out.len(), 12);
        assert!(out.contains(&0u8));
    }

    #[test]
    fn explode_has_many_labels() {
        let out = explode_subdomains(b"example.com");
        let s = String::from_utf8(out).unwrap();
        assert!(s.ends_with("example.com"));
        assert!(s.matches('.').count() >= 11);
    }

    #[test]
    fn case_randomization_preserves_bytes_count_and_letters() {
        let out = randomize_case_sni(b"example.com");
        assert_eq!(out.len(), 11);
        assert_eq!(
            String::from_utf8(out).unwrap().to_lowercase(),
            "example.com"
        );
    }

    #[test]
    fn trailing_dot_added_once() {
        assert_eq!(add_trailing_dot(b"example.com"), b"example.com.".to_vec());
        assert_eq!(add_trailing_dot(b"example.com."), b"example.com.".to_vec());
    }

    #[test]
    fn underscore_swap() {
        assert_eq!(
            inject_underscore(b"my-site.com"),
            b"my_site.com".to_vec()
        );
    }

    #[test]
    fn overflow_exceeds_255() {
        let out = force_length_overflow(b"example.com");
        assert!(out.len() > 255);
    }

    #[test]
    fn port_suffix_appended() {
        assert_eq!(
            append_port_suffix(b"example.com"),
            b"example.com:443".to_vec()
        );
    }

    #[test]
    fn whitespace_is_space_or_tab_at_edge() {
        let out = inject_whitespace(b"example.com");
        assert_eq!(out.len(), 12);
        let edge = out[0] == 0x20 || out[0] == 0x09 || out[11] == 0x20 || out[11] == 0x09;
        assert!(edge);
    }

    #[test]
    fn consecutive_dots_inserted() {
        let out = insert_consecutive_dots(b"a.b.com");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains(".."));
    }

    #[test]
    fn homoglyphs_may_emit_non_ascii() {
        let mut saw = false;
        for _ in 0..40 {
            let out = apply_homoglyphs(b"aeopcx");
            if out.iter().any(|b| *b > 127) {
                saw = true;
                break;
            }
        }
        // 1 - 0.7^6 ≈ 88% chance per call; 40 tries is plenty.
        assert!(saw);
    }

    #[test]
    fn profile_contents() {
        assert_eq!(get_mutation_profile(MutationProfile::Stealth).len(), 1);
        assert_eq!(get_mutation_profile(MutationProfile::ChinaGfw).len(), 1);
        assert_eq!(get_mutation_profile(MutationProfile::RussiaDpi).len(), 1);
        assert_eq!(get_mutation_profile(MutationProfile::ChinaRegional).len(), 2);
        assert_eq!(get_mutation_profile(MutationProfile::Henan).len(), 2);
        assert!(get_mutation_profile(MutationProfile::Aggressive).len() >= 6);
    }

    #[test]
    fn new_profiles_have_small_chunks_and_disorder() {
        assert_eq!(MutationProfile::Henan.recommended_fragment_size(), 24);
        assert_eq!(MutationProfile::ChinaRegional.recommended_fragment_size(), 32);
        assert!(MutationProfile::Henan.uses_disorder());
        assert!(MutationProfile::ChinaRegional.uses_disorder());
        assert!(MutationProfile::Henan.uses_quic_bypass());
        assert!(MutationProfile::ChinaRegional.uses_quic_bypass());
        assert!(!MutationProfile::Stealth.uses_disorder());
    }

    #[test]
    fn disguise_type_is_grease_or_private() {
        for _ in 0..20 {
            let t = random_disguise_type();
            let is_grease = SNI_DISGUISE_GREASE_TYPES.contains(&t);
            let is_private = (SNI_DISGUISE_PRIVATE_RANGE.0..=SNI_DISGUISE_PRIVATE_RANGE.1).contains(&t);
            assert!(is_grease || is_private);
        }
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!(MutationProfile::from_str("Nope").is_err());
        assert_eq!(
            MutationProfile::from_str("Stealth").unwrap(),
            MutationProfile::Stealth
        );
    }

    #[test]
    fn full_chain_runs_for_every_profile() {
        for p in MutationProfile::ALL {
            let out = mutate_sni_full(b"example.com", p);
            assert!(!out.is_empty());
        }
    }
}
