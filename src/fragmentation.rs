//! fragmentation — locate SNI, splice it, split ClientHello across TCP
//! segments. [DONE] for byte math; live send is the capture loop.
//!
//! `fragment_sni_byte_chunk` returns **TCP-payload slices** of the original
//! TLS record (before-SNI / each SNI byte / after-SNI). They are not
//! wrapped as new TLS records — Zapret-style evasion splits at the TCP
//! layer so a stateless DPI box never sees the full name in one segment.

use crate::error::DpiGuardError;

/// Offsets of every length field that must move when the SNI host_name
/// changes size. All offsets are absolute in the TLS record buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SniLocation {
    pub name_start: usize,
    pub name_end: usize,
    pub name_len_off: usize,
    pub list_len_off: usize,
    pub ext_len_off: usize,
    pub extensions_len_off: usize,
    pub handshake_len_off: usize,
    pub record_len_off: usize,
}

#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    pub sni: Option<SniLocation>,
    /// Byte offset of the first cipher-suite value (after the 2-byte length).
    pub cipher_suites_off: usize,
    /// Length in bytes of the cipher-suite list (always even).
    pub cipher_suites_len: usize,
}

fn need(record: &[u8], p: usize, n: usize) -> Result<(), DpiGuardError> {
    // Guard against `p + n` wrapping on a corrupt length field.
    if n > record.len() || p > record.len() - n {
        Err(DpiGuardError::PacketTooShort {
            need: p.saturating_add(n),
            have: record.len(),
        })
    } else {
        Ok(())
    }
}

/// Walk a TLS record that should contain a ClientHello.
pub fn parse_client_hello(record: &[u8]) -> Result<ClientHelloInfo, DpiGuardError> {
    let mut pos = 0usize;
    need(record, pos, 5)?;
    if record[0] != 0x16 {
        return Err(DpiGuardError::NotClientHello);
    }
    // TLS 1.0–1.2 record version 0x03 0x01/02/03; TLS 1.3 still uses 0x03 0x01
    // or 0x03 0x03 on the record layer. Reject clearly non-TLS.
    if record[1] != 0x03 || record[2] < 0x01 {
        return Err(DpiGuardError::NotClientHello);
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let record_len_off = 3;
    pos += 5;
    if 5 + record_len > record.len() {
        // Truncated — caller may be reassembling.
        return Err(DpiGuardError::PacketTooShort {
            need: 5 + record_len,
            have: record.len(),
        });
    }

    need(record, pos, 4)?;
    if record[pos] != 0x01 {
        return Err(DpiGuardError::NotClientHello);
    }
    let handshake_len_off = pos + 1;
    let hs_len = u32::from_be_bytes([0, record[pos + 1], record[pos + 2], record[pos + 3]]) as usize;
    pos += 4;
    // First handshake message must fit in this record.
    if pos + hs_len > 5 + record_len {
        return Err(DpiGuardError::NotClientHello);
    }

    need(record, pos, 2 + 32)?;
    pos += 2 + 32; // client_version + random

    need(record, pos, 1)?;
    let sid_len = record[pos] as usize;
    need(record, pos + 1, sid_len)?;
    pos += 1 + sid_len;

    need(record, pos, 2)?;
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    if cs_len % 2 == 1 {
        return Err(DpiGuardError::NotClientHello);
    }
    pos += 2;
    need(record, pos, cs_len)?;
    let cipher_suites_off = pos;
    let cipher_suites_len = cs_len;
    pos += cs_len;

    need(record, pos, 1)?;
    let comp_len = record[pos] as usize;
    need(record, pos + 1, comp_len)?;
    pos += 1 + comp_len;

    need(record, pos, 2)?;
    let extensions_len_off = pos;
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() || ext_end > 5 + record_len {
        return Err(DpiGuardError::PacketTooShort {
            need: ext_end,
            have: record.len(),
        });
    }

    let mut sni = None;
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len_off = pos + 2;
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        let ext_body_start = pos + 4;
        if ext_body_start + ext_len > ext_end {
            return Err(DpiGuardError::NotClientHello);
        }
        if ext_type == 0x0000 && sni.is_none() {
            need(record, ext_body_start, 5)?;
            let list_len_off = ext_body_start;
            let name_type = record[ext_body_start + 2];
            let name_len_off = ext_body_start + 3;
            let name_len =
                u16::from_be_bytes([record[name_len_off], record[name_len_off + 1]]) as usize;
            let name_start = name_len_off + 2;
            let name_end = name_start + name_len;
            if name_type != 0 || name_end > ext_body_start + ext_len {
                return Err(DpiGuardError::NotClientHello);
            }
            sni = Some(SniLocation {
                name_start,
                name_end,
                name_len_off,
                list_len_off,
                ext_len_off,
                extensions_len_off,
                handshake_len_off,
                record_len_off,
            });
        }
        pos = ext_body_start + ext_len;
    }

    Ok(ClientHelloInfo {
        sni,
        cipher_suites_off,
        cipher_suites_len,
    })
}

/// Return `(name_start, name_end)` absolute in `record` (NOT exclusive of
/// the 5-byte TLS record header — they index the full buffer).
pub fn calculate_smart_split_points(record: &[u8]) -> Result<(usize, usize), DpiGuardError> {
    let info = parse_client_hello(record)?;
    let sni = info.sni.ok_or(DpiGuardError::SniNotFound)?;
    Ok((sni.name_start, sni.name_end))
}

pub fn sni_bytes(record: &[u8]) -> Option<Vec<u8>> {
    calculate_smart_split_points(record)
        .ok()
        .map(|(s, e)| record[s..e].to_vec())
}

/// One extension's type and its body span (after the 2-byte length field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionSpan {
    pub ext_type: u16,
    /// Absolute offset of the first body byte (skips the 2-byte length).
    pub body_start: usize,
    /// Absolute offset one past the last body byte.
    pub body_end: usize,
}

/// Walk a ClientHello's extension list and return each extension's type and
/// body byte range. Mirrors the walk in `parse_client_hello` but exposes the
/// spans so callers (e.g. uTLS reordering) can mutate individual extension
/// payloads without re-deriving the layout.
pub fn list_extensions(record: &[u8]) -> Result<Vec<ExtensionSpan>, DpiGuardError> {
    let mut pos = 0usize;
    need(record, pos, 5)?;
    if record[0] != 0x16 {
        return Err(DpiGuardError::NotClientHello);
    }
    pos += 5;
    need(record, pos, 4)?;
    if record[pos] != 0x01 {
        return Err(DpiGuardError::NotClientHello);
    }
    pos += 4;
    need(record, pos, 2 + 32)?;
    pos += 2 + 32; // client_version + random

    need(record, pos, 1)?;
    let sid_len = record[pos] as usize;
    need(record, pos + 1, sid_len)?;
    pos += 1 + sid_len;

    need(record, pos, 2)?;
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;

    need(record, pos, 1)?;
    let comp_len = record[pos] as usize;
    need(record, pos + 1, comp_len)?;
    pos += 1 + comp_len;

    need(record, pos, 2)?;
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() {
        return Err(DpiGuardError::PacketTooShort {
            need: ext_end,
            have: record.len(),
        });
    }

    let mut out = Vec::new();
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        let body_start = pos + 4;
        let body_end = body_start + ext_len;
        if body_end > ext_end {
            return Err(DpiGuardError::NotClientHello);
        }
        out.push(ExtensionSpan {
            ext_type,
            body_start,
            body_end,
        });
        pos = body_end;
    }
    Ok(out)
}

fn patch_u16(buf: &mut [u8], off: usize, delta: i32) {
    if buf.len() < off + 2 {
        return;
    }
    let cur = u16::from_be_bytes([buf[off], buf[off + 1]]) as i32;
    let new = (cur + delta).clamp(0, u16::MAX as i32) as u16;
    buf[off..off + 2].copy_from_slice(&new.to_be_bytes());
}

fn patch_u24(buf: &mut [u8], off: usize, delta: i32) {
    if buf.len() < off + 3 {
        return;
    }
    let cur = u32::from_be_bytes([0, buf[off], buf[off + 1], buf[off + 2]]) as i32;
    let new = (cur + delta).clamp(0, 0xFF_FFFF) as u32;
    let b = new.to_be_bytes();
    buf[off] = b[1];
    buf[off + 1] = b[2];
    buf[off + 2] = b[3];
}

/// Replace the SNI host_name and rewrite every enclosing length field so
/// the ClientHello stays structurally valid.
pub fn splice_sni(record: &[u8], new_sni: &[u8]) -> Result<Vec<u8>, DpiGuardError> {
    if new_sni.len() > u16::MAX as usize {
        return Err(DpiGuardError::OutOfRange("SNI longer than 65535".into()));
    }
    let info = parse_client_hello(record)?;
    let loc = info.sni.ok_or(DpiGuardError::SniNotFound)?;
    let old_len = loc.name_end - loc.name_start;
    let delta = new_sni.len() as i32 - old_len as i32;

    let mut out = Vec::with_capacity(record.len() + delta.max(0) as usize);
    out.extend_from_slice(&record[..loc.name_start]);
    out.extend_from_slice(new_sni);
    out.extend_from_slice(&record[loc.name_end..]);

    // Length fields all sit *before* name_start, so their offsets are stable.
    patch_u16(&mut out, loc.record_len_off, delta);
    patch_u24(&mut out, loc.handshake_len_off, delta);
    patch_u16(&mut out, loc.extensions_len_off, delta);
    patch_u16(&mut out, loc.ext_len_off, delta);
    patch_u16(&mut out, loc.list_len_off, delta);
    patch_u16(&mut out, loc.name_len_off, delta);
    Ok(out)
}

/// --- NEW: SNI Disguise as Unknown Extension (2025 research) ---
/// Change SNI extension type 0x0000 -> private/GREASE type so naive DPI
/// that only looks for 0x0000 misses the real SNI. Server should ignore
/// unknown extensions per RFC 8446, but will not know virtual host
/// without SNI -> may serve default cert. Use only with Aggressive / fronting.
pub fn disguise_sni_extension_type(record: &[u8], new_type: u16) -> Result<Vec<u8>, DpiGuardError> {
    let info = parse_client_hello(record)?;
    let loc = info.sni.ok_or(DpiGuardError::SniNotFound)?;
    // ext_len_off points to length field of SNI extension, type is 2 bytes before
    if loc.ext_len_off < 2 {
        return Err(DpiGuardError::NotClientHello);
    }
    let type_off = loc.ext_len_off - 2;
    if type_off + 2 > record.len() {
        return Err(DpiGuardError::PacketTooShort {
            need: type_off + 2,
            have: record.len(),
        });
    }
    let mut out = record.to_vec();
    out[type_off..type_off + 2].copy_from_slice(&new_type.to_be_bytes());
    Ok(out)
}

/// Replace visible SNI with a benign domain (domain fronting).
/// This is still using splice_sni internally but flagged as fronting
/// for strategy scoring.
pub fn front_sni_with_benign(record: &[u8], benign_sni: &[u8]) -> Result<Vec<u8>, DpiGuardError> {
    splice_sni(record, benign_sni)
}

/// Inject hidden real SNI as an unknown private extension while keeping
/// benign SNI visible as 0x0000. This is layered fronting:
/// visible SNI = benign (e.g., www.microsoft.com), hidden = real in type 0xFF01.
/// DPI that only checks first 0x0000 sees benign; server ignores unknown.
pub fn inject_hidden_sni_in_unknown_ext(
    record: &[u8],
    hidden_sni: &[u8],
    unknown_type: u16,
) -> Result<Vec<u8>, DpiGuardError> {
    if hidden_sni.len() > u16::MAX as usize {
        return Err(DpiGuardError::OutOfRange("hidden SNI too long".into()));
    }
    // Validate record is ClientHello
    let _info = parse_client_hello(record)?;
    // Re-parse to get ext_end accurately
    let mut pos = 0usize;
    need(record, pos, 5)?;
    pos += 5;
    need(record, pos, 4)?;
    pos += 4;
    need(record, pos, 2 + 32)?;
    pos += 2 + 32;
    need(record, pos, 1)?;
    let sid_len = record[pos] as usize;
    need(record, pos + 1, sid_len)?;
    pos += 1 + sid_len;
    need(record, pos, 2)?;
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;
    need(record, pos, 1)?;
    let comp_len = record[pos] as usize;
    need(record, pos + 1, comp_len)?;
    pos += 1 + comp_len;
    need(record, pos, 2)?;
    let extensions_len_off_inner = pos;
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    let ext_start = pos + 2;
    let ext_end = ext_start + ext_total;
    if ext_end > record.len() {
        return Err(DpiGuardError::PacketTooShort {
            need: ext_end,
            have: record.len(),
        });
    }
    // Build unknown extension: type + len + payload
    // Payload: we just put raw hidden_sni bytes (or could mimic SNI format). Use raw for simplicity.
    let ext_payload_len = hidden_sni.len();
    let mut new_ext = Vec::with_capacity(4 + ext_payload_len);
    new_ext.extend_from_slice(&unknown_type.to_be_bytes());
    new_ext.extend_from_slice(&(ext_payload_len as u16).to_be_bytes());
    new_ext.extend_from_slice(hidden_sni);

    // Insert new extension at end of existing extensions
    let mut out = Vec::with_capacity(record.len() + new_ext.len());
    out.extend_from_slice(&record[..ext_end]);
    out.extend_from_slice(&new_ext);
    out.extend_from_slice(&record[ext_end..]);

    // Patch lengths: extensions_len, handshake_len, record_len
    let delta = new_ext.len() as i32;
    // extensions_len_off_inner is same as earlier ext_len_off maybe
    patch_u16(&mut out, extensions_len_off_inner, delta);
    // handshake_len_off is 4 bytes before? We can get from parse info: need to find handshake_len_off
    // We have handshake_len_off = 5+1 =6? Actually record[5] is handshake type, 6..8 is length
    // Simpler: handshake_len_off = 5 +1 =6 always? No, record has 5-byte header, then handshake header 4 bytes
    // handshake_len_off is 6 (record[6..9]) in our encode. Use generic: from info or recalc
    // We'll find it via parse again for patched out? Easier: we know handshake body includes extensions, so patch handshake and record
    // handshake_len_off is at 6
    patch_u24(&mut out, 6, delta);
    patch_u16(&mut out, 3, delta);

    // Also need to keep original SNI if present - we didn't touch it
    Ok(out)
}

/// Shuffle the ClientHello cipher-suite list in place (same wire length).
pub fn shuffle_cipher_suites_in_hello(record: &mut [u8]) -> Result<(), DpiGuardError> {
    let info = parse_client_hello(record)?;
    if info.cipher_suites_len < 4 {
        return Ok(());
    }
    let start = info.cipher_suites_off;
    let end = start + info.cipher_suites_len;
    if record.len() < end {
        return Err(DpiGuardError::PacketTooShort {
            need: end,
            have: record.len(),
        });
    }
    let mut suites: Vec<u16> = record[start..end]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    crate::stealth::shuffle_cipher_suites(&mut suites);
    for (i, s) in suites.iter().enumerate() {
        let off = start + i * 2;
        record[off..off + 2].copy_from_slice(&s.to_be_bytes());
    }
    Ok(())
}

/// TCP-level split of a TLS record around the SNI: one chunk before the
/// name, one 1-byte chunk per SNI byte, one chunk after. Caller wraps
/// each chunk in its own TCP segment (`packet::tcp_segment_payload` or
/// `rebuild_with_payload`).
pub fn fragment_sni_byte_chunk(record: &[u8]) -> Result<Vec<Vec<u8>>, DpiGuardError> {
    let (sni_start, sni_end) = calculate_smart_split_points(record)?;
    let mut chunks = Vec::new();
    if sni_start > 0 {
        chunks.push(record[..sni_start].to_vec());
    }
    for &byte in &record[sni_start..sni_end] {
        chunks.push(vec![byte]);
    }
    if sni_end < record.len() {
        chunks.push(record[sni_end..].to_vec());
    }
    Ok(chunks)
}

/// Walk a TLS byte stream and cut Handshake (0x16) / AppData (0x17)
/// records into `chunk_size`-byte **TCP payload** pieces. This is not
/// valid TLS-record framing; it is intentional TCP segmentation.
pub fn persistent_fragmentation(stream: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let chunk_size = chunk_size.max(1);
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < stream.len() {
        if pos + 5 > stream.len() {
            out.push(stream[pos..].to_vec());
            break;
        }
        let record_type = stream[pos];
        let len = u16::from_be_bytes([stream[pos + 3], stream[pos + 4]]) as usize;
        let record_end = (pos + 5 + len).min(stream.len());
        let record = &stream[pos..record_end];
        if record_type == 0x16 || record_type == 0x17 {
            for chunk in record.chunks(chunk_size) {
                out.push(chunk.to_vec());
            }
        } else {
            out.push(record.to_vec());
        }
        pos = record_end;
    }
    out
}

/// IPv4 fragment offset table. `mtu` is the full L3 MTU (including the
/// 20-byte IPv4 header). Offsets are in 8-byte units; the last fragment
/// has MF=false.
pub fn ip_level_fragment_offsets(payload_len: usize, mtu: usize) -> Vec<(u16, bool)> {
    const IPV4_HEADER: usize = 20;
    let max_payload = (mtu.saturating_sub(IPV4_HEADER)).max(8) & !0x7;
    let mut offsets = Vec::new();
    let mut sent = 0usize;
    while sent < payload_len {
        let remaining = payload_len - sent;
        let this_len = remaining.min(max_payload);
        let more = sent + this_len < payload_len;
        offsets.push(((sent / 8) as u16, more));
        sent += this_len;
    }
    offsets
}

/// Test helper: a structurally valid ClientHello whose SNI is `sni`.
pub fn encode_client_hello(sni: &str) -> Vec<u8> {
    let mut ext_body = Vec::new();
    ext_body.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
    ext_body.push(0x00);
    ext_body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext_body.extend_from_slice(sni.as_bytes());

    let mut extension = Vec::new();
    extension.extend_from_slice(&0x0000u16.to_be_bytes());
    extension.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
    extension.extend_from_slice(&ext_body);

    let mut handshake_body = Vec::new();
    handshake_body.extend_from_slice(&0x0303u16.to_be_bytes());
    handshake_body.extend_from_slice(&[0u8; 32]);
    handshake_body.push(0);
    handshake_body.extend_from_slice(&4u16.to_be_bytes());
    handshake_body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
    handshake_body.push(1);
    handshake_body.push(0);
    handshake_body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
    handshake_body.extend_from_slice(&extension);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let len = handshake_body.len() as u32;
    handshake.extend_from_slice(&len.to_be_bytes()[1..]);
    handshake.extend_from_slice(&handshake_body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn finds_sni_exactly() {
        let record = encode_client_hello("example.com");
        let (start, end) = calculate_smart_split_points(&record).unwrap();
        assert_eq!(&record[start..end], b"example.com");
    }

    #[test]
    fn splice_longer_sni_roundtrips_and_reparses() {
        let record = encode_client_hello("a.com");
        let out = splice_sni(&record, b"longer.example.com").unwrap();
        let (s, e) = calculate_smart_split_points(&out).unwrap();
        assert_eq!(&out[s..e], b"longer.example.com");
        // record length field matches body
        let rec_len = u16::from_be_bytes([out[3], out[4]]) as usize;
        assert_eq!(5 + rec_len, out.len());
    }

    #[test]
    fn splice_shorter_sni_roundtrips() {
        let record = encode_client_hello("example.com");
        let out = splice_sni(&record, b"x.io").unwrap();
        let (s, e) = calculate_smart_split_points(&out).unwrap();
        assert_eq!(&out[s..e], b"x.io");
    }

    #[test]
    fn byte_chunking_reassembles_to_original_sni_bytes() {
        let record = encode_client_hello("test.org");
        let chunks = fragment_sni_byte_chunk(&record).unwrap();
        let sni_chunks: Vec<u8> = chunks
            .iter()
            .filter(|c| c.len() == 1)
            .map(|c| c[0])
            .collect();
        assert_eq!(sni_chunks, b"test.org".to_vec());
        let joined: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(joined, record);
    }

    #[test]
    fn persistent_fragmentation_covers_full_stream() {
        let mut stream = encode_client_hello("a.com");
        stream.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]);
        let chunks = persistent_fragmentation(&stream, 3);
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, stream.len());
    }

    #[test]
    fn ip_fragment_offsets_subtract_header_and_last_has_mf_false() {
        let offsets = ip_level_fragment_offsets(3000, 1500);
        assert!(!offsets.is_empty());
        assert_eq!(offsets.last().unwrap().1, false);
        for (_off, more) in &offsets[..offsets.len() - 1] {
            assert!(more);
        }
        // 1500 MTU → 1480 payload aligned down to 1480 (already % 8 == 0)
        let first_span = 1480u16 / 8;
        assert_eq!(offsets[1].0, first_span);
    }

    #[test]
    fn fuzz_calculate_smart_split_points_never_panics() {
        let mut rng = rand::thread_rng();
        for _ in 0..200 {
            let len = rng.gen_range(0..300);
            let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let _ = calculate_smart_split_points(&data);
        }
    }

    #[test]
    fn truncated_client_hello_is_packet_too_short() {
        let record = encode_client_hello("example.com");
        let err = calculate_smart_split_points(&record[..20]).unwrap_err();
        matches_too_short(err);
    }

    fn matches_too_short(err: DpiGuardError) {
        match err {
            DpiGuardError::PacketTooShort { .. } | DpiGuardError::NotClientHello => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn disguise_extension_type_hides_sni_from_naive_parser() {
        let record = encode_client_hello("example.com");
        assert!(sni_bytes(&record).is_some());
        let disguised = disguise_sni_extension_type(&record, 0x0A0A).unwrap();
        assert!(sni_bytes(&disguised).is_none());
        let rec_len = u16::from_be_bytes([disguised[3], disguised[4]]) as usize;
        assert_eq!(5 + rec_len, disguised.len());
        assert!(disguised.windows(11).any(|w| w == b"example.com"));
    }

    #[test]
    fn fronting_replaces_visible_sni() {
        let record = encode_client_hello("real.example.com");
        let fronted = front_sni_with_benign(&record, b"www.microsoft.com").unwrap();
        let (s, e) = calculate_smart_split_points(&fronted).unwrap();
        assert_eq!(&fronted[s..e], b"www.microsoft.com");
    }

    #[test]
    fn hidden_sni_in_unknown_ext_appends_and_patches_lengths() {
        let record = encode_client_hello("benign.example");
        let with_hidden =
            inject_hidden_sni_in_unknown_ext(&record, b"real.example.com", 0xFF01).unwrap();
        assert!(with_hidden.len() > record.len());
        let (s, e) = calculate_smart_split_points(&with_hidden).unwrap();
        assert_eq!(&with_hidden[s..e], b"benign.example");
        assert!(with_hidden.windows(16).any(|w| w == b"real.example.com"));
        let rec_len = u16::from_be_bytes([with_hidden[3], with_hidden[4]]) as usize;
        assert_eq!(5 + rec_len, with_hidden.len());
    }

    #[test]
    fn disguise_with_grease_values() {
        let record = encode_client_hello("test.com");
        for grease in [0x0A0Au16, 0x1A1A, 0x2A2A, 0x4A4A, 0xFAFA] {
            let out = disguise_sni_extension_type(&record, grease).unwrap();
            assert_eq!(out.len(), record.len());
        }
    }

    #[test]
    fn list_extensions_exposes_sni_and_injected_span() {
        let record = encode_client_hello("example.com");
        let exts = list_extensions(&record).unwrap();
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].ext_type, 0x0000);
        // Inject a supported_groups extension and confirm it is listed with
        // the correct body span.
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x1D, 0x00, 0x17]);
        let with = inject_hidden_sni_in_unknown_ext(&record, &body, 0x000A).unwrap();
        let exts = list_extensions(&with).unwrap();
        let sg = exts.iter().find(|e| e.ext_type == 0x000A).unwrap();
        assert_eq!(&with[sg.body_start..sg.body_end], body.as_slice());
    }
}
