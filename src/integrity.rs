//! integrity — SHA-256 pinning helpers used by the WinDivert driver
//! loader. [DONE] cfg-free so Linux CI can test the compare logic.
//!
//! Hash comparison is constant-time in the pin *values* (every pin is
//! always scanned) so a local attacker cannot use a timing oracle to
//! recover a configured pin nibble-by-nibble.

use crate::error::DpiGuardError;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Refuse to hash a "driver" that is implausibly large — a planted
/// multi-gigabyte file next to the exe would otherwise OOM the process
/// during `version_check`.
pub const MAX_DRIVER_BYTES: u64 = 16 * 1024 * 1024;

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Length-independent compare: always scan `min(len(a), len(b))` bytes
/// and mix the length mismatch into the accumulator so a shorter input
/// cannot short-circuit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let n = a.len().min(b.len());
    for i in 0..n {
        diff |= (a[i] ^ b[i]) as usize;
    }
    diff == 0
}

/// True iff `hash_hex` (already lowercase hex) equals one of `pins`.
/// Every pin is compared; the function does not return early on a match.
pub fn hash_is_pinned(hash_hex: &str, pins: &[String]) -> bool {
    let h = hash_hex.as_bytes();
    let mut ok = false;
    for p in pins {
        let normalised = p.trim().to_ascii_lowercase();
        let matched = constant_time_eq(h, normalised.as_bytes());
        ok |= matched;
    }
    ok
}

pub fn sha256_hex_file(path: &Path, max_bytes: u64) -> Result<String, DpiGuardError> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > max_bytes {
        return Err(DpiGuardError::Driver(format!(
            "{} is {len} bytes, over the {max_bytes} byte driver-size cap (refusing to hash; possible planted file)",
            path.display()
        )));
    }
    let mut buf = Vec::with_capacity(len as usize);
    file.read_to_end(&mut buf)?;
    Ok(sha256_hex(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_is_known() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn pin_list_accepts_any_matching_entry_and_is_case_insensitive() {
        let pins = vec!["AA".repeat(32), "bb".repeat(32)];
        assert!(hash_is_pinned(&"aa".repeat(32), &pins));
        assert!(hash_is_pinned(&"bb".repeat(32), &pins));
        assert!(!hash_is_pinned(&"cc".repeat(32), &pins));
        assert!(!hash_is_pinned("short", &pins));
    }

    #[test]
    fn file_hash_rejects_oversize() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("dpi_guard_hash_{}.bin", std::process::id()));
        std::fs::write(&path, b"hello").unwrap();
        let hex = sha256_hex_file(&path, 16).unwrap();
        assert_eq!(hex, sha256_hex(b"hello"));
        let err = sha256_hex_file(&path, 2).unwrap_err();
        match err {
            DpiGuardError::Driver(msg) => assert!(msg.contains("cap")),
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }
}
