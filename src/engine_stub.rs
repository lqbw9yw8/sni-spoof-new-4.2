//! engine_stub — compiled in place of `engine.rs` on any non-Windows
//! target. Signatures match `engine.rs` so the rest of the crate links.

use crate::error::DpiGuardError;
use crate::fail_open::WireAction;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub use crate::DEFAULT_FILTER;

fn not_supported() -> DpiGuardError {
    DpiGuardError::PlatformNotSupported {
        os: std::env::consts::OS,
    }
}

pub fn inject_packet(_packet: &[u8]) -> Result<(), DpiGuardError> {
    Err(not_supported())
}

pub fn reinject_held_packets(_packets: &[Vec<u8>]) -> Result<(), DpiGuardError> {
    Err(not_supported())
}

pub fn capture_loop<F>(
    _filter: &str,
    _running: Arc<AtomicBool>,
    _on_packet: F,
) -> Result<(), DpiGuardError>
where
    F: FnMut(Vec<u8>) -> Result<WireAction, DpiGuardError> + Send + 'static,
{
    Err(not_supported())
}

pub fn version_check(_expected_hashes: &[String]) -> Result<(), DpiGuardError> {
    Err(not_supported())
}

pub fn graceful_shutdown(_running: Arc<AtomicBool>) -> Result<(), DpiGuardError> {
    Err(not_supported())
}

pub fn request_shutdown() {}

pub fn request_filter_reload(_new_filter: &str) {
    // No-op: the WinDivert capture loop (and its open handle) only exists
    // on Windows.
}

pub fn thread_safe_logging_init() {
    crate::init_logging();
}

pub fn parse_tls_client_hello(tcp_payload: &[u8]) -> Option<Vec<u8>> {
    crate::fragmentation::sni_bytes(tcp_payload)
}

pub fn recalculate_checksums(pkt: &mut Vec<u8>) {
    crate::packet::recalculate_all_checksums(pkt);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_packet_reports_unsupported_off_windows() {
        let err = inject_packet(&[]).unwrap_err();
        assert!(matches!(err, DpiGuardError::PlatformNotSupported { .. }));
    }

    #[test]
    fn capture_loop_signature_matches_windows() {
        let running = Arc::new(AtomicBool::new(false));
        let err = capture_loop("true", running, |_| Ok(WireAction::Hold)).unwrap_err();
        assert!(matches!(err, DpiGuardError::PlatformNotSupported { .. }));
    }
}
