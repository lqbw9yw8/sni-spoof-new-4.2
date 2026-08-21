//! engine — Windows-only packet I/O on WinDivert 0.5. [PARTIAL]
//!
//! Written against the published 0.5.5 API (`network`, `recv(Some(&mut buf))`,
//! `send`, `shutdown`, `close`). Still needs a Windows host with the
//! driver to field-test. Pure logic (checksums, fail-open, TLS parse) is
//! delegated to cfg-free modules and is unit-tested on every OS.
#![allow(unsafe_code)]

use crate::error::DpiGuardError;
use crate::fail_open::{handle_exception_fail_open, WireAction};
use crate::sequence::race_condition_fix_delay;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use windivert::prelude::{
    CloseAction, WinDivert, WinDivertFlags, WinDivertPacket, WinDivertShutdownMode,
};
use windivert::layer::NetworkLayer;

pub use crate::DEFAULT_FILTER;

type Divert = WinDivert<NetworkLayer>;

/// Raw pointer so `WinDivertShutdown` can run concurrent with a blocking
/// `recv` (the C API documents this; the Rust wrapper takes `&mut self`).
static DIVERT: AtomicPtr<Divert> = AtomicPtr::new(std::ptr::null_mut());

const MAX_HELD: usize = 256;

type DivertPacket = WinDivertPacket<NetworkLayer>;

struct Held {
    key: Option<(IpAddr, IpAddr, u16, u16)>,
    packet: DivertPacket,
}

fn held_lock() -> std::sync::MutexGuard<'static, Vec<Held>> {
    static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());
    match HELD.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn flow_key_of(raw: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    let p = crate::packet::parse_l3l4(raw)?;
    Some((p.src, p.dst, p.src_port, p.dst_port))
}

fn remember_hold(packet: DivertPacket) -> bool {
    let mut g = held_lock();
    if g.len() >= MAX_HELD {
        return false;
    }
    let key = flow_key_of(packet.data.as_ref());
    g.push(Held { key, packet });
    true
}

fn forget_held_for_flow(raw: &[u8]) {
    let key = flow_key_of(raw);
    let mut g = held_lock();
    g.retain(|h| {
        if h.packet.data.as_ref() == raw {
            return false;
        }
        match (h.key, key) {
            (Some(a), Some(b)) => a != b,
            _ => true,
        }
    });
}

fn send_packet(ptr: *mut Divert, packet: &DivertPacket) {
    if ptr.is_null() {
        return;
    }
    if let Err(e) = unsafe { (*ptr).send(packet) } {
        log::error!("WinDivert send error: {e}");
    }
}

/// Re-inject packets previously returned as `WireAction::Hold`, using the
/// WinDivert address captured with the original divert (not a zeroed
/// send-only address). Called by the 200ms watchdog after
/// `Pipeline::take_expired_held`.
pub fn reinject_held_packets(packets: &[Vec<u8>]) -> Result<(), DpiGuardError> {
    let ptr = DIVERT.load(Ordering::SeqCst);
    for want in packets {
        let found = {
            let mut g = held_lock();
            let idx = g
                .iter()
                .position(|h| h.packet.data.as_ref() == want.as_slice())
                .or_else(|| {
                    let k = flow_key_of(want);
                    g.iter().position(|h| h.key.is_some() && h.key == k)
                });
            idx.map(|i| g.remove(i))
        };
        match found {
            Some(h) => send_packet(ptr, &h.packet),
            None => {
                // Desync: still fail-open rather than drop.
                inject_packet(want)?;
            }
        }
    }
    Ok(())
}

fn flush_all_holds(ptr: *mut Divert) {
    let leftover: Vec<Held> = {
        let mut g = held_lock();
        std::mem::take(&mut *g)
    };
    for h in leftover {
        send_packet(ptr, &h.packet);
    }
}

pub fn open_handle(filter: &str) -> Result<Divert, DpiGuardError> {
    WinDivert::network(filter, 0, WinDivertFlags::new())
        .map_err(|e| DpiGuardError::Driver(format!("WinDivert::network open failed: {e}")))
}

fn store_handle(wd: Divert) -> *mut Divert {
    let ptr = Box::into_raw(Box::new(wd));
    let old = DIVERT.swap(ptr, Ordering::SeqCst);
    if !old.is_null() {
        unsafe {
            let mut prev = Box::from_raw(old);
            let _ = prev.shutdown(WinDivertShutdownMode::Both);
            let _ = prev.close(CloseAction::Nothing);
        }
    }
    ptr
}

fn drop_stored_handle() {
    let ptr = DIVERT.swap(std::ptr::null_mut(), Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe {
            let mut wd = Box::from_raw(ptr);
            let _ = wd.shutdown(WinDivertShutdownMode::Both);
            let _ = wd.close(CloseAction::Nothing);
        }
    }
}

/// Abort a blocking `recv` so Ctrl+C does not wait for the next packet.
pub fn request_shutdown() {
    let ptr = DIVERT.load(Ordering::SeqCst);
    if !ptr.is_null() {
        // SAFETY: WinDivertShutdown is defined to fail in-flight Recv calls.
        unsafe {
            let _ = (*ptr).shutdown(WinDivertShutdownMode::Both);
        }
    }
}

/// Pending filter change, requested by the config hot-reload watcher when
/// `intercept_ports` / `intercept_all_*` change. The capture loop consumes
/// it and reopens the handle before the next packet.
fn pending_filter_lock() -> std::sync::MutexGuard<'static, Option<String>> {
    static PENDING_FILTER: Mutex<Option<String>> = Mutex::new(None);
    match PENDING_FILTER.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Store a new filter and abort the in-flight `recv` so the capture loop
/// can reopen with it. No-op until the capture loop is running.
pub fn request_filter_reload(new_filter: &str) {
    *pending_filter_lock() = Some(new_filter.to_string());
    request_shutdown();
}

/// Reopen the capture handle with a pending filter, if one was requested.
/// Returns true when a pending filter was consumed. The old handle has
/// already been shut down by `request_filter_reload`, so on open failure we
/// fall back to the previous filter to keep the packet path alive.
fn apply_pending_filter(ptr: &mut *mut Divert, current: &mut String) -> bool {
    let pending = match pending_filter_lock().take() {
        Some(f) => f,
        None => return false,
    };
    match open_handle(&pending) {
        Ok(h) => {
            *ptr = store_handle(h);
            log::info!("WinDivert filter reloaded: {pending}");
            *current = pending;
        }
        Err(e) => {
            log::error!("WinDivert filter reload failed ({e}); falling back to previous filter");
            match open_handle(current.as_str()) {
                Ok(h) => *ptr = store_handle(h),
                Err(e2) => log::error!("previous-filter reopen also failed: {e2}"),
            }
        }
    }
    true
}

/// Blocking capture loop. Run it on a dedicated thread / `spawn_blocking`
/// — `recv` is a blocking driver call.
pub fn capture_loop<F>(
    filter: &str,
    running: Arc<AtomicBool>,
    mut on_packet: F,
) -> Result<(), DpiGuardError>
where
    F: FnMut(Vec<u8>) -> Result<WireAction, DpiGuardError> + Send + 'static,
{
    let handle = open_handle(filter)?;
    let mut ptr = store_handle(handle);
    let mut current_filter = filter.to_string();
    let mut buf = vec![0u8; 65535];

    while running.load(Ordering::SeqCst) {
        // Apply a hot-reloaded filter before blocking on the next packet.
        apply_pending_filter(&mut ptr, &mut current_filter);
        let recv = unsafe { (*ptr).recv(Some(&mut buf)) };
        let recv = match recv {
            Ok(pkt) => pkt,
            Err(e) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                log::warn!("WinDivert recv error, continuing: {e}");
                continue;
            }
        };

        let original: Vec<u8> = recv.data.to_vec();
        let address = recv.address.clone();
        let action = handle_exception_fail_open(&original, &mut on_packet);
        match action {
            WireAction::Hold => {
                let held = WinDivertPacket::<NetworkLayer> {
                    address: address.clone(),
                    data: Cow::Owned(original.clone()),
                };
                if !remember_hold(held) {
                    // Cap full: fail-open the original immediately with
                    // the real divert address so the connection cannot
                    // black-hole.
                    let pkt = WinDivertPacket::<NetworkLayer> {
                        address,
                        data: Cow::Owned(original),
                    };
                    send_packet(ptr, &pkt);
                }
            }
            WireAction::Send(packets) => {
                forget_held_for_flow(&original);
                for (i, bytes) in packets.into_iter().enumerate() {
                    if i > 0 {
                        std::thread::sleep(race_condition_fix_delay());
                    }
                    let pkt = WinDivertPacket::<NetworkLayer> {
                        address,
                        data: Cow::Owned(bytes),
                    };
                    send_packet(ptr, &pkt);
                }
            }
        }
    }
    flush_all_holds(ptr);
    drop_stored_handle();
    Ok(())
}

pub fn parse_tls_client_hello(tcp_payload: &[u8]) -> Option<Vec<u8>> {
    crate::fragmentation::sni_bytes(tcp_payload)
}

pub fn recalculate_checksums(pkt: &mut Vec<u8>) {
    crate::packet::recalculate_all_checksums(pkt);
}

/// Inject via a **send-only** handle whose filter matches nothing, so it
/// never competes with the capture handle for diverted packets.
pub fn inject_packet(packet: &[u8]) -> Result<(), DpiGuardError> {
    let flags = WinDivertFlags::new().set_send_only();
    let handle = WinDivert::network("false", 0, flags)
        .map_err(|e| DpiGuardError::Driver(format!("send-only open failed: {e}")))?;
    // SAFETY: address is zeroed; WinDivert infers direction from headers
    // when possible. Prefer capture_loop's path which copies the real address.
    let pkt = unsafe { WinDivertPacket::<NetworkLayer>::new(packet.to_vec()) };
    handle
        .send(&pkt)
        .map_err(|e| DpiGuardError::Driver(format!("send failed: {e}")))?;
    Ok(())
}

pub fn thread_safe_logging_init() {
    crate::init_logging();
}

pub fn graceful_shutdown(running: Arc<AtomicBool>) -> Result<(), DpiGuardError> {
    running.store(false, Ordering::SeqCst);
    request_shutdown();
    Ok(())
}

/// Confirm the WinDivert binaries sit next to the **executable** (never
/// cwd — that is a DLL-planting vector) AND — when the operator pinned
/// expected SHA-256 digests in config — that every loaded driver binary
/// matches a pinned digest. Presence-only trust is still allowed for
/// unpinned deployments, but it is logged loudly because a dropped-in
/// `WinDivert.dll`/`WinDivert64.sys` runs with kernel/admin privileges
/// (classic driver supply-chain attack).
pub fn version_check(expected_hashes: &[String]) -> Result<(), DpiGuardError> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .ok_or_else(|| {
            DpiGuardError::Driver("cannot determine executable directory for driver search".into())
        })?;

    let dll = ["WinDivert64.dll", "WinDivert.dll"]
        .iter()
        .map(|n| exe_dir.join(n))
        .find(|p| p.exists());
    let sys = ["WinDivert64.sys", "WinDivert.sys"]
        .iter()
        .map(|n| exe_dir.join(n))
        .find(|p| p.exists());

    let (Some(dll), Some(sys)) = (dll, sys) else {
        return Err(DpiGuardError::Driver(
            "WinDivert.dll and WinDivert64.sys not found next to the executable — download the official release, do not commit the driver to git, do not load from cwd".into(),
        ));
    };

    let pins: Vec<String> = expected_hashes
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();

    if pins.is_empty() {
        log::warn!(
            "no WinDivert SHA-256 pin configured (win_divert_sha256) — driver binaries are trusted by presence only. \
             This is a supply-chain risk; pin the official release digests."
        );
        return Ok(());
    }

    for path in [&dll, &sys] {
        let hash = crate::integrity::sha256_hex_file(path, crate::integrity::MAX_DRIVER_BYTES)?;
        if !crate::integrity::hash_is_pinned(&hash, &pins) {
            return Err(DpiGuardError::Driver(format!(
                "refusing to load {}: SHA-256 {hash} is not in the trusted pin list (possible tampered driver)",
                path.display()
            )));
        }
        log::info!("verified {} SHA-256 {hash}", path.display());
    }
    log::info!("WinDivert dll+sys found next to the executable and hash-verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    // Fail-open tests live in `fail_open.rs` so they run on Linux CI.
}
