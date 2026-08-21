//! dpi_guard
//!
//! Modular DPI-evasion engine. Pure-logic modules build and test on any
//! OS. Packet capture/injection needs Windows + WinDivert and only
//! compiles on `cfg(windows)`.
//!
//! STATUS LEGEND used in doc comments:
//!   [DONE]    - implemented and unit tested in this build.
//!   [PARTIAL] - implemented, with documented limits.
//!   [STUB]    - compiles, returns a typed error, needs Windows/WFP FFI.
#![deny(unsafe_code)] // only `engine.rs` (WinDivert FFI) is allowed to opt back in

pub mod config;
pub mod connection;
pub mod dns_guard;
pub mod doh;
pub mod ech;
pub mod error;
pub mod fail_open;
pub mod fooling;
pub mod fragmentation;
pub mod geedge;
pub mod integrity;
pub mod packet;
pub mod pipeline;
pub mod quic;
pub mod relay;
pub mod sequence;
pub mod sni_mutations;
pub mod stealth;
pub mod strategy;
pub mod utls;
pub mod webui;

#[cfg(windows)]
pub mod engine;
#[cfg(not(windows))]
pub mod engine_stub;
#[cfg(not(windows))]
pub use engine_stub as engine;

pub use error::DpiGuardError;

/// TCP/443 and UDP/443, both directions, never loopback — legacy default
pub const DEFAULT_FILTER: &str =
    "!loopback and ((tcp and (tcp.DstPort == 443 or tcp.SrcPort == 443)) or (udp and (udp.DstPort == 443 or udp.SrcPort == 443)))";

/// Build the WinDivert filter from settings. Both protocols are always
/// written out (never a bare `tcp or udp`), and the wildcard
/// `intercept_all_tcp` / `intercept_all_udp` modes always exclude the
/// never-intercept ports (SSH 22, DNS 53, RDP 3389) so "all ports" mode
/// cannot cut the operator's own remote access or plaintext DNS.
pub fn build_filter(settings: &config::Settings) -> String {
    // Relay mode needs its own destination port diverted (to observe the
    // handshake for the fake-SNI injection) even when it is not in
    // intercept_ports. Never-intercept ports are still excluded.
    let mut ports = settings.explicit_port_list();
    if settings.relay_enabled {
        ports.push(settings.relay_connect_port);
        ports.retain(|p| !config::NEVER_INTERCEPT_PORTS.contains(p));
        ports.sort_unstable();
        ports.dedup();
    }
    let tcp = tcp_clause(settings, &ports);
    let udp = udp_clause(settings, &ports);
    format!("!loopback and ({tcp} or {udp})")
}

/// Exclusions expressed per protocol: in WinDivert a protocol field read
/// against the wrong transport is meaningless, so each clause is guarded
/// by `{proto} and ...`.
fn never_clause(proto: &str) -> String {
    config::NEVER_INTERCEPT_PORTS
        .iter()
        .map(|p| format!("{proto}.DstPort != {p} and {proto}.SrcPort != {p}"))
        .collect::<Vec<String>>()
        .join(" and ")
}

fn tcp_clause(settings: &config::Settings, ports: &[u16]) -> String {
    if settings.intercept_all_tcp {
        return format!("(tcp and {})", never_clause("tcp"));
    }
    if ports.is_empty() {
        // Every configured port was a never-intercept port.
        return "false".to_string();
    }
    let conds = ports
        .iter()
        .map(|p| format!("tcp.DstPort == {p} or tcp.SrcPort == {p}"))
        .collect::<Vec<String>>()
        .join(" or ");
    format!("(tcp and ({conds}))")
}

fn udp_clause(settings: &config::Settings, ports: &[u16]) -> String {
    if settings.intercept_all_udp {
        return format!("(udp and {})", never_clause("udp"));
    }
    if ports.is_empty() {
        return "false".to_string();
    }
    let conds = ports
        .iter()
        .map(|p| format!("udp.DstPort == {p} or udp.SrcPort == {p}"))
        .collect::<Vec<String>>()
        .join(" or ");
    format!("(udp and ({conds}))")
}

/// `RUST_LOG` controls verbosity; default `dpi_guard=info`.
pub fn init_logging() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("dpi_guard=info"),
    )
    .is_test(false)
    .try_init();
}

/// Recover a `Mutex` after a panic in another thread. Poisoning must not
/// take the packet path down — fail-open prefers a possibly-stale
/// pipeline over black-holing every subsequent packet.
pub fn recover_mutex<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_is_443() {
        let s = config::Settings::default();
        let f = build_filter(&s);
        assert!(f.contains("443"));
        assert!(f.contains("!loopback"));
    }

    #[test]
    fn all_ports_filter_excludes_never_ports() {
        let mut s = config::Settings::default();
        s.intercept_all_tcp = true;
        s.intercept_all_udp = true;
        let f = build_filter(&s);
        assert!(f.contains("!loopback"));
        for p in config::NEVER_INTERCEPT_PORTS {
            assert!(f.contains(&format!("tcp.DstPort != {p}")));
            assert!(f.contains(&format!("tcp.SrcPort != {p}")));
            assert!(f.contains(&format!("udp.DstPort != {p}")));
            assert!(f.contains(&format!("udp.SrcPort != {p}")));
        }
    }

    #[test]
    fn all_tcp_only_keeps_udp_on_target_ports() {
        let mut s = config::Settings::default();
        s.intercept_all_tcp = true;
        let f = build_filter(&s);
        assert!(f.contains("(tcp and"));
        assert!(f.contains("tcp.DstPort != 22"));
        assert!(f.contains("udp.DstPort == 443"));
    }

    #[test]
    fn explicit_ports_drop_never_touch_ports() {
        let mut s = config::Settings::default();
        s.intercept_ports = vec![443, 53, 8443];
        let f = build_filter(&s);
        assert!(f.contains("tcp.DstPort == 443"));
        assert!(f.contains("tcp.DstPort == 8443"));
        assert!(!f.contains("tcp.DstPort == 53"));
        assert!(!f.contains("udp.DstPort == 53"));
    }

    #[test]
    fn custom_ports_filter_contains_all() {
        let mut s = config::Settings::default();
        s.intercept_ports = vec![443, 8443, 8080];
        let f = build_filter(&s);
        assert!(f.contains("443"));
        assert!(f.contains("8443"));
        assert!(f.contains("8080"));
    }
}
