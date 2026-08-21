//! config — TOML settings + mtime hot-reload. [DONE]
//! `HotReloadWatcher::new` snapshots the current mtime so the first
//! `reload_if_changed` is a no-op unless the file actually changes.

use crate::error::DpiGuardError;
use crate::sni_mutations::MutationProfile;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default = "default_profile")]
    pub mutation_profile: String,
    #[serde(default = "default_ttl")]
    pub decoy_ttl: u8,
    #[serde(default = "default_idle_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub trusted_dns: Option<String>,
    /// 0 = do not TCP-segment ClientHello. Default 64 (never 1).
    #[serde(default = "default_fragment_chunk")]
    pub fragment_chunk_size: usize,
    #[serde(default = "default_true")]
    pub enable_decoys: bool,
    #[serde(default = "default_true")]
    pub enable_sni_fragmentation: bool,
    #[serde(default)]
    pub enable_swap_foolers: bool,
    #[serde(default)]
    pub enable_kill_switch: bool,
    #[serde(default)]
    pub kill_switch_adapter: String,
    #[serde(default)]
    pub rotate_ips: Vec<String>,
    #[serde(default)]
    pub win_divert_sha256: Vec<String>,
    #[serde(default)]
    pub enable_web_ui: bool,
    #[serde(default = "default_web_ui_port")]
    pub web_ui_port: u16,
    #[serde(default)]
    pub web_ui_token: String,
    // --- 2025-2026 extensions ---
    #[serde(default)]
    pub enable_quic_port_bypass: bool,
    #[serde(default)]
    pub quic_bypass_use_low_port: bool,
    #[serde(default)]
    pub enable_sni_disguise: bool,
    #[serde(default)]
    pub fronting_benign_sni: String,
    #[serde(default = "default_true")]
    pub enable_combined_fragmentation: bool,
    // --- ALL PORTS upgrade ---
    /// List of TCP/UDP ports to intercept. Empty = default [443]. Use [443, 8443, 2053, 2083, 2087, 2096, 8080, 80] for all HTTPS-like
    #[serde(default)]
    pub intercept_ports: Vec<u16>,
    /// If true, intercept ALL TCP ports (0 = all). Dangerous, only for testing. Default false.
    #[serde(default)]
    pub intercept_all_tcp: bool,
    /// If true, intercept ALL UDP ports (for QUIC). Default false.
    #[serde(default)]
    pub intercept_all_udp: bool,
    /// Enable uTLS/JA3/JA4 fingerprint rotation (browser profile)
    #[serde(default)]
    pub enable_utls_fingerprint: bool,
    /// Browser to mimic: chrome, firefox, safari, edge, random
    #[serde(default = "default_browser")]
    pub utls_browser: String,
    /// Enable ECH (Encrypted Client Hello) GREASE and outer SNI
    #[serde(default)]
    pub enable_ech_grease: bool,
    /// Enable MD5SIG fooling (adds TCP option 19) - breaks some servers, only for zapret-style evasion
    #[serde(default)]
    pub enable_md5sig_fooling: bool,
    /// Enable Geedge-style evasion: extra padding, SNI with IP literal, etc.
    #[serde(default = "default_true")]
    pub enable_geedge_evasion: bool,
    // --- Relay mode (patterniha-style local relay) ---
    /// Bind 127.0.0.1:<relay_listen_port> and relay to a fixed destination.
    #[serde(default)]
    pub relay_enabled: bool,
    /// Local port v2rayN connects to (default 40443).
    #[serde(default = "default_relay_listen_port")]
    pub relay_listen_port: u16,
    /// Real destination host (domain or IP literal). Domain = resolved via DoH.
    #[serde(default)]
    pub relay_connect_host: String,
    /// Real destination port (default 443).
    #[serde(default = "default_relay_connect_port")]
    pub relay_connect_port: u16,
    /// Benign SNI shown to the DPI in the injected fake ClientHello.
    #[serde(default)]
    pub relay_fake_sni: String,
    /// Resolve `relay_connect_host` via DoH (no plaintext DNS). IP literals
    /// skip DNS entirely.
    #[serde(default = "default_true")]
    pub relay_resolve_doh: bool,
    /// After the fake handshake, also run the relay flow's real ClientHello
    /// through the normal SNI-mutation pipeline (item 1).
    #[serde(default)]
    pub relay_mutate_real_sni: bool,
    /// At injection time, also emit a TTL-limited wrong-checksum decoy of the
    /// fake ClientHello (item 2).
    #[serde(default)]
    pub relay_emit_decoy: bool,
    /// DoH endpoint URL.
    #[serde(default = "default_doh_url")]
    pub doh_server: String,
}

/// Ports never intercepted, even by the `intercept_all_tcp` /
/// `intercept_all_udp` wildcards: SSH (22), DNS (53), RDP (3389). Diverting
/// these would cut the operator's own remote access or plaintext DNS — the
/// exact leaks this tool is meant to avoid.
pub const NEVER_INTERCEPT_PORTS: [u16; 3] = [22, 53, 3389];

fn default_profile() -> String { "Stealth".to_string() }
fn default_ttl() -> u8 { 8 }
fn default_idle_secs() -> u64 { 120 }
fn default_fragment_chunk() -> usize { 64 }
fn default_web_ui_port() -> u16 { 9090 }
fn default_true() -> bool { true }
fn default_browser() -> String { "chrome".to_string() }
fn default_relay_listen_port() -> u16 { 40443 }
fn default_relay_connect_port() -> u16 { 443 }
fn default_doh_url() -> String { crate::doh::DEFAULT_DOH_URL.to_string() }

impl Default for Settings {
    fn default() -> Self {
        Self {
            mutation_profile: default_profile(),
            decoy_ttl: default_ttl(),
            idle_timeout_secs: default_idle_secs(),
            trusted_dns: None,
            fragment_chunk_size: default_fragment_chunk(),
            enable_decoys: true,
            enable_sni_fragmentation: true,
            enable_swap_foolers: false,
            enable_kill_switch: false,
            kill_switch_adapter: String::new(),
            rotate_ips: Vec::new(),
            win_divert_sha256: Vec::new(),
            enable_web_ui: false,
            web_ui_port: default_web_ui_port(),
            web_ui_token: String::new(),
            enable_quic_port_bypass: false,
            quic_bypass_use_low_port: false,
            enable_sni_disguise: false,
            fronting_benign_sni: String::new(),
            enable_combined_fragmentation: true,
            intercept_ports: Vec::new(),
            intercept_all_tcp: false,
            intercept_all_udp: false,
            enable_utls_fingerprint: false,
            utls_browser: default_browser(),
            enable_ech_grease: false,
            enable_md5sig_fooling: false,
            enable_geedge_evasion: true,
            relay_enabled: false,
            relay_listen_port: default_relay_listen_port(),
            relay_connect_host: String::new(),
            relay_connect_port: default_relay_connect_port(),
            relay_fake_sni: String::new(),
            relay_resolve_doh: true,
            relay_mutate_real_sni: false,
            relay_emit_decoy: false,
            doh_server: default_doh_url(),
        }
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("mutation_profile", &self.mutation_profile)
            .field("decoy_ttl", &self.decoy_ttl)
            .field("idle_timeout_secs", &self.idle_timeout_secs)
            .field("trusted_dns", &self.trusted_dns)
            .field("fragment_chunk_size", &self.fragment_chunk_size)
            .field("enable_decoys", &self.enable_decoys)
            .field("enable_sni_fragmentation", &self.enable_sni_fragmentation)
            .field("enable_swap_foolers", &self.enable_swap_foolers)
            .field("enable_kill_switch", &self.enable_kill_switch)
            .field("kill_switch_adapter", &self.kill_switch_adapter)
            .field("rotate_ips", &self.rotate_ips)
            .field("win_divert_sha256", &format!("{} pin(s)", self.win_divert_sha256.len()))
            .field("enable_web_ui", &self.enable_web_ui)
            .field("web_ui_port", &self.web_ui_port)
            .field("web_ui_token", &if self.web_ui_token.is_empty() { "<empty>" } else { "<redacted>" })
            .field("enable_quic_port_bypass", &self.enable_quic_port_bypass)
            .field("quic_bypass_use_low_port", &self.quic_bypass_use_low_port)
            .field("enable_sni_disguise", &self.enable_sni_disguise)
            .field("fronting_benign_sni", &self.fronting_benign_sni)
            .field("enable_combined_fragmentation", &self.enable_combined_fragmentation)
            .field("intercept_ports", &self.intercept_ports)
            .field("intercept_all_tcp", &self.intercept_all_tcp)
            .field("intercept_all_udp", &self.intercept_all_udp)
            .field("enable_utls_fingerprint", &self.enable_utls_fingerprint)
            .field("utls_browser", &self.utls_browser)
            .field("enable_ech_grease", &self.enable_ech_grease)
            .field("enable_md5sig_fooling", &self.enable_md5sig_fooling)
            .field("enable_geedge_evasion", &self.enable_geedge_evasion)
            .field("relay_enabled", &self.relay_enabled)
            .field("relay_listen_port", &self.relay_listen_port)
            .field("relay_connect_host", &self.relay_connect_host)
            .field("relay_connect_port", &self.relay_connect_port)
            .field("relay_fake_sni", &self.relay_fake_sni)
            .field("relay_resolve_doh", &self.relay_resolve_doh)
            .field("relay_mutate_real_sni", &self.relay_mutate_real_sni)
            .field("relay_emit_decoy", &self.relay_emit_decoy)
            .field("doh_server", &self.doh_server)
            .finish()
    }
}

impl Settings {
    /// Configured interception ports, independent of the all-* wildcards:
    /// `intercept_ports` minus the never-intercept ports, or `[443]` when
    /// empty. Used by the filter builder and by `is_target_port` on the
    /// non-wildcard path.
    pub fn explicit_port_list(&self) -> Vec<u16> {
        let mut v: Vec<u16> = if self.intercept_ports.is_empty() {
            vec![443]
        } else {
            self.intercept_ports.clone()
        };
        v.retain(|p| !NEVER_INTERCEPT_PORTS.contains(p));
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Display view for logs / dashboard: the sorted explicit list, or
    /// `[]` to mean "all ports" when a wildcard flag is on.
    pub fn effective_ports(&self) -> Vec<u16> {
        if self.intercept_all_tcp || self.intercept_all_udp {
            return vec![]; // meaning all, handled by the filter builder
        }
        self.explicit_port_list()
    }

    pub fn is_target_port(&self, port: u16, is_udp: bool) -> bool {
        if NEVER_INTERCEPT_PORTS.contains(&port) {
            return false;
        }
        if is_udp {
            if self.intercept_all_udp {
                return true;
            }
        } else if self.intercept_all_tcp {
            return true;
        }
        self.explicit_port_list().contains(&port)
    }

    pub fn validate(&self) -> Result<(), DpiGuardError> {
        MutationProfile::from_str(&self.mutation_profile)?;
        if self.decoy_ttl == 0 || self.decoy_ttl > 64 {
            return Err(DpiGuardError::Config("decoy_ttl must be 1..=64".into()));
        }
        if self.idle_timeout_secs == 0 {
            return Err(DpiGuardError::Config("idle_timeout_secs must be > 0".into()));
        }
        if self.fragment_chunk_size == 1 {
            return Err(DpiGuardError::Config("fragment_chunk_size=1 is rejected; use 0 or >=8".into()));
        }
        if self.fragment_chunk_size > 0 && self.fragment_chunk_size < 8 {
            return Err(DpiGuardError::Config("fragment_chunk_size must be 0 or >=8".into()));
        }
        if self.fragment_chunk_size > 16384 {
            return Err(DpiGuardError::Config("fragment_chunk_size must be <=16384".into()));
        }
        if self.idle_timeout_secs > 86_400 {
            return Err(DpiGuardError::Config("idle_timeout_secs must be <=86400".into()));
        }
        if self.enable_kill_switch {
            crate::stealth::sanitize_adapter_name(&self.kill_switch_adapter)?;
        }
        if let Some(dns) = &self.trusted_dns {
            if dns.parse::<IpAddr>().is_err() {
                return Err(DpiGuardError::Config("trusted_dns must be valid IP".into()));
            }
        }
        for ip in &self.rotate_ips {
            if ip.parse::<IpAddr>().is_err() {
                return Err(DpiGuardError::Config(format!("rotate_ips {ip:?} invalid")));
            }
        }
        for h in &self.win_divert_sha256 {
            let h = h.trim();
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(DpiGuardError::Config("win_divert_sha256 must be 64 hex".into()));
            }
        }
        if self.web_ui_port == 0 {
            return Err(DpiGuardError::Config("web_ui_port must be >0".into()));
        }
        if !self.web_ui_token.is_empty() {
            if self.web_ui_token.len() < 16 {
                return Err(DpiGuardError::Config("web_ui_token must be >=16".into()));
            }
            if !self.web_ui_token.chars().all(|c| c.is_ascii_graphic() && c != '"' && c != '\\') {
                return Err(DpiGuardError::Config("web_ui_token must be printable ASCII without quotes".into()));
            }
        }
        if !self.fronting_benign_sni.is_empty() {
            if self.fronting_benign_sni.len() > 253 {
                return Err(DpiGuardError::Config("fronting_benign_sni too long".into()));
            }
            if !self.fronting_benign_sni.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' ) {
                return Err(DpiGuardError::Config("fronting_benign_sni must be valid hostname".into()));
            }
        }
        if !self.intercept_ports.is_empty() {
            for &p in &self.intercept_ports {
                if p == 0 { return Err(DpiGuardError::Config("intercept_ports cannot contain 0".into())); }
                if NEVER_INTERCEPT_PORTS.contains(&p) {
                    log::warn!(
                        "intercept_ports contains {p}, which is never intercepted by design \
                         (SSH/DNS/RDP) — it will be ignored"
                    );
                }
            }
            if self.intercept_ports.len() > 100 {
                return Err(DpiGuardError::Config("intercept_ports max 100 entries".into()));
            }
        }
        let valid_browsers = ["chrome", "firefox", "safari", "edge", "random"];
        if !valid_browsers.contains(&self.utls_browser.to_ascii_lowercase().as_str()) {
            return Err(DpiGuardError::Config(format!("utls_browser must be one of {:?}", valid_browsers)));
        }
        if self.relay_enabled {
            if self.relay_listen_port == 0 {
                return Err(DpiGuardError::Config("relay_listen_port must be > 0".into()));
            }
            if self.relay_connect_port == 0 {
                return Err(DpiGuardError::Config("relay_connect_port must be > 0".into()));
            }
            let host = self.relay_connect_host.trim();
            if host.is_empty() {
                return Err(DpiGuardError::Config(
                    "relay_connect_host is required when relay_enabled".into(),
                ));
            }
            if host.parse::<IpAddr>().is_err()
                && !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                return Err(DpiGuardError::Config(
                    "relay_connect_host must be an IP or a valid hostname".into(),
                ));
            }
            if self.relay_fake_sni.is_empty() {
                return Err(DpiGuardError::Config(
                    "relay_fake_sni is required when relay_enabled".into(),
                ));
            }
            if !self
                .relay_fake_sni
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                return Err(DpiGuardError::Config(
                    "relay_fake_sni must be a valid hostname".into(),
                ));
            }
            if !self.doh_server.starts_with("https://") {
                return Err(DpiGuardError::Config("doh_server must be https://".into()));
            }
            if self.enable_web_ui && self.relay_listen_port == self.web_ui_port {
                return Err(DpiGuardError::Config(format!(
                    "relay_listen_port {} collides with web_ui_port",
                    self.relay_listen_port
                )));
            }
        }
        if self.intercept_all_tcp && self.intercept_all_udp {
            log::warn!("intercept_all_tcp AND intercept_all_udp both ON - will intercept ALL traffic, high risk!");
        }
        Ok(())
    }

    pub fn profile(&self) -> MutationProfile {
        MutationProfile::from_str(&self.mutation_profile).unwrap_or(MutationProfile::Stealth)
    }
}

pub fn parse(toml_text: &str) -> Result<Settings, DpiGuardError> {
    let s: Settings = toml::from_str(toml_text).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    s.validate()?;
    Ok(s)
}

pub fn load_from_file(path: &Path) -> Result<Settings, DpiGuardError> {
    let text = std::fs::read_to_string(path)?;
    parse(&text)
}

/// Merge a *partial* TOML document over `base`, producing validated
/// `Settings`. Used by the web UI: the dashboard POSTs only the fields the
/// user changed; everything else is inherited from the currently running
/// settings. Unknown keys are still rejected (deny_unknown_fields applies to
/// the final deserialization).
pub fn merge_partial(base: &Settings, partial_toml: &str) -> Result<Settings, DpiGuardError> {
    let partial: toml::Value =
        toml::from_str(partial_toml).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    let overrides = match partial {
        toml::Value::Table(t) => t,
        _ => {
            return Err(DpiGuardError::Config(
                "config must be a TOML table".into(),
            ))
        }
    };
    let base_str = toml::to_string(base).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    let mut base_value: toml::Value =
        toml::from_str(&base_str).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    let base_table = base_value
        .as_table_mut()
        .ok_or_else(|| DpiGuardError::Config("base config is not a table".into()))?;
    for (k, v) in overrides {
        base_table.insert(k, v);
    }
    let merged_str = toml::to_string(&base_value).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    let merged: Settings =
        toml::from_str(&merged_str).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    merged.validate()?;
    Ok(merged)
}

/// Serialize settings to TOML for the dashboard's advanced editor, with the
/// web-UI bearer token and driver pins redacted. Saving that text back via
/// `merge_partial` leaves the real token/pins in place (they are simply not
/// overridden).
pub fn redacted_toml(s: &Settings) -> Result<String, DpiGuardError> {
    let mut copy = s.clone();
    copy.web_ui_token = String::new();
    copy.win_divert_sha256 = Vec::new();
    toml::to_string(&copy).map_err(|e| DpiGuardError::Config(e.to_string()))
}

pub struct HotReloadWatcher {
    path: PathBuf,
    last_mtime: Option<SystemTime>,
}

impl HotReloadWatcher {
    pub fn new(path: PathBuf) -> Self {
        let last_mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        Self { path, last_mtime }
    }
    pub fn reload_if_changed(&mut self) -> Result<Option<Settings>, DpiGuardError> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mtime = meta.modified()?;
        let changed = self.last_mtime.map(|prev| mtime > prev).unwrap_or(true);
        if !changed { return Ok(None); }
        let settings = load_from_file(&self.path)?;
        self.last_mtime = Some(mtime);
        Ok(Some(settings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_fields_missing() {
        let s = parse("").unwrap();
        assert_eq!(s, Settings::default());
        assert_eq!(s.fragment_chunk_size, 64);
        assert!(s.enable_decoys);
        assert!(!s.enable_swap_foolers);
        assert!(!s.enable_quic_port_bypass);
        assert!(s.effective_ports() == vec![443]);
        assert!(s.is_target_port(443, false));
        assert!(!s.is_target_port(80, false));
    }

    #[test]
    fn parses_overrides() {
        let toml = r#"
            mutation_profile = "Aggressive"
            decoy_ttl = 5
            idle_timeout_secs = 60
            trusted_dns = "1.1.1.1"
            fragment_chunk_size = 32
            enable_decoys = false
        "#;
        let s = parse(toml).unwrap();
        assert_eq!(s.mutation_profile, "Aggressive");
        assert_eq!(s.decoy_ttl, 5);
        assert_eq!(s.trusted_dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(s.fragment_chunk_size, 32);
        assert!(!s.enable_decoys);
    }

    #[test]
    fn rejects_malformed_toml() {
        assert!(parse("not = [valid").is_err());
    }

    #[test]
    fn rejects_unknown_profile_and_chunk_size_one() {
        assert!(parse("mutation_profile = \"Nope\"\n").is_err());
        assert!(parse("fragment_chunk_size = 1\n").is_err());
        assert!(parse("decoy_ttl = 0\n").is_err());
    }

    #[test]
    fn web_ui_defaults_off_and_port_9090() {
        let s = Settings::default();
        assert!(!s.enable_web_ui);
        assert_eq!(s.web_ui_port, 9090);
        assert!(s.web_ui_token.is_empty());
        assert!(parse("web_ui_port = 0\n").is_err());
        assert!(parse("enable_web_ui = true\nweb_ui_port = 9091\nweb_ui_token = \"0123456789abcdef\"\n").is_ok());
    }

    #[test]
    fn win_divert_pins_must_be_64_hex_chars() {
        let good = "a".repeat(64);
        assert!(parse(&format!("win_divert_sha256 = [\"{good}\"]\n")).is_ok());
        assert!(parse("win_divert_sha256 = [\"abcd\"]\n").is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(parse("not_a_real_key = 1\n").is_err());
    }

    #[test]
    fn new_quic_and_fronting_options_parse() {
        let toml = r#"
            enable_quic_port_bypass = true
            quic_bypass_use_low_port = true
            enable_sni_disguise = true
            fronting_benign_sni = "www.microsoft.com"
            enable_combined_fragmentation = true
            mutation_profile = "Henan"
        "#;
        let s = parse(toml).unwrap();
        assert!(s.enable_quic_port_bypass);
        assert!(s.enable_sni_disguise);
        assert_eq!(s.mutation_profile, "Henan");
    }

    #[test]
    fn all_ports_upgrade_parses() {
        let toml = r#"
            intercept_ports = [443, 8443, 2053, 2083, 8080, 80]
            intercept_all_tcp = false
            intercept_all_udp = false
            enable_utls_fingerprint = true
            utls_browser = "firefox"
            enable_ech_grease = true
            enable_md5sig_fooling = true
        "#;
        let s = parse(toml).unwrap();
        assert_eq!(s.effective_ports(), vec![80,443,2053,2083,8080,8443]);
        assert!(s.is_target_port(8443, false));
        assert!(s.is_target_port(80, false));
        assert!(!s.is_target_port(22, false));
        assert!(s.enable_utls_fingerprint);
        assert!(s.enable_ech_grease);
    }

    #[test]
    fn intercept_all_flags_exclude_never_ports() {
        let toml = r#"
            intercept_all_tcp = true
            intercept_all_udp = true
        "#;
        let s = parse(toml).unwrap();
        // Never-intercept ports stay off-limits even in "all" mode.
        assert!(!s.is_target_port(22, false));
        assert!(!s.is_target_port(53, true));
        assert!(!s.is_target_port(3389, false));
        assert!(!s.is_target_port(3389, true));
        // Ordinary ports are intercepted.
        assert!(s.is_target_port(12345, true));
        assert!(s.is_target_port(12345, false));
    }

    #[test]
    fn never_ports_are_ignored_in_explicit_list() {
        let s = parse("intercept_ports = [443, 53, 22]\n").unwrap();
        assert!(!s.is_target_port(53, true));
        assert!(!s.is_target_port(22, false));
        assert!(s.is_target_port(443, false));
        assert_eq!(s.explicit_port_list(), vec![443]);
    }

    #[test]
    fn rejects_invalid_ports_and_browser() {
        assert!(parse("intercept_ports = [0]\n").is_err());
        assert!(parse("utls_browser = \"opera\"\n").is_err());
        assert!(parse("utls_browser = \"chrome\"\n").is_ok());
    }

    #[test]
    fn relay_config_parses_and_validates() {
        let toml = r#"
            relay_enabled = true
            relay_listen_port = 40555
            relay_connect_host = "speedtest.example.com"
            relay_connect_port = 443
            relay_fake_sni = "www.microsoft.com"
            relay_resolve_doh = true
        "#;
        let s = parse(toml).unwrap();
        assert!(s.relay_enabled);
        assert_eq!(s.relay_listen_port, 40555);
        assert_eq!(s.relay_fake_sni, "www.microsoft.com");
        assert_eq!(s.doh_server, crate::doh::DEFAULT_DOH_URL);

        // Missing fake SNI -> error
        assert!(parse("relay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\n").is_err());
        // Non-https DoH endpoint -> error
        assert!(parse("relay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\ndoh_server = \"http://x\"\n").is_err());
        // Invalid hostname -> error
        assert!(parse("relay_enabled = true\nrelay_connect_host = \"bad host\"\nrelay_fake_sni = \"a.com\"\n").is_err());
    }

    #[test]
    fn merge_partial_overrides_and_preserves_base() {
        let base = Settings::default();
        let merged = merge_partial(&base, "mutation_profile = \"Henan\"\nrelay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\n").unwrap();
        assert_eq!(merged.mutation_profile, "Henan");
        assert!(merged.relay_enabled);
        // Untouched fields keep their base values.
        assert_eq!(merged.decoy_ttl, base.decoy_ttl);
        assert_eq!(merged.fragment_chunk_size, base.fragment_chunk_size);
        assert_eq!(merged.intercept_ports, base.intercept_ports);
    }

    #[test]
    fn merge_partial_rejects_unknown_key_and_bad_value() {
        let base = Settings::default();
        assert!(merge_partial(&base, "not_a_real_key = 1\n").is_err());
        assert!(merge_partial(&base, "decoy_ttl = 0\n").is_err());
        assert!(merge_partial(&base, "relay_enabled = true\n").is_err()); // missing fake_sni
    }

    #[test]
    fn merge_partial_new_relay_flags_parse() {
        let base = Settings::default();
        let merged = merge_partial(
            &base,
            "relay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\nrelay_mutate_real_sni = true\nrelay_emit_decoy = true\n",
        )
        .unwrap();
        assert!(merged.relay_mutate_real_sni);
        assert!(merged.relay_emit_decoy);
    }

    #[test]
    fn redacted_toml_hides_token_and_pins() {
        let mut s = Settings::default();
        s.web_ui_token = "secret-secret-secret".into();
        s.win_divert_sha256 = vec!["a".repeat(64)];
        let toml = redacted_toml(&s).unwrap();
        assert!(!toml.contains("secret-secret-secret"));
        assert!(!toml.contains(&"a".repeat(64)));
        // And merging it back keeps the original token/pins untouched.
        let merged = merge_partial(&s, &toml).unwrap();
        assert_eq!(merged.web_ui_token, "secret-secret-secret");
        assert_eq!(merged.win_divert_sha256, vec!["a".repeat(64)]);
    }

    #[test]
    fn relay_disabled_by_default_and_port_collision_rejected() {
        assert!(!Settings::default().relay_enabled);
        assert_eq!(Settings::default().relay_listen_port, 40443);
        // web_ui (9090) + relay on the same port -> error
        let toml = r#"
            enable_web_ui = true
            relay_enabled = true
            relay_listen_port = 9090
            relay_connect_host = "1.1.1.1"
            relay_fake_sni = "a.com"
        "#;
        assert!(parse(toml).is_err());
    }

    #[test]
    fn hot_reload_detects_change() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("dpi_guard_test_{}.toml", std::process::id()));
        std::fs::write(&path, "decoy_ttl = 1\n").unwrap();
        let mut watcher = HotReloadWatcher::new(path.clone());
        assert!(watcher.reload_if_changed().unwrap().is_none());
        let mut seen = None;
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            std::fs::write(&path, "decoy_ttl = 2\n").unwrap();
            if let Some(s) = watcher.reload_if_changed().unwrap() {
                seen = Some(s);
                break;
            }
        }
        assert_eq!(seen.unwrap().decoy_ttl, 2);
        let _ = std::fs::remove_file(&path);
    }
}
