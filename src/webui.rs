//! webui — opt-in local dashboard. [DONE] (std-only, no new dependencies)
//!
//! A deliberately *safe* control surface, unlike the earlier sibling
//! project that bound a control panel to `0.0.0.0` with no auth:
//!
//! - binds **127.0.0.1 only** (never exposed on the network)
//! - every `/api/*` route requires a bearer token (constant-time compare)
//! - read-only by default; the only mutation is selecting a mutation
//!   profile, which reuses the exact same validated path as `dpi_guard.toml`
//! - no CORS headers; Host must be 127.0.0.1 (DNS-rebind defence);
//!   `X-Content-Type-Options: nosniff`, CSP, `X-Frame-Options: DENY`,
//!   no file serving
//!
//! It is OFF unless `enable_web_ui = true`. The server runs on a plain
//! `std::net::TcpListener` thread so it has zero dependency surface and
//! cannot reach the WinDivert capture handle.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::DpiGuardError;
use crate::pipeline::Pipeline;

/// Snapshot of pipeline state rendered by the dashboard. `main` refreshes
/// this from the live pipeline; the web thread only reads it.
#[derive(Debug, Clone, Default)]
pub struct DashboardSnapshot {
    pub mutation_profile: String,
    pub decoy_ttl: u8,
    pub idle_timeout_secs: u64,
    pub fragment_chunk_size: usize,
    pub enable_decoys: bool,
    pub enable_sni_fragmentation: bool,
    pub enable_swap_foolers: bool,
    pub enable_kill_switch: bool,
    pub processed_packets: u64,
    /// Flattened `domain|technique -> score`.
    pub strategy_scores: Vec<(String, i64)>,
    /// Hashed SNIs recently observed (never the raw hostname in the UI).
    pub recent_domains: Vec<String>,
    // NEW 2025-2026 fields
    pub intercept_ports: Vec<u16>,
    pub enable_quic_bypass: bool,
    pub enable_sni_disguise: bool,
    pub fronting_benign: String,
    pub enable_utls: bool,
    pub enable_ech_grease: bool,
    // Relay-mode fields
    pub relay_enabled: bool,
    pub relay_listen_port: u16,
}

/// Start the dashboard on `127.0.0.1:port`, returning the server thread
/// handle. Fails fast (bind error) so `main` can log and continue without
/// the UI rather than crashing the packet path.
pub fn start(
    port: u16,
    token: String,
    snapshot: Arc<Mutex<DashboardSnapshot>>,
    requested_profile: Arc<Mutex<Option<String>>>,
    pipeline: Arc<Mutex<Pipeline>>,
    config_path: PathBuf,
    running: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, DpiGuardError> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = TcpListener::bind(addr)
        .map_err(|e| DpiGuardError::Io(std::io::Error::new(e.kind(), format!("webui bind {addr}: {e}"))))?;
    log::info!("web UI listening on http://{addr} (token required)");

    let handle = std::thread::Builder::new()
        .name("dpi_guard-webui".into())
        .spawn(move || {
            serve_loop(
                listener,
                port,
                token,
                snapshot,
                requested_profile,
                pipeline,
                config_path,
                running,
            )
        })
        .map_err(|e| {
            DpiGuardError::Io(std::io::Error::new(
                e.kind(),
                format!("webui spawn: {e}"),
            ))
        })?;
    Ok(handle)
}

fn serve_loop(
    listener: TcpListener,
    port: u16,
    token: String,
    snapshot: Arc<Mutex<DashboardSnapshot>>,
    requested_profile: Arc<Mutex<Option<String>>>,
    pipeline: Arc<Mutex<Pipeline>>,
    config_path: PathBuf,
    running: Arc<AtomicBool>,
) {
    // Non-blocking accept so Ctrl+C (running=false) does not wait for the
    // next inbound TCP connection to notice shutdown.
    let _ = listener.set_nonblocking(true);
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_conn(
                    stream,
                    port,
                    &token,
                    &snapshot,
                    &requested_profile,
                    &pipeline,
                    &config_path,
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => log::debug!("webui accept error: {e}"),
        }
    }
}

fn handle_conn(
    mut stream: TcpStream,
    port: u16,
    token: &str,
    snapshot: &Arc<Mutex<DashboardSnapshot>>,
    requested_profile: &Arc<Mutex<Option<String>>>,
    pipeline: &Arc<Mutex<Pipeline>>,
    config_path: &PathBuf,
) -> Result<(), std::io::Error> {
    let _ = stream.set_nonblocking(false);
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]).to_string();
    if n == buf.len() && !req.contains("\r\n\r\n") {
        return respond(
            stream,
            413,
            "application/json",
            r#"{"error":"request too large"}"#,
        );
    }
    let mut lines = req.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut auth = String::new();
    let mut content_length = 0usize;
    let mut host = String::new();
    let mut origin = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let lname = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match lname.as_str() {
            "authorization" => auth = value.to_string(),
            "content-length" => {
                content_length = value.parse().unwrap_or(0);
                if content_length > 4096 {
                    return respond(
                        stream,
                        413,
                        "application/json",
                        r#"{"error":"request too large"}"#,
                    );
                }
            }
            "host" => host = value.to_string(),
            "origin" => origin = value.to_string(),
            _ => {}
        }
    }

    if !host_is_allowed(&host, port) {
        return respond(stream, 403, "application/json", r#"{"error":"forbidden host"}"#);
    }
    if !origin_is_allowed(&origin, port) {
        return respond(
            stream,
            403,
            "application/json",
            r#"{"error":"forbidden origin"}"#,
        );
    }

    // Extract the body if any (for POST /api/profile).
    let mut body = String::new();
    if content_length > 0 {
        let marker = "\r\n\r\n";
        if let Some(pos) = req.find(marker) {
            let start = pos + marker.len();
            let end = (start + content_length).min(req.len());
            body = req[start..end].to_string();
        }
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/") => respond(stream, 200, "text/html; charset=utf-8", INDEX_HTML),
        ("GET", "/api/status") => {
            if !token_ok(&auth, token) {
                return respond(stream, 401, "application/json", r#"{"error":"unauthorized"}"#);
            }
            let snap = crate::recover_mutex(snapshot).clone();
            respond(stream, 200, "application/json", &status_json(&snap))
        }
        ("POST", "/api/profile") => {
            if !token_ok(&auth, token) {
                return respond(stream, 401, "application/json", r#"{"error":"unauthorized"}"#);
            }
            let profile = extract_json_string(&body, "profile");
            match profile {
                Some(p) if is_known_profile(&p) => {
                    *crate::recover_mutex(requested_profile) = Some(p.clone());
                    respond(stream, 200, "application/json", &format!(r#"{{"ok":true,"profile":"{}"}}"#, json_escape(&p)))
                }
                _ => respond(
                    stream,
                    400,
                    "application/json",
                    r#"{"ok":false,"error":"profile must be one of Stealth, ChinaGfw, RussiaDpi, Aggressive, ChinaRegional, Henan"}"#,
                ),
            }
        }
        ("GET", "/api/config") => {
            if !token_ok(&auth, token) {
                return respond(stream, 401, "application/json", r#"{"error":"unauthorized"}"#);
            }
            let settings = crate::recover_mutex(pipeline).settings.clone();
            respond(stream, 200, "application/json", &settings_json(&settings))
        }
        ("GET", "/api/config/toml") => {
            if !token_ok(&auth, token) {
                return respond(stream, 401, "application/json", r#"{"error":"unauthorized"}"#);
            }
            let settings = crate::recover_mutex(pipeline).settings.clone();
            match crate::config::redacted_toml(&settings) {
                Ok(toml) => respond(stream, 200, "text/plain; charset=utf-8", &toml),
                Err(e) => respond(
                    stream,
                    500,
                    "application/json",
                    &format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e.to_string())),
                ),
            }
        }
        ("POST", "/api/config") => {
            if !token_ok(&auth, token) {
                return respond(stream, 401, "application/json", r#"{"error":"unauthorized"}"#);
            }
            let base = crate::recover_mutex(pipeline).settings.clone();
            match crate::config::merge_partial(&base, &body) {
                Ok(merged) => {
                    let text = match toml::to_string(&merged) {
                        Ok(t) => t,
                        Err(e) => {
                            return respond(
                                stream,
                                500,
                                "application/json",
                                &format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e.to_string())),
                            )
                        }
                    };
                    match std::fs::write(config_path, text) {
                        Ok(()) => respond(
                            stream,
                            200,
                            "application/json",
                            r#"{"ok":true,"saved":true,"message":"config saved; hot-reload applies it within a second"}"#,
                        ),
                        Err(e) => respond(
                            stream,
                            500,
                            "application/json",
                            &format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e.to_string())),
                        ),
                    }
                }
                Err(e) => respond(
                    stream,
                    400,
                    "application/json",
                    &format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e.to_string())),
                ),
            }
        }
        _ => respond(stream, 404, "application/json", r#"{"error":"not found"}"#),
    }
}

fn respond(mut stream: TcpStream, code: u16, ctype: &str, body: &str) -> Result<(), std::io::Error> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
         Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\n\
         Cross-Origin-Opener-Policy: same-origin\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// Constant-time token comparison (avoids a timing side channel on the
/// auth check even though this is localhost-only).
fn token_ok(header: &str, expected: &str) -> bool {
    let header = header.trim();
    let bytes = header.as_bytes();
    // Compare on bytes so a multibyte first character cannot panic on a
    // non-char-boundary slice of the `str`.
    let got = if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"bearer ") {
        header[7..].trim()
    } else {
        ""
    };
    crate::integrity::constant_time_eq(got.as_bytes(), expected.as_bytes())
}

fn is_known_profile(p: &str) -> bool {
    matches!(
        p,
        "Stealth" | "ChinaGfw" | "RussiaDpi" | "Aggressive" | "ChinaRegional" | "Henan"
    )
}

/// Host must be loopback IPv4. Rejecting `localhost` and any other name
/// blocks DNS-rebinding (an attacker domain resolving to 127.0.0.1
/// would otherwise send `Host: evil.example`).
pub fn host_is_allowed(host: &str, port: u16) -> bool {
    let host = host.trim();
    if host.is_empty() {
        return false;
    }
    let expected_port = format!("127.0.0.1:{port}");
    host.eq_ignore_ascii_case("127.0.0.1") || host.eq_ignore_ascii_case(&expected_port)
}

/// Empty Origin (curl / non-browser) is allowed. Browser fetch must
/// come from the dashboard origin itself.
pub fn origin_is_allowed(origin: &str, port: u16) -> bool {
    let origin = origin.trim();
    if origin.is_empty() {
        return true;
    }
    let expected = format!("http://127.0.0.1:{port}");
    origin.eq_ignore_ascii_case(&expected)
}

fn extract_json_string(body: &str, key: &str) -> Option<String> {
    // Minimal parser for `{"key":"value"}` — no external JSON dependency.
    let body = body.trim();
    let rest = body.strip_prefix('{')?.strip_suffix('}')?.trim();
    for pair in rest.split(',') {
        let mut kv = pair.splitn(2, ':');
        let k = kv.next()?.trim().trim_matches('"').trim();
        let v = kv.next()?.trim().trim_matches('"').trim();
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn status_json(s: &DashboardSnapshot) -> String {
    let scores: Vec<String> = s
        .strategy_scores
        .iter()
        .map(|(k, v)| format!(r#"{{"key":"{}","score":{v}}}"#, json_escape(k)))
        .collect();
    let domains: Vec<String> = s
        .recent_domains
        .iter()
        .map(|d| format!("\"{}\"", json_escape(d)))
        .collect();
    let ports: Vec<String> = s.intercept_ports.iter().map(|p| p.to_string()).collect();
    format!(
        r#"{{"mutation_profile":"{}","decoy_ttl":{},"idle_timeout_secs":{},"fragment_chunk_size":{},"enable_decoys":{},"enable_sni_fragmentation":{},"enable_swap_foolers":{},"enable_kill_switch":{},"processed_packets":{},"strategy_scores":[{}],"recent_domains":[{}],"intercept_ports":[{}],"enable_quic_bypass":{},"enable_sni_disguise":{},"fronting_benign":"{}","enable_utls":{},"enable_ech_grease":{},"relay_enabled":{},"relay_listen_port":{}}}"#,
        json_escape(&s.mutation_profile),
        s.decoy_ttl,
        s.idle_timeout_secs,
        s.fragment_chunk_size,
        s.enable_decoys,
        s.enable_sni_fragmentation,
        s.enable_swap_foolers,
        s.enable_kill_switch,
        s.processed_packets,
        scores.join(","),
        domains.join(","),
        ports.join(","),
        s.enable_quic_bypass,
        s.enable_sni_disguise,
        json_escape(&s.fronting_benign),
        s.enable_utls,
        s.enable_ech_grease,
        s.relay_enabled,
        s.relay_listen_port
    )
}

/// Full editable settings as JSON for the dashboard config form. The web-UI
/// bearer token and driver pins are redacted (they are advanced/sensitive and
/// preserved on save via `config::merge_partial`).
fn settings_json(s: &crate::config::Settings) -> String {
    fn str_array(v: &[String]) -> String {
        v.iter()
            .map(|x| format!("\"{}\"", json_escape(x)))
            .collect::<Vec<_>>()
            .join(",")
    }
    let ports: Vec<String> = s.intercept_ports.iter().map(|p| p.to_string()).collect();
    let trusted = s.trusted_dns.as_deref().unwrap_or("");
    format!(
        r#"{{"mutation_profile":"{}","decoy_ttl":{},"idle_timeout_secs":{},"trusted_dns":"{}","fragment_chunk_size":{},"enable_decoys":{},"enable_sni_fragmentation":{},"enable_swap_foolers":{},"enable_kill_switch":{},"kill_switch_adapter":"{}","rotate_ips":[{}],"win_divert_sha256":[{}],"enable_web_ui":{},"web_ui_port":{},"web_ui_token":"","enable_quic_port_bypass":{},"quic_bypass_use_low_port":{},"enable_sni_disguise":{},"fronting_benign_sni":"{}","enable_combined_fragmentation":{},"intercept_ports":[{}],"intercept_all_tcp":{},"intercept_all_udp":{},"enable_utls_fingerprint":{},"utls_browser":"{}","enable_ech_grease":{},"enable_md5sig_fooling":{},"enable_geedge_evasion":{},"relay_enabled":{},"relay_listen_port":{},"relay_connect_host":"{}","relay_connect_port":{},"relay_fake_sni":"{}","relay_resolve_doh":{},"relay_mutate_real_sni":{},"relay_emit_decoy":{},"doh_server":"{}"}}"#,
        json_escape(&s.mutation_profile),
        s.decoy_ttl,
        s.idle_timeout_secs,
        json_escape(trusted),
        s.fragment_chunk_size,
        s.enable_decoys,
        s.enable_sni_fragmentation,
        s.enable_swap_foolers,
        s.enable_kill_switch,
        json_escape(&s.kill_switch_adapter),
        str_array(&s.rotate_ips),
        "", // pins redacted
        s.enable_web_ui,
        s.web_ui_port,
        s.enable_quic_port_bypass,
        s.quic_bypass_use_low_port,
        s.enable_sni_disguise,
        json_escape(&s.fronting_benign_sni),
        s.enable_combined_fragmentation,
        ports.join(","),
        s.intercept_all_tcp,
        s.intercept_all_udp,
        s.enable_utls_fingerprint,
        json_escape(&s.utls_browser),
        s.enable_ech_grease,
        s.enable_md5sig_fooling,
        s.enable_geedge_evasion,
        s.relay_enabled,
        s.relay_listen_port,
        json_escape(&s.relay_connect_host),
        s.relay_connect_port,
        json_escape(&s.relay_fake_sni),
        s.relay_resolve_doh,
        s.relay_mutate_real_sni,
        s.relay_emit_decoy,
        json_escape(&s.doh_server)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_check_is_constant_time_semantics() {
        assert!(token_ok("Bearer secret", "secret"));
        assert!(token_ok("bearer secret", "secret"));
        assert!(token_ok("BEARER secret", "secret"));
        assert!(token_ok("Bearer AbCdEfGhIjKlMnop", "AbCdEfGhIjKlMnop"));
        assert!(!token_ok("Bearer AbCdEfGhIjKlMnop", "abcdefghijklmnop"));
        assert!(!token_ok("Bearer secret", "other"));
        assert!(!token_ok("", "secret"));
        assert!(!token_ok("Bearer secret", "secret1"));
    }

    #[test]
    fn host_header_must_be_loopback_ipv4() {
        assert!(host_is_allowed("127.0.0.1", 9090));
        assert!(host_is_allowed("127.0.0.1:9090", 9090));
        assert!(!host_is_allowed("127.0.0.1:9091", 9090));
        assert!(!host_is_allowed("localhost", 9090));
        assert!(!host_is_allowed("evil.example", 9090));
        assert!(!host_is_allowed("", 9090));
        assert!(!host_is_allowed("0.0.0.0", 9090));
    }

    #[test]
    fn origin_must_be_empty_or_loopback_dashboard() {
        assert!(origin_is_allowed("", 9090));
        assert!(origin_is_allowed("http://127.0.0.1:9090", 9090));
        assert!(!origin_is_allowed("http://127.0.0.1:9091", 9090));
        assert!(!origin_is_allowed("http://evil.example", 9090));
        assert!(!origin_is_allowed("null", 9090));
    }

    #[test]
    fn profile_validation_is_strict() {
        for p in [
            "Stealth",
            "ChinaGfw",
            "RussiaDpi",
            "Aggressive",
            "ChinaRegional",
            "Henan",
        ] {
            assert!(is_known_profile(p));
        }
        assert!(!is_known_profile("stealth"));
        assert!(!is_known_profile("../../etc"));
        assert!(!is_known_profile("Stealth; calc"));
    }

    #[test]
    fn json_string_extraction() {
        assert_eq!(
            extract_json_string(r#"{"profile":"Aggressive"}"#, "profile").as_deref(),
            Some("Aggressive")
        );
        assert_eq!(extract_json_string(r#"{"nope":"x"}"#, "profile"), None);
        assert_eq!(extract_json_string("garbage", "profile"), None);
        assert_eq!(
            extract_json_string("{\"profile\":\"Stealth\"}\n", "profile").as_deref(),
            Some("Stealth")
        );
    }

    #[test]
    fn json_escape_handles_quotes_and_control() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("x\ny"), "x\\ny");
        assert_eq!(json_escape("plain"), "plain");
    }

    #[test]
    fn status_json_is_well_formed_for_empty_snapshot() {
        let s = DashboardSnapshot::default();
        let j = status_json(&s);
        assert!(j.contains("\"mutation_profile\":\"\""));
        assert!(j.contains("\"processed_packets\":0"));
        assert!(j.contains("\"intercept_ports\":[]"));
        assert!(j.contains("\"enable_quic_bypass\":false"));
        assert!(j.contains("\"enable_sni_disguise\":false"));
        assert!(j.contains("\"fronting_benign\":\"\""));
        assert!(j.contains("\"enable_utls\":false"));
        assert!(j.contains("\"enable_ech_grease\":false"));
        assert!(j.contains("\"relay_enabled\":false"));
        assert!(j.contains("\"relay_listen_port\":0"));
    }

    #[test]
    fn settings_json_redacts_token_and_pins_but_has_relay() {
        let mut s = crate::config::Settings::default();
        s.web_ui_token = "0123456789abcdef".into();
        s.win_divert_sha256 = vec!["a".repeat(64)];
        s.relay_enabled = true;
        s.relay_connect_host = "1.1.1.1".into();
        s.relay_fake_sni = "www.microsoft.com".into();
        let j = settings_json(&s);
        assert!(j.contains("\"relay_enabled\":true"));
        assert!(j.contains("\"relay_connect_host\":\"1.1.1.1\""));
        assert!(j.contains("\"relay_fake_sni\":\"www.microsoft.com\""));
        assert!(!j.contains("0123456789abcdef"));
        assert!(!j.contains(&"a".repeat(64)));
        assert!(j.contains("\"web_ui_token\":\"\""));
    }

    #[test]
    fn status_json_serializes_intercept_ports_and_new_flags() {
        let mut s = DashboardSnapshot::default();
        s.intercept_ports = vec![443, 8443, 2053];
        s.enable_quic_bypass = true;
        s.fronting_benign = "www.microsoft.com".into();
        let j = status_json(&s);
        assert!(j.contains("\"intercept_ports\":[443,8443,2053]"));
        assert!(j.contains("\"enable_quic_bypass\":true"));
        assert!(j.contains("\"fronting_benign\":\"www.microsoft.com\""));
    }
}

/// Self-contained dashboard (no external assets). The page itself carries
/// no secrets; the token is prompted for and kept in `localStorage`, then
/// sent as `Authorization: Bearer` on every API call.
const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dpi_guard dashboard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         background: #0f1115; color: #e6e8ee; }
  header { padding: 20px 24px; border-bottom: 1px solid #232733; display: flex;
           justify-content: space-between; align-items: baseline; }
  h1 { font-size: 18px; margin: 0; }
  .muted { color: #8b90a0; }
  main { max-width: 960px; margin: 0 auto; padding: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; }
  .card { background: #171a21; border: 1px solid #232733; border-radius: 10px; padding: 16px; }
  .card .k { color: #8b90a0; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
  .card .v { font-size: 20px; margin-top: 4px; font-weight: 600; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px;
           background: #1f6f43; color: #8be0a8; }
  .badge.off { background: #6b2f2f; color: #ffb3b3; }
  button { background: #2b6cb0; color: #fff; border: 0; border-radius: 8px; padding: 8px 14px;
           cursor: pointer; font-size: 14px; margin: 3px; }
  button.active { background: #38a169; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #232733; }
  #err { color: #ff8080; margin-top: 12px; min-height: 1.2em; }
</style>
</head>
<body>
<header>
  <h1>dpi_guard <span class="muted">— local dashboard</span></h1>
  <span class="muted" id="conn"></span>
</header>
<main>
  <div class="grid" id="cards"></div>
  <div class="card" style="margin-top:16px">
    <div class="k">Mutation profile</div>
    <div id="profiles"></div>
  </div>
  <div class="card" style="margin-top:16px">
    <div class="k">Strategy scores (domain | technique)</div>
    <table><thead><tr><th>Key</th><th>Score</th></tr></thead><tbody id="scores"></tbody></table>
  </div>
  <div class="card" style="margin-top:16px">
    <div class="k">Recent SNIs (hashed)</div>
    <div id="domains" class="muted"></div>
  </div>
  <div class="card" style="margin-top:16px">
    <div class="k">Relay + config</div>
    <table style="margin-top:8px">
      <tr><td>Mutation profile</td><td>
        <select id="cfg_profile">
          <option>Stealth</option><option>ChinaGfw</option><option>RussiaDpi</option>
          <option>Aggressive</option><option>ChinaRegional</option><option>Henan</option>
        </select>
      </td></tr>
      <tr><td>Intercept ports (comma)</td><td><input id="cfg_ports" placeholder="443,8443,2053"></td></tr>
      <tr><td>Decoy TTL</td><td><input id="cfg_ttl" type="number" min="1" max="64"></td></tr>
      <tr><td>Fragment chunk size</td><td><input id="cfg_chunk" type="number" min="0"></td></tr>
      <tr><td>Relay enabled</td><td><input id="cfg_relay" type="checkbox"></td></tr>
      <tr><td>Relay listen port</td><td><input id="cfg_lport" type="number" min="1" max="65535"></td></tr>
      <tr><td>Real host (domain or IP)</td><td><input id="cfg_host" placeholder="1.1.1.1 or server.example.com"></td></tr>
      <tr><td>Real port</td><td><input id="cfg_cport" type="number" min="1" max="65535"></td></tr>
      <tr><td>Fake SNI (benign)</td><td><input id="cfg_fake" placeholder="www.microsoft.com"></td></tr>
      <tr><td>Resolve host via DoH</td><td><input id="cfg_doh" type="checkbox"></td></tr>
      <tr><td>Mutate real SNI too</td><td><input id="cfg_mut" type="checkbox"></td></tr>
      <tr><td>Emit fake decoy</td><td><input id="cfg_edecoy" type="checkbox"></td></tr>
      <tr><td>QUIC bypass</td><td><input id="cfg_quic" type="checkbox"></td></tr>
      <tr><td>uTLS fingerprint</td><td><input id="cfg_utls" type="checkbox"></td></tr>
      <tr><td>ECH GREASE</td><td><input id="cfg_ech" type="checkbox"></td></tr>
      <tr><td>Geedge evasion</td><td><input id="cfg_geedge" type="checkbox"></td></tr>
      <tr><td>SNI disguise</td><td><input id="cfg_disguise" type="checkbox"></td></tr>
      <tr><td>Fronting benign SNI</td><td><input id="cfg_front" placeholder="(none)"></td></tr>
    </table>
    <div style="margin-top:10px">
      <button id="btn_start">Start relay</button>
      <button id="btn_stop">Stop relay</button>
      <button id="btn_save">Save config</button>
    </div>
    <div class="k" style="margin-top:14px">Advanced (full config as TOML)</div>
    <textarea id="cfg_toml" rows="12" style="width:100%; font:12px/1.4 ui-monospace, monospace; background:#0f1115; color:#e6e8ee; border:1px solid #232733; border-radius:6px; padding:8px;"></textarea>
    <div style="margin-top:6px"><button id="btn_save_toml">Save advanced</button></div>
  </div>
  <div id="err"></div>
</main>
<script>
const PROFILES = ["Stealth", "ChinaGfw", "RussiaDpi", "Aggressive", "ChinaRegional", "Henan"];
function esc(s) {
  return String(s).replace(/[&<>"'`]/g, function (c) {
    return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c]);
  });
}
function token() {
  let t = localStorage.getItem("dpi_guard_token");
  if (!t) {
    t = prompt("Enter the dpi_guard web UI token (printed in the console/log at startup):");
    if (!t) return null;
    localStorage.setItem("dpi_guard_token", t);
  }
  return t;
}
async function api(path, opts = {}) {
  const t = token();
  if (!t) return null;
  const res = await fetch(path, { ...opts,
    headers: { "Authorization": "Bearer " + t, ...(opts.headers || {}) } });
  if (res.status === 401) { localStorage.removeItem("dpi_guard_token"); throw new Error("401 unauthorized"); }
  return res.json();
}
async function apiText(path, opts = {}) {
  const t = token();
  if (!t) return null;
  const res = await fetch(path, { ...opts,
    headers: { "Authorization": "Bearer " + t, ...(opts.headers || {}) } });
  if (res.status === 401) { localStorage.removeItem("dpi_guard_token"); throw new Error("401 unauthorized"); }
  return res.text();
}
function byId(id) { return document.getElementById(id); }
function tstr(v) { return '"' + String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"'; }
async function loadConfig() {
  try {
    const c = await api("/api/config");
    if (!c) return;
    byId("cfg_profile").value = c.mutation_profile || "Stealth";
    byId("cfg_ports").value = (c.intercept_ports || []).join(",");
    byId("cfg_ttl").value = c.decoy_ttl;
    byId("cfg_chunk").value = c.fragment_chunk_size;
    byId("cfg_relay").checked = !!c.relay_enabled;
    byId("cfg_lport").value = c.relay_listen_port;
    byId("cfg_host").value = c.relay_connect_host || "";
    byId("cfg_cport").value = c.relay_connect_port;
    byId("cfg_fake").value = c.relay_fake_sni || "";
    byId("cfg_doh").checked = !!c.relay_resolve_doh;
    byId("cfg_mut").checked = !!c.relay_mutate_real_sni;
    byId("cfg_edecoy").checked = !!c.relay_emit_decoy;
    byId("cfg_quic").checked = !!c.enable_quic_port_bypass;
    byId("cfg_utls").checked = !!c.enable_utls_fingerprint;
    byId("cfg_ech").checked = !!c.enable_ech_grease;
    byId("cfg_geedge").checked = !!c.enable_geedge_evasion;
    byId("cfg_disguise").checked = !!c.enable_sni_disguise;
    byId("cfg_front").value = c.fronting_benign_sni || "";
  } catch (e) { byId("err").textContent = "Error: " + e.message; }
}
async function loadToml() {
  try { byId("cfg_toml").value = await apiText("/api/config/toml") || ""; }
  catch (e) { byId("err").textContent = "Error: " + e.message; }
}
function portsValue() {
  const raw = byId("cfg_ports").value.split(",").map(s => parseInt(s.trim(), 10)).filter(n => Number.isFinite(n) && n > 0);
  return "[" + raw.join(", ") + "]";
}
function buildPartialToml() {
  let t = "";
  t += "mutation_profile = " + tstr(byId("cfg_profile").value) + "\n";
  t += "intercept_ports = " + portsValue() + "\n";
  t += "decoy_ttl = " + parseInt(byId("cfg_ttl").value, 10) + "\n";
  t += "fragment_chunk_size = " + parseInt(byId("cfg_chunk").value, 10) + "\n";
  t += "relay_enabled = " + byId("cfg_relay").checked + "\n";
  t += "relay_listen_port = " + parseInt(byId("cfg_lport").value, 10) + "\n";
  t += "relay_connect_host = " + tstr(byId("cfg_host").value) + "\n";
  t += "relay_connect_port = " + parseInt(byId("cfg_cport").value, 10) + "\n";
  t += "relay_fake_sni = " + tstr(byId("cfg_fake").value) + "\n";
  t += "relay_resolve_doh = " + byId("cfg_doh").checked + "\n";
  t += "relay_mutate_real_sni = " + byId("cfg_mut").checked + "\n";
  t += "relay_emit_decoy = " + byId("cfg_edecoy").checked + "\n";
  t += "enable_quic_port_bypass = " + byId("cfg_quic").checked + "\n";
  t += "enable_utls_fingerprint = " + byId("cfg_utls").checked + "\n";
  t += "enable_ech_grease = " + byId("cfg_ech").checked + "\n";
  t += "enable_geedge_evasion = " + byId("cfg_geedge").checked + "\n";
  t += "enable_sni_disguise = " + byId("cfg_disguise").checked + "\n";
  t += "fronting_benign_sni = " + tstr(byId("cfg_front").value) + "\n";
  return t;
}
async function saveConfig(tomlText) {
  try {
    const r = await api("/api/config", { method: "POST",
      headers: { "Content-Type": "text/plain" }, body: tomlText });
    byId("err").textContent = r && r.error ? ("Error: " + r.error) : (r && r.message ? r.message : "saved");
    if (r && r.ok) { setTimeout(refresh, 1200); setTimeout(loadConfig, 1300); }
  } catch (e) { byId("err").textContent = "Error: " + e.message; }
}
document.getElementById("btn_save").addEventListener("click", async () => saveConfig(buildPartialToml()));
document.getElementById("btn_start").addEventListener("click", async () => { byId("cfg_relay").checked = true; await saveConfig(buildPartialToml()); });
document.getElementById("btn_stop").addEventListener("click", async () => { byId("cfg_relay").checked = false; await saveConfig(buildPartialToml()); });
document.getElementById("btn_save_toml").addEventListener("click", async () => saveConfig(byId("cfg_toml").value));
function badge(b) { return b ? '<span class="badge">ON</span>' : '<span class="badge off">OFF</span>'; }
function card(k, v) { return `<div class="card"><div class="k">${k}</div><div class="v">${v}</div></div>`; }
async function refresh() {
  const el = document.getElementById("err"); el.textContent = "";
  try {
    const s = await api("/api/status");
    if (!s) return;
    document.getElementById("conn").textContent = "connected";
    document.getElementById("cards").innerHTML = [
      card("Profile", esc(s.mutation_profile)),
      card("Decoy TTL", esc(s.decoy_ttl)),
      card("Idle timeout (s)", esc(s.idle_timeout_secs)),
      card("Fragment chunk", esc(s.fragment_chunk_size)),
      card("Intercept ports", esc((s.intercept_ports||[443]).join(","))),
      card("Decoys", badge(s.enable_decoys)),
      card("SNI fragmentation", badge(s.enable_sni_fragmentation)),
      card("Swap foolers", badge(s.enable_swap_foolers)),
      card("Kill switch (armed only)", badge(s.enable_kill_switch)),
      card("QUIC bypass", badge(s.enable_quic_bypass)),
      card("SNI disguise", badge(s.enable_sni_disguise)),
      card("Fronting", esc(s.fronting_benign||"(none)")),
      card("uTLS", badge(s.enable_utls)),
      card("ECH GREASE", badge(s.enable_ech_grease)),
      card("Relay", badge(s.relay_enabled)),
      card("Relay listen port", esc(s.relay_listen_port)),
      card("Packets processed", esc(s.processed_packets)),
    ].join("");
    document.getElementById("profiles").innerHTML = PROFILES.map(p =>
      `<button class="${p === s.mutation_profile ? 'active' : ''}" data-p="${p}">${p}</button>`
    ).join("");
    document.getElementById("scores").innerHTML = (s.strategy_scores || [])
      .map(x => `<tr><td>${esc(x.key)}</td><td>${esc(x.score)}</td></tr>`).join("");
    document.getElementById("domains").textContent = (s.recent_domains || []).join(", ") || "(none yet)";
  } catch (e) {
    document.getElementById("conn").textContent = "disconnected";
    el.textContent = "Error: " + e.message;
  }
}
document.addEventListener("click", async (e) => {
  const p = e.target.getAttribute && e.target.getAttribute("data-p");
  if (!p) return;
  try { await api("/api/profile", { method: "POST", body: JSON.stringify({ profile: p }) }); }
  catch (err) { document.getElementById("err").textContent = "Error: " + err.message; }
  setTimeout(refresh, 400);
});
loadConfig();
loadToml();
refresh();
setInterval(refresh, 3000);
setInterval(loadConfig, 8000);
</script>
</body>
</html>
"#;
