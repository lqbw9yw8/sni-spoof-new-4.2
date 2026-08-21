# dpi_guard (Rust)

Modular DPI-evasion engine. Crate name: `dpi_guard` (GitHub repo:
`sni-spoof-new-`). Windows-only for packet capture/injection (WinDivert);
every pure-logic module builds and tests on Linux/macOS/CI.

This crate is standalone. It does not include a Python engine or Node
control panel.

## Status: read this before deploying

This is a first pass, not a finished, field-tested tool. Two tiers:

- **[DONE]** — implemented and covered by unit tests (`cargo test` on any OS).
- **[STUB]** — compiles, returns a typed `PlatformNotSupported` / `Driver`
  error. Remaining stubs: WFP FFI (`FwpmEngineOpen0` / `FwpmFilterAdd0`),
  the signed WFP callout driver for DNS redirect, and auto-spawning the
  kill-switch process (command is built and sanitised, never executed).

`engine.rs` is written against the published `windivert` 0.5.5 API
(`WinDivert::network`, `recv(Some(&mut buf))`, `send`, `shutdown`,
`close`) but has **not** been compiled on a Windows host in this
environment. Before a real network path: `cargo build --release --target
x86_64-pc-windows-msvc`, place official `WinDivert.dll` +
`WinDivert64.sys` next to the binary (never commit them), run as
Administrator.

## Why this should not destabilize Windows

- **Fail-open on every packet.** `fail_open::handle_exception_fail_open`
  wraps every mutation in `catch_unwind`. Panic *or* `Err` re-injects the
  original packet. The fallback is logged.
- **Filter.** `!loopback and ((tcp and (tcp.DstPort == 443 or tcp.SrcPort == 443)) or (udp and (udp.DstPort == 443 or udp.SrcPort == 443)))`.
  UDP/443 is diverted and passed through unmodified (live QUIC is not
  corrupted). Inbound TCP/443 is diverted so RSTs can update strategy
  scores, then passed through. "All ports" mode (`intercept_all_tcp` /
  `intercept_all_udp`) always excludes SSH (22), DNS (53) and RDP (3389)
  (`NEVER_INTERCEPT_PORTS`), so the wildcard can never cut the operator's
  own remote access or plaintext DNS.
- **Hot-reload filter.** When `intercept_ports` / `intercept_all_*` change
  in `dpi_guard.toml`, the watcher requests a WinDivert filter reload: the
  capture loop closes the old handle and reopens with the new filter
  (`engine::request_filter_reload`).
- **Dynamic WFP session spec.** If/when WFP FFI is wired,
  `dns_guard::init_wfp_hook_spec` requests a *dynamic* session.
- **Graceful shutdown.** Ctrl+C (`tokio::signal`) sets a flag and calls
  `WinDivertShutdown`, which unblocks `recv` so diversion does not sit on
  the NIC until the next packet.
- **One capture handle.** Extra injects use a send-only handle with
  filter `false`, so they do not steal packets from capture. Decoys
  produced by the pipeline are sent on the capture handle with the
  original WinDivert address.
- **Outbound decoys** use this host's existing 5-tuple and a TTL low
  enough to die before the real server. Endpoint-swap SYN-ACK/RST
  foolers are off unless `enable_swap_foolers = true`.

None of this makes kernel-level packet interception risk-free. Test on a
VM first. Tune `decoy_ttl` by measuring hops to the DPI box.

## Build & Dev

```bash
# pure-logic modules — any OS, no WinDivert needed
# RUST_LOG=dpi_guard=debug cargo test
cargo test

# formatting + lint (rust-toolchain.toml requires stable + clippy + rustfmt)
cargo fmt --check
cargo clippy -- -D warnings

# the real binary — Windows only
cargo build --release --target x86_64-pc-windows-msvc
```

### What still needs a real Windows host

`engine.rs` was written against the published `windivert` 0.5.5 docs and type
signatures but has NOT been field-tested in this sandbox (no Windows, no driver):
- `WinDivert::network`, `recv(Some(&mut buf))`, `send`, `shutdown`, `close`
- TTL-limited decoys actually reaching DPI but expiring before origin
- `take_expired_held` watchdog (200ms) re-injecting with original WinDivert address
- graceful shutdown unblocking `recv`

To test: Windows 10/11 VM, Administrator, official WinDivert dll/sys from
reqrypt.org next to exe, `RUST_LOG=dpi_guard=debug`, measure `decoy_ttl`
by `tracert -d 1.1.1.1` and set to hops-to-DPI.

Hold/reassembly integration tests are now covered in `pipeline.rs`:
`expired_held_is_flushed_by_watchdog`, `max_flows_cap_fail_opens`,
`flow_buf_overflow_fail_opens_both`, `recent_eviction_halves_on_cap`,
`idle_flush_removes_old_flows_and_recent`.

Copy `dpi_guard.toml.example` to `dpi_guard.toml` next to the binary and
edit it. Run as Administrator. Place `WinDivert.dll`/`WinDivert64.sys`
next to the binary — **do not commit those binaries**; `.gitignore`
excludes `*.dll` / `*.sys`. Fetch WinDivert from its official release:
https://reqrypt.org/windivert.html and https://github.com/basil00/Divert/releases

Pin the driver hashes (supply-chain protection):
```powershell
# Windows PowerShell - after downloading official WinDivert zip
certutil -hashfile WinDivert.dll SHA256
certutil -hashfile WinDivert64.sys SHA256
# paste the two hex strings into win_divert_sha256 in dpi_guard.toml
```
```bash
# Linux verify (if you check the zip on Linux first)
sha256sum WinDivert.dll WinDivert64.sys
```

## DNS leak warning (important)

SNI mutation alone does **NOT** hide which domain you visit — the OS still
sends a plaintext DNS query on UDP/53 that a local observer / DPI box can log.
`dns_guard` in this crate currently only builds the WFP **specs** (allow
127.0.0.1:53 + block :53); real WFP FFI that would actually block port 53
needs a signed callout driver and is intentionally STUB.

**What to do instead:**
- Windows 11: Settings → Network → DNS → enable DNS over HTTPS (DoH) to
  `1.1.1.1` / `8.8.8.8` / `9.9.9.9` with template `https://cloudflare-dns.com/dns-query`
- Windows 10: use [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) or
  [AdGuard](https://adguard.com/) or YogaDNS with DoH/DoT upstream
- Verify: https://www.cloudflare.com/ssl/encrypted-sni/ and `https://1.1.1.1/help`
  should show "Using DNS over HTTPS (DoH) - Yes"
- `trusted_dns` in `dpi_guard.toml` is only a *documented target* for future
  hijack specs; it does NOT enable DoH by itself.

If you keep plain UDP/53, DPI sees the domain even if SNI is mutated.

## Security note

An earlier sibling codebase (not in this repo) was flagged for binding a
proxy to `0.0.0.0`, a control-panel API without auth/CSRF, and committing
pre-built WinDivert binaries. This crate:

- has **no** network-facing listen socket. The optional dashboard
  (`enable_web_ui = true`) binds `127.0.0.1` only, requires
  `Host: 127.0.0.1` (DNS-rebind names and `localhost` are rejected),
  checks `Origin` on browser fetches, and requires a bearer token on
  every API call; it is OFF by default. Tokens in logs/`Debug` are
  redacted except the one-time auto-generated print.
- gitignores `*.dll` / `*.sys` / `dpi_guard.toml`
- `version_check` searches **only the executable directory** (never cwd)
  and refuses to start if the driver files are missing. When
  `win_divert_sha256` pins are configured, every driver binary is
  SHA-256 compared in constant time against the pin list; files over
  16 MiB are refused.
- a missing default `dpi_guard.toml` uses compiled defaults; an
  **invalid or explicitly-passed missing** config file is fail-closed
  (process exits). Unknown TOML keys are rejected.
- kill-switch adapter names are restricted to `[A-Za-z0-9 _-]+` and the
  process is never spawned unless you add that yourself with
  `enable_kill_switch` (even then only the command string is logged)
- fail-open: panics, parse errors, and held ClientHello fragments that
  time out are re-injected unmodified. Mutex poisoning does not take
  the packet path down.

## Optional local dashboard

Set `enable_web_ui = true` (and optionally `web_ui_port`, `web_ui_token`)
in `dpi_guard.toml`. The dashboard serves at `http://127.0.0.1:9090`
(**not** `http://localhost:9090` — the `Host` header must be loopback
IPv4) and shows live settings, packet count, hashed per-domain strategy
scores, and hashed recent SNIs. Every `/api/*` route requires the bearer
token; leave `web_ui_token` empty to auto-generate one (printed to the
log). A configured token must be at least 16 printable ASCII characters.
The only mutation is selecting a mutation profile, which reuses the same
validated parse path as the TOML config.

## Module map (2025-2026 upgrades)

| File | Role | Status |
|---|---|---|
| `sni_mutations.rs` | 12+ SNI mutations + 6 profiles (Stealth, ChinaGfw, RussiaDpi, Aggressive, ChinaRegional, Henan) + SNI disguise GREASE/private | DONE |
| `fragmentation.rs` | TLS parse, SNI splice + length rewrite, TCP-level split + **disguise_sni_extension_type**, **front_sni_with_benign**, **inject_hidden_sni_in_unknown_ext** | DONE + NEW |
| `packet.rs` | IPv4/IPv6 + TCP/UDP parse, checksums, segmentation, l3_slice | DONE |
| `quic.rs` | **NEW**: QUIC Initial detection, port blindspot (src<=dst bypass per USENIX 2025), UDP src rewrite, decoy, QuicPortMapper | DONE + NEW |
| `pipeline.rs` | live packet processor + QUIC bypass + SNI fronting/disguise + combined TCP+TLS frag for Henan | DONE + ENHANCED |
| `fail_open.rs` | panic/Err → original packet | DONE |
| `sequence.rs` | decoy / SEQ / TTL | DONE |
| `fooling.rs` | checksum/RST/SYN-ACK/disorder/UDP-len builders | DONE |
| `strategy.rs` | per-domain scoring, A/B block-type | DONE |
| `stealth.rs` | jitter, options, GREASE, hash, kill-switch string | PARTIAL |
| `connection.rs` | health, IP rotate, LRU tickets, backoff | DONE |
| `dns_guard.rs` | WFP specs | spec DONE, FFI STUB |
| `engine.rs` | WinDivert I/O | written to 0.5.5 API, unverified on Windows |
| `engine_stub.rs` | same signatures, PlatformNotSupported | DONE |
| `config.rs` | TOML + validated fields + hot reload + new QUIC/fronting options | DONE + ENHANCED |
| `integrity.rs` | SHA-256 pin compare (constant-time) | DONE |
| `webui.rs` | opt-in 127.0.0.1 dashboard + 6 profiles | DONE + ENHANCED |
| `error.rs` | crate error type | DONE |

### New profiles (2025 research)

- **ChinaGfw**: case randomization + 64-byte TCP frag + QUIC port bypass if enabled. Classic GFW.
- **ChinaRegional / Henan**: case + trailing dot, 32/24-byte chunks, disorder_mode always ON, combined TCP+TLS fragmentation (persistent_fragmentation 16), TTL decoys. Targets Henan Firewall stateless parsing bug (IEEE S&P 2025).
- **Stealth**: minimal, identity-preserving.
- **Aggressive**: null-byte, explode, underscore, dots, overflow, port suffix + optional SNI disguise + fronting.

### QUIC blindspot (USENIX 2025 #1)

GFW inspects QUIC Initial only when `src_port > dst_port`. Setting `src_port <= dst_port` (e.g., 443->443) bypasses completely. This crate implements:

```rust
quic::is_quic_initial(payload) -> bool
quic::gfw_would_inspect_quic(src, dst) -> bool // src > dst
quic::choose_bypass_source_port(dst) -> u16 // dst itself (equal)
quic::rewrite_udp_src_port(packet, new_sport)
```

Enable via `enable_quic_port_bypass = true` in config. WinDivert can spoof any
src port even privileged. The pipeline now tracks every spoofed flow in
`quic::QuicPortMapper` and rewrites the whole flow, not just the Initial:
outbound packets keep the spoofed source port, and inbound replies to the
spoofed port are rewritten back to the client's original source port
(`quic::rewrite_udp_dst_port`). The blindspot rule applies to any intercepted
UDP port, not just 443. Mappings are capped (`quic::MAX_QUIC_MAPS`) and pruned
on idle.

## Relay mode (patterniha-style, opt-in)

In addition to the transparent SNI-mutation mode, the crate can run as a
**local TCP relay** like `patterniha/SNI-Spoofing`:

1. `dpi_guard` binds `127.0.0.1:<relay_listen_port>`.
2. You point v2rayN at `127.0.0.1:<relay_listen_port>` with the real server
   domain as SNI.
3. For each connection the relay connects to the fixed destination
   `relay_connect_host:relay_connect_port` and injects a fake ClientHello
   carrying `relay_fake_sni` (a benign domain) with a wrong sequence number,
   so a stateless DPI whitelists the flow on the benign SNI while the real
   server drops the fake.

Safety properties (differences from the reference implementation):

- The listener binds **127.0.0.1 only** (never `0.0.0.0`).
- The destination is **fixed** (`relay_connect_host`), so the relay can never
  be used as an open proxy by third parties.
- Domain resolution is **DoH-only** (`relay_resolve_doh`); there is no
  plaintext-DNS fallback. Configuring `relay_connect_host` as an IP literal
  skips DNS entirely (zero leak).

> **DNS / IP leak notes:** (1) use an IP literal for `relay_connect_host` or
> keep `relay_resolve_doh = true`; (2) the injected fake uses the real
> connection's IP — this is SNI spoofing, not IP hiding; the DPI still sees
> the destination IP. Hiding the destination IP is a different technique
> (e.g. VLESS Reality) and out of scope here. (3) For zero DNS leakage, point
> `doh_server` at an IP-literal endpoint (`https://1.1.1.1/dns-query`), since
> the DoH endpoint's own hostname is otherwise resolved by the system resolver
> first (that leaks only the endpoint name, not your target domain).

Extra relay toggles (defense-in-depth, both off by default):

- `relay_mutate_real_sni = true` — after the fake handshake completes, the
  flow's *real* ClientHello is also run through the normal SNI-mutation
  pipeline.
- `relay_emit_decoy = true` — at injection time, an extra TTL-limited
  wrong-checksum decoy of the fake ClientHello is also emitted.

### Dashboard config editing & Start/Stop

With `enable_web_ui = true`, the dashboard (`http://127.0.0.1:9090`) has a
"Relay + config" card that edits the key settings, a full TOML editor for
everything else, and **Start relay** / **Stop relay** / **Save config**
buttons. Save writes `dpi_guard.toml` through the exact same validated parse
path as the file itself (`config::merge_partial`), and the running relay is
restarted automatically when the relay settings change — no process restart
needed. The web-UI bearer token and driver pins are never echoed back by the
config API.

### uTLS fingerprint rotation (passive rewriter)

`utls::apply_fingerprint_to_hello` rotates the JA3/JA4 fingerprint in place:
cipher suites (TLS 1.3 kept at the front), `supported_groups`,
`signature_algorithms` and `ec_point_formats` are all reordered while
preserving each list's multiset and the wire length. This is the correct
scope for a packet rewriter — the `key_share` and ALPN are deliberately not
regenerated, because a MITM that swaps in a fresh key share produces a
ClientHello the client's own stack cannot complete. Enable via
`enable_utls_fingerprint = true`.

### SNI disguise as unknown extension (#54)

Instead of deleting SNI, change its extension type 0x0000 -> 0x0A0A (GREASE) or 0xFF01 (private). Naive DPI that looks for 0x0000 misses it; server per RFC 8446 should ignore unknown extensions (but loses vhost routing, serves default cert). Use with fronting:

```
visible SNI = www.microsoft.com (benign)
hidden real = example.com in extension 0xFF01
```

Implemented as `fragmentation::disguise_sni_extension_type` and `inject_hidden_sni_in_unknown_ext`. Enable via `enable_sni_disguise` + `fronting_benign_sni`.

### Combined TCP+TLS fragmentation (Henan)

Regional firewalls like Henan are stateless and fail when BOTH layers are fragmented simultaneously. Pipeline now:

- effective_chunk = min(config, profile.recommended_fragment_size())
- disorder_mode always ON for Henan/ChinaRegional
- if Henan + combined enabled: TCP segments are further split via `persistent_fragmentation(..., 16)` simulating TLS-level fragmentation inside TCP segmentation.

Config: `enable_combined_fragmentation = true` (default ON).

## License

MIT. See `LICENSE`.
