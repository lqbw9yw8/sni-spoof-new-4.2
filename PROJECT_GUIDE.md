# PROJECT_GUIDE — dpi_guard / sni-spoof-new-4.2

**Single source of truth for a new chat, a new machine, or a new contributor.**
Read this file first, then `README.md`, `IMPLEMENTATION_STATUS.md`,
`SECURITY_REVIEW_FIXES.md`, `REVIEW_2026_STRICT.md`.

| | |
|---|---|
| GitHub | https://github.com/lqbw9yw8/sni-spoof-new-4.2 |
| Branch this session tracks | `arena/01a02428-sni-spoof-new-4-2` |
| Default branch | `main` |
| Base snapshot | `2bd5cca` — “Add files via upload” |
| Crate / binary | `dpi_guard` 0.1.0, edition 2021, MIT |
| Language | Rust. Packet I/O is Windows + WinDivert only. Pure-logic modules test on any OS. |
| Toolchain | `rust-toolchain.toml` → `stable` + `rustfmt` + `clippy` |
| Date of this guide | 2026-08-21 |

This crate is a **user-mode DPI-evasion engine**: it mutates / disguises TLS
SNI (and related handshake bytes) and, optionally, runs a **loopback TCP
relay** that injects a fake ClientHello with a wrong TCP sequence number
(patterniha-style). It is **not** a VPN, **not** an open proxy, and **does
not hide the destination IP**. Dual-use: the operator is responsible for
local law.

Sibling lineage (not this repo): `sni-spoof-new-2`, `sin-new-4`
(`arena/01a021cd-sin-new-4`), `sin-4.1` (`arena/01a023bf-sin-4-1`). This
repository is a fresh GitHub upload of that work as a single commit.

---

## 0. Paste this into a new chat

> I am working on `lqbw9yw8/sni-spoof-new-4.2`, branch
> `arena/01a02428-sni-spoof-new-4-2`. Crate name `dpi_guard`. It is a Rust
> DPI-evasion engine: transparent SNI mutation via WinDivert on Windows,
> plus an opt-in patterniha-style local relay (loopback listener + DoH +
> fake ClientHello with `wrong_seq`).
>
> **Read first:** `PROJECT_GUIDE.md`, then `README.md`,
> `IMPLEMENTATION_STATUS.md`, `dpi_guard.toml.example`.
>
> Hygiene just applied on this branch: `.gitignore` exists; `WinDivert.dll`
> / `WinDivert64.sys` are **not** tracked. Fetch the official WinDivert
> 2.2.2-A zip yourself.
>
> **Not done on a real host:** `cargo test` / `cargo build --release
> --target x86_64-pc-windows-msvc` (this sandbox has no Rust toolchain and
> previous sandboxes blocked crates.io). Compile/test first, then Windows
> VM field tests (Admin + official driver + Wireshark).
>
> Honest limits: WFP FFI is STUB (port 53 still leaks unless the OS uses
> DoH/DoT or you use an IP literal); ECH is GREASE-only (no HPKE);
> destination IP is never hidden; relay injection timing is untested on a
> real NIC.

Persian short form:

> روی `lqbw9yw8/sni-spoof-new-4.2` شاخه `arena/01a02428-sni-spoof-new-4-2`
> کار می‌کنم. اول `PROJECT_GUIDE.md` را بخوان. موتور Rust به نام
> `dpi_guard` است (WinDivert + رلهٔ patterniha). هنوز روی ماشین واقعی
> `cargo test/build` نشده. WFP استاب است؛ IP مقصد مخفی نمی‌شود.

---

## 1. What this crate actually does

Two **opt-in** operating modes share one pipeline.

### Mode A — transparent (default)

WinDivert diverts matching TCP/UDP packets. For outbound TLS ClientHello
on an intercepted port the pipeline may:

1. Reassemble a multi-segment hello (hold ≤ 200 ms).
2. Mutate the SNI string per profile (`sni_mutations`).
3. Optionally front with a benign SNI and/or disguise ext type 0x0000 as
   GREASE / private.
4. Optionally inject ECH GREASE, uTLS reorder, Geedge padding.
5. Rebuild TCP payload, fix checksums, optionally TCP-segment (and for
   Henan, further TLS-level 16-byte fragments) with disorder.
6. Optionally prepend a TTL-limited wrong-checksum decoy.
7. Score the technique on inbound RST vs ServerHello.

UDP/QUIC: if `enable_quic_port_bypass`, rewrite source port so
`src ≤ dst` (GFW QUIC SNI blindspot, USENIX Security 2025) and reverse-NAT
the reply.

### Mode B — relay (patterniha-style, `relay_enabled = true`)

1. Bind **`127.0.0.1:<relay_listen_port>`** (never `0.0.0.0`).
2. Destination is a **single fixed** `relay_connect_host:relay_connect_port`
   (cannot become an open proxy).
3. Resolve the host via **DoH only** (`doh.rs`, no plaintext fallback).
   An IP literal skips DNS entirely.
4. Bind the outbound socket *before* connect so the 4-tuple is known.
5. Register the flow in `Pipeline`. The capture path watches the 3-way
   handshake (`relay::HandshakeMonitor`).
6. After the client’s final ACK, inject a fake ClientHello carrying
   `relay_fake_sni` with TCP SEQ = `syn_seq + 1 − len` so a real stack
   treats it as already-received (dup-ACK + drop) while a **stateless**
   DPI still parses the TLS record.
7. Gate the relay (3 s timeout, then fail-open) and splice the two
   TCP streams.

v2rayN (or any local TLS client) connects to `127.0.0.1:listen` with the
**real** server name as SNI — **not** `relay_fake_sni`.

---

## 2. Repository layout

```
sni-spoof-new-4.2/
├── Cargo.toml / Cargo.lock
├── rust-toolchain.toml          # stable + rustfmt + clippy
├── dpi_guard.toml.example       # copy to dpi_guard.toml next to the exe
├── LICENSE                      # MIT
├── README.md
├── IMPLEMENTATION_STATUS.md     # checklist vs original plan
├── SECURITY_REVIEW_FIXES.md     # 16 security items + sources
├── REVIEW_2026_STRICT.md        # scored 92/100 (Persian); refers to an older sibling branch
├── PROJECT_GUIDE.md             # this file
├── .gitignore
└── src/
    ├── lib.rs          crate root, build_filter, recover_mutex
    ├── main.rs         Windows binary; RelayRuntime; capture + watchdog + webui
    ├── config.rs       TOML Settings, validate, merge_partial, hot-reload
    ├── error.rs        DpiGuardError
    ├── engine.rs       WinDivert I/O  [cfg(windows)]  — written, not field-tested
    ├── engine_stub.rs  same signatures, PlatformNotSupported
    ├── pipeline.rs     live packet processor (largest module, ~32 tests)
    ├── packet.rs       IPv4/IPv6 + TCP/UDP parse, checksums, rebuild, segment
    ├── fragmentation.rs TLS ClientHello parse/splice/disguise/front/fragment
    ├── sni_mutations.rs 12 string mutations + 6 profiles
    ├── sequence.rs     wrong SEQ, TTL decoy, 50 µs gap
    ├── fooling.rs      wrong checksum, MD5SIG, RST/SYN-ACK, disorder, reverse
    ├── strategy.rs     per-domain scores, A/B block-type
    ├── stealth.rs      jitter, GREASE, hash+salt, kill-switch string (never spawned)
    ├── connection.rs   health, IP rotate, LRU tickets, backoff
    ├── dns_guard.rs    WFP *specs* only; FFI STUB
    ├── doh.rs          DNS-over-HTTPS A records, fail-closed, IP literals skip net
    ├── relay.rs        loopback TCP relay + HandshakeMonitor (pure)
    ├── quic.rs         Initial detect, blindspot, src/dst rewrite, QuicPortMapper
    ├── utls.rs         JA3-ish reorder (multiset-preserving, no key_share)
    ├── ech.rs          ECH GREASE + outer SNI; HPKE STUB
    ├── geedge.rs       padding ext 0x0015, GREASE prepend, fake record, IP literal SNI
    ├── integrity.rs    SHA-256 pin, constant-time compare, 16 MiB cap
    ├── fail_open.rs    catch_unwind → original packet
    └── webui.rs        127.0.0.1 dashboard, bearer token, Start/Stop/Save
```

~9.5k lines of Rust, ~197 `#[test]` functions. No Python, no Node panel.

---

## 3. Module status (honest)

Legend: **DONE** = implemented + unit tests. **PARTIAL** = works with
documented limits. **STUB** = compiles, returns a typed error.

| Module | Status | Notes |
|---|---|---|
| `sni_mutations` | DONE | 12 techniques. Homoglyphs exist but are in **no** default profile (RFC 6066). |
| `fragmentation` | DONE | Parse, splice lengths, disguise 0x0000, fronting, hidden 0xFF01, TCP/TLS split. `ip_level_fragment_offsets` is computed, **not wired** into the live pipeline. |
| `packet` | DONE | IPv4/IPv6, TCP/UDP, `l3_slice`, checksums (UDP 0 → 0xFFFF). |
| `pipeline` | DONE | Transparent + relay + QUIC NAT + hold/reassembly. Tests cover watchdog, caps, reverse NAT, fake hello. |
| `fail_open` | DONE | Panic **or** `Err` **or** empty `Send` → original. Hold preserved. |
| `sequence` | DONE | Signed wrap, outside-window SEQ, TTL decoy, 50 µs gap. |
| `fooling` | DONE | Live path uses TTL + wrong-checksum decoys. Swap RST/SYN-ACK off unless `enable_swap_foolers`. |
| `strategy` | DONE | First-wins ties. Inbound RST −2, ServerHello +1 once (`remove`). Cap 4096/512. |
| `stealth` | PARTIAL | `validate_dnssec` = RRSIG presence, not crypto. `prevent_dns_leak` STUB. Kill-switch command is logged, never spawned. |
| `connection` | DONE | Not on the hot packet path except ticket touch / rotate_ip list parse. |
| `dns_guard` | spec DONE, FFI STUB | Dynamic WFP session spec. `block_port_53_except_localhost` always `Err`. |
| `doh` | DONE | RFC 8484 GET `?dns=`, A records, no plaintext fallback. |
| `relay` | DONE (logic) | Handshake machine unit-tested. **Injection timing untested on a real NIC.** |
| `quic` | DONE (logic) | Forward + reverse NAT in pipeline. Mapper cap 4096, idle prune. |
| `utls` | PARTIAL | Reorder ciphers / groups / sigalgs / point formats. Does **not** rebuild extensions, curves, ALPN, or `key_share`. |
| `ech` | PARTIAL | GREASE injection + outer SNI. `parse_ech_config_from_https_record` is a stub. No HPKE. |
| `geedge` | DONE (helpers) | Padding/GREASE/fake-record/IP-literal. Pipeline currently uses padding only when the flag is on. |
| `integrity` | DONE | Constant-time pin compare. |
| `webui` | DONE | Host/Origin/token/CSP. Config save via `merge_partial`. |
| `config` | DONE | `deny_unknown_fields`, fail-closed invalid file, NEVER_INTERCEPT 22/53/3389. |
| `engine` | written vs windivert 0.5.5 | **Never compiled or run on Windows in this environment.** |
| `engine_stub` | DONE | Non-Windows link. |
| WFP callout driver | out of scope | Needs a signed kernel driver. |
| Kill-switch spawn | never automatic | Even with the flag, only the PowerShell string is logged. |

`REVIEW_2026_STRICT.md` scores the sibling at **92/100**. Deductions that
still apply here: no Windows field test, no real ECH HPKE, uTLS is shuffle
not full rebuild, WFP FFI stub. QUIC reverse NAT **is** wired in *this*
tree (the 92/100 review said it was still stub — that review is slightly
stale relative to `pipeline.rs` / `quic.rs`).

---

## 4. Runtime architecture

```
                    dpi_guard.exe  (Administrator, Windows)
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
   capture thread        watchdog/reload      webui thread
   engine::capture_loop  200 ms hold flush    127.0.0.1:9090
          │              1 s config poll      (opt-in)
          │              relay reconcile
          ▼
   fail_open::handle_exception_fail_open
          ▼
   Pipeline::handle
      ├─ UDP → QUIC mapper / passthrough
      ├─ TCP relay flow → HandshakeMonitor → inject fake CH
      ├─ inbound target port → RST/ServerHello scoring
      └─ outbound ClientHello → mutate / fragment / decoy
          ▼
   WireAction::Send(packets) | Hold
          ▼
   WinDivert send with original address
   (extra injects: send-only handle, filter "false")
```

`main.rs` also owns `RelayRuntime`: identity of the running relay; on
config change it **resolves first** (fail-closed — keep the old relay if
DoH fails), then stops, `configure_relay`, `relay::run`.

Hot-reload of `intercept_ports` / `intercept_all_*` calls
`engine::request_filter_reload`, which stores the new filter and
`WinDivertShutdown` so `recv` unblocks and the loop reopens the handle.
Reload failure falls back to the previous filter.

Release profile: `panic = "unwind"` (required for fail-open) and
`overflow-checks = true` (length math must panic into fail-open, not wrap).
`#![deny(unsafe_code)]` except `engine.rs`.

---

## 5. Configuration reference

Copy `dpi_guard.toml.example` → `dpi_guard.toml` next to the binary.
Unknown keys are rejected. Invalid file or an **explicit** missing path
→ exit 1. Missing *default* `dpi_guard.toml` → compiled defaults + warn.

### Profiles (`mutation_profile`)

| Profile | SNI mutations | Frag chunk | Disorder | Identity-preserving |
|---|---|---|---|---|
| `Stealth` (default) | case only | 64 | no | yes |
| `ChinaGfw` | case only | 64 | no | yes |
| `RussiaDpi` | trailing dot | 0 | no | yes |
| `ChinaRegional` | case + trailing dot | 32 | yes | yes |
| `Henan` | case + trailing dot | 24 | yes | yes |
| `Aggressive` | null, explode, case, underscore, dots, overflow, `:443` | 32 | yes | **no** — breaks many servers |

`fragment_chunk_size = 1` is rejected (classic DPI fingerprint). Must be
0 or 8..=16384.

### Ports

- Default intercept: TCP+UDP 443 both directions, never loopback.
- `intercept_ports = [443, 8443, …]` (max 100, no 0).
- `intercept_all_tcp` / `intercept_all_udp` — dangerous; always excludes
  **`NEVER_INTERCEPT_PORTS = [22, 53, 3389]`** (SSH / DNS / RDP).
- Filter and `Settings::is_target_port` honour the same list.
- Relay mode also diverts `relay_connect_port` even if not in the list.

### Feature flags (defaults)

| Flag | Default | Risk |
|---|---|---|
| `enable_decoys` | true | TTL must be hops-to-DPI, not to origin |
| `enable_sni_fragmentation` | true | |
| `enable_combined_fragmentation` | true | Henan path |
| `enable_geedge_evasion` | true | extra padding ext |
| `enable_swap_foolers` | **false** | forged RST/SYN-ACK — IDS/EDR |
| `enable_kill_switch` | false | logged only |
| `enable_web_ui` | false | loopback + token |
| `enable_quic_port_bypass` | false | needs field test |
| `enable_sni_disguise` | false | breaks vhost unless fronting |
| `enable_utls_fingerprint` | false | reorder only |
| `enable_ech_grease` | false | |
| `enable_md5sig_fooling` | false | TCP option 19, breaks some servers |
| `relay_enabled` | false | needs host + fake SNI |

### Example — Iran-like regional DPI (transparent)

```toml
mutation_profile = "Henan"
intercept_ports = [443, 8443, 2053, 2083, 2087, 2096, 8080, 80, 4433]
enable_quic_port_bypass = true
enable_combined_fragmentation = true
enable_utls_fingerprint = true
utls_browser = "chrome"
enable_ech_grease = true
enable_geedge_evasion = true
fragment_chunk_size = 24
enable_decoys = true
decoy_ttl = 8
```

### Example — Russia

```toml
mutation_profile = "RussiaDpi"
intercept_ports = [443, 80, 8443]
```

Tune `decoy_ttl` with `tracert -d <dpi-or-1.1.1.1>`: large enough to reach
the inline box, small enough to expire before the origin.

---

## 6. Relay mode + v2rayN

**1. Build** (Windows, MSVC target):

```powershell
cargo build --release --target x86_64-pc-windows-msvc
```

**2. Official WinDivert** (not in git):

- https://reqrypt.org/windivert.html
- https://github.com/basil00/Divert/releases → `WinDivert-2.2.2-A.zip`

Place `WinDivert.dll` + `WinDivert64.sys` **next to the exe**. Pin hashes
in `win_divert_sha256` after computing them yourself:

```
# Example only — SHA-256 of official WinDivert 2.2.2 64-bit (recompute yours)
WinDivert.dll     c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2
WinDivert64.sys   8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2
```

```powershell
certutil -hashfile WinDivert.dll SHA256
certutil -hashfile WinDivert64.sys SHA256
```

**3. `dpi_guard.toml` next to the exe:**

```toml
relay_enabled = true
relay_listen_port = 40443
relay_connect_host = "1.1.1.1"          # IP literal = zero DNS leak
relay_connect_port = 443
relay_fake_sni = "www.microsoft.com"    # what DPI sees
relay_resolve_doh = true
doh_server = "https://1.1.1.1/dns-query"  # IP-literal endpoint = zero leak of DoH name
relay_mutate_real_sni = false
relay_emit_decoy = false
enable_web_ui = true
web_ui_port = 9090
```

**4. v2rayN outbound / server:**

| Field | Value |
|---|---|
| address | `127.0.0.1` |
| port | `40443` (or your `relay_listen_port`) |
| SNI / host | **real server domain** (`relay_connect_host` if it was a name) — **not** `relay_fake_sni` |

**5. Run as Administrator:**

```powershell
.\dpi_guard.exe
# or: .\dpi_guard.exe C:\path\to\dpi_guard.toml
```

Dashboard: `http://127.0.0.1:9090` (Host must be `127.0.0.1`, not
`localhost`). Token is printed at startup if auto-generated. Buttons:
**Start relay / Stop relay / Save config**. Save writes TOML through
`config::merge_partial` (same validation as the file). Relay restarts
automatically when relay fields change.

Extra toggles:

- `relay_mutate_real_sni = true` — after the fake handshake, the *real*
  ClientHello also goes through the normal mutation pipeline.
- `relay_emit_decoy = true` — also emit a TTL-limited wrong-checksum copy
  of the fake hello.

---

## 7. Dashboard security (do not regress)

- Bind `127.0.0.1` only.
- `Host` must be `127.0.0.1` or `127.0.0.1:<port>` (`localhost` rejected —
  DNS-rebind defence).
- `Origin` empty (curl) or `http://127.0.0.1:<port>`.
- Every `/api/*` needs `Authorization: Bearer <token>` (constant-time).
- Configured token ≥ 16 printable ASCII, no quotes/backslashes.
- `Settings` `Debug` redacts token and pin values.
- `/api/config` and `/api/config/toml` never echo token or driver pins;
  `merge_partial` leaves them in place if omitted.
- CSP, `X-Frame-Options: DENY`, CORP/COOP, nosniff, no file serving.
- JS uses `esc()`; strategy scores and recent SNIs are **hashed** with a
  per-process salt (`stealth::run_salt`).
- Body cap 4 KiB; request cap 8 KiB.

API:

| Method | Path | Auth | Effect |
|---|---|---|---|
| GET | `/` | no | HTML dashboard |
| GET | `/api/status` | yes | snapshot |
| POST | `/api/profile` | yes | `{profile}` one of the 6 names |
| GET | `/api/config` | yes | JSON settings (token/pins redacted) |
| GET | `/api/config/toml` | yes | redacted TOML |
| POST | `/api/config` | yes | partial TOML → validate → write file |

---

## 8. Packet-path safety properties (do not regress)

1. **Fail-open:** panic, `Err`, empty `Send`, hold overflow, seq mismatch,
   200 ms hold timeout → original bytes re-injected (watchdog uses the
   **original WinDivert address**, not a zeroed send-only address).
2. **One capture handle.** Extra injects use send-only + filter `false`.
3. **Never-intercept 22/53/3389** even in all-ports mode.
4. **Mutex poison** recovered (`recover_mutex`) — does not black-hole.
5. **Driver search** is exe-dir only (not cwd — DLL planting). Files > 16
   MiB refused. Pins compared in constant time.
6. **Relay** cannot be an open proxy (loopback + fixed destination).
7. **DoH has no plaintext fallback.** IP literal = zero DNS.
8. **Outbound decoys** keep this host’s 5-tuple and a low TTL.
9. `version_check` refuses to start if dll+sys are missing.

---

## 9. Honest limitations (do not claim otherwise)

1. **Never compiled in this sandbox.** No `rustc`/`cargo` here; previous
   environments blocked crates.io / rustup. Expect small compile errors
   (especially `main.rs` / `relay.rs` / `webui.rs`) and a `Cargo.lock`
   bump for `ureq`.
2. **Never field-tested on Windows.** TTL decoys, hold watchdog addresses,
   graceful `recv` unblock, **and relay injection timing** need a Win10/11
   VM + Administrator + official driver + Wireshark.
3. **DNS leak:** WFP port-53 block is STUB. SNI mutation does **not** hide
   the domain from a plaintext resolver. Use OS DoH/DoT, or relay with an
   IP literal + `https://1.1.1.1/dns-query`.
4. **Destination IP is visible.** This is SNI spoofing / handshake
   fooling, not VLESS Reality / a VPN.
5. **ECH is GREASE, not real ECH.** No HPKE, no HTTPS/SVCB fetch.
6. **uTLS is reorder-only.** A terminating stack (refraction-networking/utls)
   can rebuild key shares; this packet rewriter cannot.
7. **Aggressive mutations** (null, explode, overflow, …) are themselves a
   fingerprint and often invalid per RFC 6066 — they break real servers.
   Prefer Stealth / RussiaDpi / Henan.
8. **IP-level fragmentation** helper exists (`ip_level_fragment_offsets`)
   but is **not** in the live pipeline.
9. **`trusted_dns`** is documentation for a future hijack spec, not DoH.
10. **Kill-switch** never disables the NIC by itself.

---

## 10. What was true of this snapshot *before* the handoff commit

The uploaded tree (`2bd5cca`) disagreed with its own docs:

| Claim in README / IMPLEMENTATION_STATUS | Reality at `2bd5cca` |
|---|---|
| `.gitignore` exists (`target`, `*.dll`, `*.sys`, `dpi_guard.toml`) | **File missing** |
| WinDivert binaries not committed | **`WinDivert.dll` + `WinDivert64.sys` were tracked** (hashes match official 2.2.2 64-bit) |

This branch adds `.gitignore` and untracks those binaries. Fetch the
driver from reqrypt.org / basil00/Divert yourself.

`REVIEW_2026_STRICT.md` still names branch `arena/01a021cd-sin-new-4` and
talks about zip artifacts that are **not** in this repo — treat it as
historical scoring, not a file inventory.

---

## 11. Priority plan

### P0 — compile and unit-test on a real machine

```bash
cargo test
cargo fmt --check
cargo clippy -- -D warnings
cargo build --release --target x86_64-pc-windows-msvc
```

Fix whatever the compiler says. Do not “complete” new features until
green.

### P1 — Windows VM field test

- Win10/11, Administrator, official WinDivert next to exe, `RUST_LOG=dpi_guard=debug`.
- Scenario A: transparent Stealth/Henan against a known SNI-filtered site;
  Wireshark on the NIC — confirm mutated SNI / fragments / decoy TTL.
- Scenario B: relay + v2rayN; confirm fake ClientHello SEQ and dup-ACK,
  then real hello unmodified (unless `relay_mutate_real_sni`).
- Measure hops for `decoy_ttl`.

### P2 — remaining technical gaps (92 → ~98)

1. Real ECH (crates `hpke` + DNS HTTPS/SVCB via `hickory-resolver`).
2. WFP FFI (`FwpmEngineOpen0` / `FwpmFilterAdd0`) — still no callout
   driver, so this only blocks/allows; hijack stays out of scope.
3. Wire `ip_level_fragment_offsets` into the pipeline (careful: many
   middleboxes drop fragments).
4. Signed DNS-redirect callout — **out of scope** for user-mode.

### P3 — UX

- Hot-apply dashboard fields without writing the file (today: write TOML,
  wait ≤ 1 s).
- Live relay logs on the dashboard.
- Real cert pinning (`MemoryCertCache` is empty → identity-breaking
  mutations warn but still apply).
- More integration tests around filter reload and RelayRuntime.

---

## 12. Dependencies (`Cargo.toml`)

```
rand 0.8, rand_distr 0.4
dashmap =5.5.3, indexmap =2.2.6
serde 1 + derive, toml 0.8
sha2 0.10, log 0.4, env_logger 0.11
tokio 1 (rt-multi-thread, macros, time, sync, signal, net, io-util)
thiserror 1
ureq 2 + tls          # DoH only
windivert 0.5         # cfg(windows) only
```

No HTTP framework, no JSON crate (webui hand-rolls a tiny parser).

---

## 13. Tests worth knowing

`pipeline.rs` (the contract of the live path):

- SNI splice + length rewrite, IPv4 and IPv6
- `all_ports_custom_intercept_works` (8443 yes, 22 passthrough)
- truncated hello → Hold; reassembly uses **first** segment SEQ
- seq mismatch / flow-buf overflow → fail-open both packets
- `MAX_FLOWS=256` extra flow fail-opens; `MAX_RECENT=512` halves
- 200 ms watchdog returns original bytes (src IP preserved)
- inbound RST −2; ServerHello scores **once**
- UI scores hashed (raw hostname never in JSON)
- QUIC rewrite src 54321→443; reverse NAT restores 54321; follow-up keeps spoof
- Relay: fake SNI injected, real hello unmodified; `mutate_real_sni`
  applies trailing-dot; `emit_decoy` adds third packet with TTL
- Henan combined frag produces ≥ 2 packets
- disguise removes ext 0x0000; fronting shows benign + hidden real
- uTLS / ECH GREASE / Geedge padding do not panic

`relay.rs`: happy-path SEQ math, wrap, reject wrong SEQ / SYN-with-ACK /
packet after InjectFake / dup-ACK before `mark_fake_sent`.

`doh.rs`: RFC 4648 base64url vectors, A-record parse, NXDOMAIN error, IP
literal skips the network.

`lib.rs`: all-ports filter contains `!= 22/53/3389`; explicit 53 is dropped.

`webui.rs`: token case, Host/Origin, profile allow-list, redaction.

---

## 14. Key types / constants

```
HOLD_TIMEOUT        200 ms
MAX_FLOW_BUF        16 KiB
MAX_FLOWS           256
MAX_RECENT          512
MAX_QUIC_MAPS       4096
MAX_HELD (engine)   256
MAX_DRIVER_BYTES    16 MiB
FAKE_ACK_WAIT       3 s
NEVER_INTERCEPT     22, 53, 3389
DEFAULT_FILTER      !loopback and (tcp|udp) 443 both ways
```

`WireAction::{Send(Vec<Vec<u8>>), Hold}`

`HsAction::{Pass, InjectFake, Complete, Fail}`

`DpiGuardError`: PacketTooShort, SniNotFound, NotClientHello, OutOfRange,
PlatformNotSupported, Driver, Config, Resolution, Io.

---

## 15. Legal / dual-use

This is a censorship-circumvention toolkit. Laws differ by jurisdiction.
Do not use it to attack networks you do not operate, to hide crime, or to
ship unsigned kernel drivers you did not obtain from the official
WinDivert release.

---

*End of guide. If this file and the code disagree, believe the code and
update this file in the same change.*
