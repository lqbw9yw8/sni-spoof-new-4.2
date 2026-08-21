# Implementation status vs. the original checklist

Legend: DONE = implemented + unit tested (`cargo test`). STUB = typed
error / out of scope. PARTIAL = works with documented limits.

## 1. sni_mutations.rs (12/12 present)
inject_null_byte DONE · explode_subdomains DONE · randomize_case_sni DONE
· add_trailing_dot DONE · inject_whitespace DONE · inject_underscore DONE
· apply_homoglyphs DONE (not in any default profile — non-ASCII SNI is
invalid per RFC 6066) · insert_consecutive_dots DONE ·
force_length_overflow DONE · append_port_suffix DONE ·
get_mutation_profile DONE · mutate_sni_full DONE

Profiles: Stealth/ChinaGfw = case only; RussiaDpi = trailing dot;
Aggressive = null + explode + case + underscore + dots + overflow + port.

## 2. sequence.rs (6/6 present)
calculate_wrong_seq DONE (signed wrap) ·
calculate_wrong_seq_outside_window DONE · build_decoy_packet DONE
(preserves TCP options) · inject_ttl_limited_decoy DONE ·
send_simultaneous decoy-then-delay-then-real DONE · add_padding_to_decoy
DONE · race_condition_fix (50us) DONE

## 3. fragmentation.rs (4/4 present)
parse_client_hello / calculate_smart_split_points DONE (absolute offsets
in the full record; fuzzed 200 cases) · splice_sni DONE (rewrites record,
handshake, extension, list, name lengths) · fragment_sni_byte_chunk DONE
(TCP payload slices, not fake TLS records) · persistent_fragmentation
DONE · ip_level_fragment_offsets DONE (MTU minus 20-byte IPv4 header)

## 4. fooling.rs (8/8 present)
build_wrong_checksum DONE · build_tcp_md5sig_option DONE ·
build_synack_fooler DONE · build_rst_fooler DONE · tcp_wrap_packet DONE ·
udp_len_fooling + build_udp_len_decoy DONE · disorder_mode DONE ·
reverse_mode DONE

Live path: TTL-limited wrong-checksum outbound decoys. Swap foolers only
if `enable_swap_foolers`.

## 5. strategy.rs (4/4 present)
select_best DONE (first-wins ties) · update_score DONE ·
ab_test_block_type DONE · per_domain_tracking DONE. Pipeline updates
scores on inbound RST / ServerHello.

## 6. stealth.rs (15/15 present)
add_dynamic_jitter DONE · add_random_padding DONE · normalize_ttl DONE ·
fake_tcp_options + encode_tcp_options (NOP-padded, Chrome order) DONE ·
match_sni_cert + MemoryCertCache DONE · shuffle_cipher_suites DONE ·
add_grease_values DONE · simulate_browser_fingerprint + shape_fingerprint
DONE (representative lists) · hash_sensitive DONE · validate_dnssec
PARTIAL (RRSIG presence, not crypto) · prevent_dns_leak STUB (WFP FFI) ·
randomize_window_size DONE · inject_noise_entropy DONE (~25% bit flips) ·
deep_sleep_idle DONE · kill_switch_command sanitised DONE, process spawn
never automatic

## 7. engine.rs
WinDivert.open DONE as written against 0.5.5 · capture_loop DONE on a
dedicated thread, `recv(Some(&mut buf))` · parse_tls_client_hello
delegates to fragmentation · recalculate_checksums delegates to packet ·
inject_packet send-only + filter `false` · handle_exception_fail_open in
`fail_open.rs` (Linux tests) · logging via `init_logging` / `RUST_LOG` ·
graceful_shutdown calls WinDivertShutdown to unblock recv · version_check
looks for dll+sys next to the exe

## 8. connection.rs (5/5 present)
is_healthy + health_from_probe DONE · rotate_ip + parse_ip_list DONE ·
SessionTicketCache LRU-on-access via indexmap DONE · smart_backoff DONE ·
health_check_interval DONE

## 9. dns_guard.rs
init_wfp_hook_spec DONE (dynamic) · dns_protection_filters = allow
localhost:53 + block :53 DONE · hijack_dns_requests_spec validates
target, flags `needs_callout_driver` · real WFP FFI STUB · callout
driver out of scope

## Pipeline / main
SNI is spliced back into the ClientHello with length fields updated.
TLS is parsed from the TCP **payload** (data-offset), not the TCP header.
IPv6 TCP/443 is handled. Multi-segment ClientHello is held ≤200ms and
reassembled. Config values, hot reload, strategy, decoys, fragmentation
are wired. Kill switch is not spawned.

New integration tests (pipeline.rs):
- expired_held_is_flushed_by_watchdog — documents fix #8, ensures watchdog
  returns raw bytes that engine matches to stored DivertPacket for real address
- max_flows_cap_fail_opens — MAX_FLOWS=256, extra flow Send(original) not Hold
- flow_buf_overflow_fail_opens_both — MAX_FLOW_BUF=16k, seq mismatch path returns held+current
- recent_eviction_halves_on_cap — MAX_RECENT=512, halves then inserts
- idle_flush_removes_old_flows_and_recent — deep_sleep_idle threshold path
- hold_watchdog_preserves_original_winDivert_address_semantics — src IP preserved

Engineering TODOs completed in this branch:
- .gitignore added (target, *.dll, *.sys, dpi_guard.toml)
- dpi_guard.toml.example documents how to get official SHA256 pins
- README adds DNS leak warning + DoH/DoT guide + Build & Dev section with fmt/clippy
- pipeline tests increased (6 new)

2026-08-21 follow-up (branch arena/01a023bf-sin-4-1):
- `.gitignore` now actually exists; the committed `WinDivert.dll` /
  `WinDivert64.sys` were untracked from git (kept locally, ignored).
- `dpi_guard.toml.example` carries real (non-placeholder) SHA-256 of the
  WinDivert 2.2.2 64-bit binaries, with instructions to recompute from your
  own download.
- `build_filter` all-ports mode excludes SSH 22 / DNS 53 / RDP 3389
  (`config::NEVER_INTERCEPT_PORTS`); `Settings::explicit_port_list` +
  `is_target_port` honour the same list so filter and pipeline agree.
- Config hot-reload now reopens the WinDivert capture handle when
  `intercept_ports` / `intercept_all_*` change (`engine::request_filter_reload`).
- `webui` `status_json` test covers `intercept_ports` + the new flags; the
  profile-rejection message lists all 6 profiles.
- QUIC reverse NAT is now wired end-to-end: `QuicPortMapper` (keyed on
  client+server) allocates a distinct spoofed port per flow, the pipeline
  rewrites every outbound packet of a mapped flow and restores the original
  destination port on inbound replies (`quic::rewrite_udp_dst_port`). The
  blindspot rule applies to any intercepted UDP port, not just 443.
- uTLS fingerprinting now reorders `supported_groups` / `signature_algorithms`
  / `ec_point_formats` in place (multiset-preserving, via the new
  `fragmentation::list_extensions`) in addition to cipher suites. `key_share`
  and ALPN are intentionally left untouched: a passive rewriter cannot
  regenerate key material without breaking the handshake.
- Relay mode: `relay.rs` adds a loopback-only local TCP relay with a fixed
  destination and a pure `HandshakeMonitor` state machine for the fake-SNI
  `wrong_seq` injection (unit-tested on Linux). `doh.rs` resolves the
  destination domain over DNS-over-HTTPS with no plaintext fallback. The
  pipeline injects the fake ClientHello right after the final ACK; two extra
  toggles (`relay_mutate_real_sni`, `relay_emit_decoy`) optionally run the
  real ClientHello through normal mutation or add a decoy of the fake. The
  relay binds before connect and awaits an injection-complete gate. The
  dashboard can edit/save the config and start/stop the relay at runtime
  (`RelayRuntime` in `main.rs` + `config::merge_partial`). Windows
  field-testing of the injection timing is still required (same caveat as
  `engine.rs`).

## Why some items stay STUB

1. WFP `Fwpm*` FFI needs `windows` bindings not pinned here.
2. DNS redirect needs a signed kernel callout driver.
3. Kill-switch process spawn is opt-in and even then only logged — an
   automatic "disable my NIC" trigger does not belong in a library call.
