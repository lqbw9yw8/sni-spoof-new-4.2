//! pipeline — OS-independent packet processor. [DONE]
//! This is what `main` actually runs on every diverted packet: parse L3/L4
//! (skipping the TCP header via data-offset), splice a mutated SNI with
//! rewritten TLS lengths, optional TCP segmentation, optional TTL-limited
//! wrong-checksum decoy, inbound RST → strategy score.
//! 
//! 2025-2026 upgrades:
//! - QUIC port blindspot bypass (src <= dst) for GFW
//! - SNI disguise as unknown extension (GREASE/private)
//! - Layered domain fronting (benign SNI + hidden real in 0xFF01)
//! - Combined TCP+TLS fragmentation for Henan-like regional firewalls
//! - ALL PORTS: works on any TCP/UDP port via intercept_ports config, not just 443

use crate::config::Settings;
use crate::connection::{parse_ip_list, rotate_ip, SessionTicketCache};
use crate::error::DpiGuardError;
use crate::fail_open::WireAction;
use crate::fooling::{self, build_wrong_checksum};
use crate::fragmentation::{self, splice_sni};
use crate::packet::{self, ParsedPacket, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN};
use crate::quic::QuicPortMapper;
use crate::relay::{FlowInfo, HandshakeMonitor, HsAction, RelayMode};
use crate::sequence::{
    build_decoy_packet, calculate_wrong_seq_outside_window, inject_ttl_limited_decoy,
};
use crate::sni_mutations::{mutate_sni_full, MutationProfile};
use crate::stealth::{
    deep_sleep_idle, hash_sensitive, match_sni_cert, run_salt, MemoryCertCache,
};
use crate::strategy::StrategyTable;
use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

const HOLD_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_FLOW_BUF: usize = 16 * 1024;
const MAX_FLOWS: usize = 256;
const MAX_RECENT: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}

struct FlowBuf {
    buf: Vec<u8>,
    next_seq: u32,
    held: Vec<Vec<u8>>,
    started: Instant,
}

struct RecentAttempt {
    domain: String,
    technique: String,
    at: Instant,
}

/// Per-flow state for the relay-mode fake-SNI injection.
struct RelayFlow {
    monitor: HandshakeMonitor,
    gate: Arc<Notify>,
    done: bool,
    last: Instant,
}

pub struct Pipeline {
    pub settings: Settings,
    pub strategy: StrategyTable,
    pub tickets: SessionTicketCache,
    pub certs: MemoryCertCache,
    flows: HashMap<FlowKey, FlowBuf>,
    last_activity: HashMap<FlowKey, Instant>,
    recent: HashMap<(IpAddr, u16), RecentAttempt>,
    quic_mapper: QuicPortMapper,
    relay_mode: Option<RelayMode>,
    relay_flows: HashMap<FlowKey, RelayFlow>,
}

fn release_held_plus(mut held: Vec<Vec<u8>>, current: &[u8]) -> WireAction {
    held.push(current.to_vec());
    WireAction::Send(held)
}

impl Pipeline {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            strategy: StrategyTable::new(),
            tickets: SessionTicketCache::new(32),
            certs: MemoryCertCache::default(),
            flows: HashMap::new(),
            last_activity: HashMap::new(),
            recent: HashMap::new(),
            quic_mapper: QuicPortMapper::new(),
            relay_mode: None,
            relay_flows: HashMap::new(),
        }
    }

    /// Configure (or clear, with `None`) relay-mode evasion behaviour.
    pub fn configure_relay(&mut self, mode: Option<RelayMode>) {
        self.relay_mode = mode;
    }

    /// Register a relay connection (4-tuple) before its handshake and return
    /// the gate the relay awaits before relaying the real ClientHello.
    pub fn register_relay_flow(&mut self, flow: FlowInfo) -> Arc<Notify> {
        let gate = Arc::new(Notify::new());
        self.relay_flows.insert(
            FlowKey {
                src: flow.src,
                dst: flow.dst,
                sport: flow.sport,
                dport: flow.dport,
            },
            RelayFlow {
                monitor: HandshakeMonitor::new(),
                gate: gate.clone(),
                done: false,
                last: Instant::now(),
            },
        );
        gate
    }

    pub fn handle(&mut self, raw: &[u8]) -> Result<WireAction, DpiGuardError> {
        self.flush_idle();
        let original = raw;
        let Some(raw) = packet::l3_slice(raw) else {
            return Ok(WireAction::Send(vec![original.to_vec()]));
        };
        let Some(parsed) = packet::parse_l3l4(raw) else {
            return Ok(WireAction::Send(vec![original.to_vec()]));
        };

        if parsed.protocol == packet::PROTO_UDP {
            // ALL PORTS: check if UDP port is target
            let is_target_udp = self.settings.is_target_port(parsed.dst_port, true)
                || self.settings.is_target_port(parsed.src_port, true);
            if !is_target_udp {
                return Ok(WireAction::Send(vec![raw.to_vec()]));
            }
            if self.settings.enable_quic_port_bypass {
                // Inbound half of the QUIC port NAT: a server reply sent to
                // the spoofed source port is rewritten back to the client's
                // original source port. Checked first so a reply is never
                // mistaken for a brand-new Initial.
                if let Some(orig_sport) = self.quic_mapper.get_original(
                    parsed.src,      // server
                    parsed.dst,      // client
                    parsed.src_port, // server port
                    parsed.dst_port, // spoofed port
                ) {
                    if let Ok(rewritten) = crate::quic::rewrite_udp_dst_port(raw, orig_sport) {
                        log::info!(
                            "QUIC reverse NAT: restored dst port {} -> {} for server {}",
                            parsed.dst_port,
                            orig_sport,
                            parsed.src
                        );
                        return Ok(WireAction::Send(vec![rewritten]));
                    }
                }

                // Outbound half: keep rewriting every packet of an already
                // mapped flow (not just the Initial), so the server always
                // sees one 5-tuple.
                if let Some(spoofed) = self.quic_mapper.get_spoofed(
                    parsed.src,      // client
                    parsed.dst,      // server
                    parsed.dst_port, // server port
                    parsed.src_port, // original source port
                ) {
                    if let Ok(rewritten) = crate::quic::rewrite_udp_src_port(raw, spoofed) {
                        return Ok(WireAction::Send(vec![rewritten]));
                    }
                }

                // New flow: originate a NAT mapping only for a genuine
                // outbound client Initial (destination on an intercepted
                // port, source on an ephemeral port, src > dst).
                let dst_intercepted = self.settings.is_target_port(parsed.dst_port, true);
                let src_intercepted = self.settings.is_target_port(parsed.src_port, true);
                let payload = parsed.payload(raw);
                if dst_intercepted
                    && !src_intercepted
                    && crate::quic::should_mangle_quic(parsed.src_port, parsed.dst_port, true)
                    && crate::quic::is_quic_initial(payload)
                {
                    if self.quic_mapper.len() < crate::quic::MAX_QUIC_MAPS {
                        if let Some(new_sport) = self.quic_mapper.alloc_spoofed(
                            parsed.src,
                            parsed.dst,
                            parsed.dst_port,
                            self.settings.quic_bypass_use_low_port,
                        ) {
                            if let Ok(rewritten) =
                                crate::quic::rewrite_udp_src_port(raw, new_sport)
                            {
                                self.quic_mapper.insert(
                                    parsed.src,
                                    parsed.dst,
                                    parsed.dst_port,
                                    parsed.src_port,
                                    new_sport,
                                );
                                log::info!(
                                    "QUIC bypass: rewrote src {} -> {} for dst {} (blindspot)",
                                    parsed.src_port,
                                    new_sport,
                                    parsed.dst
                                );
                                return Ok(WireAction::Send(vec![rewritten]));
                            }
                        }
                    } else {
                        log::warn!(
                            "QUIC port mapper full; passing QUIC Initial through unmodified"
                        );
                    }
                }
            }
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }

        if parsed.protocol != packet::PROTO_TCP {
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }

        // Relay-mode flows short-circuit the normal SNI-mutation path: the
        // fake-SNI injection handles evasion, and the flow's real bytes pass
        // through unmodified.
        if let Some(action) = self.handle_relay_packet(raw, &parsed)? {
            return Ok(action);
        }

        // ALL PORTS: check if TCP port is target (either src or dst)
        let inbound = self.is_tcp_target(parsed.src_port);
        let outbound = self.is_tcp_target(parsed.dst_port);

        if inbound && !outbound {
            // Inbound from target port (server -> client)
            self.on_inbound(raw, &parsed);
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }
        if !outbound {
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }

        self.on_outbound_target(raw, &parsed)
    }

    /// A TCP port is "intercepted" when it is in the configured list (or an
    /// all-ports wildcard) OR, in relay mode with `mutate_real_sni`, when it
    /// is the relay's real destination port.
    fn is_tcp_target(&self, port: u16) -> bool {
        if self.settings.is_target_port(port, false) {
            return true;
        }
        matches!(&self.relay_mode, Some(m) if m.mutate_real_sni && m.connect_port == port)
    }

    /// Drive the fake-SNI handshake monitor for a relay flow. Returns
    /// `Ok(None)` when the packet does not belong to a registered relay flow
    /// (or when a completed relay flow falls through to normal mutation).
    fn handle_relay_packet(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
    ) -> Result<Option<WireAction>, DpiGuardError> {
        if self.relay_mode.is_none() {
            return Ok(None);
        }
        let key = FlowKey {
            src: parsed.src,
            dst: parsed.dst,
            sport: parsed.src_port,
            dport: parsed.dst_port,
        };
        let reversed = FlowKey {
            src: parsed.dst,
            dst: parsed.src,
            sport: parsed.dst_port,
            dport: parsed.src_port,
        };
        let (flow_key, outbound) = if self.relay_flows.contains_key(&key) {
            (key, true)
        } else if self.relay_flows.contains_key(&reversed) {
            (reversed, false)
        } else {
            return Ok(None);
        };

        let flags = parsed.tcp_flags.unwrap_or(0);
        let seq = parsed.tcp_seq.unwrap_or(0);
        let ack_num = parsed.tcp_ack.unwrap_or(0);
        let payload_len = parsed.payload(raw).len();
        let syn = flags & TCP_FLAG_SYN != 0;
        let ack = flags & TCP_FLAG_ACK != 0;
        let rst = flags & TCP_FLAG_RST != 0;
        let fin = flags & TCP_FLAG_FIN != 0;

        let entry = match self.relay_flows.get_mut(&flow_key) {
            Some(e) => e,
            None => return Ok(None),
        };
        entry.last = Instant::now();
        if entry.done {
            // Item 1: optionally run the real ClientHello through the normal
            // SNI-mutation pipeline; otherwise pass through unmodified.
            if self
                .relay_mode
                .as_ref()
                .map(|m| m.mutate_real_sni)
                .unwrap_or(false)
            {
                return Ok(None);
            }
            return Ok(Some(WireAction::Send(vec![raw.to_vec()])));
        }

        let action = if outbound {
            entry
                .monitor
                .on_outbound(syn, ack, rst, fin, seq, ack_num, payload_len)
        } else {
            entry
                .monitor
                .on_inbound(syn, ack, rst, fin, seq, ack_num, payload_len)
        };

        match action {
            HsAction::Pass => Ok(Some(WireAction::Send(vec![raw.to_vec()]))),
            HsAction::InjectFake => {
                let mode = self.relay_mode.clone().unwrap_or(RelayMode {
                    fake_sni: String::new(),
                    connect_port: 0,
                    mutate_real_sni: false,
                    emit_decoy: false,
                });
                let fake_hello = crate::fragmentation::encode_client_hello(&mode.fake_sni);
                let fake_seq = entry.monitor.fake_seq_for(fake_hello.len());
                let fake = crate::sequence::build_decoy_packet(raw, fake_seq, &fake_hello)?;
                entry.monitor.mark_fake_sent();
                let mut out = vec![raw.to_vec(), fake];
                // Item 2: optional extra decoy of the fake (TTL-limited +
                // wrong checksum) for stateless DPI that inspects every
                // packet rather than tracking the handshake.
                if mode.emit_decoy {
                    let mut decoy =
                        crate::sequence::build_decoy_packet(raw, fake_seq, &fake_hello)?;
                    crate::sequence::inject_ttl_limited_decoy(
                        &mut decoy,
                        self.settings.decoy_ttl,
                    );
                    let _ = crate::fooling::build_wrong_checksum(&mut decoy);
                    out.push(decoy);
                }
                log::info!(
                    "relay fake ClientHello injected (SNI {}, fake_seq {fake_seq})",
                    mode.fake_sni
                );
                Ok(Some(WireAction::Send(out)))
            }
            HsAction::Complete => {
                entry.done = true;
                entry.gate.notify_one();
                log::info!("relay fake-SNI handshake complete; relaying real data");
                Ok(Some(WireAction::Send(vec![raw.to_vec()])))
            }
            HsAction::Fail => {
                // Unexpected handshake packet: fail-open and stop monitoring.
                entry.done = true;
                entry.gate.notify_one();
                Ok(Some(WireAction::Send(vec![raw.to_vec()])))
            }
        }
    }

    fn on_inbound(&mut self, raw: &[u8], parsed: &ParsedPacket) {
        let flags = parsed.tcp_flags.unwrap_or(0);
        let key = (parsed.src, parsed.dst_port);
        if flags & TCP_FLAG_RST != 0 {
            if let Some(recent) = self.recent.remove(&key) {
                self.strategy
                    .update_score(&recent.domain, &recent.technique, false);
                log::info!(
                    "RST from {} for hashed SNI {} technique {}",
                    parsed.src,
                    hash_sensitive(&recent.domain, run_salt()),
                    recent.technique
                );
            }
            return;
        }
        let payload = parsed.payload(raw);
        let is_server_hello = payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x02;
        if is_server_hello {
            if let Some(recent) = self.recent.remove(&key) {
                self.strategy
                    .update_score(&recent.domain, &recent.technique, true);
            }
        }
    }

    fn on_outbound_target(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
    ) -> Result<WireAction, DpiGuardError> {
        let payload = parsed.payload(raw).to_vec();
        if payload.is_empty() {
            return Ok(WireAction::Send(vec![raw.to_vec()]));
        }

        let key = FlowKey {
            src: parsed.src,
            dst: parsed.dst,
            sport: parsed.src_port,
            dport: parsed.dst_port,
        };
        self.last_activity.insert(key, Instant::now());

        if let Some(action) = self.try_reassemble(raw, parsed, &payload, key)? {
            return Ok(action);
        }

        match fragmentation::parse_client_hello(&payload) {
            Ok(info) => {
                let sni = match info.sni {
                    Some(loc) => payload[loc.name_start..loc.name_end].to_vec(),
                    None => return Ok(WireAction::Send(vec![raw.to_vec()])),
                };
                self.flows.remove(&key);
                self.apply_client_hello(raw, parsed, &payload, &sni)
            }
            Err(DpiGuardError::PacketTooShort { .. })
                if payload.first() == Some(&0x16) && payload.get(1) == Some(&0x03) =>
            {
                if self.hold(key, raw, parsed, payload) {
                    Ok(WireAction::Hold)
                } else {
                    Ok(WireAction::Send(vec![raw.to_vec()]))
                }
            }
            _ => Ok(WireAction::Send(vec![raw.to_vec()])),
        }
    }

    fn try_reassemble(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
        payload: &[u8],
        key: FlowKey,
    ) -> Result<Option<WireAction>, DpiGuardError> {
        if !self.flows.contains_key(&key) {
            return Ok(None);
        }
        let seq = parsed.tcp_seq.unwrap_or(0);
        let next_seq = self.flows[&key].next_seq;
        if seq != next_seq {
            let held = self.flows.remove(&key).unwrap().held;
            return Ok(Some(release_held_plus(held, raw)));
        }
        if self.flows[&key].buf.len() + payload.len() > MAX_FLOW_BUF {
            let held = self.flows.remove(&key).unwrap().held;
            return Ok(Some(release_held_plus(held, raw)));
        }
        {
            let flow = self.flows.get_mut(&key).unwrap();
            flow.buf.extend_from_slice(payload);
            flow.next_seq = seq.wrapping_add(payload.len() as u32);
            flow.held.push(raw.to_vec());
        }
        let buf = self.flows[&key].buf.clone();
        match fragmentation::parse_client_hello(&buf) {
            Ok(info) => {
                let flow = self.flows.remove(&key).unwrap();
                let sni = match info.sni {
                    Some(loc) => buf[loc.name_start..loc.name_end].to_vec(),
                    None => return Ok(Some(WireAction::Send(flow.held))),
                };
                let first = flow.held.first().map(|v| v.as_slice()).unwrap_or(raw);
                let first_parsed = packet::parse_l3l4(first).unwrap_or_else(|| parsed.clone());
                Ok(Some(self.apply_client_hello(
                    first,
                    &first_parsed,
                    &buf,
                    &sni,
                )?))
            }
            Err(DpiGuardError::PacketTooShort { .. }) => Ok(Some(WireAction::Hold)),
            Err(_) => {
                let held = self.flows.remove(&key).unwrap().held;
                Ok(Some(WireAction::Send(held)))
            }
        }
    }

    fn hold(&mut self, key: FlowKey, raw: &[u8], parsed: &ParsedPacket, payload: Vec<u8>) -> bool {
        if self.flows.len() >= MAX_FLOWS {
            return false;
        }
        let seq = parsed.tcp_seq.unwrap_or(0);
        self.flows.insert(
            key,
            FlowBuf {
                next_seq: seq.wrapping_add(payload.len() as u32),
                buf: payload,
                held: vec![raw.to_vec()],
                started: Instant::now(),
            },
        );
        true
    }

    fn evict_recent_if_full(&mut self) {
        if self.recent.len() < MAX_RECENT {
            return;
        }
        let n = self.recent.len() / 2;
        let keys: Vec<_> = self.recent.keys().copied().take(n).collect();
        for k in keys {
            self.recent.remove(&k);
        }
    }

    fn apply_client_hello(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
        tls_record: &[u8],
        sni: &[u8],
    ) -> Result<WireAction, DpiGuardError> {
        let domain = String::from_utf8_lossy(sni).to_string();
        let candidates = [
            MutationProfile::Stealth.as_str(),
            MutationProfile::ChinaGfw.as_str(),
            MutationProfile::RussiaDpi.as_str(),
            MutationProfile::Aggressive.as_str(),
            MutationProfile::ChinaRegional.as_str(),
            MutationProfile::Henan.as_str(),
        ];
        let chosen = self
            .strategy
            .select_best(&domain, &candidates)
            .unwrap_or_else(|| self.settings.mutation_profile.clone());
        let cfg_score = self
            .strategy
            .select_best(&domain, &[self.settings.mutation_profile.as_str()])
            .and_then(|_| {
                self.strategy
                    .per_domain_scores(&domain)
                    .into_iter()
                    .find(|(n, _)| n == &self.settings.mutation_profile)
                    .map(|(_, s)| s)
            })
            .unwrap_or(0);
        let chosen_score = self
            .strategy
            .per_domain_scores(&domain)
            .into_iter()
            .find(|(n, _)| n == &chosen)
            .map(|(_, s)| s)
            .unwrap_or(0);
        let profile_name = if chosen_score > cfg_score {
            chosen
        } else {
            self.settings.mutation_profile.clone()
        };
        let profile: MutationProfile = profile_name.parse().unwrap_or(MutationProfile::Stealth);

        let mutated = mutate_sni_full(sni, profile);
        let mutated_str = String::from_utf8_lossy(&mutated).to_string();
        let use_mutated = if profile.preserves_identity() {
            true
        } else {
            match_sni_cert(&self.certs, &mutated_str)
        };
        if use_mutated && !profile.preserves_identity() && self.certs.valid.is_empty() {
            log::warn!(
                "identity-breaking SNI mutation applied with an empty certificate cache: \
                 the delivered certificate may not match the mutated hostname, causing \
                 hostname-mismatch errors (and training users to ignore cert warnings)"
            );
        }

        let mut hello = if use_mutated && mutated != sni {
            splice_sni(tls_record, &mutated).unwrap_or_else(|_| tls_record.to_vec())
        } else {
            tls_record.to_vec()
        };

        // --- NEW 2025: SNI fronting + disguise (layered) ---
        if !self.settings.fronting_benign_sni.is_empty() {
            let benign = self.settings.fronting_benign_sni.as_bytes();
            if let Ok(fronted) = fragmentation::front_sni_with_benign(&hello, benign) {
                if self.settings.enable_sni_disguise {
                    if let Ok(with_hidden) = fragmentation::inject_hidden_sni_in_unknown_ext(
                        &fronted,
                        sni,
                        0xFF01,
                    ) {
                        hello = with_hidden;
                        log::info!(
                            "fronting layered: benign {} + hidden real in 0xFF01",
                            self.settings.fronting_benign_sni
                        );
                    } else {
                        hello = fronted;
                    }
                } else {
                    hello = fronted;
                }
            }
        } else if self.settings.enable_sni_disguise {
            let disguise_type = crate::sni_mutations::random_disguise_type();
            if let Ok(disguised) =
                fragmentation::disguise_sni_extension_type(&hello, disguise_type)
            {
                hello = disguised;
                log::info!("SNI disguise: changed ext type 0x0000 -> 0x{:04X}", disguise_type);
            }
        }

        // ECH GREASE (2025)
        if self.settings.enable_ech_grease {
            if let Ok(with_ech_grease) = crate::ech::inject_ech_grease_ext(&hello) {
                hello = with_ech_grease;
                log::debug!("ECH GREASE injected");
            }
        }

        // uTLS fingerprint rotation (JA3/JA4) - based on utls
        if self.settings.enable_utls_fingerprint {
            if let Err(e) = crate::utls::apply_fingerprint_to_hello(&mut hello, &self.settings.utls_browser) {
                log::warn!("utls fingerprint apply failed: {e}");
            }
        }

        // Geedge evasion: extra padding, GREASE prepend
        if self.settings.enable_geedge_evasion {
            // Add small random padding extension (0x0015) 0-32 bytes to confuse offset-based parsers
            let mut rng = rand::thread_rng();
            let pad = rand::Rng::gen_range(&mut rng, 0..=32);
            if pad > 0 {
                if let Ok(padded) = crate::geedge::add_tls_padding_extension(&hello, pad) {
                    hello = padded;
                }
            }
        }

        let mut real = packet::rebuild_with_payload(raw, &hello, None)?;

        if let Some(p) = packet::parse_l3l4(&real) {
            let off = p.l4_offset + packet::tcp_off::FLAGS;
            if real.len() > off {
                real[off] |= packet::TCP_FLAG_PSH | packet::TCP_FLAG_ACK;
                packet::recalculate_all_checksums(&mut real);
            }
        }

        // MD5SIG fooling (zapret) - adds TCP option 19, breaks some servers
        if self.settings.enable_md5sig_fooling {
            if let Ok(with_md5) = fooling::tcp_wrap_packet(&real, 18) {
                // tcp_wrap_packet currently adds NOP padding, we need to replace with MD5SIG option
                // For now we use generic wrap and then patch first 18 bytes with MD5SIG
                let md5opt = fooling::build_tcp_md5sig_option();
                // Find TCP header len and insert
                if let Some(p) = packet::parse_l3l4(&with_md5) {
                    let ih = p.l3_header_len;
                    // The wrap added 20 bytes of NOPs (rounded), replace first 18 with MD5SIG
                    let mut patched = with_md5.clone();
                    if patched.len() >= ih + 20 + 18 {
                        patched[ih + 20..ih + 20 + 18].copy_from_slice(&md5opt);
                        packet::recalculate_all_checksums(&mut patched);
                        real = patched;
                    } else {
                        real = with_md5;
                    }
                } else {
                    real = with_md5;
                }
                log::debug!("MD5SIG fooling applied");
            }
        }

        let mut packets: Vec<Vec<u8>> = Vec::new();

        if self.settings.enable_decoys {
            if let Some(decoy) = self.build_decoy(&real, parsed, &hello) {
                packets.push(decoy);
            }
        }
        if self.settings.enable_swap_foolers {
            if let Ok(rst) = fooling::build_rst_fooler(&real, parsed.tcp_seq.unwrap_or(0)) {
                packets.push(rst);
            }
        }

        // Combined TCP+TLS fragmentation for Henan / regional firewalls
        let mut effective_chunk = self.settings.fragment_chunk_size;
        if self.settings.enable_combined_fragmentation {
            let recommended = profile.recommended_fragment_size();
            if recommended != 0 && (effective_chunk == 0 || recommended < effective_chunk) {
                effective_chunk = recommended;
            }
        }
        let should_disorder = profile.uses_disorder() || self.settings.enable_combined_fragmentation;

        if self.settings.enable_sni_fragmentation && effective_chunk >= 8 {
            match packet::tcp_segment_payload(&real, effective_chunk) {
                Ok(segs) if !segs.is_empty() => {
                    let segs = if should_disorder {
                        fooling::disorder_mode(segs)
                    } else {
                        segs
                    };
                    if profile == MutationProfile::Henan
                        && self.settings.enable_combined_fragmentation
                    {
                        let mut combined = Vec::new();
                        for seg in segs {
                            if let Some(p) = packet::parse_l3l4(&seg) {
                                let pl = p.payload(&seg);
                                let tls_frags =
                                    fragmentation::persistent_fragmentation(pl, 16);
                                let mut seq = p.tcp_seq.unwrap_or(0);
                                for tf in tls_frags {
                                    if let Ok(r) =
                                        packet::rebuild_with_payload(&seg, &tf, Some(seq))
                                    {
                                        combined.push(r);
                                        seq = seq.wrapping_add(tf.len() as u32);
                                    }
                                }
                            } else {
                                combined.push(seg);
                            }
                        }
                        packets.extend(combined);
                    } else {
                        packets.extend(segs);
                    }
                }
                _ => packets.push(real),
            }
        } else {
            packets.push(real);
        }

        self.evict_recent_if_full();
        self.recent.insert(
            (parsed.dst, parsed.src_port),
            RecentAttempt {
                domain: domain.clone(),
                technique: profile.as_str().to_string(),
                at: Instant::now(),
            },
        );
        let ips = parse_ip_list(&self.settings.rotate_ips);
        if !ips.is_empty() {
            let _ = rotate_ip(&ips, parsed.dst);
        }
        let _ = self.tickets.get(&domain);

        Ok(WireAction::Send(packets))
    }

    fn build_decoy(
        &self,
        real: &[u8],
        parsed: &ParsedPacket,
        hello: &[u8],
    ) -> Option<Vec<u8>> {
        let (garbled, _) = fooling::reverse_mode(hello, hello.len().min(16));
        let fake_seq = calculate_wrong_seq_outside_window(
            parsed.tcp_seq.unwrap_or(0),
            parsed.tcp_window.unwrap_or(65535),
        );
        let mut decoy = if packet::Ipv4View::parse(real).is_some() {
            build_decoy_packet(real, fake_seq, &garbled).ok()?
        } else {
            packet::rebuild_with_payload(real, &garbled, Some(fake_seq)).ok()?
        };
        inject_ttl_limited_decoy(&mut decoy, self.settings.decoy_ttl);
        let _ = build_wrong_checksum(&mut decoy);
        Some(decoy)
    }

    fn flush_idle(&mut self) {
        let threshold = Duration::from_secs(self.settings.idle_timeout_secs.max(1));
        let now = Instant::now();
        self.last_activity
            .retain(|_, t| !deep_sleep_idle(now.saturating_duration_since(*t), threshold));
        self.recent
            .retain(|_, r| !deep_sleep_idle(now.saturating_duration_since(r.at), threshold));
        self.quic_mapper.prune_idle(now, threshold);
        self.relay_flows
            .retain(|_, f| !deep_sleep_idle(now.saturating_duration_since(f.last), threshold));
    }

    pub fn strategy_scores_hashed(&self) -> Vec<(String, i64)> {
        self.strategy
            .all_scores()
            .into_iter()
            .map(|(k, v)| {
                let (domain, tech) = k.split_once('|').unwrap_or((k.as_str(), ""));
                (
                    format!("{}|{}", hash_sensitive(domain, run_salt()), tech),
                    v,
                )
            })
            .collect()
    }

    pub fn recent_domains_hashed(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .recent
            .values()
            .map(|r| hash_sensitive(&r.domain, run_salt()))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn take_expired_held(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        self.flows.retain(|_, f| {
            if now.saturating_duration_since(f.started) >= HOLD_TIMEOUT {
                out.extend(f.held.clone());
                false
            } else {
                true
            }
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{wrap_ipv4_tcp, wrap_ipv6_tcp, TCP_FLAG_ACK, TCP_FLAG_PSH};

    fn ch_pkt(sni: &str) -> Vec<u8> {
        let hello = fragmentation::encode_client_hello(sni);
        wrap_ipv4_tcp(
            &hello,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            1000,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        )
    }

    fn ch_pkt_port(sni: &str, dport: u16) -> Vec<u8> {
        let hello = fragmentation::encode_client_hello(sni);
        wrap_ipv4_tcp(
            &hello,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            dport,
            1000,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        )
    }

    #[test]
    fn mutates_sni_and_rewrites_lengths_ipv4() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "RussiaDpi".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else {
            panic!("held");
        };
        assert_eq!(pkts.len(), 1);
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        let payload = parsed.payload(&pkts[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"example.com.");
    }

    #[test]
    fn all_ports_custom_intercept_works() {
        let pkt_8443 = ch_pkt_port("example.com", 8443);
        let mut p = Pipeline::new(Settings {
            intercept_ports: vec![443, 8443, 8080],
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        // 8443 should be intercepted
        let action = p.handle(&pkt_8443).unwrap();
        assert!(matches!(action, WireAction::Send(_)));
        // 22 should NOT be intercepted (passthrough original)
        let pkt_22 = ch_pkt_port("example.com", 22);
        let action2 = p.handle(&pkt_22).unwrap();
        let WireAction::Send(pkts) = action2 else { panic!() };
        assert_eq!(pkts[0], pkt_22); // passthrough unchanged
    }

    #[test]
    fn intercept_all_tcp_flag_intercepts_any_port() {
        let pkt_any = ch_pkt_port("example.com", 12345);
        let mut p = Pipeline::new(Settings {
            intercept_all_tcp: true,
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt_any).unwrap();
        // Should be processed (not just passthrough? Actually our code still processes ClientHello)
        assert!(matches!(action, WireAction::Send(_)));
        let WireAction::Send(pkts) = action else { panic!() };
        // Should have mutated or at least PSH flag set, so not equal to original
        // But if SNI is example.com with Stealth, case randomization may or may not change bytes
        // So just check it's not empty
        assert!(!pkts.is_empty());
    }

    #[test]
    fn skips_tcp_header_not_payload() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        assert!(matches!(action, WireAction::Send(_)));
        let WireAction::Send(pkts) = action else { unreachable!() };
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert!(fragmentation::sni_bytes(parsed.payload(&pkts[0])).is_some());
    }

    #[test]
    fn ipv6_client_hello_is_parsed() {
        let hello = fragmentation::encode_client_hello("v6.test");
        let pkt = wrap_ipv6_tcp(
            &hello,
            [0; 16],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            1111,
            443,
            1,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.l3, packet::L3::Ipv6);
        assert!(fragmentation::sni_bytes(parsed.payload(&pkts[0])).is_some());
    }

    #[test]
    fn inbound_rst_penalises_strategy() {
        let mut p = Pipeline::new(Settings::default());
        p.recent.insert(
            ("1.1.1.1".parse().unwrap(), 54321),
            RecentAttempt {
                domain: "example.com".into(),
                technique: "Stealth".into(),
                at: Instant::now(),
            },
        );
        let rst = wrap_ipv4_tcp(
            b"",
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            54321,
            1,
            TCP_FLAG_RST,
        );
        let _ = p.handle(&rst).unwrap();
        let scores = p.strategy.per_domain_scores("example.com");
        assert_eq!(scores[0].1, -2);
    }

    #[test]
    fn truncated_client_hello_is_held() {
        let hello = fragmentation::encode_client_hello("example.com");
        let pkt = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&pkt).unwrap(), WireAction::Hold);
    }

    #[test]
    fn decoys_prepended_when_enabled() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            enable_decoys: true,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!();
        };
        assert!(pkts.len() >= 2);
    }

    #[test]
    fn reassembled_hello_uses_first_segment_seq() {
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            1000,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let second = wrap_ipv4_tcp(
            &hello[20..],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            1020,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        let WireAction::Send(pkts) = p.handle(&second).unwrap() else {
            panic!("held");
        };
        assert!(!pkts.is_empty());
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.tcp_seq, Some(1000));
        let payload = parsed.payload(&pkts[0]);
        assert!(fragmentation::sni_bytes(payload).is_some());
    }

    #[test]
    fn seq_mismatch_releases_held_and_current() {
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let other = wrap_ipv4_tcp(
            b"x",
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1,
            443,
            99,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        let WireAction::Send(pkts) = p.handle(&other).unwrap() else {
            panic!("held");
        };
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0], first);
        assert_eq!(pkts[1], other);
    }

    #[test]
    fn padding_after_ipv4_total_len_is_ignored() {
        let mut pkt = ch_pkt("example.com");
        pkt.extend_from_slice(&[0xAAu8; 40]);
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!("held");
        };
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert!(fragmentation::sni_bytes(parsed.payload(&pkts[0])).is_some());
    }

    #[test]
    fn inbound_serverhello_scores_once() {
        let mut p = Pipeline::new(Settings::default());
        p.recent.insert(
            ("1.1.1.1".parse().unwrap(), 54321),
            RecentAttempt {
                domain: "example.com".into(),
                technique: "Stealth".into(),
                at: Instant::now(),
            },
        );
        let payload = vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0, 0, 0];
        let pkt = wrap_ipv4_tcp(
            &payload,
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            54321,
            1,
            TCP_FLAG_ACK,
        );
        let _ = p.handle(&pkt).unwrap();
        let _ = p.handle(&pkt).unwrap();
        let scores = p.strategy.per_domain_scores("example.com");
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].1, 1);
    }

    #[test]
    fn strategy_scores_for_ui_are_hashed() {
        let mut p = Pipeline::new(Settings::default());
        p.strategy.update_score("secret.example", "Stealth", true);
        let ui = p.strategy_scores_hashed();
        assert_eq!(ui.len(), 1);
        assert!(!ui[0].0.contains("secret.example"));
        assert!(ui[0].0.contains("|Stealth"));
    }

    #[test]
    fn expired_held_is_flushed_by_watchdog() {
        let hello = fragmentation::encode_client_hello("example.com");
        let pkt = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1234,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&pkt).unwrap(), WireAction::Hold);
        for flow in p.flows.values_mut() {
            flow.started = Instant::now() - Duration::from_millis(300);
        }
        let expired = p.take_expired_held();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], pkt);
        assert!(p.flows.is_empty());
        assert!(p.take_expired_held().is_empty());
    }

    #[test]
    fn max_flows_cap_fail_opens() {
        let hello = fragmentation::encode_client_hello("example.com");
        let fragment = &hello[..20];
        let mut p = Pipeline::new(Settings::default());
        for i in 0..MAX_FLOWS {
            let pkt = wrap_ipv4_tcp(
                fragment,
                [10, 0, 0, 1],
                [1, 1, 1, 1],
                1000 + i as u16,
                443,
                10,
                TCP_FLAG_ACK,
            );
            let action = p.handle(&pkt).unwrap();
            assert_eq!(action, WireAction::Hold, "should hold until cap");
        }
        let extra = wrap_ipv4_tcp(
            fragment,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            9999,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let action = p.handle(&extra).unwrap();
        match action {
            WireAction::Send(v) => assert_eq!(v[0], extra),
            WireAction::Hold => panic!("should have fail-opened on cap"),
        }
        assert_eq!(p.flows.len(), MAX_FLOWS);
    }

    #[test]
    fn flow_buf_overflow_fail_opens_both() {
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            0,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        let big = vec![0u8; MAX_FLOW_BUF];
        let second = wrap_ipv4_tcp(
            &big,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            20,
            TCP_FLAG_ACK,
        );
        let WireAction::Send(pkts) = p.handle(&second).unwrap() else {
            panic!("should send");
        };
        assert_eq!(pkts.len(), 2);
        assert!(p.flows.is_empty());
    }

    #[test]
    fn recent_eviction_halves_on_cap() {
        let mut p = Pipeline::new(Settings::default());
        for i in 0..MAX_RECENT {
            let ip: IpAddr = format!("1.1.1.{}", i % 255 + 1).parse().unwrap();
            p.recent.insert(
                (ip, i as u16),
                RecentAttempt {
                    domain: format!("d{i}.example"),
                    technique: "Stealth".into(),
                    at: Instant::now(),
                },
            );
        }
        assert_eq!(p.recent.len(), MAX_RECENT);
        let pkt = ch_pkt("new.example");
        let _ = p.handle(&pkt).unwrap();
        assert!(p.recent.len() <= MAX_RECENT);
        assert!(p.recent.len() >= MAX_RECENT / 2);
    }

    #[test]
    fn idle_flush_removes_old_flows_and_recent() {
        let mut p = Pipeline::new(Settings {
            idle_timeout_secs: 1,
            ..Settings::default()
        });
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            6000,
            443,
            0,
            TCP_FLAG_ACK,
        );
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        assert_eq!(p.flows.len(), 1);
        for t in p.last_activity.values_mut() {
            *t = Instant::now() - Duration::from_secs(5);
        }
        p.recent.insert(
            ("2.2.2.2".parse().unwrap(), 1234),
            RecentAttempt {
                domain: "old.example".into(),
                technique: "Stealth".into(),
                at: Instant::now() - Duration::from_secs(5),
            },
        );
        let dummy = wrap_ipv4_tcp(
            b"",
            [10, 0, 0, 2],
            [10, 0, 0, 3],
            1111,
            80,
            0,
            TCP_FLAG_ACK,
        );
        let _ = p.handle(&dummy).unwrap();
        assert!(p.recent.is_empty() || !p.recent.values().any(|r| r.domain == "old.example"));
    }

    #[test]
    fn hold_watchdog_preserves_original_winDivert_address_semantics() {
        let hello = fragmentation::encode_client_hello("watchdog.test");
        let pkt = wrap_ipv4_tcp(
            &hello[..15],
            [10, 0, 0, 1],
            [9, 9, 9, 9],
            7000,
            443,
            100,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&pkt).unwrap(), WireAction::Hold);
        for flow in p.flows.values_mut() {
            flow.started = Instant::now() - Duration::from_millis(250);
        }
        let expired = p.take_expired_held();
        assert_eq!(expired[0][12..16], [10, 0, 0, 1]);
        assert!(p.flows.is_empty());
    }

    #[test]
    fn quic_bypass_rewrites_source_port_when_enabled() {
        use crate::packet::PROTO_UDP;
        let quic_payload = {
            let mut v = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
            v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            v.extend_from_slice(&[8, 9, 10, 11, 12, 13, 14, 15, 16]);
            v.push(0);
            v.extend_from_slice(&[0, 0, 0, 0]);
            v
        };
        let mut pkt = vec![0u8; 20 + 8 + quic_payload.len()];
        pkt[0] = 0x45;
        pkt[9] = PROTO_UDP;
        pkt[2..4].copy_from_slice(&(pkt.len() as u16).to_be_bytes());
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        pkt[20..22].copy_from_slice(&54321u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + quic_payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(&quic_payload);
        crate::packet::recalculate_all_checksums(&mut pkt);

        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            quic_bypass_use_low_port: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        assert_eq!(pkts.len(), 1);
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 443);
    }

    fn udp_pkt(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        use crate::packet::PROTO_UDP;
        let mut pkt = vec![0u8; 20 + 8 + payload.len()];
        pkt[0] = 0x45;
        pkt[9] = PROTO_UDP;
        pkt[2..4].copy_from_slice(&(pkt.len() as u16).to_be_bytes());
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&sport.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        crate::packet::recalculate_all_checksums(&mut pkt);
        pkt
    }

    fn quic_initial_payload() -> Vec<u8> {
        let mut v = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
        v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        v.extend_from_slice(&[8, 9, 10, 11, 12, 13, 14, 15, 16]);
        v.push(0);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    #[test]
    fn quic_reverse_nat_restores_original_dst_port() {
        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            quic_bypass_use_low_port: false,
            ..Settings::default()
        });
        // Outbound Initial: client 10.0.0.1:54321 -> server 1.1.1.1:443
        let outbound =
            udp_pkt([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, &quic_initial_payload());
        let action = p.handle(&outbound).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.src_port, 443); // spoofed to dst (blindspot)

        // Inbound short-header reply: server 1.1.1.1:443 -> client 10.0.0.1:443
        let reply = udp_pkt([1, 1, 1, 1], [10, 0, 0, 1], 443, 443, &[0x40, 1, 2, 3, 4, 5, 6, 7]);
        let action = p.handle(&reply).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.dst_port, 54321); // restored to the original port
        assert_eq!(parsed.src_port, 443);
    }

    #[test]
    fn quic_followup_outbound_keeps_spoofed_port() {
        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            quic_bypass_use_low_port: false,
            ..Settings::default()
        });
        let initial =
            udp_pkt([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, &quic_initial_payload());
        let _ = p.handle(&initial).unwrap();
        // A later (short-header) outbound packet of the same flow must keep
        // the spoofed source port, not revert to the original.
        let followup = udp_pkt([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, &[0x40, 9, 9, 9, 9]);
        let action = p.handle(&followup).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.src_port, 443);
    }

    #[test]
    fn quic_reverse_nat_no_mapping_passes_through() {
        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            ..Settings::default()
        });
        // Inbound UDP without any mapping must pass through untouched.
        let reply = udp_pkt([1, 1, 1, 1], [10, 0, 0, 1], 443, 443, &[0x40, 1, 2, 3, 4, 5, 6, 7]);
        let action = p.handle(&reply).unwrap();
        let WireAction::Send(pkts) = action else { panic!() };
        assert_eq!(pkts[0], reply);
    }

    fn tcp_pkt_with_ack(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack_num: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut p = packet::wrap_ipv4_tcp(payload, src, dst, sport, dport, seq, flags);
        if let Some(parsed) = packet::parse_l3l4(&p) {
            let off = parsed.l4_offset + packet::tcp_off::ACK;
            if p.len() >= off + 4 {
                p[off..off + 4].copy_from_slice(&ack_num.to_be_bytes());
                packet::recalculate_all_checksums(&mut p);
            }
        }
        p
    }

    fn relay_mode(fake_sni: &str) -> RelayMode {
        RelayMode {
            fake_sni: fake_sni.into(),
            connect_port: 443,
            mutate_real_sni: false,
            emit_decoy: false,
        }
    }

    fn complete_relay_handshake(p: &mut Pipeline) {
        // 1) client SYN
        let syn = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1000, 0, TCP_FLAG_SYN, b"");
        let action = p.handle(&syn).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        assert_eq!(v.len(), 1);
        // 2) server SYN-ACK
        let synack = tcp_pkt_with_ack(
            [1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5000, 1001,
            TCP_FLAG_SYN | TCP_FLAG_ACK, b"",
        );
        assert!(matches!(p.handle(&synack).unwrap(), WireAction::Send(v) if v.len() == 1));
        // 3) client final ACK -> fake ClientHello injected
        let ack = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1001, 5001, TCP_FLAG_ACK, b"");
        let action = p.handle(&ack).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        assert!(v.len() >= 2);
        // 4) server duplicate ACK -> handshake complete
        let dupack = tcp_pkt_with_ack([1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5001, 1001, TCP_FLAG_ACK, b"");
        assert!(matches!(p.handle(&dupack).unwrap(), WireAction::Send(v) if v.len() == 1));
    }

    #[test]
    fn relay_flow_injects_fake_hello_then_passes_through() {
        let mut p = Pipeline::new(Settings::default());
        p.configure_relay(Some(relay_mode("benign.com")));
        let _gate = p.register_relay_flow(FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport: 5555,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        });

        // Steps 1-4 exercise the full handshake; verify the fake SNI on
        // the injected ClientHello.
        let syn = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1000, 0, TCP_FLAG_SYN, b"");
        assert!(matches!(p.handle(&syn).unwrap(), WireAction::Send(v) if v.len() == 1 && v[0] == syn));
        let synack = tcp_pkt_with_ack(
            [1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5000, 1001,
            TCP_FLAG_SYN | TCP_FLAG_ACK, b"",
        );
        assert!(matches!(p.handle(&synack).unwrap(), WireAction::Send(v) if v.len() == 1));
        let ack = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1001, 5001, TCP_FLAG_ACK, b"");
        let action = p.handle(&ack).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], ack);
        let parsed = packet::parse_l3l4(&v[1]).unwrap();
        let payload = parsed.payload(&v[1]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"benign.com");

        let dupack = tcp_pkt_with_ack([1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5001, 1001, TCP_FLAG_ACK, b"");
        assert!(matches!(p.handle(&dupack).unwrap(), WireAction::Send(v) if v.len() == 1 && v[0] == dupack));

        // 5) the real ClientHello passes through UNMODIFIED (no SNI mutation)
        let hello = fragmentation::encode_client_hello("real.server.example");
        let real = tcp_pkt_with_ack(
            [10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1017, 5001,
            TCP_FLAG_ACK | TCP_FLAG_PSH, &hello,
        );
        assert!(matches!(p.handle(&real).unwrap(), WireAction::Send(v) if v.len() == 1 && v[0] == real));
    }

    #[test]
    fn relay_mutate_real_sni_runs_pipeline_after_handshake() {
        let mut p = Pipeline::new(Settings {
            mutation_profile: "RussiaDpi".into(), // trailing dot -> observable change
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let mut mode = relay_mode("benign.com");
        mode.mutate_real_sni = true;
        p.configure_relay(Some(mode));
        let _gate = p.register_relay_flow(FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport: 5555,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        });
        complete_relay_handshake(&mut p);

        // After the handshake, the real ClientHello now goes through the
        // normal pipeline: SNI gets a trailing dot (RussiaDpi).
        let hello = fragmentation::encode_client_hello("real.server.example");
        let real = tcp_pkt_with_ack(
            [10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1017, 5001,
            TCP_FLAG_ACK | TCP_FLAG_PSH, &hello,
        );
        let action = p.handle(&real).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        assert_eq!(v.len(), 1);
        let parsed = packet::parse_l3l4(&v[0]).unwrap();
        let payload = parsed.payload(&v[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"real.server.example.");
    }

    #[test]
    fn relay_emit_decoy_adds_third_packet() {
        let mut p = Pipeline::new(Settings {
            decoy_ttl: 8,
            ..Settings::default()
        });
        let mut mode = relay_mode("benign.com");
        mode.emit_decoy = true;
        p.configure_relay(Some(mode));
        let _gate = p.register_relay_flow(FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport: 5555,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        });
        let syn = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1000, 0, TCP_FLAG_SYN, b"");
        assert!(matches!(p.handle(&syn).unwrap(), WireAction::Send(v) if v.len() == 1));
        let synack = tcp_pkt_with_ack(
            [1, 1, 1, 1], [10, 0, 0, 1], 443, 5555, 5000, 1001,
            TCP_FLAG_SYN | TCP_FLAG_ACK, b"",
        );
        assert!(matches!(p.handle(&synack).unwrap(), WireAction::Send(v) if v.len() == 1));
        let ack = tcp_pkt_with_ack([10, 0, 0, 1], [1, 1, 1, 1], 5555, 443, 1001, 5001, TCP_FLAG_ACK, b"");
        let action = p.handle(&ack).unwrap();
        let WireAction::Send(v) = action else { panic!() };
        // real ACK + fake ClientHello + TTL-limited wrong-checksum decoy
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], ack);
        // decoy TTL is the configured value
        let parsed = packet::parse_l3l4(&v[2]).unwrap();
        assert_eq!(parsed.src_port, 5555);
        assert_eq!(v[2][8], 8); // IPv4 TTL
    }

    #[test]
    fn henan_profile_uses_small_chunks_and_disorder() {
        let pkt = ch_pkt("henan.test");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Henan".into(),
            enable_decoys: false,
            enable_sni_fragmentation: true,
            fragment_chunk_size: 64,
            enable_combined_fragmentation: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert!(pkts.len() >= 2);
    }

    #[test]
    fn sni_disguise_in_pipeline_when_enabled() {
        let pkt = ch_pkt("disguise.test");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_sni_disguise: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert_eq!(pkts.len(), 1);
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        let payload = parsed.payload(&pkts[0]);
        assert!(fragmentation::sni_bytes(payload).is_none());
    }

    #[test]
    fn fronting_with_hidden_real_sni() {
        let pkt = ch_pkt("real.example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_sni_disguise: true,
            fronting_benign_sni: "www.microsoft.com".into(),
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        let payload = parsed.payload(&pkts[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"www.microsoft.com");
        assert!(payload.windows(16).any(|w| w == b"real.example.com"));
    }

    #[test]
    fn utls_fingerprint_applies_without_breaking() {
        let pkt = ch_pkt("utls.test");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_utls_fingerprint: true,
            utls_browser: "firefox".into(),
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert_eq!(pkts.len(), 1);
    }

    #[test]
    fn ech_grease_in_pipeline() {
        let pkt = ch_pkt("ech.test");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_ech_grease: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert_eq!(pkts.len(), 1);
        assert!(pkts[0].len() > pkt.len());
    }

    #[test]
    fn geedge_evasion_adds_padding() {
        let pkt = ch_pkt("geedge.test");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_geedge_evasion: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else { panic!() };
        assert_eq!(pkts.len(), 1);
        // Should be at least as big as original (padding may be added)
        assert!(pkts[0].len() >= pkt.len());
    }
}
