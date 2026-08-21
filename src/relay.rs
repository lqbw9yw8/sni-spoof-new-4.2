//! relay — patterniha-style local TCP relay. [DONE] for the loop + the
//! handshake state machine; the Windows fake-SNI *injection* lives in
//! `engine.rs` (WinDivert) and is wired from `main`.
//!
//! v2rayN (or any client) connects to `127.0.0.1:<relay_listen_port>`; each
//! accepted connection is relayed to the single fixed destination
//! `<connect_ip>:<connect_port>`. Binding loopback + a fixed destination
//! means this can never become an open proxy that third parties abuse.

use crate::error::DpiGuardError;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Notify;

/// How long the relay waits for the fake-SNI injection handshake to complete
/// before failing open (relaying anyway). Mirrors patterniha's 2s timeout.
const FAKE_ACK_WAIT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
pub struct RelayTarget {
    pub connect_ip: IpAddr,
    pub connect_port: u16,
    pub fake_sni: String,
}

/// Behaviour knobs for relay-mode evasion, kept separate from the transport
/// (`RelayTarget`) so the pipeline can carry them without an IP address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayMode {
    /// Benign SNI shown to the DPI in the injected fake ClientHello.
    pub fake_sni: String,
    /// Real destination port (used to recognise relay flows for mutation).
    pub connect_port: u16,
    /// Item 1: after the fake handshake completes, also run the flow's real
    /// ClientHello through the normal SNI-mutation pipeline (default false).
    pub mutate_real_sni: bool,
    /// Item 2: at injection time, also emit a TTL-limited wrong-checksum
    /// decoy copy of the fake ClientHello (default false).
    pub emit_decoy: bool,
}

/// The real 4-tuple of an established relay connection. The Windows glue
/// uses this to recognise the flow's packets for handshake monitoring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowInfo {
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
}

/// Source address the OS would use to reach `dst`, discovered with the UDP
/// connect trick (no packets are actually sent). Needed so the relay can bind
/// its outbound socket *before* the TCP handshake and know the source port
/// the WinDivert side must monitor.
pub fn local_ip_for(dst: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if dst.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        "::0".parse().ok()?
    };
    let sock = std::net::UdpSocket::bind(bind).ok()?;
    sock.connect((dst, 1)).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Run the relay accept loop on a dedicated thread (own current-thread tokio
/// runtime). `on_flow` is called once per connection *before* the outbound
/// handshake with the real 4-tuple, and returns a `Notify` gate the relay
/// awaits before relaying (so the fake ClientHello is injected first).
pub fn run<F>(
    target: RelayTarget,
    listen_port: u16,
    running: Arc<AtomicBool>,
    on_flow: F,
) -> Result<std::thread::JoinHandle<()>, DpiGuardError>
where
    F: Fn(FlowInfo) -> Arc<Notify> + Send + Sync + 'static,
{
    std::thread::Builder::new()
        .name("dpi_guard-relay".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("relay tokio runtime");
            rt.block_on(async move {
                relay_loop(target, listen_port, running, Arc::new(on_flow)).await;
            });
        })
        .map_err(|e| DpiGuardError::Io(std::io::Error::new(e.kind(), format!("relay spawn: {e}"))))
}

async fn relay_loop<F>(
    target: RelayTarget,
    listen_port: u16,
    running: Arc<AtomicBool>,
    on_flow: Arc<F>,
) where
    F: Fn(FlowInfo) -> Arc<Notify> + Send + Sync + 'static,
{
    let addr: SocketAddr = ([127, 0, 0, 1], listen_port).into();
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("relay bind {addr} failed: {e}");
            return;
        }
    };
    log::info!(
        "relay listening on {addr} -> {}:{} (fake SNI: {})",
        target.connect_ip,
        target.connect_port,
        target.fake_sni
    );

    while running.load(Ordering::SeqCst) {
        // Non-blocking-ish accept so shutdown is prompt.
        let accept = tokio::select! {
            r = listener.accept() => r,
            _ = tokio::time::sleep(Duration::from_millis(200)) => continue,
        };
        let (client, _peer) = match accept {
            Ok(x) => x,
            Err(e) => {
                log::debug!("relay accept error: {e}");
                continue;
            }
        };
        let target = target.clone();
        let cb = on_flow.clone();
        tokio::spawn(async move {
            handle_conn(client, target, cb).await;
        });
    }
}

async fn handle_conn<F>(client: TcpStream, target: RelayTarget, on_flow: Arc<F>)
where
    F: Fn(FlowInfo) -> Arc<Notify> + Send + Sync + 'static,
{
    let local_ip = match local_ip_for(target.connect_ip) {
        Some(ip) => ip,
        None => {
            log::warn!("cannot determine local IP for {}", target.connect_ip);
            return;
        }
    };
    // Bind before connecting so the source port is known *before* the TCP
    // handshake — the monitor must recognise SYN/SYN-ACK/ACK by 4-tuple.
    let socket = match if target.connect_ip.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    } {
        Ok(s) => s,
        Err(e) => {
            log::warn!("relay socket create failed: {e}");
            return;
        }
    };
    if let Err(e) = socket.bind(SocketAddr::new(local_ip, 0)) {
        log::warn!("relay socket bind failed: {e}");
        return;
    }
    let sport = match socket.local_addr() {
        Ok(a) => a.port(),
        Err(e) => {
            log::warn!("relay socket local_addr failed: {e}");
            return;
        }
    };
    let flow = FlowInfo {
        src: local_ip,
        sport,
        dst: target.connect_ip,
        dport: target.connect_port,
    };
    let gate = on_flow(flow);

    let server = match socket
        .connect(SocketAddr::new(target.connect_ip, target.connect_port))
        .await
    {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "relay connect {}:{} failed: {e}",
                target.connect_ip,
                target.connect_port
            );
            return;
        }
    };
    let _ = server.set_nodelay(true);

    // Wait for the fake-SNI injection to complete before relaying the real
    // ClientHello. Fail-open (relay anyway) after the timeout.
    let _ = tokio::time::timeout(FAKE_ACK_WAIT, gate.notified()).await;

    let (mut client_r, mut client_w) = client.into_split();
    let (mut server_r, mut server_w) = server.into_split();
    let a = tokio::io::copy(&mut client_r, &mut server_w);
    let b = tokio::io::copy(&mut server_r, &mut client_w);
    let _ = tokio::join!(a, b);
    // Best-effort FIN to the client so v2rayN sees a clean close.
    let _ = client_w.shutdown().await;
}

/// Pure TCP-handshake state machine for the fake-SNI injection
/// (patterniha's `wrong_seq` technique). No I/O: the caller feeds observed
/// handshake packets and performs the returned action. Unit-testable on any
/// OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsAction {
    /// Re-inject the real packet unchanged (handshake still in progress).
    Pass,
    /// After passing this packet through (the final ACK of the 3-way
    /// handshake), inject the fake ClientHello.
    InjectFake,
    /// The server ACKed the fake (duplicate ACK): stop monitoring and relay
    /// the real bytes.
    Complete,
    /// Unexpected packet: abort the connection (fail-closed).
    Fail,
}

#[derive(Debug)]
pub struct HandshakeMonitor {
    syn_seq: i64,
    syn_ack_seq: i64,
    fake_sent: bool,
    scheduled_fake: bool,
}

fn add1(seq: i64) -> u32 {
    ((seq + 1) & 0xFFFF_FFFF) as u32
}

impl HandshakeMonitor {
    pub fn new() -> Self {
        Self {
            syn_seq: -1,
            syn_ack_seq: -1,
            fake_sent: false,
            scheduled_fake: false,
        }
    }

    /// The sequence number to stamp on the fake ClientHello: it occupies
    /// `[syn_seq+1-len, syn_seq+1)`, i.e. ends exactly where the server next
    /// expects data, so a real TCP stack ACKs it as already-received and
    /// drops it while a stateless DPI still parses the TLS record.
    pub fn fake_seq_for(&self, payload_len: usize) -> u32 {
        (self.syn_seq + 1 - payload_len as i64) as u32
    }

    pub fn mark_fake_sent(&mut self) {
        self.fake_sent = true;
    }

    pub fn on_outbound(
        &mut self,
        syn: bool,
        ack: bool,
        rst: bool,
        fin: bool,
        seq: u32,
        ack_num: u32,
        payload_len: usize,
    ) -> HsAction {
        if self.scheduled_fake {
            return HsAction::Fail;
        }
        // SYN (no ACK): the first packet of the handshake.
        if syn && !ack && !rst && !fin && payload_len == 0 {
            if ack_num != 0 {
                return HsAction::Fail;
            }
            if self.syn_seq != -1 && self.syn_seq as u32 != seq {
                return HsAction::Fail;
            }
            self.syn_seq = seq as i64;
            return HsAction::Pass;
        }
        // Final ACK (no SYN, no payload): completes the 3-way handshake.
        if ack && !syn && !rst && !fin && payload_len == 0 {
            if self.syn_seq == -1 || seq != add1(self.syn_seq) {
                return HsAction::Fail;
            }
            if self.syn_ack_seq == -1 || ack_num != add1(self.syn_ack_seq) {
                return HsAction::Fail;
            }
            self.scheduled_fake = true;
            return HsAction::InjectFake;
        }
        HsAction::Fail
    }

    pub fn on_inbound(
        &mut self,
        syn: bool,
        ack: bool,
        rst: bool,
        fin: bool,
        seq: u32,
        ack_num: u32,
        payload_len: usize,
    ) -> HsAction {
        if self.syn_seq == -1 {
            return HsAction::Fail;
        }
        // SYN-ACK.
        if ack && syn && !rst && !fin && payload_len == 0 {
            if self.syn_ack_seq != -1 && self.syn_ack_seq as u32 != seq {
                return HsAction::Fail;
            }
            if ack_num != add1(self.syn_seq) {
                return HsAction::Fail;
            }
            self.syn_ack_seq = seq as i64;
            return HsAction::Pass;
        }
        // Duplicate ACK after the fake was injected: server saw old data.
        if ack && !syn && !rst && !fin && payload_len == 0 && self.fake_sent {
            if self.syn_ack_seq == -1 || seq != add1(self.syn_ack_seq) {
                return HsAction::Fail;
            }
            if ack_num != add1(self.syn_seq) {
                return HsAction::Fail;
            }
            return HsAction::Complete;
        }
        HsAction::Fail
    }
}

impl Default for HandshakeMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_happy_path(mon: &mut HandshakeMonitor) {
        // 1. client SYN
        assert_eq!(
            mon.on_outbound(true, false, false, false, 1000, 0, 0),
            HsAction::Pass
        );
        // 2. server SYN-ACK
        assert_eq!(
            mon.on_inbound(false, true, false, false, 5000, 1001, 0),
            HsAction::Pass
        );
        // 3. client final ACK -> inject fake
        assert_eq!(
            mon.on_outbound(false, true, false, false, 1001, 5001, 0),
            HsAction::InjectFake
        );
    }

    #[test]
    fn fake_seq_lands_one_past_syn() {
        let mut mon = HandshakeMonitor::new();
        run_happy_path(&mut mon);
        // Fake occupies [syn+1-len, syn+1) == ends exactly at syn+1.
        assert_eq!(mon.fake_seq_for(517), 1000 + 1 - 517);
        // Wraps mod 2^32 for payloads larger than syn+1.
        assert_eq!(mon.fake_seq_for(5000), ((1001 - 5000) as i64) as u32);
    }

    #[test]
    fn happy_path_completes_after_dup_ack() {
        let mut mon = HandshakeMonitor::new();
        run_happy_path(&mut mon);
        mon.mark_fake_sent();
        assert_eq!(
            mon.on_inbound(false, true, false, false, 5001, 1001, 0),
            HsAction::Complete
        );
    }

    #[test]
    fn wrong_seq_is_rejected() {
        let mut mon = HandshakeMonitor::new();
        assert_eq!(
            mon.on_outbound(true, false, false, false, 1000, 0, 0),
            HsAction::Pass
        );
        assert_eq!(
            mon.on_inbound(false, true, false, false, 5000, 1001, 0),
            HsAction::Pass
        );
        // ACK with a seq that doesn't equal syn_seq+1 -> Fail
        assert_eq!(
            mon.on_outbound(false, true, false, false, 999, 5001, 0),
            HsAction::Fail
        );
    }

    #[test]
    fn syn_with_nonzero_ack_is_rejected() {
        let mut mon = HandshakeMonitor::new();
        assert_eq!(
            mon.on_outbound(true, false, false, false, 1000, 5, 0),
            HsAction::Fail
        );
    }

    #[test]
    fn outbound_after_fake_scheduled_is_rejected() {
        let mut mon = HandshakeMonitor::new();
        run_happy_path(&mut mon);
        // Any further outbound packet before injection completes -> Fail
        assert_eq!(
            mon.on_outbound(false, true, false, false, 1001, 5001, 0),
            HsAction::Fail
        );
    }

    #[test]
    fn inbound_dupack_before_fake_sent_is_rejected() {
        let mut mon = HandshakeMonitor::new();
        run_happy_path(&mut mon);
        // fake_sent is still false, so a bare ACK is unexpected -> Fail
        assert_eq!(
            mon.on_inbound(false, true, false, false, 5001, 1001, 0),
            HsAction::Fail
        );
    }
}
