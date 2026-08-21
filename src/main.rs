//! dpi_guard binary entry point.
//!
//! Windows: config → pipeline → WinDivert capture thread, Ctrl+C via
//! tokio::signal (not the `ctrlc` crate). Other OS: print a platform
//! message and exit 1; `cargo test` still exercises every pure-logic module.

#[cfg(windows)]
fn main() {
    use dpi_guard::{config, engine, pipeline::Pipeline, webui};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    /// Identity of a running relay, used to detect config changes that
    /// require a restart.
    #[derive(Clone, PartialEq)]
    struct RelayId {
        enabled: bool,
        listen_port: u16,
        connect_host: String,
        connect_port: u16,
        fake_sni: String,
        resolve_doh: bool,
        doh_server: String,
        mutate_real_sni: bool,
        emit_decoy: bool,
    }

    /// Owns the relay thread and restarts it whenever the relay-related
    /// settings change (including via the dashboard's Start/Stop buttons,
    /// which save `relay_enabled` and rely on the hot-reload watcher).
    struct RelayRuntime {
        flag: Option<Arc<AtomicBool>>,
        handle: Option<std::thread::JoinHandle<()>>,
        id: Option<RelayId>,
    }

    impl RelayRuntime {
        fn new() -> Self {
            Self {
                flag: None,
                handle: None,
                id: None,
            }
        }

        fn desired(settings: &config::Settings) -> RelayId {
            RelayId {
                enabled: settings.relay_enabled,
                listen_port: settings.relay_listen_port,
                connect_host: settings.relay_connect_host.clone(),
                connect_port: settings.relay_connect_port,
                fake_sni: settings.relay_fake_sni.clone(),
                resolve_doh: settings.relay_resolve_doh,
                doh_server: settings.doh_server.clone(),
                mutate_real_sni: settings.relay_mutate_real_sni,
                emit_decoy: settings.relay_emit_decoy,
            }
        }

        fn stop(&mut self) {
            if let Some(f) = self.flag.take() {
                f.store(false, Ordering::SeqCst);
            }
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
            self.id = None;
        }

        fn reconcile(&mut self, settings: &config::Settings, pipeline: Arc<Mutex<Pipeline>>) {
            let want = Self::desired(settings);
            if self.id.as_ref() == Some(&want) {
                return;
            }
            if !want.enabled {
                self.stop();
                {
                    let mut p = dpi_guard::recover_mutex(&pipeline);
                    p.configure_relay(None);
                }
                return;
            }
            // Resolve BEFORE tearing down the old relay: fail-closed, keep
            // the previous relay running if the new destination won't resolve.
            let connect_ip = if want.resolve_doh {
                match dpi_guard::doh::resolve_a_v4(&want.connect_host, &want.doh_server).and_then(
                    |ips| {
                        ips.into_iter().next().ok_or_else(|| {
                            dpi_guard::DpiGuardError::Resolution("no addresses resolved".into())
                        })
                    },
                ) {
                    Ok(ip) => ip,
                    Err(e) => {
                        log::error!("relay destination resolution failed: {e}");
                        return;
                    }
                }
            } else {
                match want.connect_host.parse::<std::net::IpAddr>() {
                    Ok(ip) => ip,
                    Err(e) => {
                        log::error!(
                            "relay_connect_host is not an IP and relay_resolve_doh is off: {e}"
                        );
                        return;
                    }
                }
            };
            self.stop();
            {
                let mut p = dpi_guard::recover_mutex(&pipeline);
                p.configure_relay(Some(dpi_guard::relay::RelayMode {
                    fake_sni: want.fake_sni.clone(),
                    connect_port: want.connect_port,
                    mutate_real_sni: want.mutate_real_sni,
                    emit_decoy: want.emit_decoy,
                }));
            }
            let target = dpi_guard::relay::RelayTarget {
                connect_ip,
                connect_port: want.connect_port,
                fake_sni: want.fake_sni.clone(),
            };
            let flag = Arc::new(AtomicBool::new(true));
            let pipe = pipeline.clone();
            match dpi_guard::relay::run(target, want.listen_port, flag.clone(), move |flow| {
                let mut p = dpi_guard::recover_mutex(&pipe);
                p.register_relay_flow(flow)
            }) {
                Ok(h) => {
                    log::info!(
                        "relay started: 127.0.0.1:{} -> {}:{} (fake SNI {})",
                        want.listen_port,
                        connect_ip,
                        want.connect_port,
                        want.fake_sni
                    );
                    self.flag = Some(flag);
                    self.handle = Some(h);
                    self.id = Some(want);
                }
                Err(e) => log::error!("relay start failed: {e}"),
            }
        }
    }

    engine::thread_safe_logging_init();

    let (explicit_path, settings_path) = match std::env::args().nth(1) {
        Some(p) => (true, p),
        None => (false, "dpi_guard.toml".to_string()),
    };
    let path = std::path::Path::new(&settings_path);
    let settings = if path.exists() {
        match config::load_from_file(path) {
            Ok(s) => s,
            Err(e) => {
                log::error!("invalid config {settings_path}: {e}");
                std::process::exit(1);
            }
        }
    } else if explicit_path {
        log::error!("config file not found: {settings_path}");
        std::process::exit(1);
    } else {
        log::warn!("no dpi_guard.toml next to the process; using compiled defaults");
        config::Settings::default()
    };
    log::info!("loaded settings: {:?}", settings);
    log::info!("RUST_LOG controls verbosity (default dpi_guard=info)");

    if settings.enable_swap_foolers {
        log::warn!(
            "enable_swap_foolers is ON: this injects forged RST/SYN-ACK packets with swapped \
             endpoints, which network IDS/EDR may flag as packet-injection attacks and which can \
             disturb other connections sharing the 5-tuple. Leave OFF unless you know why you need it."
        );
    }

    // DNS-leak warning: the WFP DNS block is a STUB in this build, so the
    // domain is still sent in plaintext over port 53 unless the host uses
    // DoH/DoT. SNI mutation alone does not hide the visited hostname.
    log::warn!(
        "DNS leak protection is INACTIVE (WFP FFI is a stub): port-53 queries are plaintext. \
         SNI mutation does not hide the domain from a resolver that logs queries. Use DoH/DoT."
    );

    if let Err(e) = engine::version_check(&settings.win_divert_sha256) {
        log::error!("{e}");
        std::process::exit(1);
    }

    if settings.enable_kill_switch {
        match dpi_guard::stealth::kill_switch_trigger(
            &settings.kill_switch_adapter,
            true,
        ) {
            Ok(Some(cmd)) => log::warn!(
                "kill switch ARMED (not spawned). command would be: {cmd}"
            ),
            Ok(None) => {}
            Err(e) => log::error!("kill switch config rejected: {e}"),
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let processed = Arc::new(AtomicU64::new(0));
    let pipeline = Arc::new(Mutex::new(Pipeline::new(settings.clone())));
    let pipeline_cap = pipeline.clone();
    let running_cap = running.clone();
    let processed_cap = processed.clone();
    let filter = dpi_guard::build_filter(&settings);
    log::info!("WinDivert filter: {filter} (ports: {:?}, all_tcp={}, all_udp={})", settings.effective_ports(), settings.intercept_all_tcp, settings.intercept_all_udp);
    if settings.intercept_all_tcp || settings.intercept_all_udp {
        log::warn!("ALL PORTS mode is ON - will intercept ALL TCP/UDP traffic! High risk, use only for testing specific ports via intercept_ports.");
    }
    if settings.enable_quic_port_bypass {
        log::warn!("QUIC port blindspot bypass ON: will spoof UDP src port to <= dst port for QUIC Initial. Requires WinDivert kernel driver.");
    }
    if settings.enable_sni_disguise {
        log::warn!("SNI disguise ON: changes SNI ext type 0x0000 -> GREASE/private. Breaks vhost unless fronting_benign_sni is set.");
    }
    if !settings.fronting_benign_sni.is_empty() {
        log::info!("Domain fronting: benign SNI {} will be used, real SNI hidden in 0xFF01 if disguise ON", settings.fronting_benign_sni);
    }
    if settings.enable_utls_fingerprint {
        log::info!("uTLS fingerprint rotation ON: mimicking {} with JA3/JA4 rotation", settings.utls_browser);
    }
    if settings.enable_ech_grease {
        log::info!("ECH GREASE injection ON");
    }
    if settings.enable_md5sig_fooling {
        log::warn!("MD5SIG fooling ON: adds TCP option 19, breaks some servers, IDS may flag");
    }

    // Relay controller: starts/stops the relay and restarts it whenever the
    // relay config changes (startup + hot-reload + dashboard Save/Start/Stop).
    let mut relay_rt = RelayRuntime::new();
    relay_rt.reconcile(&settings, pipeline.clone());

    let capture = std::thread::Builder::new()
        .name("dpi_guard-capture".into())
        .spawn(move || {
            engine::capture_loop(&filter, running_cap, move |raw| {
                processed_cap.fetch_add(1, Ordering::Relaxed);
                let mut p = dpi_guard::recover_mutex(&pipeline_cap);
                // Only this packet. Expired holds are flushed by the
                // watchdog with their *original* WinDivert addresses —
                // mixing them into this Send would stamp the wrong address
                // and can black-hole the held flow.
                p.handle(&raw)
            })
        })
        .expect("spawn capture thread");

    // Optional local dashboard (127.0.0.1, bearer token). OFF by default.
    let snapshot = Arc::new(Mutex::new(webui::DashboardSnapshot::default()));
    let requested_profile = Arc::new(Mutex::new(None::<String>));
    if settings.enable_web_ui {
        let token = if settings.web_ui_token.is_empty() {
            let t = dpi_guard::stealth::generate_token();
            log::warn!("web UI token (auto-generated): {t}");
            t
        } else {
            settings.web_ui_token.clone()
        };
        match webui::start(
            settings.web_ui_port,
            token,
            snapshot.clone(),
            requested_profile.clone(),
            pipeline.clone(),
            std::path::PathBuf::from(settings_path.clone()),
            running.clone(),
        ) {
            Ok(_) => {}
            Err(e) => log::error!("web UI failed to start: {e}"),
        }
    }

    // Hot-reload watcher on a second thread (1s poll). Also refreshes the
    // dashboard snapshot and applies any profile chosen via the web UI.
    let reload_running = running.clone();
    let reload_pipeline = pipeline.clone();
    let reload_path = settings_path.clone();
    let reload_snapshot = snapshot.clone();
    let reload_requested = requested_profile.clone();
    let reload_processed = processed.clone();
    std::thread::spawn(move || {
        let mut watcher = config::HotReloadWatcher::new(std::path::PathBuf::from(reload_path));
        let mut last_cfg = std::time::Instant::now();
        while reload_running.load(Ordering::SeqCst) {
            // 200ms so HOLD_TIMEOUT held packets are flushed even if no
            // further 443 traffic arrives to tick the capture callback.
            std::thread::sleep(std::time::Duration::from_millis(200));
            let expired = {
                let mut p = dpi_guard::recover_mutex(&reload_pipeline);
                p.take_expired_held()
            };
            if !expired.is_empty() {
                if let Err(e) = engine::reinject_held_packets(&expired) {
                    log::warn!("failed to flush held packet: {e}");
                }
            }
            if last_cfg.elapsed() >= std::time::Duration::from_secs(1) {
                last_cfg = std::time::Instant::now();
                match watcher.reload_if_changed() {
                    Ok(Some(s)) => {
                        log::info!("config reloaded: {:?}", s);
                        let new_filter = dpi_guard::build_filter(&s);
                        let filter_changed = {
                            let mut p = dpi_guard::recover_mutex(&reload_pipeline);
                            let old_filter = dpi_guard::build_filter(&p.settings);
                            p.settings = s.clone();
                            old_filter != new_filter
                        };
                        if filter_changed {
                            log::info!(
                                "intercept ports / all-ports flags changed — requesting \
                                 WinDivert filter reload"
                            );
                            engine::request_filter_reload(&new_filter);
                        }
                        // Apply relay start/stop/config changes (the dashboard
                        // Start/Stop buttons save relay_enabled and land here).
                        relay_rt.reconcile(&s, reload_pipeline.clone());
                    }
                    Ok(None) => {}
                    Err(e) => log::warn!("config reload failed: {e}"),
                }
                let mut p = dpi_guard::recover_mutex(&reload_pipeline);
                if let Some(prof) = dpi_guard::recover_mutex(&reload_requested).take() {
                    log::info!("mutation profile set via web UI: {prof}");
                    p.settings.mutation_profile = prof;
                }
                let mut snap = dpi_guard::recover_mutex(&reload_snapshot);
                *snap = webui::DashboardSnapshot {
                    mutation_profile: p.settings.mutation_profile.clone(),
                    decoy_ttl: p.settings.decoy_ttl,
                    idle_timeout_secs: p.settings.idle_timeout_secs,
                    fragment_chunk_size: p.settings.fragment_chunk_size,
                    enable_decoys: p.settings.enable_decoys,
                    enable_sni_fragmentation: p.settings.enable_sni_fragmentation,
                    enable_swap_foolers: p.settings.enable_swap_foolers,
                    enable_kill_switch: p.settings.enable_kill_switch,
                    processed_packets: reload_processed.load(Ordering::Relaxed),
                    strategy_scores: p.strategy_scores_hashed(),
                    recent_domains: p.recent_domains_hashed(),
                    intercept_ports: p.settings.effective_ports(),
                    enable_quic_bypass: p.settings.enable_quic_port_bypass,
                    enable_sni_disguise: p.settings.enable_sni_disguise,
                    fronting_benign: p.settings.fronting_benign_sni.clone(),
                    enable_utls: p.settings.enable_utls_fingerprint,
                    enable_ech_grease: p.settings.enable_ech_grease,
                    relay_enabled: p.settings.relay_enabled,
                    relay_listen_port: p.settings.relay_listen_port,
                };
            }
        }
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Ctrl+C received");
        let _ = engine::graceful_shutdown(running.clone());
    });

    match capture.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            log::error!("capture loop exited with error: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            log::error!("capture thread panicked");
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "dpi_guard: packet capture/injection needs Windows + the WinDivert driver.\n\
         This build ({os}) can still run the test suite for every pure-logic module:\n\
         \n    cargo test\n\
         \nLogging: RUST_LOG=dpi_guard=debug cargo test\n\
         See src/engine.rs for the Windows-only capture/inject implementation.",
        os = std::env::consts::OS
    );
    std::process::exit(1);
}
