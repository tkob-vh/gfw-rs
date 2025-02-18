use std::path::Path;
use std::{sync::Arc, time::Duration};

use clap::Parser;
use cmd::config::load_config_from_file;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, error, info};

use nt_engine::Engine;
use nt_ruleset::expr_rule::read_expr_rules_from_file;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[clap(short, long)]
    config_file: String,
    #[clap(short, long)]
    ruleset_file: String,
    #[clap(short, long)]
    pcap_file: Option<String>,
    #[clap(short, long, default_value_t=tracing::Level::INFO)]
    log_level: tracing::Level,
}

#[tokio::main]
async fn main() {
    // Setup analyzers
    let analyzers: Vec<Arc<dyn nt_analyzer::Analyzer>> = vec![
        Arc::new(nt_analyzer::tcp::http::HTTPAnalyzer::new()),
        Arc::new(nt_analyzer::tcp::tls::TLSAnalyzer::new()),
        Arc::new(nt_analyzer::udp::dns::DNSAnalyzer::new()),
        Arc::new(nt_analyzer::udp::openvpn::OpenVPNAnalyzer::new()),
        Arc::new(nt_analyzer::udp::wireguard::WireGuardAnalyzer::new()),
    ];

    let modifiers: Vec<Arc<dyn nt_modifier::Modifier>> =
        vec![Arc::new(nt_modifier::udp::dns::DNSModifier::new())];

    let cli = Cli::parse();

    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(cli.log_level)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(true)
        .init();

    debug!("Loading config from {}...", &cli.config_file);
    let config = load_config_from_file(&cli.config_file)
        .await
        .map_err(|e| format!("failed to parse config file: {}", e))
        .unwrap();
    debug!("config: {:?}", config);

    debug!("Setting up the io...");
    let io_impl: Arc<dyn nt_io::PacketIO> = if cli.pcap_file.is_some() {
        let pcap_file = cli.pcap_file.unwrap();
        debug!("Replaying from pcap file {:?}", &pcap_file);
        Arc::new(
            nt_io::pcap::PcapPacketIO::new(nt_io::pcap::PcapPacketIOConfig {
                pcap_file,
                real_time: config.replay.realtime,
            })
            .unwrap(),
        )
    } else {
        debug!("Setup IO for nfqueue...");
        Arc::new(
            nt_io::nfqueue::NFQueuePacketIO::new(nt_io::nfqueue::NFQueuePacketIOConfig {
                queue_size: config.io.queue_size,
                local: config.io.local,
                rst: config.io.rst,
            })
            .unwrap(),
        )
    };

    debug!("Setting up the ruleset engine");
    let engine = Arc::new(rhai::Engine::new());

    debug!("Loading the ruleset from {}...", &cli.ruleset_file);
    let raw_rs = read_expr_rules_from_file(&cli.ruleset_file)
        .await
        .map_err(|e| format!("failed to parse ruleset file: {}", e))
        .unwrap();
    debug!("rules: {:?}", raw_rs);

    debug!("Compiling the rules");
    let rs = nt_ruleset::expr_rule::compile_expr_rules(raw_rs, &analyzers, &modifiers, engine);

    let engine_config = nt_engine::Config {
        workers: config.workers.count,
        worker_queue_size: config.workers.queue_size,
        worker_tcp_max_buffered_pages_total: config.workers.tcp_max_buffered_pages_total,
        worker_tcp_max_buffered_pages_per_conn: config.workers.tcp_max_buffered_pages_per_conn,
        worker_tcp_timeout: Duration::from_secs(config.workers.tcp_timeout),
        worker_udp_max_streams: config.workers.udp_max_streams,
        io: io_impl,
        ruleset: Arc::new(rs),
    };
    let mut engine =
        nt_engine::engine::Engine::new(engine_config).expect("Failed to setup the gfw engine");

    // Initialize the tokio task tracker.
    let tracker = tokio_util::task::TaskTracker::new();

    // Initialize the program cancellation token.
    let program_cancellation_token = tokio_util::sync::CancellationToken::new();

    // Initialize the service cancellation signal (only used in apiserver).
    // `true` represents the active state, while `false` represents the inactive state.
    let (service_tx, _service_rx) = tokio::sync::watch::channel(true);

    tokio::spawn({
        let service_tx = service_tx.clone();
        let service_rx = service_tx.subscribe();
        async move {
            let mut signal =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
            loop {
                signal.recv().await;
                if *service_rx.borrow() {
                    info!("Stopping the service");
                    let _ = service_tx.send(false);
                } else {
                    info!("Starting the service");
                    let _ = service_tx.send(true);
                }
            }
        }
    });

    debug!("Setting up the ctrl_c handler");
    tracker.spawn({
        let program_cancellation_token = program_cancellation_token.clone();
        async move {
            tokio::signal::ctrl_c().await.unwrap();
            info!("Received ctrl_c, shutting down the program...");
            program_cancellation_token.cancel();
        }
    });

    // Handle file monitoring for config reload
    let (config_tx, _config_rx) = tokio::sync::watch::channel(());

    tracker.spawn({
        let ruleset_file = cli.ruleset_file.clone();
        let config_tx = config_tx.clone();
        let program_cancellation_token = program_cancellation_token.clone();

        async move {
            let mut watcher = match RecommendedWatcher::new(
                move |res: Result<notify::Event, notify::Error>| match res {
                    Ok(event) => {
                        debug!("File change event: {:?}", event);
                        if matches!(
                            event.kind,
                            notify::EventKind::Modify(_) | notify::EventKind::Create(_)
                        ) {
                            if let Err(e) = config_tx.send(()) {
                                error!("Failed to send config reload notification: {:?}", e);
                            } else {
                                debug!("Sent config reload notification");
                            }
                        }
                    }
                    Err(e) => error!("Watch error: {:?}", e),
                },
                notify::Config::default()
                    .with_poll_interval(Duration::from_secs(1))
                    .with_compare_contents(false),
            ) {
                Ok(watcher) => watcher,
                Err(e) => {
                    error!("Failed to create file watcher: {:?}", e);
                    return;
                }
            };

            info!("Starting file watcher for {}", &ruleset_file);
            if let Err(e) = watcher.watch(Path::new(&ruleset_file), RecursiveMode::NonRecursive) {
                error!("Failed to watch ruleset file: {:?}", e);
                return;
            }

            // Keep the watcher alive and handle cancellation
            loop {
                tokio::select! {
                    _ = program_cancellation_token.cancelled() => {
                        info!("Shutting down ruleset file watcher");
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        // Verify watcher is still working
                        if let Err(e) = watcher.watch(Path::new(&ruleset_file), RecursiveMode::NonRecursive) {
                            error!("Watcher verification failed, attempting to recover: {:?}", e);
                        }
                    }
                }
            }
        }
    });

    info!("Engine started");

    // Run the engine until shutdown signal
    let _engine_handle = tracker.spawn({
        let program_cancellation_token = program_cancellation_token.clone();
        let service_tx = service_tx.clone();
        async move {
            engine
                .run(
                    program_cancellation_token,
                    service_tx,
                    config_tx,
                    cli.ruleset_file.clone(),
                    analyzers,
                    modifiers,
                )
                .await
        }
    });

    tracker.close();
    tracker.wait().await;
    info!("Program stopped");
}
