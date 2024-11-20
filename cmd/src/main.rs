use std::{sync::Arc, time::Duration};

use clap::Parser;
use cmd::config::load_config_from_file;
use tokio::sync::Mutex;
use tracing::{error, info};

use nt_engine::Engine;
use nt_ruleset::expr_rule::read_expr_rules_from_file;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(short)]
    config_file: String,
    #[clap(short)]
    ruleset_file: String,
    #[clap(short)]
    pcap_file: Option<String>,
}

#[tokio::main]
async fn main() {
    // Setup analyzers
    let analyzers: Vec<Arc<dyn nt_analyzer::Analyzer>> = vec![
        Arc::new(nt_analyzer::tcp::http::HTTPAnalyzer::new()),
        Arc::new(nt_analyzer::udp::dns::DNSAnalyzer::new()),
        Arc::new(nt_analyzer::udp::openvpn::OpenVPNAnalyzer::new()),
        Arc::new(nt_analyzer::udp::wireguard::WireGuardAnalyzer::new()),
    ];

    // Setup modifiers
    let modifiers: Vec<Arc<dyn nt_modifier::Modifier>> =
        vec![Arc::new(nt_modifier::udp::dns::DNSModifier::new())];

    // Setup logger
    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(true)
        .init();

    // Parse CLI
    let cli = Cli::parse();

    // Load config file
    let config = load_config_from_file(&cli.config_file)
        .await
        .map_err(|e| format!("failed to parse config file: {}", e))
        .unwrap();

    // Load ruleset file
    let raw_rs = read_expr_rules_from_file(&cli.ruleset_file)
        .await
        .map_err(|e| format!("failed to parse ruleset file: {}", e))
        .unwrap();
    info!("{:?}", config);
    info!("{:?}", raw_rs);

    // Setup IO
    let io_impl: Arc<dyn nt_io::PacketIO> = if cli.pcap_file.is_some() {
        let pcap_file = cli.pcap_file.unwrap();
        info!("Replaying from pcap file {:?}", &pcap_file);
        Arc::new(
            nt_io::pcap::PcapPacketIO::new(nt_io::pcap::PcapPacketIOConfig {
                pcap_file,
                real_time: config.replay.realtime,
            })
            .unwrap(),
        )
    } else {
        info!("Setup IO for nfqueue...");
        Arc::new(
            nt_io::nfqueue::NFQueuePacketIO::new(nt_io::nfqueue::NFQueuePacketIOConfig {
                queue_size: config.io.queue_size,
                local: config.io.local,
                rst: config.io.rst,
            })
            .unwrap(),
        )
    };

    // Setup ruleset
    let engine = Arc::new(rhai::Engine::new());
    let rs = nt_ruleset::expr_rule::compile_expr_rules(raw_rs, &analyzers, &modifiers, engine);

    // Setup engine
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
    let engine = Arc::new(Mutex::new(
        nt_engine::engine::Engine::new(engine_config).expect("Failed to setup the gfw engine"),
    ));

    // Setup signal handling
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);

    // Handle Ctrl+C for graceful shutdown
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        info!("Shutting down gracefully...");
        shutdown_tx_clone.send(()).await.unwrap();
    });

    // Handle SIGHUP for config reload
    let ruleset_file = cli.ruleset_file.clone();
    let engine_clone = engine.clone();
    tokio::spawn(async move {
        let mut signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
        loop {
            signal.recv().await;
            info!("Reloading rules...");

            match read_expr_rules_from_file(&ruleset_file).await {
                Ok(raw_rs) => {
                    let new_engine = Arc::new(rhai::Engine::new());
                    let rs = nt_ruleset::expr_rule::compile_expr_rules(
                        raw_rs, &analyzers, &modifiers, new_engine,
                    );
                    if let Err(e) = engine_clone.lock().await.update_ruleset(Arc::new(rs)).await {
                        error!("Failed to update ruleset: {}", e);
                    } else {
                        info!("Rules reloaded successfully");
                    }
                }
                Err(e) => error!("Failed to load rules: {}", e),
            }
        }
    });

    info!("Engine started");

    // Run the engine until shutdown signal
    let engine_handle = tokio::spawn(async move { engine.lock().await.run(shutdown_rx).await });

    // Cleanup and shutdown
    drop(engine_handle);
    info!("Engine stopped");
}
