use apiserver::logger::LogWriter;
use apiserver::ServerConfig;
use axum::Extension;
use axum::Router;
use clap::Parser;
use gfw_analyzer::Analyzer;
use gfw_modifier::Modifier;
use gfw_ruleset::engine::Engine as RulesetEngine;
use gfw_ruleset::expr_rule::read_expr_rules_from_file;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use std::path::Path;

use tracing::{debug, error, info};

async fn create_router() -> Router {
    apiserver::file::create_router()
        .await
        .merge(apiserver::save::create_router().await)
        .merge(apiserver::service::create_router().await)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[clap(short, long)]
    ruleset_file: String,
    #[clap(short, long, default_value_t=tracing::Level::INFO)]
    log_level: tracing::Level,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let app = create_router().await;

    // Initialize the tokio task tracker.
    let tracker = tokio_util::task::TaskTracker::new();

    // Initialize the program cancellation token.
    let program_cancellation_token = tokio_util::sync::CancellationToken::new();

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

    // ctrl c
    debug!("Setting up the ctrl_c handler");
    let signal = {
        let program_cancellation_token = program_cancellation_token.clone();
        let tracker = tracker.clone();
        async move {
            tokio::signal::ctrl_c().await.unwrap();
            info!("Received ctrl_c, shutting down the program...");
            tracker.close();
            program_cancellation_token.cancel();
            tracker.wait().await;
            println!("Shutting down...");
        }
    };

    // server config
    let raw_rs = read_expr_rules_from_file(&cli.ruleset_file)
        .await
        .map_err(|e| format!("failed to parse ruleset file: {}", e))
        .unwrap();

    let analyzers: Vec<Arc<dyn Analyzer>> = vec![
        Arc::new(gfw_analyzer::tcp::http::HTTPAnalyzer::new()),
        Arc::new(gfw_analyzer::tcp::tls::TLSAnalyzer::new()),
        Arc::new(gfw_analyzer::udp::dns::DNSAnalyzer::new()),
        Arc::new(gfw_analyzer::udp::openvpn::OpenVPNAnalyzer::new()),
        Arc::new(gfw_analyzer::udp::wireguard::WireGuardAnalyzer::new()),
    ];
    let modifiers: Vec<Arc<dyn Modifier>> =
        vec![Arc::new(gfw_modifier::udp::dns::DNSModifier::new())];

    let config = Arc::new(gfw_config::config::CliConfig::default());
    let ruleset_engine = RulesetEngine::new(&config.ruleset.geoip, &config.ruleset.geosite);

    let ruleset = gfw_ruleset::expr_rule::compile_expr_rules(
        raw_rs,
        &analyzers,
        &modifiers,
        ruleset_engine.clone(),
    )
    .await;
    let log_writer = LogWriter::new(100);
    let app = app.layer(Extension(Arc::new(RwLock::new(ServerConfig {
        log_writer: log_writer.clone(),
        analyzers,
        modifiers,
        ruleset_engine,
        config,
        ruleset_file: cli.ruleset_file.clone(),
        config_tx: config_tx.clone(),
        io_impl: None,
        rule_set: Some(Arc::new(ruleset)),
        engine_starter: None,
        program_cancellation_token,
        tracker,
    }))));

    // log
    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(cli.log_level)
        .with_writer(log_writer)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false)
        .init();

    // Start the server
    println!("Listening on {}", addr);
    info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app)
        .with_graceful_shutdown(signal)
        .await
        .unwrap();
}
