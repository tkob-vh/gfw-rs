use clap::Parser;
use cmd::config::load_config_from_file;
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
    let cli = Cli::parse();
    let config = load_config_from_file(&cli.config_file)
        .await
        .map_err(|e| format!("failed to parse config file: {}", e))
        .unwrap();

    let rules = read_expr_rules_from_file(&cli.ruleset_file)
        .await
        .map_err(|e| format!("failed to parse ruleset file: {}", e))
        .unwrap();
    println!("{:?}", config);
    println!("{:?}", rules);
}
