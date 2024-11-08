use clap::Parser;
use cmd::config::load_config_from_file;

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
    let config = load_config_from_file(&cli.config_file).await.unwrap();
    println!("{:?}", config);
}
