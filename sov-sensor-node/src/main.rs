use clap::Parser;
use sov_core::load_node_sensor_config;
use sov_transport::{MessageType, MessageWriter, WireMessage};
use tokio::net::TcpStream;

mod source;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config/node-sensor.yaml")]
    config: String,

    /// Выбор источника событий (по умолчанию авто по ОС)
    #[arg(long, value_enum)]
    os: Option<source::OsKind>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let args = Args::parse();
    let cfg = load_node_sensor_config(&args.config)?;
    tracing::info!(
        sensor = "node",  // или "net"
        node_id = %cfg.node_id,
        server = %cfg.server_addr,
        "sensor started"
    );

    // Канал остановки
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Отдельная задача: ждём Ctrl+C
    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::warn!("Ctrl+C received, shutting down...");
                let _ = shutdown_tx.send(true);
            }
        });
    }

    loop {
        match TcpStream::connect(&cfg.server_addr).await {
            Ok(stream) => {
                println!("Node sensor connected to analyzer at {}", cfg.server_addr);
                if let Err(e) = run_sensor(stream, &cfg, os).await {
                    eprintln!("Node sensor error: {e}");
                }
            }
            Err(e) => eprintln!("Connect error: {e}"),
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn run_sensor(
    stream: TcpStream,
    cfg: &sov_core::NodeSensorConfig,
    os: source::OsKind,
) -> anyhow::Result<()> {
    let mut writer = MessageWriter::new(stream);
    let mut src = source::create_source(os, cfg)?;

    loop {
        let events = src.poll().await?;

        for ev in events {
            let msg = WireMessage {
                kind: MessageType::Event,
                event: Some(ev),
                ruleset: None,
            };
            writer.send(&msg).await?;
        }

        tokio::time::sleep(std::time::Duration::from_millis(cfg.poll_interval_ms)).await;
    }
}
fn init_logging() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .init();
}
