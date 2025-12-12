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
    let args = Args::parse();
    let cfg = load_node_sensor_config(&args.config)?;

    let os = args.os.unwrap_or_else(source::default_os);
    println!("Node sensor mode: {:?}", os);

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

