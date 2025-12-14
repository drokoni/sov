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

    let os = args.os.unwrap_or_else(source::default_os);

    tracing::info!(
        sensor = "node",
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
                tracing::info!("Node sensor connected to analyzer at {}", cfg.server_addr);

                if let Err(e) = run_sensor(stream, &cfg, os, shutdown_rx.clone()).await {
                    tracing::error!("Node sensor error: {e}");
                }
            }
            Err(e) => tracing::warn!("Connect error: {e}"),
        }

        // если shutdown уже поднят — выходим, не реконнектимся
        if *shutdown_rx.borrow() {
            tracing::warn!("shutdown flag set, stopping reconnect loop");
            break;
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    tracing::info!("node sensor stopped");
    Ok(())
}

async fn run_sensor(
    stream: TcpStream,
    cfg: &sov_core::NodeSensorConfig,
    os: source::OsKind,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut writer = MessageWriter::new(stream);

    let mut src = source::create_source(os, cfg)?;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::warn!("shutdown received, stopping node sensor loop");
                    return Ok(());
                }
            }

            res = src.poll() => {
                let events = res?;
                for ev in events {
                    let msg = WireMessage {
                        kind: MessageType::Event,
                        event: Some(ev),
                        ruleset: None,
                        status: None,
                        config_patch: None,
                    };
                    writer.send(&msg).await?;
                }
            }
        }
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
