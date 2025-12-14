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
            Ok(tcp) => {
                tracing::info!("Node sensor connected to analyzer at {}", cfg.server_addr);

                let res = if cfg.tls.as_ref().map(|t| t.enabled).unwrap_or(false) {
                    run_sensor_tls(tcp, &cfg, args.os, shutdown_rx.clone()).await
                } else {
                    run_sensor_plain(tcp, &cfg, args.os, shutdown_rx.clone()).await
                };

                if let Err(e) = res {
                    tracing::error!("Node sensor error: {e}");
                }
            }
            Err(e) => tracing::error!("Connect error: {e}"),
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

async fn run_sensor_plain(
    tcp: TcpStream,
    cfg: &sov_core::NodeSensorConfig,
    os: Option<source::OsKind>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let os = os.unwrap_or_else(source::default_os);
    let mut src = source::create_source(os, cfg)?;
    let mut writer = MessageWriter::new(tcp);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            res = src.poll() => {
                let events = res?;
                for ev in events {
                    let msg = WireMessage {
                        kind: MessageType::Event,
                        event: Some(ev),
                        ruleset: None,
                        config_patch: None,
                        status: None,
                    };
                    writer.send(&msg).await?;
                }
            }
        }
    }
    Ok(())
}

async fn run_sensor_tls(
    tcp: TcpStream,
    cfg: &sov_core::NodeSensorConfig,
    os: Option<source::OsKind>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let t = cfg.tls.as_ref().unwrap();
    let tls_cfg = tls_cfg_from_section(t);
    let connector = sov_transport::tls::build_tls_connector(&tls_cfg)?;

    let sni = tls_cfg
        .server_name
        .clone()
        .unwrap_or_else(|| "sov-analyzer".to_string());
    let server_name = rustls::ServerName::try_from(sni.as_str())?;
    let tls_stream = connector.connect(server_name, tcp).await?;
    tracing::info!("TLS connected to analyzer");

    let (_rd, wr) = tokio::io::split(tls_stream);
    let mut writer = MessageWriter::new(wr);

    let os = os.unwrap_or_else(source::default_os);
    let mut src = source::create_source(os, cfg)?;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            res = src.poll() => {
                let events = res?;
                for ev in events {
                    let msg = WireMessage {
                        kind: MessageType::Event,
                        event: Some(ev),
                        ruleset: None,
                        config_patch: None,
                        status: None,
                    };
                    writer.send(&msg).await?;
                }
            }
        }
    }
    Ok(())
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
fn tls_cfg_from_section(t: &sov_core::TlsSection) -> sov_transport::tls::TlsConfig {
    sov_transport::tls::TlsConfig {
        ca_path: t.ca_path.clone(),
        cert_path: t.cert_path.clone(),
        key_path: t.key_path.clone(),
        server_name: t.server_name.clone(),
        require_mtls: t.require_mtls,
    }
}
