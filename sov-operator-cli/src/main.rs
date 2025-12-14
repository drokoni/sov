use clap::{Parser, Subcommand};
use sov_core::{CliConfig, load_cli_config};
use sov_transport::tls::{TlsConfig, build_tls_connector};
use sov_transport::{MessageReader, MessageType, MessageWriter, WireMessage};
use tokio::net::TcpStream;
use tokio_rustls::rustls::ServerName;

#[derive(Parser, Debug)]
#[command(name = "sov-operator")]
#[command(about = "CLI оператора СОВ (просмотр status/alerts по TLS/mTLS)", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "config/operator-cli.yaml")]
    config: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Status,
    /// Подписаться на алерты (стрим). Пока analyzer может шлёпать алерты сюда в будущем.
    AlertsSubscribe,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg: CliConfig = load_cli_config(&cli.config)?;
    if !cfg.tls.enabled {
        anyhow::bail!("operator-cli expects tls.enabled=true");
    }

    let (mut reader, mut writer) = connect_cli(&cfg).await?;

    match cli.command {
        Command::Status => {
            writer
                .send(&WireMessage {
                    kind: MessageType::GetStatus,
                    event: None,
                    ruleset: None,
                    status: None,
                    config_patch: None,
                })
                .await?;

            if let Some(reply) = reader.read().await? {
                println!("Reply: {:?}", reply.status);
            } else {
                println!("No reply (connection closed).");
            }
        }

        Command::AlertsSubscribe => {
            writer
                .send(&WireMessage {
                    kind: MessageType::SubscribeAlerts,
                    event: None,
                    ruleset: None,
                    status: None,
                    config_patch: None,
                })
                .await?;

            println!("Subscribed. Waiting for alerts...");
            loop {
                match reader.read().await? {
                    Some(msg) => {
                        if msg.kind == MessageType::Alert {
                            println!("ALERT: {:?}", msg.event);
                        } else {
                            // полезно для дебага
                            println!("MSG: kind={:?} status={:?}", msg.kind, msg.status);
                        }
                    }
                    None => break,
                }
            }
        }
    }

    Ok(())
}

async fn connect_cli(
    cfg: &CliConfig,
) -> anyhow::Result<(
    MessageReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    MessageWriter<tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
)> {
    let tcp = TcpStream::connect(&cfg.server_addr).await?;

    let tls = build_tls_connector(&TlsConfig {
        ca_path: cfg.tls.ca_path.clone(),
        cert_path: cfg.tls.cert_path.clone(),
        key_path: cfg.tls.key_path.clone(),
        server_name: cfg.tls.server_name.clone(),
        require_mtls: false,
    })?;

    let sni = cfg
        .tls
        .server_name
        .clone()
        .unwrap_or_else(|| "sov-analyzer".into());
    let server_name = ServerName::try_from(sni.as_str())
        .map_err(|_| anyhow::anyhow!("bad tls server_name: {sni}"))?;

    let tls_stream = tls.connect(server_name, tcp).await?;

    let (r, w) = tokio::io::split(tls_stream);
    Ok((MessageReader::new(r), MessageWriter::new(w)))
}
