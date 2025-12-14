use clap::{Parser, Subcommand};
use sov_core::{CliConfig, RolesConfig, RuleSet, load_cli_config, load_roles, load_rules};
use sov_transport::tls::{TlsConfig, build_tls_connector};
use sov_transport::{MessageReader, MessageType, MessageWriter, WireMessage};
use std::path::PathBuf;
use tokio::net::TcpStream;
use tokio_rustls::rustls::ServerName;

#[derive(Parser, Debug)]
#[command(name = "sov-admin")]
#[command(about = "CLI администратора СОВ (управление analyzer по TLS/mTLS)", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "config/admin-cli.yaml")]
    config: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Показать локальный rules.yaml (просто просмотр)
    ShowRules {
        #[arg(short, long, default_value = "config/rules.yaml")]
        rules: String,
    },

    /// Отправить rules.yaml на analyzer (горячее обновление правил)
    RulesPush {
        #[arg(short, long, default_value = "config/rules.yaml")]
        rules: String,
    },

    /// Получить статус analyzer
    Status,

    /// Локальная работа с roles.yaml (не влияет на mTLS RBAC, оставлено как каркас)
    ShowRoles {
        #[arg(short, long, default_value = "config/roles.yaml")]
        roles: String,
    },

    /// Локально поменять roles.yaml (не влияет на mTLS RBAC)
    SetRole {
        #[arg(short, long)]
        user: String,
        #[arg(short, long)]
        role: String,
        #[arg(short, long, default_value = "config/roles.yaml")]
        roles: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ShowRules { rules } => {
            let rs: RuleSet = load_rules(&rules)?;
            println!("RuleSet version: {}", rs.version);
            for r in rs.rules {
                println!("- [{}] {} (severity {})", r.id, r.name, r.severity);
            }
            return Ok(());
        }
        Command::ShowRoles { roles } => {
            let rc: RolesConfig = load_roles(&roles)?;
            for b in rc.bindings {
                println!("{} => {:?}", b.username, b.role);
            }
            return Ok(());
        }
        Command::SetRole { user, role, roles } => {
            let mut rc: RolesConfig = load_roles(&roles)?;
            let role_parsed = match role.as_str() {
                "SecurityAdmin" => sov_core::Role::SecurityAdmin,
                "Operator" => sov_core::Role::Operator,
                _ => {
                    eprintln!("Unknown role: {role}");
                    return Ok(());
                }
            };

            if let Some(b) = rc.bindings.iter_mut().find(|b| b.username == user) {
                b.role = role_parsed;
            } else {
                rc.bindings.push(sov_core::RoleBinding {
                    username: user.clone(),
                    role: role_parsed,
                });
            }

            let yaml = serde_yaml::to_string(&rc)?;
            std::fs::write(&roles, yaml)?;
            println!("Role for user {user} set to {role} (local roles.yaml only)");
            return Ok(());
        }
        _ => {}
    }

    // Все команды ниже — сетевые (TLS/mTLS)
    let cfg: CliConfig = load_cli_config(&cli.config)?;
    let (mut reader, mut writer) = connect_cli(&cfg).await?;

    match cli.command {
        Command::RulesPush { rules } => {
            let rs: RuleSet = load_rules(&rules)?;
            writer
                .send(&WireMessage {
                    kind: MessageType::RulesetUpdate,
                    event: None,
                    ruleset: Some(rs),
                    status: None,
                    config_patch: None,
                })
                .await?;
            println!("Rules pushed to analyzer.");
        }

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

        _ => {}
    }

    Ok(())
}

async fn connect_cli(
    cfg: &CliConfig,
) -> anyhow::Result<(
    MessageReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    MessageWriter<tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
)> {
    if !cfg.tls.enabled {
        anyhow::bail!("For admin-cli we expect tls.enabled=true (mTLS RBAC).");
    }

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
