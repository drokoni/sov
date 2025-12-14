use chrono::Utc;
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use uuid::Uuid;

use sov_core::{
    AnalysisResult, AnalysisResultKind, AuditEventType, AuditLogger, AuditRecord, CollectedEvent,
    EventKind, RuleScope, RuleSet, RuleSignature, load_analyzer_config, load_rules,
};

use sov_transport::{MessageReader, MessageType, MessageWriter, WireMessage};

use sov_transport::tls::{build_tls_acceptor, extract_role_from_cert};

enum ClientRole {
    Sensor,
    Admin,
    Operator,
    Unknown,
}

fn role_from_ou(ou: Option<String>) -> ClientRole {
    match ou.as_deref() {
        Some("Sensor") => ClientRole::Sensor,
        Some("SecurityAdmin") => ClientRole::Admin,
        Some("Operator") => ClientRole::Operator,
        _ => ClientRole::Unknown,
    }
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config/analyzer.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = load_analyzer_config(&args.config)?;

    let initial_ruleset = load_rules(cfg.rules_path.to_str().unwrap())?;
    let ruleset = Arc::new(RwLock::new(initial_ruleset));

    let audit = AuditLogger::new(&cfg.audit_log_path);
    let tls_cfg = if cfg.tls_enabled {
        let cert = cfg
            .tls_cert_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("tls_enabled=true but tls_cert_path missing"))?;
        let key = cfg
            .tls_key_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("tls_enabled=true but tls_key_path missing"))?;
        let ca = cfg
            .tls_ca_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("tls_enabled=true but tls_ca_path missing"))?;

        Some(sov_transport::tls::TlsConfig {
            ca_path: ca.to_string_lossy().to_string(),
            cert_path: cert.to_string_lossy().to_string(),
            key_path: key.to_string_lossy().to_string(),
            server_name: cfg.tls_server_name.clone(),
            require_mtls: cfg.tls_require_mtls,
        })
    } else {
        None
    };

    let tls_acceptor = if let Some(t) = &tls_cfg {
        Some(build_tls_acceptor(&sov_transport::tls::TlsConfig {
            ca_path: t.ca_path.clone(),
            cert_path: t.cert_path.clone(),
            key_path: t.key_path.clone(),
            server_name: t.server_name.clone(),
            require_mtls: t.require_mtls,
        })?)
    } else {
        None
    };

    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    println!("Analyzer listening on {}", cfg.listen_addr);
    println!(
        "TLS: {}",
        if tls_acceptor.is_some() {
            "enabled"
        } else {
            "disabled"
        }
    );

    loop {
        let (tcp, addr) = listener.accept().await?;
        println!("New client from {addr}");

        let ruleset = ruleset.clone();
        let audit = audit.clone();
        let tls_acceptor = tls_acceptor.clone();
        let tls_required = tls_cfg.as_ref().map(|t| t.require_mtls).unwrap_or(false);

        tokio::spawn(async move {
            if let Err(e) =
                handle_client(tcp, addr, tls_acceptor, tls_required, ruleset, audit).await
            {
                eprintln!("client {addr} handler error: {e}");
            }
            println!("Client disconnected: {addr}");
        });
    }
}

async fn handle_client(
    tcp: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    tls_required: bool,
    ruleset: Arc<RwLock<RuleSet>>,
    audit: AuditLogger,
) -> anyhow::Result<()> {
    if tls_required && tls_acceptor.is_none() {
        anyhow::bail!("mTLS required but TLS disabled");
    }

    if let Some(acceptor) = tls_acceptor {
        let tls = acceptor.accept(tcp).await?;

        // Определяем роль по сертификату клиента
        let peer = tls.get_ref().1.peer_certificates();
        let ou = peer
            .and_then(|v| v.get(0))
            .and_then(|c| extract_role_from_cert(c));
        let role = role_from_ou(ou);

        println!("Client {addr} role: {:?}", role_name(&role));

        let (reader_half, writer_half) = tokio::io::split(tls);
        let mut reader = MessageReader::new(reader_half);
        let mut writer = MessageWriter::new(writer_half);

        client_loop(addr, role, &mut reader, &mut writer, ruleset, audit).await
    } else {
        let (reader_half, writer_half) = tokio::io::split(tcp);
        let mut reader = MessageReader::new(reader_half);
        let mut writer = MessageWriter::new(writer_half);

        let role = ClientRole::Unknown;
        client_loop(addr, role, &mut reader, &mut writer, ruleset, audit).await
    }
}

fn role_name(r: &ClientRole) -> &'static str {
    match r {
        ClientRole::Sensor => "Sensor",
        ClientRole::Admin => "SecurityAdmin",
        ClientRole::Operator => "Operator",
        ClientRole::Unknown => "Unknown",
    }
}

async fn client_loop<R, W>(
    addr: std::net::SocketAddr,
    role: ClientRole,
    reader: &mut MessageReader<R>,
    writer: &mut MessageWriter<W>,
    ruleset: Arc<RwLock<RuleSet>>,
    audit: AuditLogger,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        let msg = match reader.read().await {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(e) => {
                eprintln!("Error reading from {addr}: {e}");
                break;
            }
        };

        match msg.kind {
            MessageType::Event => {
                // Только сенсор имеет право слать Event
                if !matches!(role, ClientRole::Sensor | ClientRole::Unknown) {
                    eprintln!("Denied Event from role={}", role_name(&role));
                    continue;
                }

                if let Some(ev) = msg.event {
                    let current_rules = ruleset.read().await.clone();
                    if let Err(e) = handle_event(ev, &current_rules, &audit).await {
                        eprintln!("handle_event error: {e}");
                    }
                }
            }

            MessageType::RulesetUpdate => {
                // Только админ может обновлять правила
                if !matches!(role, ClientRole::Admin) {
                    eprintln!("Denied RulesetUpdate from role={}", role_name(&role));
                    continue;
                }

                if let Some(new_ruleset) = msg.ruleset {
                    {
                        let mut w = ruleset.write().await;
                        *w = new_ruleset.clone();
                    }

                    // аудит
                    let _ = audit.log(&AuditRecord {
                        ts: Utc::now(),
                        event_type: AuditEventType::ConfigChange,
                        subject: format!("admin@{addr}"),
                        result: "success".into(),
                        details: serde_json::json!({
                            "action": "ruleset_update",
                            "rules_count": new_ruleset.rules.len(),
                        }),
                    });

                    println!("Ruleset updated by admin@{addr}");
                }
            }

            MessageType::GetStatus => {
                // Operator и Admin могут смотреть статус
                if !matches!(role, ClientRole::Admin | ClientRole::Operator) {
                    eprintln!("Denied GetStatus from role={}", role_name(&role));
                    continue;
                }

                let rs = ruleset.read().await;
                let status = serde_json::json!({
                    "rules_count": rs.rules.len(),
                    "ts": Utc::now().to_rfc3339(),
                });

                let reply = WireMessage {
                    kind: MessageType::Status,
                    event: None,
                    ruleset: None,
                    // если у тебя нет этого поля — убери и просто не отвечай,
                    // но лучше добавить status: Option<Value> в WireMessage.
                    status: Some(status),
                    config_patch: None,
                };

                writer.send(&reply).await?;
            }

            MessageType::SubscribeAlerts => {
                // В минимальном варианте: просто подтверждаем подписку.
                if !matches!(role, ClientRole::Admin | ClientRole::Operator) {
                    eprintln!("Denied SubscribeAlerts from role={}", role_name(&role));
                    continue;
                }

                println!(
                    "alerts subscription requested from {addr} role={}",
                    role_name(&role)
                );
            }

            _ => {}
        }
    }

    Ok(())
}

async fn handle_event(
    event: CollectedEvent,
    ruleset: &RuleSet,
    audit: &AuditLogger,
) -> anyhow::Result<()> {
    let result = analyze_event(&event, ruleset);

    if let AnalysisResultKind::Intrusion | AnalysisResultKind::Suspicious = result.kind {
        let alert_id = Uuid::new_v4();
        println!("ALERT {alert_id}: {:?}", result);

        audit.log(&AuditRecord {
            ts: Utc::now(),
            event_type: AuditEventType::Alert,
            subject: format!("sensor:{}", event.meta.node_id),
            result: "success".into(),
            details: serde_json::json!({
                "alert_id": alert_id.to_string(),
                "event_id": event.meta.id.to_string(),
                "rule_id": result.rule_id,
            }),
        })?;
    }

    Ok(())
}

fn analyze_event(event: &CollectedEvent, ruleset: &RuleSet) -> AnalysisResult {
    use AnalysisResultKind::*;

    for rule in &ruleset.rules {
        if !rule_applies_to_event(rule, &event.kind) {
            continue;
        }

        if let Some(sig) = &rule.signature {
            if signature_match(event, sig) {
                return AnalysisResult {
                    event_id: event.meta.id,
                    node_id: event.meta.node_id.clone(),
                    timestamp: Utc::now(),
                    kind: Intrusion,
                    rule_id: Some(rule.id.clone()),
                    description: rule.description.clone(),
                };
            }
        }
    }

    AnalysisResult {
        event_id: event.meta.id,
        node_id: event.meta.node_id.clone(),
        timestamp: Utc::now(),
        kind: Normal,
        rule_id: None,
        description: "No rule matched".into(),
    }
}

fn rule_applies_to_event(rule: &sov_core::Rule, kind: &EventKind) -> bool {
    match (&rule.scope, kind) {
        (RuleScope::Node, EventKind::Node(_)) => true,
        (RuleScope::Net, EventKind::Net(_)) => true,
        (RuleScope::Both, _) => true,
        _ => false,
    }
}

fn signature_match(event: &CollectedEvent, sig: &RuleSignature) -> bool {
    use EventKind::*;

    let target = match (&event.kind, sig.target.as_str()) {
        (Node(node), "node.raw_line") => &node.raw_line,
        (Net(net), "net.payload") => &net.payload_snippet,
        _ => return false,
    };

    if sig.is_regex {
        target.contains(&sig.pattern) // TODO regex
    } else {
        target.contains(&sig.pattern)
    }
}
