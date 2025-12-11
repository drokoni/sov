use clap::Parser;
use sov_core::{
    load_analyzer_config, load_rules, AnalysisResult, AnalysisResultKind, AuditEventType,
    AuditLogger, AuditRecord, CollectedEvent, EventKind, RuleScope, RuleSet, RuleSignature,
};
use sov_transport::{MessageReader, MessageType, WireMessage};
use chrono::Utc;
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config/analyzer.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = load_analyzer_config(&args.config)?;

    let ruleset = load_rules(cfg.rules_path.to_str().unwrap())?;
    let audit = AuditLogger::new(&cfg.audit_log_path);

    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    println!("Analyzer listening on {}", cfg.listen_addr);

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New sensor from {addr}");

        let ruleset = ruleset.clone();
        let audit = audit.clone();

        tokio::spawn(async move {
            let mut reader = MessageReader::new(stream);

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
                        if let Some(ev) = msg.event {
                            if let Err(e) = handle_event(ev, &ruleset, &audit).await {
                                eprintln!("handle_event error: {e}");
                            }
                        }
                    }
                    MessageType::RulesRequest => {
                        // TODO: отправка rules обратно клиенту
                    }
                    _ => {}
                }
            }

            println!("Sensor disconnected: {addr}");
        });
    }
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
        // TODO: regex::Regex
        target.contains(&sig.pattern)
    } else {
        target.contains(&sig.pattern)
    }
}

