use clap::Parser;
use chrono::Utc;
use sov_core::{
    load_node_sensor_config, BaseEventMeta, CollectedEvent, EventKind, NodeEventData, SensorMode,
};
use sov_transport::{MessageType, MessageWriter, WireMessage};
use tokio::net::TcpStream;
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config/node-sensor.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = load_node_sensor_config(&args.config)?;

    loop {
        match TcpStream::connect(&cfg.server_addr).await {
            Ok(stream) => {
                println!("Connected to analyzer at {}", cfg.server_addr);
                if let Err(e) = run_sensor(stream, &cfg).await {
                    eprintln!("Sensor error: {e}");
                }
            }
            Err(e) => {
                eprintln!("Connect error: {e}");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn run_sensor(stream: TcpStream, cfg: &sov_core::NodeSensorConfig) -> anyhow::Result<()> {
    let mut writer = MessageWriter::new(stream);

    loop {
        for path in &cfg.log_paths {
            let file = match tokio::fs::File::open(path).await {
                Ok(f) => f,
                Err(_) => continue,
            };

            let reader = BufReader::new(file);
            tokio::pin!(reader);

            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await? {
                let event = CollectedEvent {
                    meta: BaseEventMeta {
                        id: Uuid::new_v4(),
                        node_id: cfg.node_id.clone(),
                        mode: SensorMode::Node,
                        collected_at: Utc::now(),
                    },
                    kind: EventKind::Node(NodeEventData {
                        source_log: path.to_string_lossy().to_string(),
                        raw_line: line,
                    }),
                };

                let msg = WireMessage {
                    kind: MessageType::Event,
                    event: Some(event),
                    ruleset: None,
                };

                writer.send(&msg).await?;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(
            cfg.poll_interval_ms,
        ))
        .await;
    }
}

