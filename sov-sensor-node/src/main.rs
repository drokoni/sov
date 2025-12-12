use clap::Parser;
use chrono::Utc;
use sov_core::{
    load_node_sensor_config, BaseEventMeta, CollectedEvent, EventKind, NodeEventData, SensorMode,
};
use sov_transport::{MessageType, MessageWriter, WireMessage};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config/node-sensor.yaml")]
    config: String,
}

#[derive(Debug, Clone)]
struct FileState {
    pos: u64,          // сколько байт уже прочитали
    partial: String,   // хвост незавершённой строки (если нет '\n')
    initialized: bool, // были ли мы уже в этом файле
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = load_node_sensor_config(&args.config)?;

    loop {
        match TcpStream::connect(&cfg.server_addr).await {
            Ok(stream) => {
                println!("Node sensor connected to analyzer at {}", cfg.server_addr);
                if let Err(e) = run_sensor(stream, &cfg).await {
                    eprintln!("Node sensor error: {e}");
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

    let mut states: HashMap<PathBuf, FileState> = HashMap::new();

    loop {
        for path in &cfg.log_paths {
            if let Err(e) = poll_file_and_send(path, cfg, &mut states, &mut writer).await {
                eprintln!("poll_file_and_send({}): {e}", path.display());
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(cfg.poll_interval_ms)).await;
    }
}

async fn poll_file_and_send(
    path: &Path,
    cfg: &sov_core::NodeSensorConfig,
    states: &mut HashMap<PathBuf, FileState>,
    writer: &mut MessageWriter,
) -> anyhow::Result<()> {
    let pbuf = path.to_path_buf();

    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    let st = states.entry(pbuf.clone()).or_insert(FileState {
        pos: 0,
        partial: String::new(),
        initialized: false,
    });

    if !st.initialized {
        st.pos = meta.len();
        st.initialized = true;
        return Ok(());
    }

    if meta.len() < st.pos {
        st.pos = 0;
        st.partial.clear();
    }

    let mut file = tokio::fs::File::open(path).await?;
    file.seek(std::io::SeekFrom::Start(st.pos)).await?;

    let mut buf = Vec::new();
    let n = file.read_to_end(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    st.pos += n as u64;

    let chunk = String::from_utf8_lossy(&buf);
    st.partial.push_str(&chunk);

    let mut lines: Vec<String> = st
        .partial
        .split('\n')
        .map(|s| s.to_string())
        .collect();

    let last_is_complete = st.partial.ends_with('\n');
    let tail = if last_is_complete {
        String::new()
    } else {
        lines.pop().unwrap_or_default()
    };
    st.partial = tail;

    for mut line in lines {
        if line.ends_with('\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }

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

    Ok(())
}

