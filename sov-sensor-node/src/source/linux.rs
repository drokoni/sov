use async_trait::async_trait;
use chrono::Utc;
use sov_core::{BaseEventMeta, CollectedEvent, EventKind, NodeEventData, SensorMode};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;

use super::NodeEventSource;

#[derive(Debug, Clone)]
struct FileState {
    pos: u64,
    partial: String,
    initialized: bool,
}

pub struct LinuxLogSource {
    node_id: String,
    log_paths: Vec<PathBuf>,
    states: HashMap<PathBuf, FileState>,
}

impl LinuxLogSource {
    pub fn new(cfg: &sov_core::NodeSensorConfig) -> anyhow::Result<Self> {
        Ok(Self {
            node_id: cfg.node_id.clone(),
            log_paths: cfg.log_paths.clone(),
            states: HashMap::new(),
        })
    }
}

#[async_trait]
impl NodeEventSource for LinuxLogSource {
    async fn poll(&mut self) -> anyhow::Result<Vec<CollectedEvent>> {
        let mut out = Vec::new();

        for path in &self.log_paths {
            poll_file(path, &self.node_id, &mut self.states, &mut out).await?;
        }

        Ok(out)
    }
}

async fn poll_file(
    path: &Path,
    node_id: &str,
    states: &mut HashMap<PathBuf, FileState>,
    out: &mut Vec<CollectedEvent>,
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

    // первый раз — прыгаем в конец, не шлём старое
    if !st.initialized {
        st.pos = meta.len();
        st.initialized = true;
        return Ok(());
    }

    // truncate/rotation
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

    let mut parts: Vec<String> = st.partial.split('\n').map(|s| s.to_string()).collect();
    let last_is_complete = st.partial.ends_with('\n');
    let tail = if last_is_complete {
        String::new()
    } else {
        parts.pop().unwrap_or_default()
    };
    st.partial = tail;

    for mut line in parts {
        if line.ends_with('\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }

        out.push(CollectedEvent {
            meta: BaseEventMeta {
                id: Uuid::new_v4(),
                node_id: node_id.to_string(),
                mode: SensorMode::Node,
                collected_at: Utc::now(),
            },
            kind: EventKind::Node(NodeEventData {
                source_log: path.to_string_lossy().to_string(),
                raw_line: line,
            }),
        });
    }

    Ok(())
}

