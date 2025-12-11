use serde::{Deserialize, Serialize};
use sov-core::{CollectedEvent, RuleSet};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Event,
    Rules,
    RulesRequest,
    Ping,
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    pub kind: MessageType,
    pub event: Option<CollectedEvent>,
    pub ruleset: Option<RuleSet>,
}

pub struct MessageWriter {
    stream: TcpStream,
}

impl MessageWriter {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub async fn send(&mut self, msg: &WireMessage) -> anyhow::Result<()> {
        let data = serde_json::to_vec(msg)?;
        self.stream.write_all(&data).await?;
        self.stream.write_all(b"\n").await?;
        Ok(())
    }
}

pub struct MessageReader {
    reader: BufReader<TcpStream>,
}

impl MessageReader {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }

    pub async fn read(&mut self) -> anyhow::Result<Option<WireMessage>> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&line)?))
    }
}

