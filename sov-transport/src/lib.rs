use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use sov_core::{CollectedEvent, RuleSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Event,
    RulesetUpdate,
    GetStatus,
    Status,
    SubscribeAlerts,
    Alert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    pub kind: MessageType,
    pub event: Option<CollectedEvent>,
    pub ruleset: Option<RuleSet>,

    // новые поля (для CLI)
    pub status: Option<serde_json::Value>,
    pub config_patch: Option<serde_json::Value>,
}

pub struct MessageWriter<W: AsyncWrite + Unpin> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> MessageWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub async fn send(&mut self, msg: &WireMessage) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(msg).context("serialize WireMessage")?;
        line.push(b'\n');
        self.inner.write_all(&line).await.context("write message")?;
        self.inner.flush().await.context("flush")?;
        Ok(())
    }
}

pub struct MessageReader<R: AsyncRead + Unpin> {
    inner: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> MessageReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(8192),
        }
    }

    pub async fn read(&mut self) -> anyhow::Result<Option<WireMessage>> {
        // читаем до '\n'
        self.buf.clear();

        loop {
            let mut byte = [0u8; 1];
            let n = self.inner.read(&mut byte).await.context("read byte")?;
            if n == 0 {
                // EOF
                return Ok(None);
            }

            if byte[0] == b'\n' {
                break;
            }

            self.buf.push(byte[0]);

            // защита от бесконечной строки
            if self.buf.len() > 10 * 1024 * 1024 {
                anyhow::bail!("incoming message too large");
            }
        }

        if self.buf.is_empty() {
            return Ok(Some(WireMessage {
                kind: MessageType::Status,
                event: None,
                ruleset: None,
                status: Some(serde_json::json!({"empty": true})),
                config_patch: None,
            }));
        }

        let msg: WireMessage =
            serde_json::from_slice(&self.buf).context("deserialize WireMessage")?;
        Ok(Some(msg))
    }
}
