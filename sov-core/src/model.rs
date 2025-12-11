use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SensorMode {
    Node,
    Net,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseEventMeta {
    pub id: Uuid,
    pub node_id: String,
    pub mode: SensorMode,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEventData {
    pub source_log: String,
    pub raw_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEventData {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub payload_snippet: String,
    pub packet_len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    Node(NodeEventData),
    Net(NetEventData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedEvent {
    pub meta: BaseEventMeta,
    pub kind: EventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisResultKind {
    Normal,
    Suspicious,
    Intrusion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub event_id: Uuid,
    pub node_id: String,
    pub timestamp: DateTime<Utc>,
    pub kind: AnalysisResultKind,
    pub rule_id: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub event: CollectedEvent,
    pub result: AnalysisResult,
}
