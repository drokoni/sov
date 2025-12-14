use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    pub listen_addr: String,
    pub tls_enabled: bool,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,

    pub rules_path: PathBuf,
    pub audit_log_path: PathBuf,
    pub alerts_log_path: PathBuf,
    pub danger_log_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSensorConfig {
    pub server_addr: String,
    pub node_id: String,
    pub log_paths: Vec<PathBuf>,
    pub poll_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetSensorConfig {
    pub server_addr: String,
    pub node_id: String,
    pub iface: String,
    pub pcap_filter: String,
    pub snapshot_len: u32,
    pub promiscuous: bool,
}

pub fn load_analyzer_config(path: &str) -> anyhow::Result<AnalyzerConfig> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}

pub fn load_node_sensor_config(path: &str) -> anyhow::Result<NodeSensorConfig> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}

pub fn load_net_sensor_config(path: &str) -> anyhow::Result<NetSensorConfig> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TlsSection {
    pub enabled: bool,
    pub require_mtls: bool,
    pub ca_path: String,
    pub cert_path: String,
    pub key_path: String,
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AnalyzerConfig {
    pub listen_addr: String,
    pub rules_path: std::path::PathBuf,
    pub audit_log_path: String,
    pub tls: Option<TlsSection>,
}
