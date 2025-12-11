use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    SystemStart,
    SystemStop,

    SensorConnect,
    SensorDisconnect,

    Alert,
    RulesUpdate,
    ConfigChange,

    AdminLogin,
    AdminLogout,
    RoleChange,

    AuditRead,
    AuditTamperDetected,
    TimeChangeDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub subject: String,
    pub result: String, // "success" / "failure" / "warning"
    pub details: serde_json::Value,
}

#[derive(Clone)]
pub struct AuditLogger {
    path: PathBuf,
}

impl AuditLogger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn log(&self, rec: &AuditRecord) -> std::io::Result<()> {
        let line =
            serde_json::to_string(rec).unwrap_or_else(|_| "{\"error\":\"serialize\"}".to_string());
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(())
    }
}
