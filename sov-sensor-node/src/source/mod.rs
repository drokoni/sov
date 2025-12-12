use async_trait::async_trait;
use clap::ValueEnum;
use sov_core::CollectedEvent;

#[async_trait]
pub trait NodeEventSource: Send {
    async fn poll(&mut self) -> anyhow::Result<Vec<CollectedEvent>>;
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum OsKind {
    Linux,
    Windows,
}

/// Автовыбор по ОС (чтобы “само поднималось”)
pub fn default_os() -> OsKind {
    #[cfg(target_os = "windows")]
    {
        OsKind::Windows
    }
    #[cfg(not(target_os = "windows"))]
    {
        OsKind::Linux
    }
}

pub fn create_source(
    os: OsKind,
    cfg: &sov_core::NodeSensorConfig,
) -> anyhow::Result<Box<dyn NodeEventSource>> {
    match os {
        OsKind::Linux => {
            #[cfg(not(target_os = "windows"))]
            {
                Ok(Box::new(crate::source::linux::LinuxLogSource::new(cfg)?))
            }
            #[cfg(target_os = "windows")]
            {
                // на Windows Linux-источник не нужен, но пусть будет понятная ошибка
                anyhow::bail!("Linux source selected, but running on Windows")
            }
        }
        OsKind::Windows => {
            #[cfg(target_os = "windows")]
            {
                Ok(Box::new(crate::source::windows::WindowsEventLogSource::new(cfg)?))
            }
            #[cfg(not(target_os = "windows"))]
            {
                anyhow::bail!("Windows source selected, but this binary is not built for Windows")
            }
        }
    }
}

pub mod linux;
pub mod windows;

