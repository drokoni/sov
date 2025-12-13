use super::NodeEventSource;
use async_trait::async_trait;

use chrono::Utc;
use sov_core::{BaseEventMeta, CollectedEvent, EventKind, NodeEventData, SensorMode};
use uuid::Uuid;

/// Публичный тип, который существует ВСЕГДА.
/// - без features: пустышка
/// - с features на Windows: реальная реализация
pub struct WindowsEventLogSource(Impl);

impl WindowsEventLogSource {
    pub fn new(cfg: &sov_core::NodeSensorConfig) -> anyhow::Result<Self> {
        Ok(Self(Impl::new(cfg)?))
    }
}

#[async_trait]
impl NodeEventSource for WindowsEventLogSource {
    async fn poll(&mut self) -> anyhow::Result<Vec<CollectedEvent>> {
        self.0.poll().await
    }
}
#[cfg(not(all(target_os = "windows", feature = "windows-eventlog")))]
struct Impl;

#[cfg(not(all(target_os = "windows", feature = "windows-eventlog")))]
impl Impl {
    fn new(_cfg: &sov_core::NodeSensorConfig) -> anyhow::Result<Self> {
        Ok(Self)
    }

    async fn poll(&mut self) -> anyhow::Result<Vec<CollectedEvent>> {
        Ok(vec![])
    }
}

#[cfg(all(target_os = "windows", feature = "windows-eventlog"))]
mod real {
    use super::*;
    use std::collections::HashMap;

    use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows::Win32::System::EventLog::{
        EVT_HANDLE, EVT_QUERY_FLAGS, EVT_RENDER_FLAGS, EvtClose, EvtNext, EvtQuery, EvtRender,
    };
    use windows::core::{HRESULT, PCWSTR};

    /// RAII для EVT_HANDLE
    pub(super) struct EvtHandle(pub(super) EVT_HANDLE);
    impl Drop for EvtHandle {
        fn drop(&mut self) {
            unsafe {
                if !self.0.is_invalid() {
                    let _ = EvtClose(self.0);
                }
            }
        }
    }

    fn to_wide_null(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    fn extract_event_record_id(xml: &str) -> Option<u64> {
        let start_tag = "<EventRecordID>";
        let end_tag = "</EventRecordID>";
        let s = xml.find(start_tag)? + start_tag.len();
        let e = xml[s..].find(end_tag)? + s;
        xml[s..e].trim().parse::<u64>().ok()
    }

    fn is_insufficient_buffer(err: &windows::core::Error) -> bool {
        // Win32 ERROR_INSUFFICIENT_BUFFER -> HRESULT
        err.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0)
    }

    fn render_event_xml(h: EVT_HANDLE) -> anyhow::Result<String> {
        unsafe {
            let mut used: u32 = 0;
            let mut props: u32 = 0;

            // 1) Пробуем без буфера, чтобы узнать размер
            let probe = EvtRender(
                EVT_HANDLE::default(),
                h,
                EVT_RENDER_FLAGS::EVT_RENDER_EVENT_XML,
                0,
                None,
                &mut used,
                &mut props,
            );

            if let Err(e) = probe {
                if !is_insufficient_buffer(&e) {
                    return Err(anyhow::anyhow!("EvtRender probe failed: {e:?}"));
                }
            }

            if used == 0 {
                return Ok(String::new());
            }

            // used — байты UTF-16 строки
            let wchar_len = (used as usize / 2).saturating_add(1);
            let mut buf: Vec<u16> = vec![0u16; wchar_len];

            // Рендерим в буфер
            EvtRender(
                EVT_HANDLE::default(),
                h,
                EVT_RENDER_FLAGS::EVT_RENDER_EVENT_XML,
                used,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut used,
                &mut props,
            )?;

            let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            Ok(String::from_utf16_lossy(&buf[..nul]))
        }
    }

    pub(super) struct RealImpl {
        node_id: String,
        channels: Vec<String>,
        last_record_id: HashMap<String, u64>,
        max_per_poll: usize,
    }

    impl RealImpl {
        pub fn new(cfg: &sov_core::NodeSensorConfig) -> anyhow::Result<Self> {
            // В Windows используем cfg.log_paths как список каналов:
            // "Security", "System", "Application"
            let channels = if cfg.log_paths.is_empty() {
                vec!["Security".to_string()]
            } else {
                cfg.log_paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect()
            };

            let mut last_record_id = HashMap::new();
            for ch in &channels {
                last_record_id.insert(ch.clone(), 0);
            }

            Ok(Self {
                node_id: cfg.node_id.clone(),
                channels,
                last_record_id,
                max_per_poll: 128,
            })
        }

        fn query_channel_since(&self, channel: &str, since_id: u64) -> anyhow::Result<EvtHandle> {
            let query = format!("*[System[EventRecordID>{}]]", since_id);

            let ch_w = to_wide_null(channel);
            let q_w = to_wide_null(&query);

            unsafe {
                let h = EvtQuery(
                    EVT_HANDLE::default(),
                    PCWSTR(ch_w.as_ptr()),
                    PCWSTR(q_w.as_ptr()),
                    EVT_QUERY_FLAGS::EVT_QUERY_CHANNEL_PATH.0,
                )?;

                if h.is_invalid() {
                    anyhow::bail!("EvtQuery returned invalid handle for channel={channel}");
                }

                Ok(EvtHandle(h))
            }
        }

        fn next_events(&self, query: &EvtHandle) -> anyhow::Result<Vec<EvtHandle>> {
            unsafe {
                let mut raw: Vec<isize> = vec![0isize; self.max_per_poll];
                let mut returned: u32 = 0;

                let res = EvtNext(query.0, &mut raw, 0, 0, &mut returned);

                if res.is_err() || returned == 0 {
                    return Ok(vec![]);
                }

                let mut out = Vec::with_capacity(returned as usize);
                for i in 0..(returned as usize) {
                    out.push(EvtHandle(EVT_HANDLE(raw[i])));
                }
                Ok(out)
            }
        }

        pub async fn poll(&mut self) -> anyhow::Result<Vec<CollectedEvent>> {
            let mut out = Vec::new();

            for ch in &self.channels {
                let since = *self.last_record_id.get(ch).unwrap_or(&0);
                let q = self.query_channel_since(ch, since)?;

                let events = self.next_events(&q)?;
                if events.is_empty() {
                    continue;
                }

                let mut max_seen = since;

                for evh in events {
                    let xml = render_event_xml(evh.0)?;

                    if let Some(rid) = extract_event_record_id(&xml) {
                        if rid > max_seen {
                            max_seen = rid;
                        }
                    }

                    out.push(CollectedEvent {
                        meta: BaseEventMeta {
                            id: Uuid::new_v4(),
                            node_id: self.node_id.clone(),
                            mode: SensorMode::Node,
                            collected_at: Utc::now(),
                        },
                        kind: EventKind::Node(NodeEventData {
                            source_log: ch.clone(),
                            raw_line: xml,
                        }),
                    });
                }

                self.last_record_id.insert(ch.clone(), max_seen);
            }

            Ok(out)
        }
    }
}

#[cfg(all(target_os = "windows", feature = "windows-eventlog"))]
struct Impl(real::RealImpl);

#[cfg(all(target_os = "windows", feature = "windows-eventlog"))]
impl Impl {
    fn new(cfg: &sov_core::NodeSensorConfig) -> anyhow::Result<Self> {
        Ok(Self(real::RealImpl::new(cfg)?))
    }

    async fn poll(&mut self) -> anyhow::Result<Vec<CollectedEvent>> {
        self.0.poll().await
    }
}
