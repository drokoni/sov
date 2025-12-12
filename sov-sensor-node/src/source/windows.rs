use async_trait::async_trait;
use chrono::Utc;
use sov_core::{BaseEventMeta, CollectedEvent, EventKind, NodeEventData, SensorMode};
use std::collections::HashMap;
use uuid::Uuid;

use super::NodeEventSource;

#[cfg(target_os = "windows")]
mod win_impl {
    use super::*;
    use windows::core::{PCWSTR};
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtRender, EVT_HANDLE, EVT_QUERY_FLAGS,
        EVT_QUERY_CHANNEL_PATH, EVT_RENDER_FLAGS, EVT_RENDER_EVENT_XML,
    };

    /// RAII-обёртка, чтобы не забывать закрывать EVT_HANDLE
    struct EvtHandle(EVT_HANDLE);
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
        // UTF-16 + \0
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    fn extract_event_record_id(xml: &str) -> Option<u64> {
        // Очень простая вырезка: <EventRecordID>123</EventRecordID>
        let start_tag = "<EventRecordID>";
        let end_tag = "</EventRecordID>";

        let s = xml.find(start_tag)? + start_tag.len();
        let e = xml[s..].find(end_tag)? + s;
        xml[s..e].trim().parse::<u64>().ok()
    }

    fn render_event_xml(h: EVT_HANDLE) -> anyhow::Result<String> {
        unsafe {
            // Сначала спросим размер буфера
            let mut used: u32 = 0;
            let mut props: u32 = 0;

            let ok = EvtRender(
                EVT_HANDLE::default(),
                h,
                EVT_RENDER_EVENT_XML,
                0,
                None,
                &mut used,
                &mut props,
            );

            if ok.as_bool() {
                // странно, но пусть
                return Ok(String::new());
            }

            let err = GetLastError();
            if err != ERROR_INSUFFICIENT_BUFFER {
                anyhow::bail!("EvtRender size probe failed: {:?}", err);
            }

            // used — в байтах. Нам нужен буфер u16.
            let wchar_len = (used as usize / 2).saturating_add(1);
            let mut buf: Vec<u16> = vec![0u16; wchar_len];

            let ok2 = EvtRender(
                EVT_HANDLE::default(),
                h,
                EVT_RENDER_EVENT_XML,
                used,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut used,
                &mut props,
            );

            if !ok2.as_bool() {
                let err2 = GetLastError();
                anyhow::bail!("EvtRender failed: {:?}", err2);
            }

            // buf содержит UTF-16 строку с '\0' в конце
            let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            Ok(String::from_utf16_lossy(&buf[..nul]))
        }
    }

    pub struct WindowsEventLogSource {
        node_id: String,
        channels: Vec<String>,
        last_record_id: HashMap<String, u64>,
        max_per_poll: u32,
    }

    impl WindowsEventLogSource {
        pub fn new(cfg: &sov_core::NodeSensorConfig) -> anyhow::Result<Self> {

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
            // XPath query: события с EventRecordID > since_id
            // Мы читаем как "channel path query"
            let query = format!("*[System[EventRecordID>{}]]", since_id);

            let channel_w = to_wide_null(channel);
            let query_w = to_wide_null(&query);

            unsafe {
                let h = EvtQuery(
                    EVT_HANDLE::default(),
                    PCWSTR(channel_w.as_ptr()),
                    PCWSTR(query_w.as_ptr()),
                    EVT_QUERY_FLAGS(EVT_QUERY_CHANNEL_PATH.0),
                );

                if h.is_invalid() {
                    anyhow::bail!("EvtQuery failed for channel={channel}");
                }

                Ok(EvtHandle(h))
            }
        }

        fn next_events(&self, query: &EvtHandle) -> anyhow::Result<Vec<EvtHandle>> {
            unsafe {
                // Возьмём батч хэндлов событий
                let mut arr: Vec<EVT_HANDLE> = vec![EVT_HANDLE::default(); self.max_per_poll as usize];
                let mut returned: u32 = 0;

                let ok = EvtNext(
                    query.0,
                    self.max_per_poll,
                    arr.as_mut_ptr(),
                    0,
                    0,
                    &mut returned,
                );

                if !ok.as_bool() {
                    // Если ничего нет — просто вернём пусто
                    return Ok(vec![]);
                }

                arr.truncate(returned as usize);
                Ok(arr.into_iter().map(EvtHandle).collect())
            }
        }
    }

    #[async_trait]
    impl NodeEventSource for WindowsEventLogSource {
        async fn poll(&mut self) -> anyhow::Result<Vec<CollectedEvent>> {
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

                // “только новые” дальше
                self.last_record_id.insert(ch.clone(), max_seen);
            }

            Ok(out)
        }
    }

    pub(super) use WindowsEventLogSource as Impl;
}

#[cfg(target_os = "windows")]
pub struct WindowsEventLogSource(win_impl::Impl);

#[cfg(target_os = "windows")]
impl WindowsEventLogSource {
    pub fn new(cfg: &sov_core::NodeSensorConfig) -> anyhow::Result<Self> {
        Ok(Self(win_impl::Impl::new(cfg)?))
    }
}

#[cfg(target_os = "windows")]
#[async_trait]
impl NodeEventSource for WindowsEventLogSource {
    async fn poll(&mut self) -> anyhow::Result<Vec<CollectedEvent>> {
        self.0.poll().await
    }
}

#[cfg(not(target_os = "windows"))]
pub struct WindowsEventLogSource;

#[cfg(not(target_os = "windows"))]
impl WindowsEventLogSource {
    pub fn new(_cfg: &sov_core::NodeSensorConfig) -> anyhow::Result<Self> {
        anyhow::bail!("WindowsEventLogSource is only available on Windows builds")
    }
}

#[cfg(not(target_os = "windows"))]
#[async_trait]
impl NodeEventSource for WindowsEventLogSource {
    async fn poll(&mut self) -> anyhow::Result<Vec<CollectedEvent>> {
        Ok(vec![])
    }
}

