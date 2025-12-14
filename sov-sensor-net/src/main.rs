use chrono::Utc;
use clap::Parser;
use sov_core::{
    BaseEventMeta, CollectedEvent, EventKind, NetEventData, SensorMode, load_net_sensor_config,
};
use sov_transport::{MessageType, MessageWriter, WireMessage};
use std::convert::TryInto;
use tokio::net::TcpStream;
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config/net-sensor.yaml")]
    config: String,

    #[arg(long)]
    list_ifaces: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    let args = Args::parse();

    if args.list_ifaces {
        list_ifaces()?;
        return Ok(());
    }

    let cfg = load_net_sensor_config(&args.config)?;

    tracing::info!(
        sensor = "net",
        node_id = %cfg.node_id,
        server = %cfg.server_addr,
        iface = %cfg.iface,
        filter = %cfg.pcap_filter,
        "sensor started"
    );

    // Канал остановки
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Отдельная задача: ждём Ctrl+C
    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::warn!("Ctrl+C received, shutting down...");
                let _ = shutdown_tx.send(true);
            }
        });
    }

    // Внешний цикл переподключения
    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        match TcpStream::connect(&cfg.server_addr).await {
            Ok(stream) => {
                tracing::info!(
                    server = %cfg.server_addr,
                    "connected to analyzer"
                );

                // Важно: передаем shutdown_rx внутрь
                if let Err(e) = run_sensor(stream, &cfg, shutdown_rx.clone()).await {
                    if *shutdown_rx.borrow() {
                        // если остановка — не шумим ошибкой
                        tracing::info!("sensor stopping, run_sensor finished");
                    } else {
                        tracing::error!(error = %e, "run_sensor error");
                    }
                }
            }
            Err(e) => {
                if *shutdown_rx.borrow() {
                    break;
                }
                tracing::error!(error = %e, "connect error");
            }
        }

        if *shutdown_rx.borrow() {
            break;
        }

        tracing::info!("reconnect in 5s...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    tracing::info!("sensor stopped");
    Ok(())
}

async fn run_sensor(
    stream: TcpStream,
    cfg: &sov_core::NetSensorConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut writer = MessageWriter::new(stream);

    let snaplen: i32 = cfg.snapshot_len.try_into().unwrap_or(i32::MAX);

    let mut cap = pcap::Capture::from_device(cfg.iface.as_str())?
        .promisc(cfg.promiscuous)
        .snaplen(snaplen)
        // важно: timeout, чтобы цикл мог проверить shutdown
        .timeout(1000)
        .open()?;

    cap.filter(&cfg.pcap_filter, true)?;

    tracing::info!(
        iface = %cfg.iface,
        snaplen = snaplen,
        promisc = cfg.promiscuous,
        "pcap capture opened"
    );

    loop {
        // Быстрая проверка: пришел ли shutdown
        if *shutdown_rx.borrow() {
            tracing::info!("shutdown signal received inside net sensor loop");
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                let (src_ip, src_port, dst_ip, dst_port, proto) = parse_packet_basic(&packet.data);

                let tcp_payload = extract_tcp_payload(packet.data).unwrap_or(&[]);
                let payload_snippet = String::from_utf8_lossy(tcp_payload)
                    .chars()
                    .take(400)
                    .collect::<String>();

                // Debug-вывод только при HTTP признаках
                if payload_snippet.contains("GET ")
                    || payload_snippet.contains("HTTP/")
                    || payload_snippet.contains("Host:")
                {
                    tracing::debug!(
                        src = %format!("{src_ip}:{src_port}"),
                        dst = %format!("{dst_ip}:{dst_port}"),
                        proto = %proto,
                        "payload snippet: {}",
                        payload_snippet
                    );
                }

                let event = CollectedEvent {
                    meta: BaseEventMeta {
                        id: Uuid::new_v4(),
                        node_id: cfg.node_id.clone(),
                        mode: SensorMode::Net,
                        collected_at: Utc::now(),
                    },
                    kind: EventKind::Net(NetEventData {
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        proto,
                        payload_snippet,
                        packet_len: packet.header.len,
                    }),
                };

                let msg = WireMessage {
                    kind: MessageType::Event,
                    event: Some(event),
                    ruleset: None,
                };

                // Если анализатор отвалился — выйдем наружу, чтобы reconnect сработал
                if let Err(e) = writer.send(&msg).await {
                    tracing::warn!(error = %e, "send failed, will reconnect");
                    return Err(e.into());
                }
            }
            Err(_) => {
                // timeout / no packet - ignore
                // за счет timeout мы регулярно возвращаемся сюда и можем выйти по shutdown
            }
        }
    }

    Ok(())
}

fn extract_tcp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return None; // not IPv4
    }

    let ip = &frame[14..];
    if ip.len() < 20 {
        return None;
    }

    let version_ihl = ip[0];
    let version = version_ihl >> 4;
    if version != 4 {
        return None;
    }

    let ihl = (version_ihl & 0x0F) as usize * 4;
    if ip.len() < ihl {
        return None;
    }

    let proto = ip[9];
    if proto != 6 {
        return None; // not TCP
    }

    let tcp = &ip[ihl..];
    if tcp.len() < 20 {
        return None;
    }

    let data_offset = (tcp[12] >> 4) as usize * 4;
    if tcp.len() < data_offset {
        return None;
    }

    Some(&tcp[data_offset..])
}

fn parse_packet_basic(data: &[u8]) -> (String, u16, String, u16, String) {
    if data.len() < 14 + 20 {
        return ("0.0.0.0".into(), 0, "0.0.0.0".into(), 0, "RAW".into());
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return ("0.0.0.0".into(), 0, "0.0.0.0".into(), 0, "NON_IPV4".into());
    }

    let ip = &data[14..];
    let version = ip[0] >> 4;
    if version != 4 {
        return ("0.0.0.0".into(), 0, "0.0.0.0".into(), 0, "NON_IPV4".into());
    }

    let ihl = (ip[0] & 0x0F) as usize * 4;
    if ip.len() < ihl {
        return ("0.0.0.0".into(), 0, "0.0.0.0".into(), 0, "BAD_IHL".into());
    }

    let proto = ip[9];
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);

    let l4 = &ip[ihl..];
    if l4.len() < 4 {
        return (src_ip, 0, dst_ip, 0, "NO_L4".into());
    }

    match proto {
        6 => {
            if l4.len() < 20 {
                return (src_ip, 0, dst_ip, 0, "TCP_SHORT".into());
            }
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            (src_ip, src_port, dst_ip, dst_port, "TCP".into())
        }
        17 => {
            if l4.len() < 8 {
                return (src_ip, 0, dst_ip, 0, "UDP_SHORT".into());
            }
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            (src_ip, src_port, dst_ip, dst_port, "UDP".into())
        }
        _ => (src_ip, 0, dst_ip, 0, format!("IP_PROTO_{proto}")),
    }
}

fn list_ifaces() -> anyhow::Result<()> {
    let devices = pcap::Device::list()?;
    println!("Available pcap interfaces:\n");
    for d in devices {
        println!("Name: {}", d.name);
        if let Some(desc) = d.desc {
            println!("  Desc: {}", desc);
        }
        println!();
    }
    Ok(())
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .init();
}
