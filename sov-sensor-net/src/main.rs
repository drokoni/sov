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

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::warn!("Ctrl+C received, shutting down...");
                let _ = shutdown_tx.send(true);
            }
        });
    }

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        match TcpStream::connect(&cfg.server_addr).await {
            Ok(tcp) => {
                tracing::info!("Net sensor connected to analyzer");

                let res = if cfg.tls.as_ref().map(|t| t.enabled).unwrap_or(false) {
                    run_sensor_tls(tcp, &cfg, shutdown_rx.clone()).await
                } else {
                    run_sensor_plain(tcp, &cfg, shutdown_rx.clone()).await
                };

                if let Err(e) = res {
                    tracing::error!("Net sensor error: {e}");
                }
            }
            Err(e) => tracing::error!("Connect error: {e}"),
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

/* ===================== TLS helpers ===================== */

fn tls_cfg_from_section(t: &sov_core::TlsSection) -> sov_transport::tls::TlsConfig {
    sov_transport::tls::TlsConfig {
        ca_path: t.ca_path.clone(),
        cert_path: t.cert_path.clone(),
        key_path: t.key_path.clone(),
        server_name: t.server_name.clone(),
        require_mtls: t.require_mtls,
    }
}

async fn run_sensor_plain(
    tcp: TcpStream,
    cfg: &sov_core::NetSensorConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut writer = MessageWriter::new(tcp);
    capture_loop(cfg, shutdown_rx, &mut writer).await
}

async fn run_sensor_tls(
    tcp: TcpStream,
    cfg: &sov_core::NetSensorConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tls = cfg.tls.as_ref().unwrap();
    let tls_cfg = tls_cfg_from_section(tls);

    let connector = sov_transport::tls::build_tls_connector(&tls_cfg)?;

    let sni = tls_cfg
        .server_name
        .clone()
        .unwrap_or_else(|| "sov-analyzer".to_string());
    let server_name = tokio_rustls::rustls::ServerName::try_from(sni.as_str())?;

    let tls_stream = connector.connect(server_name, tcp).await?;
    tracing::info!("TLS connected to analyzer");

    let (_rd, wr) = tokio::io::split(tls_stream);
    let mut writer = MessageWriter::new(wr);

    capture_loop(cfg, shutdown_rx, &mut writer).await
}

/* ===================== PCAP LOOP ===================== */

async fn capture_loop<W: tokio::io::AsyncWrite + Unpin>(
    cfg: &sov_core::NetSensorConfig,
    mut shutdown_rx: watch::Receiver<bool>,
    writer: &mut MessageWriter<W>,
) -> anyhow::Result<()> {
    let snaplen: i32 = cfg.snapshot_len.try_into().unwrap_or(i32::MAX);

    let mut cap = pcap::Capture::from_device(cfg.iface.as_str())?
        .promisc(cfg.promiscuous)
        .snaplen(snaplen)
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
        if *shutdown_rx.borrow() {
            tracing::info!("shutdown signal received");
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                let (src_ip, src_port, dst_ip, dst_port, proto) = parse_packet_basic(&packet.data);

                let payload = extract_tcp_payload(packet.data).unwrap_or(&[]);
                let payload_snippet = String::from_utf8_lossy(payload)
                    .chars()
                    .take(400)
                    .collect::<String>();

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
                    status: None,
                    config_patch: None,
                };

                if let Err(e) = writer.send(&msg).await {
                    tracing::warn!(error = %e, "send failed");
                    return Err(e.into());
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

/* ===================== PACKET PARSING ===================== */

fn extract_tcp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 34 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return None;
    }

    let ip = &frame[14..];
    let ihl = (ip[0] & 0x0F) as usize * 4;
    if ip.len() < ihl + 20 || ip[9] != 6 {
        return None;
    }

    let tcp = &ip[ihl..];
    let data_offset = (tcp[12] >> 4) as usize * 4;
    if tcp.len() < data_offset {
        return None;
    }

    Some(&tcp[data_offset..])
}

fn parse_packet_basic(data: &[u8]) -> (String, u16, String, u16, String) {
    if data.len() < 34 {
        return ("0.0.0.0".into(), 0, "0.0.0.0".into(), 0, "RAW".into());
    }

    let ip = &data[14..];
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);

    let ihl = (ip[0] & 0x0F) as usize * 4;
    let l4 = &ip[ihl..];

    if l4.len() < 4 {
        return (src_ip, 0, dst_ip, 0, "NO_L4".into());
    }

    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);

    (src_ip, src_port, dst_ip, dst_port, "TCP".into())
}

/* ===================== UTILS ===================== */

fn list_ifaces() -> anyhow::Result<()> {
    let devices = pcap::Device::list()?;
    for d in devices {
        println!("{} {:?}", d.name, d.desc);
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
