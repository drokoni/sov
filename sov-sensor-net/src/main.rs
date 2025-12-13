use chrono::Utc;
use clap::Parser;
use sov_core::{
    BaseEventMeta, CollectedEvent, EventKind, NetEventData, SensorMode, load_net_sensor_config,
};
use sov_transport::{MessageType, MessageWriter, WireMessage};
use std::convert::TryInto;
use tokio::net::TcpStream;
use uuid::Uuid;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config/net-sensor.yaml")]
    config: String,

    /// Print available pcap interfaces and exit
    #[arg(long)]
    list_ifaces: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = load_net_sensor_config(&args.config)?;
    if args.list_ifaces {
        list_ifaces()?;
        return Ok(());
    }

    loop {
        match TcpStream::connect(&cfg.server_addr).await {
            Ok(stream) => {
                println!("Net sensor connected to analyzer at {}", cfg.server_addr);
                if let Err(e) = run_sensor(stream, &cfg).await {
                    eprintln!("Net sensor error: {e}");
                }
            }
            Err(e) => {
                eprintln!("Connect error: {e}");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn run_sensor(stream: TcpStream, cfg: &sov_core::NetSensorConfig) -> anyhow::Result<()> {
    let mut writer = MessageWriter::new(stream);

    let snaplen: i32 = cfg.snapshot_len.try_into().unwrap_or(i32::MAX);

    let mut cap = pcap::Capture::from_device(cfg.iface.as_str())?
        .promisc(cfg.promiscuous)
        .snaplen(snaplen)
        .timeout(1000)
        .open()?;

    cap.filter(&cfg.pcap_filter, true)?;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let (src_ip, src_port, dst_ip, dst_port, proto) = parse_packet_basic(&packet.data);

                let tcp_payload = extract_tcp_payload(packet.data).unwrap_or(&[]);
                let payload_snippet = String::from_utf8_lossy(tcp_payload)
                    .chars()
                    .take(400)
                    .collect::<String>();

                if payload_snippet.contains("GET") || payload_snippet.contains("HTTP") {
                    println!("PAYLOAD_SNIPPET: {}", payload_snippet);
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
                writer.send(&msg).await?;
            }
            Err(_) => {
                // timeout / no packet - ignore
            }
        }
    }
}

fn extract_tcp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        // IPv4
        return None;
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
        // TCP
        return None;
    }

    let tcp = &ip[ihl..];
    if tcp.len() < 20 {
        return None;
    }

    let data_offset = (tcp[12] >> 4) as usize * 4;
    if tcp.len() < data_offset {
        return None;
    }

    let payload = &tcp[data_offset..];
    Some(payload)
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
            // TCP
            if l4.len() < 20 {
                return (src_ip, 0, dst_ip, 0, "TCP_SHORT".into());
            }
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            (src_ip, src_port, dst_ip, dst_port, "TCP".into())
        }
        17 => {
            // UDP
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
