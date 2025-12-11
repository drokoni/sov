use clap::Parser;
use chrono::Utc;
use sov_core::{
    load_net_sensor_config, BaseEventMeta, CollectedEvent, EventKind, NetEventData, SensorMode,
};
use sov_transport::{MessageType, MessageWriter, WireMessage};
use uuid::Uuid;
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config/net-sensor.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = load_net_sensor_config(&args.config)?;

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

async fn run_sensor(
    stream: TcpStream,
    cfg: &sov_core::NetSensorConfig,
) -> anyhow::Result<()> {
    let mut writer = MessageWriter::new(stream);

    let mut cap = pcap::Capture::from_device(cfg.iface.as_str())?
        .promisc(cfg.promiscuous)
        .snaplen(cfg.snapshot_len)
        .timeout(1000)
        .open()?;

    cap.filter(&cfg.pcap_filter, true)?;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let (src_ip, src_port, dst_ip, dst_port, proto) =
                    parse_packet_basic(&packet.data);

                let payload_snippet = String::from_utf8_lossy(packet.data)
                    .chars()
                    .take(200)
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
                };

                writer.send(&msg).await?;
            }
            Err(_) => {
                // timeout / no packet - ignore
            }
        }
    }
}

// Очень грубый парсер, чисто для каркаса
fn parse_packet_basic(
    _data: &[u8],
) -> (String, u16, String, u16, String) {
    // TODO: разобрать IP/TCP/UDP
    (
        "0.0.0.0".into(),
        0,
        "0.0.0.0".into(),
        0,
        "RAW".into(),
    )
}

