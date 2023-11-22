use clap::builder::ValueParserFactory;
use log::info;
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use clap::Parser;
use common::{BthHdr, CtrlSequence};
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::fs::File;
use std::io::prelude::*;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Sequence {
    #[serde(rename = "type")]
    sequence_type: BthSeqType,
    id: u32,
    last: bool,
    pre: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    qp_id: u32,
    sequence: Vec<Sequence>,
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "192.168.1.102")]
    dst: String,
    #[clap(long, default_value = "4791")]
    port: String,
    #[clap(long, default_value = "4792")]
    ctrl: String,
    #[clap(short, long, default_value = "lima1")]
    iface: String,
    #[clap(short, long, default_value = "config.yaml")]
    config: Option<String>,
    #[clap(short, long, default_value = "5")]
    messages: Option<u32>,
    #[clap(short, long, default_value = "5")]
    packets: Option<u32>,
    #[clap(short, long, default_value = "5")]
    qpid: Option<u32>,
    #[clap(short, long, default_value = "100")]
    start: Option<u32>,
    #[clap(long, default_value = "512")]
    packet_size: usize,
    #[clap(long, default_value = "false")]
    xctrl: bool,
    #[clap(long, value_parser = parse_packet_delay)]
    delay: Option<PacketDelay>,
}

#[derive(Copy, Clone, Debug)]
pub struct PacketDelay(u32,u32);

fn parse_packet_delay(s: &str) -> Result<PacketDelay, anyhow::Error> {
    let mut split = s.split(',');
    let first = split.next().ok_or(anyhow::anyhow!("missing first value"))?;
    let first = first.parse::<u32>()?;
    let second = split.next().ok_or(anyhow::anyhow!("missing second value"))?;
    let second = second.parse::<u32>()?;
    Ok(PacketDelay(first, second))
}



fn read_yaml_file(file_path: &str) -> Result<Vec<Message>, anyhow::Error> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let messages: Vec<Message> = serde_yaml::from_str(&contents)?;

    Ok(messages)
}

// specified by the iface parameter.
fn get_ip_address_from_interface(iface_name: &str) -> Result<std::net::IpAddr, anyhow::Error> {
    let iface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == iface_name)
        .ok_or(anyhow::anyhow!("interface not found"))?;
    let ip = iface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .ok_or(anyhow::anyhow!("interface has no ipv4 address"))?
        .ip();
    Ok(ip)
}

#[derive(Clone, Debug)]
struct BthSeq{
    messages: Vec<BthHdr>,
    qp_id: [u8;3],
}

impl From<Message> for BthSeq{
    fn from(message: Message) -> Self{
        let qp_id = u32::to_be(message.qp_id);
        let qp_id = qp_id.to_le_bytes();
        let mut bth_seq = BthSeq::new([qp_id[1], qp_id[2], qp_id[3]]);
        for sequence in message.sequence{
            bth_seq.add_msg(sequence.sequence_type, sequence.id, sequence.last, sequence.pre);
        }
        bth_seq
    }
}

impl BthSeq{
    fn new(qp_id: [u8;3]) -> Self{
        Self{
            messages: Vec::new(),
            qp_id,
        }
    }
    fn add_msg(&mut self, bth_seq_type: BthSeqType, seq: u32, last: bool, _pre: bool){
        let seq = u32::to_be(seq);
        let seq = seq.to_le_bytes();
        let mut bth_hdr = BthHdr{
            opcode: 1,
            sol_event: 0,
            part_key: 65535,
            res: 0,
            dest_qpn: self.qp_id,
            ack: 0,
            psn_seq: [seq[1], seq[2], seq[3]]
        };
        match bth_seq_type {
            BthSeqType::First => {
                bth_hdr.opcode = 0;
            },
            BthSeqType::Middle => {
                bth_hdr.opcode = 1;
            },
            BthSeqType::Last => {
                bth_hdr.opcode = 2;
                bth_hdr.ack = 128;
                if last { bth_hdr.res = 1;}
            },
        }
        self.messages.push(bth_hdr);
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
enum BthSeqType{
    First,
    Middle,
    Last,
}

async fn send_ctrl(sock: &UdpSocket, messages: u32, packets: u32, qpid: u32, start: u32, packet_size: usize, start_end: u8) -> anyhow::Result<()>{
    let pre_sequence = CtrlSequence{
        num_packet: messages * packets,
        first: start,
        last: start + messages * packets - 1,
        qp_id: qpid,
        start_end,
    };
    let buf = unsafe {
        let ptr = &pre_sequence as *const CtrlSequence as *const u8;
        std::slice::from_raw_parts(ptr, std::mem::size_of::<BthHdr>())
    };
    let mut b = Vec::from(buf);
    let c = Vec::with_capacity(packet_size);
    let c = c.as_slice();
    b.extend_from_slice(c);
    let b = b.as_slice();
    let _len = sock.send(b).await?;
    Ok(())

}

async fn send_messages(sock: &UdpSocket, messages: u32, packets: u32, qpid: u32, start: u32, packet_size: usize, packet_delay: Option<PacketDelay>) -> anyhow::Result<()>{
    let mut seq_counter = start;
    let tot_seq = messages * packets;
    let mut num_seq_counter = 0;
    for _i in 0..messages{
        let mut packet_counter = 0;
        let mut sequence = Vec::new();
        for j in 0..packets{
            num_seq_counter += 1;
            let sequence_type = if j == 0{
                BthSeqType::First
            } else if j == packets - 1{
                BthSeqType::Last
            } else {
                BthSeqType::Middle
            };
            sequence.push(Sequence{
                sequence_type,
                id: seq_counter,
                last: tot_seq == num_seq_counter,
                pre: false,
            });
            seq_counter += 1;
        }
        let msg = Message{
            qp_id: qpid,
            sequence,
        };
        let bth_seq = BthSeq::from(msg);
        for bth_hdr in bth_seq.messages{
            let buf = unsafe {
                let ptr = &bth_hdr as *const BthHdr as *const u8;
                std::slice::from_raw_parts(ptr, std::mem::size_of::<BthHdr>())
            };
            let mut b = Vec::from(buf);
            let c = Vec::with_capacity(packet_size);
            let c = c.as_slice();
            b.extend_from_slice(c);
            let b = b.as_slice();
            if let Some(packet_delay) = packet_delay{
                if packet_counter % packet_delay.0 == 0{
                    println!("packet {}, sleeping for {} microseconds", packet_counter, packet_delay.1);
                    tokio::time::sleep(tokio::time::Duration::from_micros(packet_delay.1 as u64)).await;
                }
            }
            let _len = sock.send(b).await?;
            packet_counter += 1;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()>{
    println!("starting udp client");
    println!("bla");
    let opt = Opt::parse();
    let ip = get_ip_address_from_interface(&opt.iface)?;
    let data_ip_port = format!("{}:{}", ip.to_string(), random_src_port());  
    let ctrl_ip_port = format!("{}:{}", ip.to_string(), random_src_port());
    let packet_size = opt.packet_size;  
    let data_sock = UdpSocket::bind(data_ip_port).await?;
    let ctrl_sock = UdpSocket::bind(ctrl_ip_port).await?;
    let data_addr = format!("{}:{}", opt.dst, opt.port);
    let ctrl_addr = format!("{}:{}", opt.dst, opt.ctrl);
    let remote_data_addr = data_addr.parse::<SocketAddr>()?;
    let remote_ctrl_addr = ctrl_addr.parse::<SocketAddr>()?;
    ctrl_sock.connect(remote_ctrl_addr).await?;
    data_sock.connect(remote_data_addr).await?;
    println!("connected to {} and {}", data_addr, ctrl_addr);
    if opt.messages.is_some() && opt.packets.is_some() && opt.qpid.is_some() && opt.start.is_some(){
        if opt.xctrl{
            send_ctrl(&ctrl_sock, opt.messages.unwrap(), opt.packets.unwrap(), opt.qpid.unwrap(), opt.start.unwrap(), packet_size, 0).await?;
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        println!("sending messages");
        send_messages(&data_sock, opt.messages.unwrap(), opt.packets.unwrap(), opt.qpid.unwrap(), opt.start.unwrap(), packet_size, opt.delay).await?;
        if opt.xctrl{
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            send_ctrl(&ctrl_sock, opt.messages.unwrap(), opt.packets.unwrap(), opt.qpid.unwrap(), opt.start.unwrap(), packet_size, 1).await?;
        }

        return Ok(());
    }

    let messages = if let Some(config) = opt.config{
        read_yaml_file(&config)?
    } else {
        panic!("either config or messages, packets, qpid, and start must be specified");
    };
    //let messages = read_yaml_file(&opt.config)?;
    for msg in messages {
        let bth_seq = BthSeq::from(msg);
        for bth_hdr in bth_seq.messages{
            let buf = unsafe {
                let ptr = &bth_hdr as *const BthHdr as *const u8;
                std::slice::from_raw_parts(ptr, std::mem::size_of::<BthHdr>())
            };
            let mut b = Vec::from(buf);
            let c = Vec::with_capacity(packet_size);
            let c = c.as_slice();
            b.extend_from_slice(c);
            let b = b.as_slice();
            let _len = data_sock.send(b).await?;
        }
    }
    Ok(())
}

fn random_src_port() -> u16 {
    rand::random::<u16>()
}


