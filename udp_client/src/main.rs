use clap::builder::ValueParserFactory;
use log::info;
use network_types::eth::{self, EthHdr};
use network_types::ip::Ipv4Hdr;
use network_types::udp::UdpHdr;
use pnet::datalink::{NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::Packet;
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::util::MacAddr;
use rtnetlink::{new_connection, Error, Handle, IpVersion};
use netlink_packet_route::RouteMessage;
use rand::distributions::{Standard, Distribution};
use rand::random;
use futures::stream::TryStreamExt;
use tokio::net::UdpSocket;
use core::panic;
use std::any;
use std::collections::BTreeMap;
use std::net::{SocketAddr, Ipv4Addr, IpAddr};
use clap::Parser;
use common::{
    BthHdr,
    DethHdr,
    MadHdr,
    CmConnectReply,
    CmConnectRequest,
    CmDisconnectReply,
    CmDisconnectRequest,
    CmReadyToUse,
    IpCmServiceId,
    IpCmPrivateData,
    InvariantCrc,
};
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
    #[clap(long, default_value = "512")]
    packet_size: usize,
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

struct CmHandler{
    transaction_id: [u8;8],
    starting_psn: [u8;3],
    qp_id: [u8;3],
}


impl CmHandler{
    async fn send_request(sock: &UdpSocket, src_ip: u32, dst_ip: u32, src_port: u16) -> anyhow::Result<Self> {
        let mut bth_hdr = BthHdr::default();
        bth_hdr.opcode = u8::to_be(100);
        bth_hdr.dest_qpn = [0,0,1];
        let mut deth_hdr = DethHdr::default();
        deth_hdr.src_qpn = [0,0,1];
        let q_key: u32 = 0x0000000080010000;
        deth_hdr.queue_key = u32::to_be(q_key);
        let mut mad_hdr = MadHdr::default();
        let tid: u64 = 0x0000000431544453;
        let tid_as_u8 = tid.to_be_bytes();
        mad_hdr.attribute_id = u16::to_be(0x0010);
        mad_hdr.transaction_id = tid_as_u8;
        mad_hdr.mgmt_class = u8::to_be(0x07);
        mad_hdr.base_version = u8::to_be(0x01);
        mad_hdr.class_version = u8::to_be(0x02);
        mad_hdr.method = u8::to_be(0x03);
        let mut cm_connect_request_hdr = CmConnectRequest::default();
        let local_comm_id: u32 = 0x53445431;
        cm_connect_request_hdr.local_comm_id = u32::to_be(local_comm_id);
        cm_connect_request_hdr.ip_cm_service_id = IpCmServiceId{
            prefix: [0,0,0,0,1],
            protocol: u8::to_be(0x06),
            destination_port: u16::to_be(0x4853),
        };
        cm_connect_request_hdr.local_ca_guid = random_id();
        cm_connect_request_hdr.local_qpn = random_id();
        cm_connect_request_hdr.starting_psn = random_id();
        cm_connect_request_hdr.partition_key = u16::to_be(0xffff);
        cm_connect_request_hdr.path_packet_payload_mtu = u8::to_be(0x0037);
        cm_connect_request_hdr.primary_local_port_lid = u16::to_be(65535);
        cm_connect_request_hdr.primary_remote_port_lid = u16::to_be(65535);
        cm_connect_request_hdr.ghost2 = u16::to_be(0xFFFF);
        cm_connect_request_hdr.primary_local_port_gid = u32::to_be(src_ip);
        cm_connect_request_hdr.ghost4 = u16::to_be(0xFFFF);
        cm_connect_request_hdr.primary_remote_port_gid = u32::to_be(dst_ip);
        cm_connect_request_hdr.primary_flow_label = random_id();
        cm_connect_request_hdr.primary_hop_limit = u8::to_be(0x40);
        cm_connect_request_hdr.ip_cm_private_data = IpCmPrivateData{
            ip_cm_major_minor_version: 0,
            ip_cm_ip_version: u8::to_be(0x40),
            ip_cm_source_port: u16::to_be(src_port),
            ghost1: [0;12],
            ip_cm_destination_ip: u32::to_be(dst_ip),
            ghost2: [0;12],
            ip_cm_source_ip: u32::to_be(src_ip),
            ip_cm_consumer_private_data: [0;14],
        };

        println!("mad hdr: {:#?}", mad_hdr);
        println!("cm connect request hdr: {:#?}", cm_connect_request_hdr);
        let invariant_crc = InvariantCrc{
            crc: random_id(),
        };
        let mut buf = Buffer::new();
        let b = buf.add(bth_hdr)
            .add(deth_hdr)
            .add(mad_hdr)
            .add(cm_connect_request_hdr)
            .add(invariant_crc)
            .as_slice();


        sock.send(b).await?;
        println!("sent request");
        Ok(CmHandler{
            transaction_id: mad_hdr.transaction_id,
            starting_psn: cm_connect_request_hdr.starting_psn,
            qp_id: [0,0,0],
        })
    }
    async fn wait_for_reply(&mut self, sock: &UdpSocket) -> anyhow::Result<()>{
        let now = tokio::time::Instant::now();
        let time_out_duration = tokio::time::Duration::from_secs(5);
        let mut buf = [0; 1024];
        println!("waiting for reply");
        loop {

            if now.elapsed() > time_out_duration{
                println!("timeout");
                panic!("timeout");
            }

            let (len, _) = sock.recv_from(&mut buf).await?;
            let buf = &buf[..len];
            let bth_hdr = unsafe {
                let ptr = &buf[0] as *const u8 as *const BthHdr;
                *ptr
            };
            if bth_hdr.opcode != u8::from_be(100) && bth_hdr.dest_qpn != [0,0,1]{
                println!("wrong opcode or dest qpn");
                continue
            }
            let mad_hdr = unsafe {
                let ptr = &buf[BthHdr::LEN + DethHdr::LEN] as *const u8 as *const MadHdr;
                *ptr
            };
            if mad_hdr.attribute_id != 0x0013 {
                println!("wrong attribute id");
                continue
            }
            let cm_connect_reply_hdr = unsafe {
                let ptr = &buf[BthHdr::LEN + DethHdr::LEN + MadHdr::LEN] as *const u8 as *const CmConnectReply;
                *ptr
            };
            self.starting_psn = cm_connect_reply_hdr.starting_psn;
            self.qp_id = cm_connect_reply_hdr.local_qpn;
            return Ok(())
        }
    }

    async fn send_ready_to_use(&self, sock: &UdpSocket) -> anyhow::Result<()>{
        println!("sending ready to use");
        let mut bth_hdr = BthHdr::default();
        bth_hdr.opcode = u8::to_be(100);
        bth_hdr.dest_qpn = [0,0,1];
        let mut deth_hdr = DethHdr::default();
        deth_hdr.src_qpn = [0,0,1];
        let mut mad_hdr = MadHdr::default();
        mad_hdr.attribute_id = 0x0010;
        mad_hdr.transaction_id = self.transaction_id;
        let cm_ready_to_use_hdr = CmReadyToUse::default();
        let mut buf = Buffer::new();
        let b = buf.add(bth_hdr)
        .add(deth_hdr)
        .add(mad_hdr)
        .add(cm_ready_to_use_hdr)
        .as_slice();
        sock.send(b).await?;
        Ok(())
    }

    async fn send_disconnect_request(&self, sock: &UdpSocket) -> anyhow::Result<()>{
        let mut bth_hdr = BthHdr::default();
        bth_hdr.opcode = u8::to_be(100);
        bth_hdr.dest_qpn = [0,0,1];
        let mut deth_hdr = DethHdr::default();
        deth_hdr.src_qpn = [0,0,1];
        let mut mad_hdr = MadHdr::default();
        mad_hdr.attribute_id = 0x0010;
        mad_hdr.transaction_id = self.transaction_id;
        let cm_disconnect_request_hdr = CmDisconnectRequest::default();
        let mut buf = Buffer::new();
        let b = buf.add(bth_hdr)
            .add(deth_hdr)
            .add(mad_hdr)
            .add(cm_disconnect_request_hdr)
            .as_slice();
        sock.send(b).await?;
        Ok(())
    }

    async fn wait_for_disconnect_reply(&self, sock: &UdpSocket) -> anyhow::Result<()>{
        let now = tokio::time::Instant::now();
        let time_out_duration = tokio::time::Duration::from_secs(5);
        let mut buf = [0; 1024];
        loop {

            if now.elapsed() > time_out_duration{
                panic!("timeout");
            }

            let (len, _) = sock.recv_from(&mut buf).await?;
            let buf = &buf[..len];
            let bth_hdr = unsafe {
                let ptr = &buf[0] as *const u8 as *const BthHdr;
                *ptr
            };
            if bth_hdr.opcode != u8::from_be(100) && bth_hdr.dest_qpn != [0,0,1]{
                continue
            }
            let mad_hdr = unsafe {
                let ptr = &buf[32] as *const u8 as *const MadHdr;
                *ptr
            };
            if mad_hdr.attribute_id != 0x0014 {
                continue
            }
            let _cm_disconnect_reply_hdr = unsafe {
                let ptr = &buf[48] as *const u8 as *const CmDisconnectReply;
                *ptr
            };
            return Ok(())
        }
    }

}

struct Buffer{
    buffer: Vec<u8>,
}

impl Buffer{
    fn new() -> Self{
        Self{
            buffer: Vec::new(),
        }
    }
    fn add<T>(&mut self, t: T) -> &mut Self{
        let buf = unsafe {
            let ptr = &t as *const T as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<T>())
        };
        self.buffer.extend_from_slice(buf);
        self
    }
    fn as_slice(&self) -> &[u8]{
        self.buffer.as_slice()
    }
}

fn random_id<T>() -> T 
where Standard: Distribution<T>
{
    rand::random::<T>()
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
    let src_port = random_src_port();
    let ipv4 = match ip {
        std::net::IpAddr::V4(ipv4) => ipv4,
        _ => {
            panic!("ipv6 not supported");
        },
    };

    let data_ip_port = format!("{}:{}", ip.to_string(), src_port);  
    let packet_size = opt.packet_size;  
    let data_sock = UdpSocket::bind(data_ip_port).await?;
    let data_addr = format!("{}:{}", opt.dst, opt.port);
    let remote_data_addr = data_addr.parse::<SocketAddr>()?;
    let dst_ip = remote_data_addr.ip();
    let dst_ipv4 = match dst_ip {
        std::net::IpAddr::V4(ipv4) => ipv4,
        _ => {
            panic!("ipv6 not supported");
        },
    };
    let mut base_packet = MyPacket::new(dst_ipv4).await?;
    data_sock.connect(remote_data_addr).await?;
    println!("connected to {}", data_addr);
    if opt.messages.is_some() && opt.packets.is_some() {
        println!("establishing connection");

        let (qp_id, starting_psn) = if base_packet.create_qp().is_ok(){
            let qp_id = if let Some(qp_id) = base_packet.remote_qp_id{
                qp_id
            } else {
                panic!("qp id not found");
            };
            let starting_psn = if let Some(starting_psn) = base_packet.start_psn{
                starting_psn
            } else {
                panic!("starting psn not found");
            };
            (qp_id, starting_psn)
        } else {
            panic!("error creating qp");
        };

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let qp_id_dec = u32::from_be_bytes([0, qp_id[0], qp_id[1], qp_id[2]]);
        let seq_num_dec = u32::from_be_bytes([starting_psn[0], starting_psn[1], starting_psn[2], 0]);

        send_messages(&data_sock, opt.messages.unwrap(), opt.packets.unwrap(), qp_id_dec, seq_num_dec, packet_size, opt.delay).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        if base_packet.destroy_qp().is_err(){
            panic!("error destroying qp");
        }

        /* 
        let mut cm_handler = CmHandler::send_request(&data_sock, src_ipv4, dst_ipv4, src_port).await?;
        cm_handler.wait_for_reply(&data_sock).await?;
        cm_handler.send_ready_to_use(&data_sock).await?;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        println!("sending messages");
        let qp_id = cm_handler.qp_id;
        let qp_id_dec = u32::from_be_bytes([0, qp_id[0], qp_id[1], qp_id[2]]);
        let seq_num = cm_handler.starting_psn;
        let seq_num_dec = u32::from_be_bytes([seq_num[0], seq_num[1], seq_num[2], 0]);
        
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        cm_handler.send_disconnect_request(&data_sock).await?;
        cm_handler.wait_for_disconnect_reply(&data_sock).await?;
        */
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

struct MyPacket{
    oif: u32,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    udp_src_port: u16,
    udp_dst_port: u16,
    gw: Ipv4Addr,
    interface: NetworkInterface,
    start_psn: Option<[u8;3]>,
    local_qp_id: Option<[u8;3]>,
    remote_qp_id: Option<[u8;3]>,
    local_communicaton_id: Option<u32>,
    remote_communicaton_id: Option<u32>,
    transaction_id: Option<[u8;8]>,
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
}


impl MyPacket{
    pub async fn new(dst_ip: Ipv4Addr) -> anyhow::Result<Self> {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let (oif, gw) = get_oif(handle.clone(), dst_ip).await?;
        let (src_ip, src_mac, interface) = match get_src_mac_ip( dst_ip, oif){
            Ok((src_ip, src_mac, interface)) => {
                (src_ip, src_mac, interface)
            },
            Err(e) => {
                panic!("error getting src ip and mac: {:#?}", e);
            }
        };
        let gw = match gw {
            IpAddr::V4(gw_v4) => {
                gw_v4
            },
            IpAddr::V6(_) => {
                panic!("ipv6 not supported");
            },
        };
    
        let dst_mac = if let Ok(dst_mac) = get_gw_mac(handle, gw).await{
            dst_mac
        } else {
            panic!("error getting dst mac");
        };

        let(tx, rx) = match pnet::datalink::channel(&interface, Default::default()) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        Ok(Self{
            oif,
            src_ip,
            dst_ip,
            src_mac,
            dst_mac,
            udp_src_port: random_src_port(),
            udp_dst_port: 4791,
            gw,
            interface,
            start_psn: None,
            local_qp_id: None,
            remote_qp_id: None,
            local_communicaton_id: None,
            remote_communicaton_id: None,
            transaction_id: None,
            tx,
            rx,
        })
    }
    fn ethernet_hdr(&self) -> Vec<u8>{
        let mut ethernet_buffer = [0u8; 14];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    
        ethernet_packet.set_destination(self.dst_mac);
        ethernet_packet.set_source(self.src_mac);
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
        ethernet_packet.packet().to_vec()
    }

    fn ip_hdr(&self) -> Vec<u8>{
        let mut ip_buffer = [0u8; 20];
        let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(308);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
        ip_packet.set_source(self.src_ip);
        ip_packet.set_destination(self.dst_ip);
        ip_packet.set_identification(0);
        ip_packet.set_flags(0);
        ip_packet.set_fragment_offset(0);
        ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
        ip_packet.packet().to_vec()
    }

    fn udp_hdr(&self) -> Vec<u8>{
        let mut udp_buffer = [0u8; 8];
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
        udp_packet.set_source(self.udp_src_port);
        udp_packet.set_destination(4791);
        udp_packet.set_length(288);
        udp_packet.set_checksum(0);
        udp_packet.packet().to_vec()
    }

    fn connect_request(&mut self) -> Vec<u8> {
        let mut bth_hdr = BthHdr::default();
        bth_hdr.opcode = u8::to_be(100);
        bth_hdr.dest_qpn = [0,0,1];
        let mut deth_hdr = DethHdr::default();
        deth_hdr.src_qpn = [0,0,1];
        let q_key: u32 = 0x0000000080010000;
        deth_hdr.queue_key = u32::to_be(q_key);
        let mut mad_hdr = MadHdr::default();
        let tid: u64 = random_id();
        let tid_as_u8 = tid.to_be_bytes();
        mad_hdr.attribute_id = u16::to_be(0x0010);
        mad_hdr.transaction_id = tid_as_u8;
        mad_hdr.mgmt_class = u8::to_be(0x07);
        mad_hdr.base_version = u8::to_be(0x01);
        mad_hdr.class_version = u8::to_be(0x02);
        mad_hdr.method = u8::to_be(0x03);
        let mut cm_connect_request_hdr = CmConnectRequest::default();
        cm_connect_request_hdr.local_comm_id = u32::to_be(random_id());
        cm_connect_request_hdr.ip_cm_service_id = IpCmServiceId{
            prefix: [0,0,0,0,1],
            protocol: u8::to_be(0x06),
            destination_port: u16::to_be(0x4853),
        };

        let src_ip = u32::from_be_bytes(self.src_ip.octets());
        let dst_ip = u32::from_be_bytes(self.dst_ip.octets());
        

        cm_connect_request_hdr.local_ca_guid = random_id();
        cm_connect_request_hdr.local_qpn = random_id();
        cm_connect_request_hdr.starting_psn = random_id();
        cm_connect_request_hdr.partition_key = u16::to_be(0xffff);
        cm_connect_request_hdr.path_packet_payload_mtu = u8::to_be(0x0037);
        cm_connect_request_hdr.primary_local_port_lid = u16::to_be(65535);
        cm_connect_request_hdr.primary_remote_port_lid = u16::to_be(65535);
        cm_connect_request_hdr.ghost2 = u16::to_be(0xFFFF);
        cm_connect_request_hdr.primary_local_port_gid = src_ip;
        cm_connect_request_hdr.ghost4 = u16::to_be(0xFFFF);
        cm_connect_request_hdr.primary_remote_port_gid = dst_ip;
        cm_connect_request_hdr.primary_flow_label = random_id();
        cm_connect_request_hdr.primary_hop_limit = u8::to_be(0x40);
        cm_connect_request_hdr.ip_cm_private_data = IpCmPrivateData{
            ip_cm_major_minor_version: 0,
            ip_cm_ip_version: u8::to_be(0x40),
            ip_cm_source_port: u16::to_be(self.udp_src_port),
            ghost1: [0;12],
            ip_cm_destination_ip: u32::to_be(dst_ip),
            ghost2: [0;12],
            ip_cm_source_ip: u32::to_be(src_ip),
            ip_cm_consumer_private_data: [0;14],
        };
        self.local_qp_id = Some(cm_connect_request_hdr.local_qpn);
        self.local_communicaton_id = Some(cm_connect_request_hdr.local_comm_id);
        self.transaction_id = Some(mad_hdr.transaction_id);
    
        let invariant_crc = InvariantCrc{
            crc: random_id(),
        };
        let mut buf = Buffer::new();
        let b = buf.add(bth_hdr)
            .add(deth_hdr)
            .add(mad_hdr)
            .add(cm_connect_request_hdr)
            .add(invariant_crc)
            .as_slice();
        b.to_vec()
    }

    fn ready_to_use(&self) -> Vec<u8> {
        let mut bth_hdr = BthHdr::default();
        bth_hdr.opcode = u8::to_be(100);
        bth_hdr.dest_qpn = [0,0,1];
        let mut deth_hdr = DethHdr::default();
        deth_hdr.src_qpn = [0,0,1];
        let q_key: u32 = 0x0000000080010000;
        deth_hdr.queue_key = u32::to_be(q_key);
        let mut mad_hdr = MadHdr::default();
        mad_hdr.attribute_id = u16::to_be(0x0014);
        mad_hdr.transaction_id = self.transaction_id.unwrap();
        mad_hdr.mgmt_class = u8::to_be(0x07);
        mad_hdr.base_version = u8::to_be(0x01);
        mad_hdr.class_version = u8::to_be(0x02);
        mad_hdr.method = u8::to_be(0x03);
        let ready_to_use_hdr = CmReadyToUse::default();
        let invariant_crc = InvariantCrc{
            crc: random_id(),
        };
        let mut buf = Buffer::new();
        let b = buf.add(bth_hdr)
            .add(deth_hdr)
            .add(mad_hdr)
            .add(ready_to_use_hdr)
            .add(invariant_crc)
            .as_slice();
        b.to_vec()
    }

    fn disconnect_request(&self) -> Vec<u8> {
        let mut bth_hdr = BthHdr::default();
        bth_hdr.opcode = u8::to_be(100);
        bth_hdr.dest_qpn = [0,0,1];
        let mut deth_hdr = DethHdr::default();
        deth_hdr.src_qpn = [0,0,1];
        let q_key: u32 = 0x0000000080010000;
        deth_hdr.queue_key = u32::to_be(q_key);
        let mut mad_hdr = MadHdr::default();
        mad_hdr.attribute_id = u16::to_be(0x0015);
        mad_hdr.transaction_id = self.transaction_id.unwrap();
        mad_hdr.mgmt_class = u8::to_be(0x07);
        mad_hdr.base_version = u8::to_be(0x01);
        mad_hdr.class_version = u8::to_be(0x02);
        mad_hdr.method = u8::to_be(0x03);
        let mut disconnect_request_hdr = CmDisconnectRequest::default();
        disconnect_request_hdr.local_comm_id = self.local_communicaton_id.unwrap();
        disconnect_request_hdr.remote_comm_id = self.remote_communicaton_id.unwrap();
        disconnect_request_hdr.remote_qpn_eecn = self.remote_qp_id.unwrap();
        let invariant_crc = InvariantCrc{
            crc: random_id(),
        };
        let mut buf = Buffer::new();
        let b = buf.add(bth_hdr)
            .add(deth_hdr)
            .add(mad_hdr)
            .add(disconnect_request_hdr)
            .add(invariant_crc)
            .as_slice();
        b.to_vec()
    }

    fn build_disconnect_request(&self) -> Vec<u8>{
        let mut buf = Vec::new();
        buf.extend_from_slice(self.ethernet_hdr().as_slice());
        buf.extend_from_slice(self.ip_hdr().as_slice());
        buf.extend_from_slice(self.udp_hdr().as_slice());
        buf.extend_from_slice(self.disconnect_request().as_slice());
        buf
    }

    fn build_connect_request(&mut self) -> Vec<u8>{
        let mut buf = Vec::new();
        buf.extend_from_slice(self.ethernet_hdr().as_slice());
        buf.extend_from_slice(self.ip_hdr().as_slice());
        buf.extend_from_slice(self.udp_hdr().as_slice());
        buf.extend_from_slice(self.connect_request().as_slice());
        buf
    }

    fn build_ready_to_use(&self) -> Vec<u8>{
        let mut buf = Vec::new();
        buf.extend_from_slice(self.ethernet_hdr().as_slice());
        buf.extend_from_slice(self.ip_hdr().as_slice());
        buf.extend_from_slice(self.udp_hdr().as_slice());
        buf.extend_from_slice(self.ready_to_use().as_slice());
        buf
    }

    fn destroy_qp(&mut self) -> anyhow::Result<()>{
        println!("destroying qp");
        let disconnect_request = self.build_disconnect_request();
        if let Some(res) = self.tx.send_to(disconnect_request.as_slice(), None) {
            match res {
                Ok(_) => {
                    println!("disconnect_request packet sent");
                },
                Err(e) => {
                    panic!("failed to send disconnect_request: {:?}", e);
                }
            }
        } else {
            panic!("failed to send disconnect_request");
        }
        println!("waiting for disconnect_reply");
        let start = tokio::time::Instant::now();
        let timeout = tokio::time::Duration::from_secs(2);
        loop {
            if start.elapsed() > timeout {
                panic!("timeout");
            }
            let buf = self.rx.next().unwrap();
            let bth_hdr = unsafe {
                let ptr: *const BthHdr = &buf[EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN] as *const u8 as *const BthHdr;
                *ptr
            };
            let op_code = u8::from_be(bth_hdr.opcode);
            let qpn = u32::from_be_bytes([0, bth_hdr.dest_qpn[0], bth_hdr.dest_qpn[1], bth_hdr.dest_qpn[2]]);
            if op_code == 100 && qpn == 1 {
                let mad_hdr = unsafe {
                    let ptr = &buf[EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN] as *const u8 as *const MadHdr;
                    *ptr
                };
                let attribute_id = u16::from_be(mad_hdr.attribute_id);
                if attribute_id == 0x0016 {
                    println!("disconnect_reply received");
                    return Ok(());
                }
            }
        }
    }

    fn create_qp(&mut self) -> anyhow::Result<()>{

        let connect_request_packet = self.build_connect_request();
        println!("sending connect_request");
        if let Some(res) = self.tx.send_to(connect_request_packet.as_slice(), None) {
            match res {
                Ok(_) => {
                    info!("connect_request packet sent");
                },
                Err(e) => {
                    panic!("failed to send connect_request: {:?}", e);
                }
            }
        } else {
            panic!("failed to send connect_request");
        }
        println!("waiting for connect_reply");
        let start = tokio::time::Instant::now();
        let timeout = tokio::time::Duration::from_secs(2);
        loop {
            if start.elapsed() > timeout {
                panic!("timeout");
            }
            let buf = self.rx.next().unwrap();
            let bth_hdr = unsafe {
                let ptr = &buf[EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN] as *const u8 as *const BthHdr;
                *ptr
            };
            let op_code = u8::from_be(bth_hdr.opcode);
            let qpn = u32::from_be_bytes([0, bth_hdr.dest_qpn[0], bth_hdr.dest_qpn[1], bth_hdr.dest_qpn[2]]);
            if op_code == 100 && qpn == 1 {
                let mad_hdr = unsafe {
                    let ptr = &buf[EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN] as *const u8 as *const MadHdr;
                    *ptr
                };
                let attribute_id = u16::from_be(mad_hdr.attribute_id);
                if attribute_id == 0x0013 {
                    let connect_reply_hdr = unsafe {
                        let ptr = &buf[EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN] as *const u8 as *const CmConnectReply;
                        *ptr
                    };
                    self.remote_communicaton_id = Some(connect_reply_hdr.local_comm_id);
                    self.remote_qp_id = Some(connect_reply_hdr.local_qpn);
                    self.start_psn = Some(connect_reply_hdr.starting_psn);
                    let ready_to_use = self.build_ready_to_use();
                    println!("sending ready_to_use");
                    if let Some(res) = self.tx.send_to(ready_to_use.as_slice(), None) {
                        match res {
                            Ok(_) => {
                                println!("ready_to_use packet sent");
                                return Ok(());
                            },
                            Err(e) => {
                                panic!("failed to send ready_to_use: {:?}", e);
                            }
                        }
                    } else {
                        panic!("failed to send ready_to_use");
                    }
                }
            }
        }
    }
}

async fn get_gw_mac(handle: Handle, gw: Ipv4Addr) -> anyhow::Result<MacAddr> {
    let mut neighbors = handle.neighbours().get().set_family(IpVersion::V4).execute();
    let mut gw_neighbor_msg = None;
    while let Some(neighbor_msg) = neighbors.try_next().await? {
        for nla in &neighbor_msg.nlas {
            match nla {
                netlink_packet_route::rtnl::neighbour::nlas::Nla::Destination(dst) => {
                    let s: [u8;4] = dst.clone().try_into().unwrap();
                    let dst_ip = Ipv4Addr::from(s);
                    if dst_ip == gw {
                        gw_neighbor_msg = Some(neighbor_msg.clone());
                        break;
                    }
                },
                _ => {
                    continue;
                },
            } 
        }
    }

    if let Some(gw_neighbor_msg) = gw_neighbor_msg{
        for nla in &gw_neighbor_msg.nlas {
            match nla {
                netlink_packet_route::rtnl::neighbour::nlas::Nla::LinkLocalAddress(mac) => {
                    let s: [u8;6] = mac.clone().try_into().unwrap();
                    return Ok(MacAddr::from(s));
                },
                _ => {
                    continue;
                },
            } 
        }
    }
    panic!("dst mac not found");

}

fn get_src_mac_ip(dst_ip: Ipv4Addr, oif: u32) -> anyhow::Result<(Ipv4Addr, MacAddr, NetworkInterface)> {
    let all_interfaces = pnet::datalink::interfaces();
    let interface = if let Some(interface) = all_interfaces
        .iter()
        .find(|e| e.index == oif){
            interface
    } else {
        panic!("interface not found");
    };
    println!("interface: {:#?}", interface);
    let mut src_ip = None;
    let src_mac = interface.mac;
    for ip in &interface.ips{
        match ip{
            IpNetwork::V4(ipv4_network) => {
                src_ip = Some(ipv4_network.ip())
            },
            _ => {
                continue;
            },
        }
    }

    let src_ip = if let Some(src_ip) = src_ip {
        src_ip
    } else {
        panic!("src ip not found");
    };

    let src_mac = if let Some(src_mac) = src_mac {
        src_mac
    } else {
        panic!("src mac not found");
    };
    Ok((src_ip,src_mac, interface.clone()))
}

async fn get_oif(handle: Handle, dst_ip: Ipv4Addr) -> anyhow::Result<(u32,IpAddr)> {
    let mut dst_map: BTreeMap<u8, RouteMessage> = BTreeMap::new();
    let mut routes = handle.route().get(IpVersion::V4).execute();
    while let Some(route_msg) = routes.try_next().await? {
        if let Some((dst_prefix, dst_prefix_len)) = &route_msg.destination_prefix(){
            let ip_network = IpNetwork::new(*dst_prefix, *dst_prefix_len).unwrap();
            if ip_network.contains(std::net::IpAddr::V4(dst_ip)){
                dst_map.insert(dst_prefix_len.clone(), route_msg.clone());
            }
        }
    }
    for (_, route_msg) in dst_map.iter().rev(){
        if let Some(oif) = route_msg.output_interface(){
            if let Some(gateway) = route_msg.gateway(){
                return Ok((oif,gateway));
            }
        }
    }
    panic!("oif or gw not found");
}