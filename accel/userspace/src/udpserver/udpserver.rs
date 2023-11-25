use std::{collections::{HashMap, HashSet}, sync::{Arc, Mutex}};
use aya::maps::{XskMap, MapData, HashMap as AyaHashMap};
use common::{
    QpState,
    CmState,
    BthHdr,
    InterfaceQueue,
    CmConnectReply,
    CmConnectRequest,
    CmReadyToUse,
    CmDisconnectReply,
    CmDisconnectRequest,
    MadHdr, DethHdr, InvariantCrc,
};
use log::info;
use rand::distributions::{Standard, Distribution};
use tokio::{
    task::JoinHandle,
    io::unix::AsyncFd,
};
use cli_server::cli_server::cli_server::UdpServerStats;
use s2n_quic_xdp::{
    io::rx::{self, WithCooldown},
    socket as afxdp_socket,
};
use afxdp::{self, AfXdp, Packet};
use s2n_quic_core::io::{
    tx::Error,
    rx::Queue
};
use s2n_quic_core::io::tx::Tx as _;
use s2n_quic_core::io::tx::Queue as _;

use crate::config::config::Interface;

const BUFF_SIZE: usize = 2048;

pub struct UdpServer{
    interface_map: HashMap<String, Interface>,
    interface_queue_map: Arc<Mutex<AyaHashMap<MapData, InterfaceQueue, u32>>>,
    xsk_map: Arc<Mutex<XskMap<MapData>>>,
    cm_state_map: Arc<Mutex<AyaHashMap<MapData, [u8;8], CmState>>>,
    qp_state_map: Arc<Mutex<AyaHashMap<MapData, [u8;3], QpState>>>,
}

pub enum UdpServerCommand{
    Get{tx: tokio::sync::oneshot::Sender<UdpServerStats>},
    Reset{tx: tokio::sync::oneshot::Sender<UdpServerStats>},
}

pub enum StatsCommand{
    Get(tokio::sync::oneshot::Sender<String>),
}

#[derive(Default)]
pub struct StatsMap{
    pub last_expected: u32,
    pub last_seq_num: u32,
    pub rx_packets: usize,
    pub out_of_order: u32,
    pub in_order: u32,
    pub ooo_packets: HashSet<u32>
}

impl UdpServer{
    pub fn new(
            interface_map: HashMap<String, Interface>,
            xsk_map: Arc<Mutex<XskMap<MapData>>>,
            interface_queue_map: Arc<Mutex<AyaHashMap<MapData, InterfaceQueue, u32>>>,
            cm_state_map: Arc<Mutex<AyaHashMap<MapData, [u8;8], CmState>>>,
            qp_state_map: Arc<Mutex<AyaHashMap<MapData, [u8;3], QpState>>>,
        ) -> UdpServer {
        UdpServer{
            interface_map,
            xsk_map,
            interface_queue_map,
            cm_state_map,
            qp_state_map,
        }
    }
    pub async fn run(&self, mut ctrl_rx: tokio::sync::mpsc::Receiver<UdpServerCommand>) -> anyhow::Result<()>{
        info!("running udp server");
        let stats_map = Arc::new(Mutex::new(StatsMap::default()));
        let stats_map_clone = Arc::clone(&stats_map);
        let mut jh_list: Vec<JoinHandle<Result<(), Error>>> = Vec::new();
        let jh = tokio::spawn( async move{
            loop {
                match ctrl_rx.recv().await{
                    Some(msg) => {
                        match msg {
                            UdpServerCommand::Get{tx} => {
                                let stats_map = Arc::clone(&stats_map_clone);
                                let stats_map = stats_map.lock().unwrap();
                                let udp_server_stats = UdpServerStats{
                                    rx: stats_map.rx_packets as i32,
                                    out_of_order: stats_map.out_of_order as i32,
                                    in_order: stats_map.in_order as i32,
                                };
                                match tx.send(udp_server_stats){
                                    Ok(_) => {  },
                                    Err(_e) => { info!("failed to send stats reply"); },
                                }
                            },
                            UdpServerCommand::Reset{tx} => {       
                                let stats_map = Arc::clone(&stats_map_clone);
                                let mut stats_map = stats_map.lock().unwrap();
                                let udp_server_stats = UdpServerStats{
                                    rx: stats_map.rx_packets as i32,
                                    out_of_order: stats_map.out_of_order as i32,
                                    in_order: stats_map.in_order as i32,
                                };
                                stats_map.rx_packets = 0;
                                stats_map.out_of_order = 0;
                                stats_map.last_seq_num = 0;
                                stats_map.last_expected = 0;
                                stats_map.in_order = 0;
                                stats_map.ooo_packets.clear();
                                match tx.send(udp_server_stats){
                                    Ok(_) => {  },
                                    Err(_e) => { info!("failed to send stats reply"); },
                                }
                            },
                        } 
                    },
                    None => {
                        info!("ctrl channel closed");
                        break;
                    }
                }
            }
            Ok(())
        });
        jh_list.push(jh);
        for (intf_name, intf) in &self.interface_map {
            let xsk_map = self.xsk_map.clone();
            info!("creating afxdp socket for interface {}", intf_name);
            let frame_size = BUFF_SIZE as u32;
            let rx_queue_len = 8192 * 2;
            let tx_queue_len = 8192;
            let rx_cooldown = 10;
            let interface_queue_map = Arc::clone(&self.interface_queue_map);
            let cm_state_map = Arc::clone(&self.cm_state_map);
            let qp_state_map = Arc::clone(&self.qp_state_map);
            let mut af_xdp = AfXdp::new(intf.idx.unwrap(), intf_name.clone(), rx_queue_len, tx_queue_len, frame_size, rx_cooldown, intf.queues.clone());
            let (rx_channel, tx_channel) = af_xdp.setup(xsk_map, interface_queue_map, 0).unwrap();
            let tx_channel = Arc::new(Mutex::new(tx_channel));
            let rx_f = move |queue: &mut rx::Queue<'_, WithCooldown<Arc<AsyncFd<afxdp_socket::Fd>>>>| {
                queue.for_each(|mut _header, payload| {
                    info!("received packet");
                    let data_ptr = payload.as_ptr() as usize;
                    let bth_hdr = data_ptr as *const BthHdr;
                    let op_code = u8::from_be(unsafe { (*bth_hdr).opcode });
                    info!("received BTH packet with opcode {}", op_code);
                    //let deth_hdr = (data_ptr + BthHdr::LEN) as *mut DethHdr;
                    let mad_hdr = (data_ptr + BthHdr::LEN + DethHdr::LEN) as *mut MadHdr;
                    let attribute_id = u16::from_be(unsafe { (*mad_hdr).attribute_id });
                    info!("received MAD packet with attribute id {}", attribute_id);
                    if attribute_id == 0x0010 || attribute_id == 0x0015{
                        let local_port = _header.path.local_address.port;
                        let remote_port = _header.path.remote_address.port;
                        _header.path.local_address.port = remote_port;
                        _header.path.remote_address.port = local_port;
                        let mut new_payload = Payload::new();
                        
                        let mut new_bth_hdr = BthHdr::default();
                        new_bth_hdr.dest_qpn = [0,0,1];
                        new_bth_hdr.part_key = u16::to_be(65535);
                        new_bth_hdr.opcode = u8::to_be(100);

                        let mut new_deth_hdr = DethHdr::default();
                        new_deth_hdr.queue_key = u32::to_be(0x0000000080010000);
                        new_deth_hdr.src_qpn = [0,0,1];

                        new_payload.add(new_bth_hdr)
                        .add(new_deth_hdr);

                        let mut new_mad_hdr = MadHdr::default();
                        new_mad_hdr.base_version = u8::to_be(0x01);
                        new_mad_hdr.mgmt_class = u8::to_be(0x07);
                        new_mad_hdr.class_version = u8::to_be(0x02);
                        new_mad_hdr.method = u8::to_be(0x03);
                        new_mad_hdr.transaction_id = unsafe { (*mad_hdr).transaction_id };
                        new_mad_hdr.attribute_id = u16::to_be(0x0013);
     
                        if attribute_id == 0x0010{
                            let comm_request_hdr = (data_ptr + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN) as *mut CmConnectRequest;
                            new_mad_hdr.attribute_id = u16::to_be(0x0013);
                            new_payload.add(new_mad_hdr);
                            let mut connection_reply_hdr = CmConnectReply::default();
                            connection_reply_hdr.local_comm_id = random_id();
                            connection_reply_hdr.remote_comm_id = unsafe { (*comm_request_hdr).local_comm_id };
                            connection_reply_hdr.local_qpn = random_id();
                            connection_reply_hdr.starting_psn = random_id();
                            new_payload.add(connection_reply_hdr);
                            
                            let starting_psn_dec = u32::from_be_bytes([0, connection_reply_hdr.starting_psn[0], connection_reply_hdr.starting_psn[1], connection_reply_hdr.starting_psn[2]]);
                            let cm_state = &CmState{
                                qp_id: connection_reply_hdr.local_qpn,
                                state: 1,
                                first_psn: starting_psn_dec,
                            };
                            let mut cm_state_map = cm_state_map.lock().unwrap();
                            if cm_state_map.insert(&new_mad_hdr.transaction_id, cm_state, 0).is_err(){
                                panic!("failed to insert cm state");
                            }

                            let qp_state = &QpState{
                                qp_id: connection_reply_hdr.local_qpn,
                                first_psn: starting_psn_dec,
                                last_psn: starting_psn_dec - 1,
                            };

                            let mut qp_state_map = qp_state_map.lock().unwrap();
                            if qp_state_map.insert(&connection_reply_hdr.local_qpn, qp_state, 0).is_err(){
                                panic!("failed to insert qp state");
                            }

                        } else if attribute_id == 0x0015{
                            new_mad_hdr.attribute_id = u16::to_be(0x0016);
                            new_payload.add(new_mad_hdr);
                            let disconnect_request_hdr = (data_ptr + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN) as *mut CmDisconnectRequest;
                            let mut disconnect_reply_hdr = CmDisconnectReply::default();
                            disconnect_reply_hdr.local_comm_id = random_id();
                            disconnect_reply_hdr.remote_comm_id = unsafe { (*disconnect_request_hdr).local_comm_id };
                            new_payload.add(disconnect_reply_hdr);

                            let mut cm_state_map = cm_state_map.lock().unwrap();
                            let qp_id = if let Ok(cm_state) = cm_state_map.get(&new_mad_hdr.transaction_id, 0){
                                cm_state.qp_id
                            } else {
                                panic!("failed to get cm state");
                            };
                            let mut qp_state_map = qp_state_map.lock().unwrap();
                            if qp_state_map.remove(&qp_id).is_err(){
                                panic!("failed to remove qp state");
                            }
                            if cm_state_map.remove(&new_mad_hdr.transaction_id).is_err(){
                                panic!("failed to remove cm state");
                            }
                        }

                        let invariant_crc = InvariantCrc{
                            crc: random_id(),
                        };
                        new_payload.add(invariant_crc);
            
                        let packet = afxdp::Packet{
                            path: _header.path,
                            ecn: _header.ecn,
                            counter: 0,
                            data: new_payload.data.to_vec(),
                        };
                        let mut tx_channel = tx_channel.lock().unwrap();
                        tx_channel.queue(|queue| {
                            queue.push(packet.clone()).unwrap();
                        });
                    }
                
                });
            };
            let jh = tokio::spawn( async move{
                af_xdp.clone().recv(rx_channel, rx_f).await;
                Ok(())
            });
            jh_list.push(jh);
        }
        futures::future::join_all(jh_list).await;
        info!("udp server finished");
        Ok(())
    }
}

struct Payload{
    data: Vec<u8>,
}

impl Payload{
    pub fn new() -> Payload{
        Payload{
            data: Vec::new(),
        }
    }
    fn add<T>(&mut self, t: T) -> &mut Self{
        let buf = unsafe {
            let ptr = &t as *const T as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<T>())
        };
        self.data.extend_from_slice(buf);
        self
    }
    pub fn as_slice(&self) -> &[u8]{
        self.data.as_slice()
    }
}

fn random_id<T>() -> T 
where Standard: Distribution<T>
{
    rand::random::<T>()
}