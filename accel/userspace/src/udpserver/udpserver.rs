use std::{collections::{HashMap, HashSet}, sync::{Arc, Mutex}};
use aya::maps::{XskMap, MapData, HashMap as AyaHashMap};
use common::{
    BthHdr,
    InterfaceQueue,
    CmConnectReply,
    CmConnectRequest,
    CmReadyToUse,
    CmDisconnectReply,
    CmDisconnectRequest,
    MadHdr, DethHdr,
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
    pub fn new(interface_map: HashMap<String, Interface>, xsk_map: Arc<Mutex<XskMap<MapData>>>, interface_queue_map: Arc<Mutex<AyaHashMap<MapData, InterfaceQueue, u32>>>,) -> UdpServer {
        UdpServer{
            interface_map,
            xsk_map,
            interface_queue_map,
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
            let stats_map = Arc::clone(&stats_map);
            let xsk_map = self.xsk_map.clone();
            info!("creating afxdp socket for interface {}", intf_name);
            let frame_size = BUFF_SIZE as u32;
            let rx_queue_len = 8192 * 2;
            let tx_queue_len = 8192;
            let rx_cooldown = 10;
            let interface_queue_map = Arc::clone(&self.interface_queue_map);
            let mut af_xdp = AfXdp::new(intf.idx.unwrap(), intf_name.clone(), rx_queue_len, tx_queue_len, frame_size, rx_cooldown, intf.queues.clone());
            let (rx_channel, tx_channel) = af_xdp.setup(xsk_map, interface_queue_map, 0).unwrap();
            let tx_channel = Arc::new(Mutex::new(tx_channel));
            let rx_f = move |queue: &mut rx::Queue<'_, WithCooldown<Arc<AsyncFd<afxdp_socket::Fd>>>>| {
                queue.for_each(|mut _header, payload| {
                    info!("received packet");
                    let data_ptr = payload.as_ptr() as usize;
                    let bth_hdr = data_ptr as *const BthHdr;     
                    let deth_hdr = (data_ptr + BthHdr::LEN) as *mut DethHdr;
                    let mad_hdr = (data_ptr + BthHdr::LEN + DethHdr::LEN) as *mut MadHdr;
                    let attribute_id = u16::from_be(unsafe { (*mad_hdr).attribute_id });
                    if attribute_id == 0x0010 {
                        unsafe { (*mad_hdr).attribute_id = u16::to_be(0x8013) };
                        //let connection_request_hdr = (data_ptr + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN) as *const CmConnectRequest;
                        let mut connection_reply_hdr = CmConnectReply::default();
                        connection_reply_hdr.local_qpn = random_id();
                        connection_reply_hdr.starting_psn = random_id();
                        let mut new_payload = Payload::new();
                        new_payload.add(bth_hdr)
                            .add(deth_hdr)
                            .add(mad_hdr)
                            .add(connection_reply_hdr);
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