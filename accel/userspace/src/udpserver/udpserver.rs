use std::{collections::{HashMap, HashSet}, sync::{Arc, Mutex}};
use aya::maps::{XskMap, MapData, HashMap as AyaHashMap};
use common::{BthHdr, InterfaceQueue};
use log::info;
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
            let (rx_channel, _tx_channel) = af_xdp.setup(xsk_map, interface_queue_map, 0).unwrap();
            //let tx_channel_m = Arc::new(Mutex::new(tx_channel));

            let rx_f = move |queue: &mut rx::Queue<'_, WithCooldown<Arc<AsyncFd<afxdp_socket::Fd>>>>| {

                queue.for_each(|mut _header, payload| {
                    let stats_map = Arc::clone(&stats_map);
                    let mut stats_map = stats_map.lock().unwrap();
                    stats_map.rx_packets += 1;
                    let data_ptr = payload.as_ptr() as usize;        
                    let bth_hdr = data_ptr as *const BthHdr;
                    let seq_num = {
                        let seq_num = unsafe { (*bth_hdr).psn_seq };
                        u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]])
                    };
                    if stats_map.last_seq_num > 0 {
                        if stats_map.last_seq_num + 1 != seq_num {
                            stats_map.out_of_order += 1;
                            stats_map.ooo_packets.insert(seq_num);
                            stats_map.last_expected = stats_map.last_seq_num + 1;
                        } else {
                            stats_map.last_seq_num = seq_num;
                            stats_map.in_order += 1;
                        }
                    } else {
                        stats_map.in_order += 1;
                        stats_map.last_seq_num = seq_num;
                    }
                    loop {
                        let l = stats_map.last_seq_num + 1;
                        if stats_map.ooo_packets.remove(&(l)){
                            stats_map.last_seq_num += 1;
                        } else {
                            break;
                        }
                    }
                    //info!("path {:?}", _header.path);
                });
                //packet_list
            };
            let jh = tokio::spawn( async move{
                af_xdp.clone().recv(rx_channel, rx_f).await;
                //af_xdp.send(tx_channels, umem.clone(), t_rx).await;
                Ok(())
            });
            jh_list.push(jh);
        }
        futures::future::join_all(jh_list).await;
        info!("udp server finished");
        Ok(())
    }
}

