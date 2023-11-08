use std::{collections::{HashMap, HashSet}, sync::Arc};
use aya::maps::{XskMap, MapData};
use common::BthHdr;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use socket::{
    Socket,
    SocketRxTx,
    SocketType,
    BufCustom
};
use log::info;
use afxdp::{mmap_area::{MmapArea, MmapAreaOptions}, buf::Buf};
use tokio::{
    task::JoinHandle,
    sync::RwLock,
};
use cli_server::cli_server::cli_server::UdpServerStats;

const BUFF_SIZE: usize = 4096;
const BUF_NUM: usize = 65535;
const BATCH_SIZE: usize = 64;

pub struct UdpServer{
    zero_copy: bool,
    interface_map: HashMap<String, u32>,
    queues: Option<u8>,
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
    pub ooo_packets: HashSet<u32>
}

impl UdpServer{
    pub fn new(zero_copy: bool, interface_map: HashMap<String, u32>, queues: Option<u8>) -> UdpServer {
        UdpServer{
            zero_copy,
            interface_map,
            queues,
        }
    }

    pub async fn run(&self, mut xsk_map: XskMap<MapData>, mut ctrl_rx: tokio::sync::mpsc::Receiver<UdpServerCommand>) -> anyhow::Result<()>{
        info!("running udp server");
        let stats_map = Arc::new(RwLock::new(StatsMap::default()));
        let stats_map_clone = Arc::clone(&stats_map);
        let mut jh_list = Vec::new();
        let jh = tokio::spawn( async move{
            loop {
                match ctrl_rx.recv().await{
                    Some(msg) => {
                        match msg {
                            UdpServerCommand::Get{tx} => {
                                let stats_map = stats_map.read().await;
                                let udp_server_stats = UdpServerStats{
                                    rx: stats_map.rx_packets as i32,
                                    out_of_order: stats_map.out_of_order as i32,
                                };
                                match tx.send(udp_server_stats){
                                    Ok(_) => {  },
                                    Err(_e) => { info!("failed to send stats reply"); },
                                }
                            },
                            UdpServerCommand::Reset{tx} => {                                
                                let mut stats_map = stats_map.write().await;
                                stats_map.rx_packets = 0;
                                stats_map.out_of_order = 0;
                                stats_map.last_seq_num = 0;
                                stats_map.last_expected = 0;
                                stats_map.ooo_packets.clear();
                                let udp_server_stats = UdpServerStats{
                                    rx: stats_map.rx_packets as i32,
                                    out_of_order: stats_map.out_of_order as i32,
                                };
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
        
        for (intf, _intf_idx) in &self.interface_map {
            let queues = if let Some(queues) = self.queues{
                queues
            } else {
                1
            };
            for queue in 0..queues{
                let stats_map = Arc::clone(&stats_map_clone);
                info!("creating socket for interface {}, queue {}", intf, queue);
                let options = MmapAreaOptions{ huge_tlb: false };
                let map_area = MmapArea::new(BUF_NUM, BUFF_SIZE, options);
                let (area, mut bufs) = match map_area {
                    Ok((ref area, bufs)) => (area, bufs),
                    Err(err) => panic!("no mmap for you: {:?}", err),
                };
                let mut rx_socket = Socket::new(area.clone(), &mut bufs, SocketRxTx::Rx, intf.clone(), BUF_NUM, self.zero_copy, queue as usize);
                let rx = match rx_socket.socket{
                    SocketType::Rx(ref mut rx) => { rx }
                    _ => panic!("socket type is not Rx"),
                };
                //let agg_tx = agg_tx.clone();
                xsk_map.set(queue as u32, rx.fd, 0)?;

                let jh: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move{
                    let rx = match rx_socket.socket{
                        SocketType::Rx(ref mut rx) => { rx }
                        _ => panic!("socket type is not Rx"),
                    };
                    let custom = BufCustom {};
                    //
                    loop {
                        let r = rx_socket.cq.service(&mut bufs, BATCH_SIZE);
                        match r {
                            Ok(n) => {
                                if n > 0 {
                                    info!("serviced {} packets", n);
                                }
                            }
                            Err(err) => panic!("error: {:?}", err),
                        };
                        match rx.try_recv(&mut rx_socket.v, BATCH_SIZE, custom) {
                            Ok(n) => {
                                if n > 0 {
                                    let mut stats_map = stats_map.write().await;
                                    stats_map.rx_packets += n;
                                    for _v in rx_socket.v.drain(0..) {
                                    //while let Some(_v) = rx_socket.v.pop_front(){
                                        let data = _v.get_data();
                                        let data_ptr = data.as_ptr() as usize;
                                        let bth_hdr = (data_ptr + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *const BthHdr;
                                        let seq_num = {
                                            let seq_num = unsafe { (*bth_hdr).psn_seq };
                                            u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]])
                                        };
                                        
                                        if stats_map.last_seq_num > 0 {
                                            if stats_map.last_seq_num + 1 != seq_num {
                                                stats_map.out_of_order += 1;
                                                stats_map.ooo_packets.insert(seq_num);
                                                stats_map.last_expected = stats_map.last_seq_num + 1;
                                                info!("out of order packet, expected {}, got {}. buffering", stats_map.last_seq_num + 1, seq_num);
                                            } else {
                                                if stats_map.last_expected == seq_num {
                                                    info!("received last missing seq {}", seq_num);
                                                }
                                                stats_map.last_seq_num = seq_num;
                                            }
                                        } else {
                                            stats_map.last_seq_num = seq_num;
                                        }
                                        loop {
                                            let l = stats_map.last_seq_num + 1;
                                            if stats_map.ooo_packets.remove(&(l)){
                                                info!("found buffered packet {}", l);
                                                stats_map.last_seq_num += 1;
                                            } else {
                                                break;
                                            }
                                        }
                                    }
                                    rx_socket.fq_deficit += n;
                                } else if rx_socket.fq.needs_wakeup() {
                                    rx.wake();
                                }
                            },
                            Err(err) => {
                                panic!("error: {:?}", err);
                            }
                        }
                        if rx_socket.fq_deficit >= BATCH_SIZE {
                            let r = rx_socket.fq.fill(&mut bufs, rx_socket.fq_deficit);
                            match r {
                                Ok(n) => {
                                    rx_socket.fq_deficit -= n;
                                }
                                Err(err) => panic!("error: {:?}", err),
                            }
                        }
                    }
                });
                jh_list.push(jh); 
            }
        }
        futures::future::join_all(jh_list).await;
        info!("udp server finished");
        Ok(())
    }
}