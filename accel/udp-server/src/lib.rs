use std::{collections::{HashMap, HashSet}, sync::{Mutex, Arc}};
use aya::maps::{XskMap, MapData, HashMap as AyaHashMap};
use common::{BthHdr, Stats};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use socket::{
    Socket,
    SocketRxTx,
    SocketType,
    BufCustom
};
use log::info;
use afxdp::{mmap_area::{MmapArea, MmapAreaOptions}, buf::Buf, buf_mmap::BufMmap};
use tokio::task::JoinHandle;
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
    Get{tx: tokio::sync::oneshot::Sender<UdpServerStats>}
    
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

        let stats = Arc::new(Mutex::new(UdpServerStats{
            rx: 0,
            out_of_order: 0,
        }));
        let stats_clone = Arc::clone(&stats);

        //let (agg_tx,agg_rx):(tokio::sync::mpsc::Sender<BufMmap<'_, BufCustom>>, tokio::sync::mpsc::Receiver<BufMmap<'_, BufCustom>>) = tokio::sync::mpsc::channel(100);
        let mut jh_list = Vec::new();
         
        let jh = tokio::spawn( async move{
            let stats = Arc::clone(&stats);
            loop {
                match ctrl_rx.recv().await{
                    Some(msg) => {
                        match msg {
                            UdpServerCommand::Get{tx} => {
                                let stats = stats.lock().unwrap();
                                let _ = tx.send(stats.clone());
                            }
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
        
        let ooo_map = Arc::new(Mutex::new(HashSet::new()));
        let mut last_expected = 0;
        info!("interface map: {:?}", self.interface_map);
        let mut last_seq_num = 0;
        let mut rx_packets = 0;
        let mut out_of_order = 0;
        for (intf, intf_idx) in &self.interface_map {
            let queues = if let Some(queues) = self.queues{
                queues
            } else {
                1
            };
            for queue in 0..queues{
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
                let stats = Arc::clone(&stats_clone);
                let ooo_map = Arc::clone(&ooo_map);
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
                                    rx_packets += n;
                                    //info!("received batch with {} packets", n);
                                    for _v in rx_socket.v.drain(0..) {
                                    //while let Some(_v) = rx_socket.v.pop_front(){
                                        let data = _v.get_data();
                                        let data_ptr = data.as_ptr() as usize;
                                        let bth_hdr = (data_ptr + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *const BthHdr;
                                        let seq_num = {
                                            let seq_num = unsafe { (*bth_hdr).psn_seq };
                                            u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]])
                                        };
                                        //info!("seq_num: {}, last_seq_num: {}", seq_num, last_seq_num);
                                        let mut ooo_map = ooo_map.lock().unwrap();
                                        if last_seq_num > 0 {
                                            
                                            if last_seq_num + 1 != seq_num {
                                                out_of_order += 1;
                                                ooo_map.insert(seq_num);
                                                last_expected = last_seq_num + 1;
                                                info!("out of order packet, expected {}, got {}. buffering", last_seq_num + 1, seq_num);
                                                loop {
                                                    if ooo_map.remove(&(last_seq_num + 1)){
                                                        info!("found buffered packet {}", last_seq_num + 1);
                                                        last_seq_num += 1;
                                                    } else {
                                                        break;
                                                    }
                                                }

                                            } else {
                                                if last_expected == seq_num {
                                                    info!("received last missing seq {}", seq_num);
                                                }
                                                last_seq_num = seq_num;
                                            }
                                        } else {
                                            last_seq_num = seq_num;
                                        }
                                        loop {
                                            if ooo_map.remove(&(last_seq_num + 1)){
                                                info!("found buffered packet 2 {}", last_seq_num + 1);
                                                last_seq_num += 1;
                                            } else {
                                                break;
                                            }
                                        }
                                        let mut stats = stats.lock().unwrap();
                                        stats.rx = rx_packets as i32;
                                        stats.out_of_order = out_of_order;
                                        /*
                                        match agg_tx.send(_v).await{
                                            Ok(_) => {
                                                
                                                //info!("sent to agg")
                                            },
                                            Err(e) => {
                                                panic!("error sending to agg: {}", e)
                                            }
                                        }
                                        */
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

pub async fn aggregator(mut rx: tokio::sync::mpsc::Receiver<BufMmap<'_, BufCustom>>) -> anyhow::Result<()>{
    info!("starting agg");
    let mut last_seq_num = 0;
    while let Some(v) = rx.recv().await{
        info!("got packet in agg");
        let data = v.get_data();
        let data_ptr = data.as_ptr() as usize;
        let bth_hdr = (data_ptr + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *const BthHdr;
        let seq_num = {
            let seq_num = unsafe { (*bth_hdr).psn_seq };
            u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]])
        };
        info!("seq_num: {}", seq_num);
        if last_seq_num > 0 {
            if last_seq_num + 1 != seq_num {
                info!("out of order packet, expected {}, got {}", last_seq_num + 1, seq_num);
            } else {
                info!("received seq {}", seq_num);
            }
            last_seq_num = seq_num;
        }
    }
    Ok(())
}