use std::{sync::Arc, future, collections::HashMap};

use aya::{
    maps::{XskMap, MapData},
    Bpf
};
use std::os::fd::{RawFd, AsRawFd};
use socket::{
    Socket,
    SocketRxTx,
    SocketType,
    BufCustom
};
use log::info;
use afxdp::{mmap_area::{MmapArea, MmapAreaOptions}, buf_mmap::BufMmap, socket::SocketRx};
use tokio::task::JoinHandle;


const BUFF_SIZE: usize = 2048;
const BUF_NUM: usize = 65535;
const BATCH_SIZE: usize = 32;

pub struct UdpServer{
    zero_copy: bool,
    interface_map: HashMap<String, u32>,
}

impl UdpServer{
    pub fn new(zero_copy: bool, interface_map: HashMap<String, u32>) -> UdpServer {
        UdpServer{
            zero_copy,
            interface_map,
        }
    }
    pub async fn run(&self, mut xsk_map: XskMap<MapData>) -> anyhow::Result<()>{
        info!("running udp server");
        let mut jh_list = Vec::new();
        info!("interface map: {:?}", self.interface_map);

        for (intf, intf_idx) in &self.interface_map {
            let options = MmapAreaOptions{ huge_tlb: false };
            let map_area = MmapArea::new(BUF_NUM, BUFF_SIZE, options);
            let (area, mut bufs) = match map_area {
                Ok((ref area, bufs)) => (area, bufs),
                Err(err) => panic!("no mmap for you: {:?}", err),
            };
            let mut rx_socket = Socket::new(area.clone(), &mut bufs, SocketRxTx::Rx, intf.clone(), BUF_NUM, self.zero_copy);
            let rx = match rx_socket.socket{
                SocketType::Rx(ref mut rx) => { rx }
                _ => panic!("socket type is not Rx"),
            };
            xsk_map.set(intf_idx.clone(), rx.fd, 0)?;
            let jh: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move{
                let rx = match rx_socket.socket{
                    SocketType::Rx(ref mut rx) => { rx }
                    _ => panic!("socket type is not Rx"),
                };
                let custom = BufCustom {};
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
                                while let Some(v) = rx_socket.v.pop_front(){
                                    info!("received packet");
                                }
                                rx_socket.fq_deficit += n;
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
        futures::future::join_all(jh_list).await;
        info!("udp server finished");
        Ok(())
    }
}