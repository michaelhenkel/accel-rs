use aya::{
    maps::{XskMap, MapData},
    Bpf
};
use socket::{
    Socket,
    SocketRxTx,
    SocketType,
    BufCustom
};
use log::info;
use afxdp::mmap_area::{MmapArea, MmapAreaOptions};


const BUFF_SIZE: usize = 2048;
const BUF_NUM: usize = 65535 * 4;
const BATCH_SIZE: usize = 32;

pub struct UdpServer{
    ingress_intf: String,
    intf_idx: u32,
    xsk_map: XskMap<MapData>,
}

impl UdpServer{
    pub fn new(ingress_intf: String, intf_idx: u32, xsk_map: XskMap<MapData>) -> UdpServer {
        UdpServer{
            ingress_intf,
            intf_idx,
            xsk_map,
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()>{
        info!("running udp server");
        let options = MmapAreaOptions{ huge_tlb: false };
        let map_area = MmapArea::new(BUF_NUM, BUFF_SIZE, options);
        let (area, mut bufs) = match map_area {
            Ok((area, bufs)) => (area, bufs),
            Err(err) => panic!("no mmap for you: {:?}", err),
        };
        let mut rx_socket = Socket::new(area.clone(), &mut bufs, SocketRxTx::Rx, self.ingress_intf.clone(), BUF_NUM);
        let rx = match rx_socket.socket{
            SocketType::Rx(ref mut rx) => { Some(rx) }
            _ => None,
        };
        let rx = rx.unwrap();
        self.xsk_map.set(0, rx.fd, 0)?;

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
    }
}